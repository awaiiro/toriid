//! wstunnel layer: WireGuard wrapped in WSS/TLS:443 -> carrier server -> upstream WireGuard endpoint.
//! The client process is supervised by the daemon itself (the daemon lives in system.slice, so there
//! are no cgroup issues), no systemd-run.
//! The real path (tunnel_works) is always the verdict. A probe (101) may only undo a downgrade; it can
//! never overrule the real path.
use crate::config::WstConf;
use crate::modes::Ctx;
use crate::nl::{wg, RuleSpec};
use crate::paths::*;
use crate::probe::{self, Carrier};
use crate::state::{self, CarrierWait};
use crate::util::{self, Tsv};
use anyhow::{anyhow, Context, Result};
use rand::seq::SliceRandom;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

pub const WST_LIVE_FAIL_TTL: u64 = 86400; // 24h
pub const WST_VARIANT_TTL: u64 = 604800; // 7d
pub const PROBE_PORT: u16 = 51897; // deliberately not WST_LOCAL_PORT: colliding with the live tunnel turns a silent probe into a daily outage

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Clean,     // no SNI + verify cert (Let's Encrypt cert for the bare IP)
    Named,     // real SNI (sslip.io) + verify cert
    Disguised, // fake SNI (www.microsoft.com) + no verification - downgrade tier, a MITM can read WST_SECRET
}
impl Variant {
    pub fn as_str(self) -> &'static str {
        match self {
            Variant::Clean => "clean",
            Variant::Named => "named",
            Variant::Disguised => "disguised",
        }
    }
    pub fn parse(s: &str) -> Option<Variant> {
        Some(match s {
            "clean" => Variant::Clean,
            "named" => Variant::Named,
            "disguised" => Variant::Disguised,
            _ => return None,
        })
    }
}

/// Client process supervised by the daemon.
#[derive(Default)]
pub struct Client {
    /// (generation, child). Each client_up bumps the generation; a stale supervisor that sees a newer
    /// generation exits. Otherwise variant 1's supervisor (mid 500ms sleep) would latch onto variant 2's
    /// child, and when it exited both supervisors would respawn one each.
    child: Arc<Mutex<Option<(u64, Child)>>>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    desired: Arc<AtomicBool>,
    pub lines: Arc<Mutex<VecDeque<String>>>,
    pub variant: Option<Variant>,
}

impl Client {
    /// Our own child is alive, or a client released by a previous daemon is running (daemon restarts keep the tunnel).
    pub fn running(&self) -> bool {
        let mut g = self.child.lock().unwrap();
        match g.as_mut() {
            Some((_, c)) => matches!(c.try_wait(), Ok(None)),
            None => !stray_pids().is_empty(),
        }
    }
    /// Last n lines of the current attempt (after the last ==== marker), ANSI stripped. The log is a file,
    /// not a pipe through the daemon: the child writes straight to it and survives the daemon dying
    /// (observed: a daemon restart once killed the tunnel because the pipe hit EPIPE).
    pub fn recent_lines(&self, n: usize) -> Vec<String> {
        log_tail_since_marker(n)
    }
}

fn client_args(conf: &WstConf, variant: Variant, local_port: u16, server: &str) -> Vec<String> {
    let mut a = vec![
        "client".to_string(),
        "-L".into(),
        format!("udp://127.0.0.1:{}:{}?timeout_sec=0", local_port, conf.upstream),
    ];
    match variant {
        Variant::Named => {
            a.push("--tls-sni-override".into());
            a.push(conf.sni_named.clone());
            a.push("--tls-verify-certificate".into());
        }
        Variant::Disguised => {
            a.push("--tls-sni-override".into());
            a.push(conf.sni_fallback.clone());
        }
        Variant::Clean => {
            a.push("--tls-sni-disable".into());
            if conf.verify {
                a.push("--tls-verify-certificate".into());
            }
        }
    }
    a.push(format!("wss://{}:{}", server, conf.port));
    a
}

/// Is someone listening on the local UDP port? Try to bind it: EADDRINUSE = ready. Does not read /proc/net/udp.
fn udp_port_taken(port: u16) -> bool {
    matches!(std::net::UdpSocket::bind(("127.0.0.1", port)), Err(e) if e.kind() == std::io::ErrorKind::AddrInUse)
}

// ── carrier ──────────────────────────────────────────────────────
/// Carrier selected for this session. Stays fixed for its lifetime (route pinning relies on it); cleared on teardown.
pub fn active_carrier(conf: &WstConf, ssid: Option<&str>) -> String {
    if let Some(p) = util::read_trim(WST_ACTIVE) {
        if conf.servers.contains(&p) {
            return p;
        }
    }
    let picked = pick_carrier(conf, ssid);
    let _ = util::write_atomic(WST_ACTIVE, &picked, 0o644);
    picked
}

/// Only one -> that one; the one that last worked on this network -> that one; otherwise **random**
/// (round-robin is itself a recognizable pattern).
pub fn pick_carrier(conf: &WstConf, ssid: Option<&str>) -> String {
    if conf.servers.len() == 1 {
        return conf.servers[0].clone();
    }
    if let Some(s) = ssid {
        if let Some((pref, _)) = Tsv::get(WST_PREF_DB, s) {
            if conf.servers.contains(&pref) {
                return pref;
            }
        }
    }
    conf.servers.choose(&mut rand::thread_rng()).cloned().unwrap_or_else(|| conf.server.clone())
}

pub fn carrier_remember(ssid: Option<&str>, carrier: &str) {
    if let Some(s) = ssid {
        let _ = Tsv::put(WST_PREF_DB, s, carrier);
    }
}

/// The /32 to the carrier must go via the physical NIC: a /32 in the main table matches at the
/// suppress_prefixlength 0 rule, before the catch-all can send it into wg0. **Do not infer it with
/// `ip route get`** - with a Tailscale exit node active it answers tailscale0.
pub async fn carrier_route_on(ctx: &Ctx, _conf: &WstConf, carrier: &str) -> Result<()> {
    let ip: Ipv4Addr = carrier.parse().context("carrier address is not IPv4")?;
    let phy = ctx.nl.phy_dev().await?.ok_or_else(|| anyhow!("no physical NIC is UP"))?;
    let gw = ctx.nl.default_gw(phy.index).await?;
    ctx.nl.route_replace(ip, 32, gw, phy.index, 254).await.context("pinning carrier /32 route")?;
    // ip rule as a second safeguard (for topologies without the suppress rule)
    ctx.nl.rule_add(RuleSpec { prio: WST_CARRIER_PRIO, table: 254, dst: Some((IpAddr::V4(ip), 32)), ..Default::default() }).await?;
    Ok(())
}

/// Remove the /32 of **every** carrier, not just the selected one. A leftover "bypass the tunnel for
/// this IP" route in the main table would make later tunnelled traffic to that IP skip the tunnel,
/// and that IP is your own carrier server.
pub async fn carrier_route_off(ctx: &Ctx) {
    let mut all = WstConf::peek_servers_all();
    if let Some(a) = util::read_trim(WST_ACTIVE) {
        all.push(a);
    }
    for c in all {
        if let Ok(ip) = c.parse::<Ipv4Addr>() {
            let _ = ctx.nl.route_del(ip, 32, 254).await;
        }
    }
    let _ = ctx.nl.rule_del_prio(WST_CARRIER_PRIO, false).await;
}

// ── client ────────────────────────────────────────────────────
pub async fn client_up(ctx: &mut Ctx, conf: &WstConf, variant: Variant, carrier: &str) -> Result<()> {
    client_down(ctx).await;
    if !std::path::Path::new(&wst_client()).exists() {
        return Err(anyhow!("wstunnel client not installed ({})", &wst_client()));
    }
    crate::util::root_trusted(&wst_client())?;
    let local_port: u16 = conf.local_port.parse().context("WST_LOCAL_PORT is not a port number")?;
    let args = client_args(conf, variant, local_port, carrier);
    // Log at DEBUG, but transport::websocket capped at INFO: that module prints the full HTTP upgrade
    // request line, which contains WST_SECRET.
    // Not truncated per run (the failed run's log is exactly what you want); cleared only past 4MB.
    // A marker line is written on every client start.
    if std::fs::metadata(WST_LOG).map(|m| m.len() > 4 << 20).unwrap_or(false) {
        let _ = std::fs::write(WST_LOG, "");
    }
    {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(WST_LOG) {
            let _ = writeln!(f, "==== {} variant={} carrier={} ====", util::iso_now(), variant.as_str(), carrier);
        }
    }
    let _ = std::fs::set_permissions(WST_LOG, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    let lines = ctx.wst.lines.clone();
    let child_slot = ctx.wst.child.clone();
    let desired = ctx.wst.desired.clone();
    desired.store(true, Ordering::SeqCst);
    let gen = ctx.wst.generation.fetch_add(1, Ordering::SeqCst) + 1;
    let secret = conf.secret.clone();
    let spawn = move || -> std::io::Result<Child> {
        // Output goes straight to the file (append), not a pipe: a daemon restart must not take the client down
        let log = std::fs::OpenOptions::new().create(true).append(true).open(WST_LOG)?;
        let log2 = log.try_clone()?;
        Command::new(&wst_client())
            .args(&args)
            .env_clear()
            .env("PATH", "/usr/bin")
            .env("WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX", &secret) // via env, not argv (/proc/PID/cmdline is world-readable)
            .env("RUST_LOG", "debug,wstunnel::tunnel::transport::websocket=info")
            .env("NO_COLOR", "true") // wstunnel parses it as the --no-color value, true/false only; "1" makes it exit immediately (observed: all three variants "not ready")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .kill_on_drop(true)
            .spawn()
    };
    let spawn = Arc::new(spawn);
    // Supervisor: respawn the process if it crashes (at most 5 times in 60s); stop once desired is cleared.
    let sp = spawn.clone();
    let slot = child_slot.clone();
    let des = desired.clone();
    let ln = lines.clone();
    tokio::spawn(async move {
        let mut restarts: VecDeque<std::time::Instant> = VecDeque::new();
        loop {
            let child = match sp() {
                Ok(c) => c,
                Err(e) => {
                    crate::journal::err("toriid", &format!("wstunnel client spawn failed: {}", e));
                    ln.lock().unwrap().push_back(format!("spawn failed: {}", e));
                    break;
                }
            };
            let st = {
                *slot.lock().unwrap() = Some((gen, child));
                // Wait for exit. Taking it out to wait() and putting it back won't work (Child isn't Clone), so poll try_wait.
                loop {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let mut g = slot.lock().unwrap();
                    match g.as_mut() {
                        Some((g2, c)) if *g2 == gen => match c.try_wait() {
                            Ok(Some(st)) => break Some(st),
                            Ok(None) => continue,
                            Err(_) => break None,
                        },
                        _ => break None, // taken by client_down, or the slot already holds the next generation
                    }
                }
            };
            if st.is_none() || !des.load(Ordering::SeqCst) {
                break;
            }
            let tail = log_tail_since_marker(3).join(" | ");
            crate::journal::notice("toriid", &format!("wstunnel client exited ({:?}), respawning in 3s. last lines: {}", st, tail));
            ln.lock().unwrap().push_back(format!("wstunnel client exited ({:?}), respawning in 3s", st));
            let now = std::time::Instant::now();
            restarts.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
            if restarts.len() >= 5 {
                ln.lock().unwrap().push_back("crashed 5 times within 60s, giving up".into());
                break;
            }
            restarts.push_back(now);
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
    for _ in 0..80 {
        if udp_port_taken(local_port) {
            ctx.wst.variant = Some(variant);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    client_down(ctx).await;
    Err(anyhow!("wstunnel client not ready on 127.0.0.1:{} within 8s", local_port))
}

fn strip_ansi(l: &str) -> String {
    let mut out = String::with_capacity(l.len());
    let mut it = l.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            if it.peek() == Some(&'[') {
                it.next();
                while let Some(&d) = it.peek() {
                    it.next();
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    out
}

/// Last n lines after the last `==== ` marker in the log file (ANSI stripped).
pub fn log_tail_since_marker(n: usize) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(WST_LOG) else { return vec![] };
    let seg = text.rsplit_once("\n==== ").map(|(_, s)| s).unwrap_or(&text);
    let lines: Vec<String> = seg.lines().skip(1).map(strip_ansi).filter(|l| !l.trim().is_empty()).collect();
    lines.iter().rev().take(n).rev().cloned().collect()
}

/// Outcome of the carrier handshake, read from the client log:
///   Some(true)  got a 101 (WebSocket upgrade succeeded)
///   Some(false) >=3 TLS reconnects without a single 101 - an NGFW is cutting it (RST on missing SNI /
///               connection closed after SNI classification)
///   None        too early to tell
pub fn carrier_verdict() -> Option<bool> {
    let lines = log_tail_since_marker(400);
    if lines.iter().any(|l| l.contains("status: 101") || l.contains("101 Switching Protocols")) {
        return Some(true);
    }
    let reconnects = lines.iter().filter(|l| l.contains("Opening TCP connection")).count();
    (reconnects >= 3).then_some(false)
}

/// The probe client is short-lived, so a pipe is fine; output is kept in memory only.
fn pump_probe(out: Option<impl tokio::io::AsyncRead + Unpin + Send + 'static>, lines: Arc<Mutex<VecDeque<String>>>) {
    let Some(out) = out else { return };
    tokio::spawn(async move {
        let mut r = BufReader::new(out).lines();
        while let Ok(Some(l)) = r.next_line().await {
            let mut g = lines.lock().unwrap();
            g.push_back(l);
            while g.len() > 400 {
                g.pop_front();
            }
        }
    });
}

pub async fn client_down(ctx: &mut Ctx) {
    ctx.wst.desired.store(false, Ordering::SeqCst);
    let child = ctx.wst.child.lock().unwrap().take().map(|(_, c)| c);
    if let Some(mut c) = child {
        let _ = c.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(3), c.wait()).await;
    }
    // Also reap clients released by a previous daemon or left behind by a dead one
    for pid in stray_pids() {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    ctx.wst.variant = None;
}

/// Release the child before the daemon exits: no kill (kill_on_drop bypassed via forget), the tunnel keeps running.
pub fn release_child(c: &mut Client) {
    c.desired.store(false, Ordering::SeqCst);
    if let Some((_, child)) = c.child.lock().unwrap().take() {
        std::mem::forget(child);
    }
}

/// Processes whose argv starts with wst_client() + " client" (scans /proc, doesn't parse ps output).
pub fn stray_pids() -> Vec<i32> {
    let mut out = vec![];
    let Ok(d) = std::fs::read_dir("/proc") else { return out };
    for e in d.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        // Only root's processes: anyone can start a process with a matching argv, and the daemon adopts
        // (and later signals) whatever this returns.
        if std::os::unix::fs::MetadataExt::uid(&match e.metadata() { Ok(m) => m, Err(_) => continue }) != 0 {
            continue;
        }
        let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else { continue };
        let parts: Vec<&[u8]> = cmd.split(|b| *b == 0).collect();
        if parts.len() >= 2 && parts[0] == wst_client().as_bytes() && parts[1] == b"client" {
            out.push(pid);
        }
    }
    out
}

// ── variant memory ──────────────────────────────────────────────────
/// Downgrade records expire: a disguised record older than 7 days retries clean first. clean is the safe tier and never expires.
pub fn variant_get(ssid: &str) -> Option<Variant> {
    let (v, ts) = Tsv::get(WST_VARIANT_DB, ssid)?;
    let v = Variant::parse(&v)?;
    if v == Variant::Disguised {
        if let Some(t) = util::parse_iso(&ts) {
            if util::now().saturating_sub(t) > WST_VARIANT_TTL {
                return None;
            }
        }
    }
    Some(v)
}
pub fn variant_put(ssid: &str, v: Variant) -> Result<()> {
    Tsv::put(WST_VARIANT_DB, ssid, v.as_str())
}
pub fn variant_clear(ssid: &str) -> Result<()> {
    Tsv::del(WST_VARIANT_DB, ssid)
}
pub fn live_fail_put(ssid: &str, v: Variant) {
    let _ = Tsv::put2(WST_LIVE_FAIL_DB, ssid, v.as_str());
}
pub fn live_fail_clear(ssid: &str, v: Variant) {
    let _ = Tsv::del2(WST_LIVE_FAIL_DB, ssid, v.as_str());
}
pub fn live_fail_age(ssid: &str, v: Variant) -> Option<u64> {
    let ts = Tsv::get2(WST_LIVE_FAIL_DB, ssid, v.as_str())?;
    Some(util::now().saturating_sub(util::parse_iso(&ts)?))
}

/// Ordered by **safety**: clean -> named -> disguised. The remembered one moves to the front; the rest keep their order.
pub fn order(pref: Option<Variant>) -> Vec<Variant> {
    match pref {
        Some(Variant::Disguised) => vec![Variant::Disguised, Variant::Clean, Variant::Named],
        Some(Variant::Named) => vec![Variant::Named, Variant::Clean, Variant::Disguised],
        _ => vec![Variant::Clean, Variant::Named, Variant::Disguised],
    }
}

// ── wait for the physical link to get out ────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    Reachable,
    Unreachable,
    Portal,
}

/// Before rotating variants, ask one thing: can TCP to the carrier be established (up to `budget`
/// seconds of wall clock)? Exit code 60 (cert verification failed) is recognized separately: a captive
/// portal's transparent proxy must accept 443 to redirect, so TCP works, but it cannot forge the Let's
/// Encrypt cert for this IP. With WST_VERIFY=no, 60 is normal and only TCP is checked.
pub async fn wait_carrier(ctx: &Ctx, conf: &WstConf, carrier: &str, budget: u64) -> Wait {
    if budget == 0 {
        return Wait::Reachable;
    }
    let ip: IpAddr = match carrier.parse() {
        Ok(i) => i,
        Err(_) => return Wait::Reachable,
    };
    let port: u16 = conf.port.parse().unwrap_or(443);
    let start = std::time::Instant::now();
    state::carrier_flag_write(CarrierWait::Waiting, budget);
    let dev = ctx.nl.phy_dev().await.ok().flatten().map(|l| l.name);
    ctx.io.step(format!("waiting for physical network: carrier {}:{} via {}", carrier, port, dev.as_deref().unwrap_or("?")).as_str());
    loop {
        let d = dev.clone();
        let verify = conf.verify;
        let r = tokio::task::spawn_blocking(move || probe::carrier(ip, port, d.as_deref(), verify)).await.unwrap_or(Carrier::Unreachable);
        let t = start.elapsed().as_secs();
        match r {
            Carrier::Ok => {
                ctx.io.done(format!("reachable after {}s", t));
                state::carrier_flag_clear();
                if t >= 10 {
                    ctx.jlog(&format!("physical network reachable only {}s after resume (delay on gateway side, {})", t, dev.as_deref().unwrap_or("?")));
                }
                return Wait::Reachable;
            }
            Carrier::BadCert => {
                ctx.io.done("TCP up but cert verification failed - a captive portal is impersonating the carrier");
                state::carrier_flag_write(CarrierWait::Portal, budget);
                ctx.jlog(&format!("carrier {}:{} cert verification failed - captive portal intercepting (or local certs expired); skipping variants, handing over to portal handling", carrier, port));
                return Wait::Portal;
            }
            Carrier::Unreachable => {}
        }
        if t >= budget {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    ctx.io.done(format!("not reachable within {}s", budget));
    state::carrier_flag_write(CarrierWait::Unreachable, budget);
    ctx.jlog(&format!("carrier {}:{} via {}: no TCP connection within {}s - physical link has no way out, skipping variants", carrier, port, dev.as_deref().unwrap_or("?"), budget));
    Wait::Unreachable
}

// ── bring-up ──────────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BringUp {
    /// Up with this variant; carries the measured exit IP
    Up(Variant, String),
    NoCarrier,
    Portal,
    AllFailed,
}

/// Bring up the carrier + wg0 once and test it for real. On failure, clean up so the next variant starts from scratch.
async fn try_variant(ctx: &mut Ctx, conf: &WstConf, wgc: &wg::WgConf, v: Variant, carrier: &str) -> Option<String> {
    ctx.io.step(format!("wstunnel[{}]: starting client", v.as_str()).as_str());
    if let Err(e) = client_up(ctx, conf, v, carrier).await {
        ctx.io.done(format!("failed to start: {}", e));
        return None;
    }
    ctx.io.done("ready");
    let local_port: u16 = conf.local_port.parse().unwrap_or(51822);
    let ep = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port);
    if let Err(e) = wg::up(&ctx.nl, wgc, Some(ep)).await {
        ctx.io.fail(format!("wg-over-wstunnel failed to start: {}", e));
        client_down(ctx).await;
        return None;
    }
    // The carrier handshake answers first: a working path yields 101 in 1-2s; a blocked path shows 3
    // reconnects (~3s). No need to wait 20s for a missing WireGuard handshake.
    ctx.io.step(format!("wstunnel[{}]: carrier handshake", v.as_str()).as_str());
    let t0 = std::time::Instant::now();
    let verdict = loop {
        match carrier_verdict() {
            Some(x) => break Some(x),
            None if t0.elapsed() > Duration::from_secs(12) => break None,
            None => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    };
    match verdict {
        Some(true) => ctx.io.done(format!("101 in {:.1}s", t0.elapsed().as_secs_f32())),
        Some(false) => {
            ctx.io.done("blocked: repeated TLS reconnects, no 101 (RST on missing SNI / blocked by SNI classification)");
            log_failure_evidence(ctx, v);
            wg::down(&ctx.nl).await;
            client_down(ctx).await;
            return None;
        }
        None => ctx.io.done("no verdict within 12s, testing the link anyway"),
    }
    ctx.io.step(format!("wstunnel[{}]: testing link (up to 40s)", v.as_str()).as_str());
    // 40, not 20: the carrier chain is set up lazily, TCP/TLS only starts when the first UDP packet arrives;
    // measured, 20s sat right at the median
    if let Some((ip, t)) = crate::modes::tunnel_check(ctx, 40).await {
        ctx.io.done(format!("up in {:.1}s, exit {}", t, ip));
        return Some(ip);
    }
    ctx.io.done("no connectivity");
    log_failure_evidence(ctx, v);
    wg::down(&ctx.nl).await;
    client_down(ctx).await;
    None
}

/// Log failure evidence to the journal: the client's key lines from this attempt (TLS handshake / Server response / rustls errors / WARN).
fn log_failure_evidence(ctx: &Ctx, v: Variant) {
    let key: Vec<String> = ctx
        .wst
        .recent_lines(400)
        .into_iter()
        .filter(|l| {
            let u = l.to_ascii_uppercase();
            u.contains(" WARN") || u.contains(" ERROR") || l.contains("Server response") || l.contains("Opening TCP") || l.contains("TLS handshake") || l.contains("encrypted extensions")
        })
        .collect();
    let n = key.len();
    let tail: Vec<&String> = key.iter().rev().take(12).collect::<Vec<_>>().into_iter().rev().collect();
    ctx.jlog(&format!("wstunnel[{}] failed, {} key client lines (last {}):", v.as_str(), n, tail.len()));
    for l in tail {
        ctx.jlog(&format!("  {}", l.trim()));
    }
}

/// **Both mode_wstunnel and mode_normal's automatic fallback must go through here.** One implementation for one job.
pub async fn bring_up(ctx: &mut Ctx, conf: &WstConf, wgc: &wg::WgConf, ssid: Option<&str>) -> BringUp {
    let carrier = active_carrier(conf, ssid);
    match wait_carrier(ctx, conf, &carrier, ctx.carrier_wait_budget).await {
        Wait::Unreachable => return BringUp::NoCarrier,
        Wait::Portal => return BringUp::Portal,
        Wait::Reachable => {}
    }
    // A pinned network tries only the pinned variant: no rotation (saves 3-8s), no live-fail record
    let pinned = ssid.and_then(|s| conf.pins.iter().find(|(n, _)| n == s)).and_then(|(_, v)| Variant::parse(v));
    let pref = ssid.and_then(variant_get);
    let plan: Vec<Variant> = match pinned {
        Some(p) => {
            ctx.io.say(format!("  {} is pinned to variant {} (WST_PIN), trying only that", ssid.unwrap_or("this network"), p.as_str()));
            vec![p]
        }
        None => {
            if let Some(p) = pref {
                ctx.io.say(format!("  {} last worked with variant {}, trying it first", ssid.unwrap_or("this network"), p.as_str()));
            }
            order(pref)
        }
    };
    for v in plan {
        if let Some(ip) = try_variant(ctx, conf, wgc, v, &carrier).await {
            if let Some(s) = ssid {
                let _ = variant_put(s, v);
                live_fail_clear(s, v);
            }
            carrier_remember(ssid, &carrier);
            return BringUp::Up(v, ip);
        }
        // Record real-path failures so tomorrow's probe can't promote a variant that was just disproven
        if let Some(s) = ssid {
            live_fail_put(s, v);
        }
        ctx.io.say(format!("  variant {} failed, trying the next", v.as_str()));
    }
    BringUp::AllFailed
}

/// Tear down wstunnel-specific state when leaving wstunnel mode.
pub async fn teardown(ctx: &mut Ctx) {
    wg::down(&ctx.nl).await;
    client_down(ctx).await;
    carrier_route_off(ctx).await;
    state::carrier_flag_clear();
    util::rm(WST_ACTIVE); // must come after route removal, which reads it
    util::rm(WST_ENVFILE);
}

// ── side probe (spare port, never touches the live tunnel) ──────────────────────
/// Proves only that the **carrier handshake** succeeds (`status: 101` in the log). It cannot overturn a
/// recent failure on the real path.
pub async fn probe_variant(conf: &WstConf, carrier: &str, v: Variant) -> bool {
    if !matches!(v, Variant::Clean | Variant::Named) {
        return false;
    }
    let mut args = client_args(conf, v, PROBE_PORT, carrier);
    if !args.iter().any(|a| a == "--tls-verify-certificate") {
        args.push("--tls-verify-certificate".into());
    }
    if crate::util::root_trusted(&wst_client()).is_err() {
        return false;
    }
    let Ok(mut child) = Command::new(&wst_client())
        .args(&args)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX", &conf.secret)
        .env("RUST_LOG", "debug") // the success marker `status: 101` only appears at DEBUG; the probe runs ~20s and sends one packet
        .env("NO_COLOR", "true") // see client_up: must be "true", "1" makes wstunnel exit
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    else {
        return false;
    };
    let lines = Arc::new(Mutex::new(VecDeque::new()));
    pump_probe(child.stdout.take(), lines.clone());
    pump_probe(child.stderr.take(), lines.clone());
    let mut ready = false;
    for _ in 0..50 {
        if udp_port_taken(PROBE_PORT) {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut ok = false;
    if ready {
        // The carrier chain is lazy: without a packet, the TCP/TLS handshake never starts
        if let Ok(s) = std::net::UdpSocket::bind(("127.0.0.1", 0)) {
            let _ = s.send_to(b"x", ("127.0.0.1", PROBE_PORT));
        }
        for _ in 0..30 {
            if lines.lock().unwrap().iter().any(|l| l.contains("status: 101") || l.contains("101 Switching Protocols")) {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
    ok
}
