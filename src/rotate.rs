//! Carrier server keys: rotate, retire, audit, and a one-time migrate. User-side admin actions over ssh
//! to the carrier server.
//!
//! Why rotate: the disguised variant doesn't verify the cert, so a MITM on the path can read WST_SECRET.
//! What that buys an attacker is limited - the server only forwards to the one upstream WireGuard
//! endpoint (the inner WireGuard has its own keys), so at worst they freeload on the VPS's traffic.
//! Rotation is low-value maintenance that just must not break anything: **never take the tunnel down for it**.
//! Why audit: the server's wstunnel INFO log carries X-Forwarded-For; grouping by source IP shows
//! whether anyone else is using it.
//!
//! ── multiple keys side by side ──────────────────────────────────
//! Old approach: replace on the server + restart, then write the new key locally. Once the process was
//! killed before the local step (the ssh session ran through the tunnel being restarted and hung until the
//! unit's 180s timeout); the two ends had no common key, every variant got 404, and the network was gone.
//! Now the server accepts several keys at once (wst-keys, restrict-config hot reload, no restart), in order:
//!   1. new key lands locally first (WST_SECRET_NEXT)  2. server add  3. local promote (NEXT->current, current->PREV)
//!   4. later (grace period over, old key not in use) server keeps current -> PREV deleted
//! An interruption at any step leaves at least one common key; the next run reconciles half-done state first.
//! Keys travel only over ssh stdin, never argv / env (the old `sudo NEW_SECRET=...` got logged by sudo
//! into the server journal).
use crate::config::{parse_kv, WstConf};
use crate::paths::*;
use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::process::{Command, Stdio};

/// Pushed to the server before every call, so both ends always run the same version.
const KEYS_SERVER_SCRIPT: &str = include_str!("../server/wst-keys.sh");
/// Minimum time an old key stays valid after promotion (slack for connected clients and other devices)
const RETIRE_GRACE: u64 = 86400;
const ROTATE_EVERY: u64 = 7 * 86400;

// ── ssh ─────────────────────────────────────────────────────────
fn ssh_target() -> Result<(String, String)> {
    let m = std::fs::read_to_string(&wst_conf()).ok().map(|t| parse_kv(&t)).unwrap_or_default();
    match (m.get("WST_SSH").filter(|v| !v.is_empty()), m.get("WST_SSH_KEY").filter(|v| !v.is_empty())) {
        (Some(t), Some(k)) => Ok((t.clone(), k.clone())),
        _ => Err(anyhow!("key management needs WST_SSH (user@host) and WST_SSH_KEY in {}", wst_conf())),
    }
}

/// One ssh call. Tailnet first; if unreachable (tailscaled cold, DERP not settled - observed several times),
/// fall back to the carrier's public IP, with the host key verified against the tailnet entry
/// (HostKeyAlias) rather than trusting a new key blindly.
/// ServerAlive: a hung session (e.g. running through a tunnel being modified) drops itself within 30s
/// instead of hanging until the unit's 180s timeout and SIGTERM.
fn ssh(cmd: &str, stdin: Option<&str>) -> Result<String> {
    let (target, key) = ssh_target()?;
    let host = target.rsplit('@').next().unwrap_or(&target).to_string();
    let user = target.split_once('@').map(|(u, _)| u.to_string());
    let public = WstConf::load().ok().map(|c| c.server).filter(|s| !s.is_empty() && *s != host);
    let mut routes: Vec<(String, Vec<String>)> = vec![(target.clone(), vec![])];
    if let Some(p) = public {
        let t = match &user { Some(u) => format!("{}@{}", u, p), None => p };
        routes.push((t, vec!["-o".into(), format!("HostKeyAlias={}", host)]));
    }
    let mut last = anyhow!("no usable ssh route");
    for (t, extra) in &routes {
        match ssh_once(t, &key, extra, cmd, stdin) {
            Ok(o) => return Ok(o),
            // Only connection-level failures try the next route; a command failure (server refused) is reported as-is
            Err(e) if format!("{:#}", e).contains("unreachable") => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

fn ssh_once(target: &str, key: &str, extra: &[String], cmd: &str, stdin: Option<&str>) -> Result<String> {
    let mut c = Command::new("ssh");
    c.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", "-i", key]);
    c.args(extra).arg(target).arg(cmd).stdout(Stdio::piped()).stderr(Stdio::piped());
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = c.spawn().context("spawning ssh")?;
    if let Some(s) = stdin {
        use std::io::Write;
        let mut si = child.stdin.take().unwrap();
        si.write_all(s.as_bytes())?;
        drop(si);
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        // ssh's own exit code 255 = connection-level problem
        if out.status.code() == Some(255) {
            return Err(anyhow!("ssh {} unreachable: {}", target, err));
        }
        return Err(anyhow!("ssh {} failed: {}", target, err));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Server-side wst-keys: install the local copy over it every time (so versions never drift), then run
/// the subcommand. Keys go in via stdin.
fn wst_keys(sub: &str, keys: &[&str]) -> Result<String> {
    let script = KEYS_SERVER_SCRIPT;
    ssh("sudo install -m 0755 /dev/stdin /usr/local/sbin/wst-keys", Some(&script))?;
    let input = keys.iter().map(|k| format!("{}\n", k)).collect::<String>();
    ssh(&format!("sudo /usr/local/sbin/wst-keys {}", sub), if keys.is_empty() { None } else { Some(&input) })
}

// ── state on both ends ────────────────────────────────────────────────────
pub fn new_secret() -> String {
    use rand::RngCore;
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| ALPHA[(*x as usize) % ALPHA.len()] as char).collect()
}

/// Same as fp() in the server's wst-keys: first 12 hex chars of sha256.
/// Uses the system sha256sum (same tool as the server; a fingerprint isn't worth another crate)
pub fn fp(k: &str) -> String {
    use std::io::Write;
    let run = || -> Option<String> {
        let mut c = Command::new("sha256sum").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().ok()?;
        c.stdin.take()?.write_all(k.as_bytes()).ok()?;
        let o = c.wait_with_output().ok()?;
        String::from_utf8(o.stdout).ok()?.get(..12).map(String::from)
    };
    run().unwrap_or_else(|| "????????????".into())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Local {
    pub cur: String,
    pub prev: Option<String>,
    pub next: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Server {
    pub new_layout: bool,
    pub fps: Vec<String>,
}
impl Server {
    fn has(&self, k: &str) -> bool {
        self.fps.contains(&fp(k))
    }
}

fn parse_status(out: &str) -> Server {
    let mut s = Server::default();
    for l in out.lines() {
        if l.trim() == "layout new" {
            s.new_layout = true;
        }
        if let Some(f) = l.trim().strip_prefix("fp ") {
            s.fps.push(f.trim().to_string());
        }
    }
    s
}

pub fn local_read_direct() -> Result<Local> {
    let m = parse_kv(&std::fs::read_to_string(&wst_conf())?);
    let get = |k: &str| m.get(k).cloned().filter(|v| !v.is_empty());
    Ok(Local { cur: get("WST_SECRET").ok_or_else(|| anyhow!("no WST_SECRET in {}", &wst_conf()))?, prev: get("WST_SECRET_PREV"), next: get("WST_SECRET_NEXT") })
}

/// Atomically rewrite the three secret lines in wstunnel.conf (rest untouched); None = drop that line
pub fn local_write_direct(l: &Local) -> Result<()> {
    let text = std::fs::read_to_string(&wst_conf())?;
    let mut out: Vec<String> = text.lines().filter(|x| !x.starts_with("WST_SECRET=") && !x.starts_with("WST_SECRET_PREV=") && !x.starts_with("WST_SECRET_NEXT=")).map(String::from).collect();
    out.push(format!("WST_SECRET={}", l.cur));
    if let Some(p) = &l.prev {
        out.push(format!("WST_SECRET_PREV={}", p));
    }
    if let Some(n) = &l.next {
        out.push(format!("WST_SECRET_NEXT={}", n));
    }
    crate::util::write_atomic(&wst_conf(), &(out.join("\n") + "\n"), 0o600)
}

/// The secrets live in a root-owned file; as the operator, go through the daemon.
fn local_read() -> Result<Local> {
    if crate::util::euid_is_root() {
        return local_read_direct();
    }
    let (rc, lines) = crate::client::capture(crate::daemon::Request { cmd: "wst-secret-get".into(), args: vec![], automated: false })?;
    let line = lines.iter().rev().find(|l| l.starts_with('{')).ok_or_else(|| anyhow!("daemon refused to return the keys (rc {}): {}", rc, lines.join(" ")))?;
    let v: serde_json::Value = serde_json::from_str(line)?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
    Ok(Local { cur: s("cur").ok_or_else(|| anyhow!("no current key"))?, prev: s("prev"), next: s("next") })
}

fn local_write(l: &Local) -> Result<()> {
    if crate::util::euid_is_root() {
        return local_write_direct(l);
    }
    let args = vec![l.cur.clone(), l.prev.clone().unwrap_or_default(), l.next.clone().unwrap_or_default()];
    let (rc, lines) = crate::client::capture(crate::daemon::Request { cmd: "wst-secret-set".into(), args, automated: false })?;
    if rc != 0 {
        return Err(anyhow!("daemon could not store the keys: {}", lines.join(" ")));
    }
    Ok(())
}

fn stamp_read(name: &str) -> Option<u64> {
    std::fs::read_to_string(crate::util::user_state_dir().join(name)).ok()?.trim().parse().ok()
}
fn stamp_write(name: &str) {
    let dir = crate::util::user_state_dir();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join(name), crate::util::now().to_string());
}
fn last_rotated() -> Option<u64> {
    stamp_read("wst-rotated")
}

// ── decisions (pure functions, tested offline) ────────────────────────────────────────
/// Reconcile both ends and finish a half-done rotation. Returns (new local state, notes);
/// Err = no common key, needs a human
pub fn reconcile(l: &Local, s: &Server) -> Result<(Local, Vec<String>)> {
    let mut l = l.clone();
    let mut notes = vec![];
    if let Some(n) = l.next.clone() {
        if s.has(&n) {
            // server has it, local wasn't promoted (last run died between steps 2 and 3)
            l.prev = Some(l.cur.clone());
            l.cur = n;
            l.next = None;
            notes.push("last rotation was interrupted (added on server, not promoted locally) - completed".into());
        } else {
            l.next = None;
            notes.push("last rotation was interrupted before reaching the server - discarded the unused key".into());
        }
    }
    if l.prev.as_deref().map(|p| !s.has(p)).unwrap_or(false) {
        l.prev = None;
        notes.push("old key already removed on the server - removed locally too".into());
    }
    if !s.has(&l.cur) {
        match l.prev.clone() {
            Some(p) if s.has(&p) => {
                l.cur = p;
                l.prev = None;
                notes.push("server rejects the current key but accepts the old one - reverted to the old key".into());
            }
            _ => return Err(anyhow!("no common key on both ends (local {} / server {:?}) - needs a human: ssh in and check /etc/wstunnel/keys", fp(&l.cur), s.fps)),
        }
    }
    Ok((l, notes))
}

/// Whether to retire the old key. Never while in wstunnel mode: the running client may still hold the
/// old key and would get 404 on its next reconnect
pub fn should_retire(l: &Local, rotated_ago: Option<u64>, in_wstunnel: bool, urgent: bool) -> bool {
    l.prev.is_some() && !in_wstunnel && (urgent || rotated_ago.map(|a| a >= RETIRE_GRACE).unwrap_or(true))
}

pub fn rotation_due(rotated_ago: Option<u64>) -> bool {
    rotated_ago.map(|a| a >= ROTATE_EVERY).unwrap_or(true)
}

fn in_wstunnel() -> bool {
    matches!(crate::state::Intent::read(), crate::state::Intent::Mode(crate::state::Mode::Only(crate::state::Tunnel::Wstunnel)))
}

// ── actions ────────────────────────────────────────────────────────
fn server_status() -> Result<Server> {
    Ok(parse_status(&wst_keys("status", &[])?))
}

/// Reconcile and write back locally. Returns the reconciled state of both ends
fn sync() -> Result<(Local, Server, Vec<String>)> {
    let s = server_status()?;
    let l0 = local_read()?;
    if !s.new_layout {
        if !s.has(&l0.cur) {
            return Err(anyhow!("server still has the old layout and rejects the local key ({}) - needs a human", fp(&l0.cur)));
        }
        return Ok((l0, s, vec!["server still has the old layout (single key, rotation needs a restart) - run torii wst migrate first".into()]));
    }
    let (l, notes) = reconcile(&l0, &s)?;
    if l != l0 {
        local_write(&l)?;
    }
    for n in &notes {
        crate::journal::notice("toriid-wst", n);
    }
    Ok((l, s, notes))
}

/// Rotate the key. Requires the new server layout (no restart, old and new coexist), so it's safe to run
/// while in wstunnel mode.
pub async fn rotate(reason: &str) -> Result<String> {
    let (mut l, s, mut notes) = tokio::task::spawn_blocking(sync).await??;
    if !s.new_layout {
        return Err(anyhow!("server still has the old layout (rotation needs a restart and drops the tunnel) - run torii wst migrate first, from a trusted network"));
    }
    // previous key not retired yet: retire it first if possible, so the server holds at most three
    if l.prev.is_some() {
        if should_retire(&l, Some(u64::MAX), in_wstunnel(), true) {
            let keep = l.cur.clone();
            tokio::task::spawn_blocking(move || wst_keys("keep", &[&keep])).await??;
            l.prev = None;
            local_write(&l)?;
            notes.push("retired the key before last first".into());
        } else {
            notes.push("previous key still in grace period / wstunnel in use, keeping it".into());
        }
    }
    let new = new_secret();
    // 1. local first
    l.next = Some(new.clone());
    local_write(&l)?;
    // 2. add on server (old keys stay)
    let n2 = new.clone();
    let out = tokio::task::spawn_blocking(move || wst_keys("add", &[&n2])).await??;
    if !out.contains("ok added") && !out.contains("ok already") {
        return Err(anyhow!("server did not confirm: {} (local NEXT will be handled at the next reconcile)", out.trim()));
    }
    // 3. promote locally
    l.prev = Some(l.cur.clone());
    l.cur = new.clone();
    l.next = None;
    local_write(&l)?;
    stamp_write("wst-rotated");
    let msg = format!("wstunnel key rotated ({}): new {} active, old {} valid during the grace period", reason, fp(&new), fp(l.prev.as_deref().unwrap_or("")));
    crate::journal::notice("toriid-wst", &msg);
    notes.push(msg);
    Ok(notes.join("\n"))
}

/// Retire the old key (server keeps only the current one)
pub async fn retire(urgent: bool) -> Result<String> {
    let (mut l, _s, mut notes) = tokio::task::spawn_blocking(sync).await??;
    let ago = last_rotated().map(|t| crate::util::now().saturating_sub(t));
    if l.prev.is_none() {
        notes.push("no old key to retire".into());
        return Ok(notes.join("\n"));
    }
    if !should_retire(&l, ago, in_wstunnel(), urgent) {
        notes.push(if in_wstunnel() { "wstunnel in use, the running client may still hold the old key - retire later, off wstunnel".into() } else { "still within the grace period (24h)".into() });
        return Ok(notes.join("\n"));
    }
    let keep = l.cur.clone();
    tokio::task::spawn_blocking(move || wst_keys("keep", &[&keep])).await??;
    let old = l.prev.take();
    local_write(&l)?;
    let msg = format!("old key {} retired, server accepts only {}", fp(old.as_deref().unwrap_or("")), fp(&l.cur));
    crate::journal::notice("toriid-wst", &msg);
    notes.push(msg);
    Ok(notes.join("\n"))
}

/// One-time migration of the server from "single hardcoded key, rotation needs restart" to wst-keys.
/// The only step that still restarts wstunnel, so it refuses while in wstunnel mode (unless --force:
/// a few seconds of outage; the server self-checks after 6s and rolls back on failure).
pub async fn migrate(force: bool) -> Result<String> {
    if in_wstunnel() && !force {
        return Err(anyhow!("wstunnel in use - migration restarts the server and drops the tunnel for a few seconds. Do it off wstunnel, or pass --force"));
    }
    let l = local_read()?;
    let s = tokio::task::spawn_blocking(server_status).await??;
    if s.new_layout {
        return Ok("server already has the new layout".into());
    }
    if !s.has(&l.cur) {
        return Err(anyhow!("server rejects the local key ({} vs {:?}) - align both ends before migrating", fp(&l.cur), s.fps));
    }
    let out = tokio::task::spawn_blocking(|| wst_keys("migrate", &[])).await??;
    if !out.contains("ok migrating") && !out.contains("ok already") {
        return Err(anyhow!("server: {}", out.trim()));
    }
    // wait for restart + self-check (2s + 4s + ~3s client test)
    tokio::time::sleep(std::time::Duration::from_secs(14)).await;
    let s2 = tokio::task::spawn_blocking(server_status).await??;
    let log = tokio::task::spawn_blocking(|| ssh("sudo journalctl -t wst-keys -n 3 --no-pager -o cat", None)).await?.unwrap_or_default();
    if s2.new_layout && s2.has(&l.cur) && log.contains("migrate ok") {
        Ok(format!("migration done: server accepts {} key(s); rotation no longer restarts or drops the tunnel", s2.fps.len()))
    } else {
        Err(anyhow!("migration not confirmed (layout {}, accepts local key {}). server log:\n{}", if s2.new_layout { "new" } else { "old (rolled back?)" }, s2.has(&l.cur), log.trim()))
    }
}

/// `torii wst keys`: which keys each end holds (fingerprints only)
pub async fn keys_status() -> Result<String> {
    let (l, s, notes) = tokio::task::spawn_blocking(sync).await??;
    let mut out = String::new();
    for n in notes {
        out += &format!("{}\n", n);
    }
    out += &format!("server: {} layout, {} key(s) {:?}\n", if s.new_layout { "new" } else { "old" }, s.fps.len(), s.fps);
    out += &format!("local: current {}{}\n", fp(&l.cur), l.prev.as_deref().map(|p| format!(", old {} (pending retirement)", fp(p))).unwrap_or_default());
    if let Some(t) = last_rotated() {
        out += &format!("last rotated: {} days ago\n", crate::util::now().saturating_sub(t) / 86400);
    }
    Ok(out)
}

/// Timer entry point: audit -> reconcile -> retire if due -> rotate if due.
/// Only foreign sources seen *after the last rotation* count: foreign IPs from the old key's lifetime were
/// already handled (that key is gone); otherwise they would force a rotation every day for the whole
/// 7-day log window.
pub async fn scheduled() -> Result<String> {
    let (table, foreign) = tokio::task::spawn_blocking(|| audit(7)).await??;
    let mut out = table;
    let (l, s, notes) = tokio::task::spawn_blocking(sync).await??;
    for n in notes {
        out += &format!("{}\n", n);
    }
    let since = last_rotated().unwrap_or(0);
    let fresh: Vec<String> = foreign.iter().filter(|(_, last)| *last + 60 >= since).map(|(ip, _)| ip.clone()).collect();
    if !s.new_layout {
        out += "server still has the old layout: no automatic rotation (needs a restart, drops the tunnel). Run torii wst migrate once, off wstunnel\n";
        if !fresh.is_empty() {
            notify_session(&format!("foreign sources on the wstunnel carrier: {:?}. Server has the old layout, cannot rotate safely - off wstunnel, run torii wst migrate, then torii wst rotate", fresh)).await;
        }
        return Ok(out);
    }
    let ago = last_rotated().map(|t| crate::util::now().saturating_sub(t));
    if !fresh.is_empty() {
        out += &format!("⚠ foreign sources since the last rotation {:?} - rotating\n", fresh);
        let r = rotate(&format!("audit found foreign sources {:?}", fresh)).await;
        let msg = match &r {
            Ok(_) if !in_wstunnel() => match retire(true).await {
                Ok(_) => format!("foreign sources on the wstunnel carrier {:?}: key rotated, old key revoked", fresh),
                Err(e) => format!("foreign sources on the wstunnel carrier {:?}: key rotated, revoking the old key failed ({:#}), will retry", fresh, e),
            },
            Ok(_) => format!("foreign sources on the wstunnel carrier {:?}: key rotated (no disconnect); old key will be revoked once off wstunnel", fresh),
            Err(e) => format!("foreign sources on the wstunnel carrier {:?}, rotation failed: {:#}", fresh, e),
        };
        notify_session(&msg).await;
        out += &format!("{}\n", msg);
        return r.map(|_| out);
    }
    if should_retire(&l, ago, in_wstunnel(), false) {
        out += &format!("{}\n", retire(false).await?);
    }
    if rotation_due(ago) {
        out += &format!("{}\n", rotate("scheduled (7 days)").await?);
    } else {
        out += "not due yet (7 days), not rotating\n";
    }
    Ok(out)
}

async fn notify_session(msg: &str) {
    if let Ok(c) = zbus::Connection::session().await {
        let _ = crate::dbus::notify::show(&c, 0, "wstunnel key", msg, false).await;
    }
}

/// Server journal short-iso timestamp (UTC, first 19 chars "YYYY-MM-DDTHH:MM:SS") -> epoch
fn utc_epoch(ts: &str) -> Option<u64> {
    chrono::NaiveDateTime::parse_from_str(ts.get(..19)?, "%Y-%m-%dT%H:%M:%S").ok().map(|t| t.and_utc().timestamp().max(0) as u64)
}

// ── audit ──────────────────────────────────────────────────────────
/// Audit: group the server's wstunnel log by source IP. Returns (table text, foreign sources [(IP, last-seen epoch)]).
pub fn audit(days: u32) -> Result<(String, Vec<(String, u64)>)> {
    let m = std::fs::read_to_string(&wst_conf()).ok().map(|t| parse_kv(&t)).unwrap_or_default();
    let known: Vec<String> = m.get("WST_KNOWN_NETS").map(|s| s.split_whitespace().map(String::from).collect()).unwrap_or_default();
    // Read-only journal query, leaves nothing new on the server.
    // One "timestamp ip" line per X-Forwarded-For entry; aggregation (count / first / last) happens locally
    let cmd = format!("journalctl -u wstunnel-server --since -{}d --no-pager -o short-iso --utc 2>/dev/null | sed 's/\\x1b\\[[0-9;]*m//g' | grep 'Request X-Forwarded-For' | awk '{{print $1, $NF}}'", days);
    let out = ssh(&cmd, None)?;
    let mut per_ip: BTreeMap<String, (u64, String, String)> = BTreeMap::new();
    for l in out.lines() {
        let mut it = l.split_whitespace();
        let (Some(ts), Some(ip)) = (it.next(), it.next()) else { continue };
        let ts = ts.get(..19).unwrap_or(ts).to_string();
        let e = per_ip.entry(ip.to_string()).or_insert((0, ts.clone(), ts.clone()));
        e.0 += 1;
        if ts < e.1 {
            e.1 = ts.clone();
        }
        if ts > e.2 {
            e.2 = ts;
        }
    }
    let mut table = format!("last {} days, by source IP (server X-Forwarded-For, times UTC):\n", days);
    let mut foreign = vec![];
    for (ip, (n, first, last)) in &per_ip {
        let is_known = known.is_empty() || known.iter().any(|net| in_net(ip, net));
        if !is_known {
            foreign.push((ip.clone(), utc_epoch(last).unwrap_or(u64::MAX)));
        }
        table += &format!("  {:<16} {:>5}x  {} .. {}{}\n", ip, n, first, last, if is_known { "" } else { "   <- not in WST_KNOWN_NETS" });
    }
    if per_ip.is_empty() {
        table += "  (no connections recorded)\n";
    }
    if known.is_empty() {
        table += "  (WST_KNOWN_NETS not set in wstunnel.conf, nothing flagged as foreign; e.g. WST_KNOWN_NETS=\"198.51.100.0/24 203.0.113.0/24\")\n";
    }
    if let Some(t) = last_rotated() {
        table += &format!("last rotation: {} days ago\n", crate::util::now().saturating_sub(t) / 86400);
    } else {
        table += "last rotation: no record\n";
    }
    Ok((table, foreign))
}

fn in_net(ip: &str, net: &str) -> bool {
    let Ok(a) = ip.parse::<std::net::Ipv4Addr>() else { return false };
    let (n, l) = match net.split_once('/') {
        Some((n, l)) => (n, l.parse::<u32>().unwrap_or(32)),
        None => (net, 32),
    };
    let Ok(b) = n.parse::<std::net::Ipv4Addr>() else { return false };
    let mask = if l == 0 { 0 } else { u32::MAX << (32 - l) };
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn srv(keys: &[&str]) -> Server {
        Server { new_layout: true, fps: keys.iter().map(|k| fp(k)).collect() }
    }
    fn loc(cur: &str, prev: Option<&str>, next: Option<&str>) -> Local {
        Local { cur: cur.into(), prev: prev.map(String::from), next: next.map(String::from) }
    }
    #[test]
    fn secret_shape() {
        let s = new_secret();
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
        assert_ne!(new_secret(), s);
    }
    #[test]
    fn fp_matches_server_side() {
        // server: printf '%s' <key> | sha256sum | cut -c1-12 - same algorithm; the ends compare fingerprints, not keys
        assert_eq!(fp("abc"), "ba7816bf8f01");
        assert_eq!(fp("abc").len(), 12);
    }
    #[test]
    fn cidr() {
        assert!(in_net("198.51.100.33", "198.51.0.0/16"));
        assert!(!in_net("10.0.0.1", "198.51.0.0/16"));
        assert!(in_net("1.2.3.4", "1.2.3.4"));
    }
    #[test]
    fn reconcile_clean_is_noop() {
        let l = loc("A", None, None);
        assert_eq!(reconcile(&l, &srv(&["A"])).unwrap().0, l);
    }
    #[test]
    fn reconcile_finishes_half_rotation() {
        // server already added the new key, local never got promoted
        let (l, n) = reconcile(&loc("A", None, Some("B")), &srv(&["A", "B"])).unwrap();
        assert_eq!(l, loc("B", Some("A"), None));
        assert!(n[0].contains("completed"));
    }
    #[test]
    fn reconcile_drops_unsent_next() {
        let (l, _) = reconcile(&loc("A", None, Some("B")), &srv(&["A"])).unwrap();
        assert_eq!(l, loc("A", None, None));
    }
    #[test]
    fn reconcile_forgets_retired_prev() {
        let (l, _) = reconcile(&loc("B", Some("A"), None), &srv(&["B"])).unwrap();
        assert_eq!(l, loc("B", None, None));
    }
    #[test]
    fn reconcile_falls_back_to_prev() {
        let (l, _) = reconcile(&loc("B", Some("A"), None), &srv(&["A"])).unwrap();
        assert_eq!(l, loc("A", None, None));
    }
    #[test]
    fn reconcile_refuses_split_brain() {
        // no common key: don't guess, needs a human
        assert!(reconcile(&loc("A", None, None), &srv(&["Z"])).is_err());
        assert!(reconcile(&loc("B", Some("A"), Some("C")), &srv(&["Z"])).is_err());
    }
    #[test]
    fn retire_rules() {
        let l = loc("B", Some("A"), None);
        assert!(!should_retire(&l, Some(3600), false, false), "within grace period");
        assert!(should_retire(&l, Some(RETIRE_GRACE), false, false));
        assert!(!should_retire(&l, Some(RETIRE_GRACE * 5), true, true), "in wstunnel: not even when urgent (the client may still hold the old key)");
        assert!(should_retire(&l, Some(60), false, true), "foreign source: retire immediately when not in wstunnel");
        assert!(!should_retire(&loc("B", None, None), None, false, true), "no old key");
    }
    #[test]
    fn due_rules() {
        assert!(rotation_due(None));
        assert!(!rotation_due(Some(86400)));
        assert!(rotation_due(Some(ROTATE_EVERY)));
    }
    #[test]
    fn status_parse() {
        let s = parse_status("layout new\nkeys 2\nfp aaaaaaaaaaaa\nfp bbbbbbbbbbbb\nwstunnel active\n");
        assert!(s.new_layout);
        assert_eq!(s.fps, vec!["aaaaaaaaaaaa", "bbbbbbbbbbbb"]);
        assert!(!parse_status("layout old\nkeys 1\nfp x\n").new_layout);
    }
    #[test]
    fn utc_parse() {
        assert_eq!(utc_epoch("2026-01-01T00:00:00+00:00"), Some(1767225600));
        assert_eq!(utc_epoch("garbage"), None);
    }
}
