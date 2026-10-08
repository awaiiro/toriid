//! Mode actions: auto (climb the tunnel ladder), a single tunnel, portal, off.
//! Every action starts by tearing everything down, so they are re-entrant. All modes share the same
//! nftables ruleset; they differ only in which path the tunnel takes.
use crate::config::WstConf;
use crate::dbus::{resolved, systemd};
use crate::journal;
use crate::nl::{netns, nft, wg, Nl, RuleSpec};
use crate::paths::*;
use crate::probe;
use crate::state::{self, Intent, Mode, Tunnel};
use crate::tailscale;
use crate::util;
use crate::wst;
use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

/// Progress output: sent to the waiting CLI (if any); with no CLI, written to stderr using the same
/// protocol. Journal entries go through jlog.
#[derive(Clone, Default)]
pub struct Io {
    pub tx: Option<UnboundedSender<String>>,
}
impl Io {
    fn emit(&self, s: String) {
        match &self.tx {
            Some(tx) => {
                let _ = tx.send(s);
            }
            None => {
                // Direct path / daemon-internal: strip protocol prefixes and write to stderr (systemd puts it in the journal)
                let plain = s.trim_start_matches(crate::ui::P_PARTIAL).trim_start_matches(crate::ui::P_STYLE);
                eprintln!("{}", plain);
            }
        }
    }
    pub fn say(&self, s: impl Into<String>) {
        self.emit(s.into())
    }
    /// Start of a step: `  › label… ` (no newline); done() appends the result
    pub fn step(&self, label: &str) {
        // The bar shows the current step live: drop a small file that the bar watches via inotify
        // (end_busy removes it when the action ends)
        let _ = crate::util::write_atomic(STEP, &format!("{}\t{}\n", crate::util::now(), label), 0o644);
        self.emit(format!("{}  › {}… ", crate::ui::P_PARTIAL, label))
    }
    pub fn done(&self, result: impl Into<String>) {
        self.emit(result.into())
    }
    pub fn ok(&self, s: impl Into<String>) {
        self.emit(format!("{}ok {}", crate::ui::P_STYLE, s.into()))
    }
    pub fn warn(&self, s: impl Into<String>) {
        self.emit(format!("{}warn {}", crate::ui::P_STYLE, s.into()))
    }
    pub fn fail(&self, s: impl Into<String>) {
        self.emit(format!("{}fail {}", crate::ui::P_STYLE, s.into()))
    }
    pub fn hint(&self, s: impl Into<String>) {
        self.emit(format!("{}hint {}", crate::ui::P_STYLE, s.into()))
    }
}

/// Context for one action: netlink handle, wstunnel client, output. There is one daemon; used serially.
pub struct Ctx {
    pub nl: Nl,
    pub io: Io,
    pub wst: wst::Client,
    pub carrier_wait_budget: u64,
    /// Triggered by automation (watchdog / portal-auto) - do not set manual-* flags
    pub automated: bool,
}
impl Ctx {
    pub fn jlog(&self, msg: &str) {
        journal::notice("toriid", msg);
    }
}

// ── shared helpers ────────────────────────────────────────────
/// The whole table is deleted and rebuilt, taking lan_allow with it: callers must `repopulate_class`
/// right after, otherwise every mode switch cuts LAN ssh sessions.
fn load_rules() -> Result<()> {
    nft::load_killswitch()
}

async fn ovpn_up() -> Result<bool> {
    // openvpn runs as root with this config (it can run scripts): same trust rule as everything else.
    util::root_trusted(&ovpn_conf())?;
    if !systemd::is_active(&ovpn_unit()).await {
        systemd::start(&ovpn_unit()).await?;
    }
    // OpenVPN comes up asynchronously; probing before the interface exists fails immediately rather than slowly
    let nl = Nl::new()?;
    for _ in 0..20 {
        if nl.link_exists(&ovpn_if()).await {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(false)
}
async fn ovpn_down() {
    if systemd::is_active(&ovpn_unit()).await {
        systemd::stop(&ovpn_unit()).await;
    }
}

fn is_tunnel_if(d: &str) -> bool {
    d == WG_IF || d == ovpn_if()
}

/// On success returns (exit IP, elapsed seconds).
pub async fn tunnel_check(ctx: &Ctx, secs: u64) -> Option<(String, f32)> {
    let start = std::time::Instant::now();
    let deadline = start + Duration::from_secs(secs);
    let mut dev: Option<String> = None;
    let mut handshaken = false;
    while std::time::Instant::now() < deadline {
        dev = ctx.nl.route_lookup_dev(Ipv4Addr::new(1, 1, 1, 1)).await.ok().flatten();
        if dev.as_deref().is_some_and(is_tunnel_if) {
            // The WireGuard handshake timestamp is a free local signal. No handshake within 20 s = the carrier
            // link is not working at all, and another 20 s of HTTP probing won't change the answer.
            // Observed: without this, every failing variant at boot waited the full 40 s (actually 51 s).
            if dev.as_deref() == Some(WG_IF) {
                match wg::handshake_age() {
                    Some(_) => handshaken = true,
                    None if start.elapsed() > Duration::from_secs(20) => {
                        ctx.jlog("tunnel check failed: no WireGuard handshake within 20s (carrier link down), giving up");
                        return None;
                    }
                    None => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        continue;
                    }
                }
            }
            // The probe timeout must not overrun the deadline: three sources at 5 s each used to stretch 38 s to 51 s
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left < Duration::from_secs(3) {
                break;
            }
            let (r, ip) = tokio::time::timeout(left, tokio::task::spawn_blocking(probe::exit_ip)).await.ok().and_then(|r| r.ok()).unwrap_or((probe::Reach::NoAnswer, None));
            if r == probe::Reach::Ok {
                let ip = ip.unwrap_or_default();
                ctx.jlog(&format!("tunnel check passed: exit {} via {}", ip, dev.as_deref().unwrap_or("?")));
                return Some((ip, start.elapsed().as_secs_f32()));
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    ctx.jlog(&match dev.as_deref() {
        Some(WG_IF) if handshaken => "tunnel check failed: WireGuard handshake ok but no exit IP (DNS / HTTP layer not working)".to_string(),
        Some(d) if is_tunnel_if(d) => format!("tunnel check failed: route goes via {} but no exit IP (carrier or peer unreachable)", dev.unwrap()),
        None => "tunnel check failed: no route to the internet".into(),
        Some(d) => format!("tunnel check failed: internet route goes via {}, not a tunnel interface", d),
    });
    None
}

// ── Tailscale rerouting ───────────────────────────────────────
/// Put the tailnet aggregate route in the main table (wins over the tunnel naturally, no priority numbers
/// involved) plus rule 5100 as a backstop.
async fn ts_net_route_on(ctx: &Ctx) {
    let Ok(Some(ts)) = ctx.nl.link_by_name("tailscale0").await else { return };
    let _ = ctx.nl.route_replace(Ipv4Addr::new(100, 64, 0, 0), 10, None, ts.index, 254).await;
    let _ = ctx.nl.rule_add(RuleSpec { prio: TS_NET_PRIO, table: TS_TABLE, dst: Some((TS_NET4.split('/').next().unwrap().parse().unwrap(), 10)), ..Default::default() }).await;
    let _ = ctx.nl.rule_add(RuleSpec { prio: TS_NET_PRIO, table: TS_TABLE, v6: true, dst: Some((TS_NET6.split('/').next().unwrap().parse::<Ipv6Addr>().unwrap().into(), 48)), ..Default::default() }).await;
    ctx.jlog(&format!("tailnet {} -> aggregate route in main table + rule prio {} backstop", TS_NET4, TS_NET_PRIO));
}

async fn ts_net_route_off(ctx: &Ctx) {
    let _ = ctx.nl.route_del(Ipv4Addr::new(100, 64, 0, 0), 10, 254).await;
    let _ = ctx.nl.rule_del_prio(TS_NET_PRIO, false).await;
    let _ = ctx.nl.rule_del_prio(TS_NET_PRIO, true).await;
}

/// tailscaled marks its own packets 0x80000, meaning "use the real NIC"; the kill switch allows none of that,
/// so reroute them into the VPN table: tailscale runs **inside** the tunnel. 5200 sorts before tailscale's
/// own 5210 and before wg's 5300.
async fn ts_rule_on(ctx: &Ctx) {
    if !crate::settings::get().tailscale.integrate {
        return;
    }
    ts_net_route_on(ctx).await;
    let mark = u32::from_str_radix(TS_MARK.split('/').next().unwrap().trim_start_matches("0x"), 16).unwrap();
    let mask = u32::from_str_radix(TS_MARK.split('/').nth(1).unwrap().trim_start_matches("0x"), 16).unwrap();
    if ctx.nl.rule_add(RuleSpec { prio: TS_PRIO, table: wg::WG_TABLE, fwmark: Some((mark, mask)), ..Default::default() }).await.is_ok() {
        ctx.jlog(&format!("tailscale rerouted into VPN table {} (rule {})", wg::WG_TABLE, TS_PRIO));
    }
}
async fn ts_rule_off(ctx: &Ctx) {
    ts_net_route_off(ctx).await;
    let _ = ctx.nl.rule_del_prio(TS_PRIO, false).await;
}

/// MagicDNS routing domains: `~<suffix>` / `~ts.net` -> tailscale0. tailscale itself sets search domains,
/// which lose to wg0's `~.`.
async fn ts_dns_on(ctx: &Ctx) {
    if !crate::settings::get().tailscale.integrate {
        return;
    }
    if !resolved::active().await {
        return;
    }
    let Ok(Some(ts)) = ctx.nl.link_by_name("tailscale0").await else { return };
    let dns: Vec<IpAddr> = vec!["100.100.100.100".parse().unwrap(), "fd7a:115c:a1e0::53".parse().unwrap()];
    // Even without the suffix (tailscaled not connected yet) `~.` must be removed. Observed at boot: when this
    // was skipped, tailscale0's `~.` sat alongside wg0's `~.` and half the queries went to an unreachable MagicDNS.
    let doms: Vec<String> = match tailscale::magicdns_suffix().await {
        Some(suffix) => vec![format!("~{}", suffix), "~ts.net".into()],
        None => {
            ctx.jlog("tailscale local API gave no MagicDNSSuffix - setting only ~ts.net and removing ~.");
            vec!["~ts.net".into()]
        }
    };
    let refs: Vec<&str> = doms.iter().map(String::as_str).collect();
    match resolved::set_link_dns(ts.index as i32, &dns, &refs).await {
        Ok(()) => ctx.jlog(&format!("MagicDNS routing domains {} -> tailscale0", doms.join(" "))),
        Err(e) => ctx.jlog(&format!("⚠ failed to set tailscale0 routing domains: {} - `~.` may still be on it", e)),
    }
}

/// Every tailscaled reconnect puts `~.` back on tailscale0 (its own --accept-dns behavior), overriding ours.
/// In tunnel modes only the tunnel interface may carry `~.`. The fast tick checks every 5 s and corrects it.
/// Returns whether a correction was made.
pub async fn ts_dns_reconcile(ctx: &Ctx, intent: Intent) -> bool {
    if !crate::settings::get().tailscale.integrate {
        return false;
    }
    let Ok(Some(ts)) = ctx.nl.link_by_name("tailscale0").await else { return false };
    let doms = resolved::link_domains(ts.index as i32).await;
    if !doms.iter().any(|(d, r)| crate::dbus::resolved::is_catchall(d, *r)) {
        return false;
    }
    match intent {
        Intent::Mode(m) if m.is_tunnel() => {
            ctx.jlog("tailscale0 has ~. again (a tailscaled reconnect overrides our settings) - resetting routing domains");
            ts_dns_on(ctx).await;
        }
        // portal / off / no tunnel: `~.` on tailscale0 causes the captive-portal DNS deadlock, remove it
        _ => ts_dns_uncatchall(ctx).await,
    }
    true
}

/// In portal / unprotected mode `~.` must be removed from tailscale0, otherwise DNS deadlocks behind a captive
/// portal: passing the portal needs name resolution -> queries go to MagicDNS -> MagicDNS needs tailscale
/// connected -> which needs the portal passed first.
async fn ts_dns_uncatchall(ctx: &Ctx) {
    if !resolved::active().await {
        return;
    }
    let Ok(Some(ts)) = ctx.nl.link_by_name("tailscale0").await else { return };
    let doms = resolved::link_domains(ts.index as i32).await;
    if !doms.iter().any(|(d, routing)| crate::dbus::resolved::is_catchall(d, *routing)) {
        return;
    }
    let keep: Vec<String> = match tailscale::magicdns_suffix().await {
        Some(s) => vec![format!("~{}", s), "~ts.net".into()],
        None => vec!["~ts.net".into()], // remove ~. even without the suffix; better to lose short names for a while than deadlock DNS
    };
    let refs: Vec<&str> = keep.iter().map(String::as_str).collect();
    match resolved::set_link_domains(ts.index as i32, &refs).await {
        Ok(()) => ctx.jlog("removed the ~. global routing domain from tailscale0 (otherwise DNS deadlocks behind a captive portal)"),
        Err(e) => ctx.jlog(&format!("⚠ failed to remove ~. from tailscale0: {}", e)),
    }
}

async fn warn_exit_node(ctx: &Ctx) {
    if let Some(en) = tailscale::exit_node().await {
        ctx.io.warn(format!("Tailscale exit node is on ({}) - it takes over the default route, so your exit will be it, not the VPN", en));
        ctx.io.hint("turn it off: sudo tailscale set --exit-node=");
    }
}

async fn warn_foreign_forward_drop(ctx: &Ctx) {
    let bad = nft::foreign_forward_drop_tables();
    if bad.is_empty() {
        return;
    }
    ctx.jlog(&format!("⚠ other tables drop on the forward hook: {} - the portal netns may not get out", bad.join(", ")));
    ctx.io.warn(format!("besides the kill switch, these tables sit on the forward hook with policy drop: {} - the portal netns may not get out", bad.join(", ")));
    ctx.io.hint("most common source is Docker (stopping it does not remove them): sudo systemctl disable --now docker.socket docker.service && sudo iptables -P FORWARD ACCEPT");
}

async fn cur_ssid() -> Option<String> {
    crate::netclass::network_id().await
}

/// After loading rules, reclassify the network and repopulate lan_allow.
pub async fn repopulate_class(ctx: &Ctx) {
    let ssid = cur_ssid().await;
    let class = crate::netclass::classify(ssid.as_deref());
    let phy = ctx.nl.phy_dev().await.ok().flatten().map(|l| l.index);
    for l in crate::netclass::apply_lan(&ctx.nl, class, phy).await {
        ctx.jlog(&l);
    }
}

async fn wg_conf() -> Result<wg::WgConf> {
    tokio::task::spawn_blocking(wg::WgConf::load).await?
}

// ── intent flags ──────────────────────────────────────────────
/// Each branch clears the other flags; a flag records what was actually executed this time, so it is
/// written at the start of the action.
fn manual_flags(ctx: &Ctx, m: Mode) {
    match m {
        Mode::Off => {
            util::touch(MANUAL_OFF);
            util::rm(MANUAL_PORTAL);
            util::rm(PORTAL_HANDOFF);
        }
        Mode::Portal => {
            util::rm(MANUAL_OFF);
            if !ctx.automated {
                util::touch(MANUAL_PORTAL);
            }
        }
        _ => {
            util::rm(MANUAL_OFF);
            util::rm(MANUAL_PORTAL);
            util::rm(PORTAL_HANDOFF);
        }
    }
}

// ── modes ─────────────────────────────────────────────────────
pub async fn apply(ctx: &mut Ctx, m: Mode) -> Result<()> {
    manual_flags(ctx, m);
    if m != Mode::Portal {
        // Leaving portal: the netns is about to be torn down, so the portal browser would have no network anyway.
        // Automatic protection after the portal is passed also goes through here - close the window too
        crate::portal_browser::close();
    }
    match m {
        Mode::Auto => {
            let ssid = cur_ssid().await;
            climb(ctx, &ladder_for(ssid.as_deref()), true).await
        }
        Mode::Only(t) => climb(ctx, &[t], false).await,
        Mode::Portal => mode_portal(ctx).await,
        Mode::Off => mode_off(ctx).await,
    }
}

/// The configured ladder ([tunnels] ladder), minus rungs that are not set up on this machine.
pub fn ladder() -> Vec<Tunnel> {
    crate::settings::get().tunnels.ladder.iter().filter_map(|t| Tunnel::parse(t)).filter(|t| available(*t)).collect()
}

/// The ladder for this network: the rung that worked here last time first, then the rest in order.
pub fn ladder_for(ssid: Option<&str>) -> Vec<Tunnel> {
    let mut l = ladder();
    if let Some(r) = ssid.and_then(state::remembered_rung) {
        if let Some(i) = l.iter().position(|t| *t == r) {
            let t = l.remove(i);
            l.insert(0, t);
        }
    }
    l
}

/// Which tunnel is actually carrying traffic right now (not what the intent names).
pub async fn actual_tunnel(ctx: &Ctx) -> Option<Tunnel> {
    if ctx.wst.running() {
        Some(Tunnel::Wstunnel)
    } else if ctx.nl.link_exists(WG_IF).await {
        Some(Tunnel::WireGuard)
    } else if ctx.nl.link_exists(&ovpn_if()).await {
        Some(Tunnel::OpenVpn)
    } else {
        None
    }
}

/// Is this rung configured at all (config files and binaries present)?
pub fn available(t: Tunnel) -> bool {
    match t {
        Tunnel::WireGuard => util::exists(&wg_conf_path()),
        Tunnel::OpenVpn => util::exists(&ovpn_conf()),
        Tunnel::Wstunnel => util::exists(&wg_conf_path()) && util::exists(&wst_conf()) && util::exists(&wst_client()),
    }
}

fn wg_conf_path() -> String {
    crate::paths::wg_conf()
}

/// Tear down every tunnel. Each rung starts from a clean slate, so a half-built previous attempt can't linger.
pub async fn tunnels_down(ctx: &mut Ctx) {
    wst::teardown(ctx).await;
    ovpn_down().await;
    ts_rule_off(ctx).await;
    wg::down(&ctx.nl).await;
}

/// Bring protection up: kill switch first, then try each rung in order until one is verified working.
/// `auto`: this is the user's "just protect me", so total failure is recorded as failed-closed.
async fn climb(ctx: &mut Ctx, rungs: &[Tunnel], auto: bool) -> Result<()> {
    warn_exit_node(ctx).await;
    netns::down(&ctx.nl).await;
    load_rules()?;
    repopulate_class(ctx).await;
    let intent = if auto { Mode::Auto } else { Mode::Only(rungs[0]) };
    if rungs.is_empty() {
        tunnels_down(ctx).await;
        state::write_intent(Intent::FailedClosed);
        ctx.io.fail("no tunnel is configured (see [tunnels] ladder in config.toml) - kill switch is on: no network, but no leaks");
        return Err(anyhow!("no tunnel configured"));
    }
    let ssid = cur_ssid().await;
    ctx.jlog(&format!("-> {} (ladder {}, class={}, ssid={})", intent, rungs.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(" > "), util::read_trim(NET_CLASS).unwrap_or_default(), ssid.as_deref().unwrap_or("")));
    let mut last_err = anyhow!("not tried");
    for (i, t) in rungs.iter().enumerate() {
        tunnels_down(ctx).await;
        // Written before the attempt so the watchdog doesn't grab the wheel midway. Auto stays auto on every
        // rung; what actually runs is judged from the interfaces, and remembered per network below.
        state::write_intent(Intent::Mode(intent));
        match rung_up(ctx, *t, ssid.as_deref()).await {
            Ok(ip) => {
                if auto && i > 0 {
                    ctx.jlog(&format!("fell back to {}", t.as_str()));
                }
                if let Some(s) = ssid.as_deref() {
                    state::remember_rung(s, *t);
                }
                ctx.io.ok(format!("{} | {} | exit {}", intent, t.as_str(), ip));
                return Ok(());
            }
            Err(e) => {
                ctx.jlog(&format!("{} failed: {:#}", t.as_str(), e));
                last_err = e;
            }
        }
    }
    tunnels_down(ctx).await;
    if auto || rungs.len() > 1 {
        state::write_intent(Intent::FailedClosed);
        ctx.jlog("every tunnel failed - staying fail-closed (no network, but no leaks)");
        ctx.io.fail(format!("every tunnel failed ({}) - kill switch stays on: no network, but no leaks", rungs.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(", ")));
        ctx.io.hint("captive portal?  torii portal        really go unprotected (exposes your real identity)?  sudo torii down");
        return Err(anyhow!("all tunnels failed, fail-closed"));
    }
    ctx.io.hint("try the whole ladder: torii up auto        go unprotected: sudo torii down");
    Err(last_err)
}

/// Bring up one rung and verify it by measuring a real exit IP. Returns the exit IP.
async fn rung_up(ctx: &mut Ctx, t: Tunnel, ssid: Option<&str>) -> Result<String> {
    match t {
        Tunnel::WireGuard => {
            let wgc = wg_conf().await?;
            ctx.io.step(&format!("WireGuard | UDP {}", wgc.endpoint.rsplit(':').next().unwrap_or("?")));
            wg::up(&ctx.nl, &wgc, None).await?;
            match tunnel_check(ctx, 10).await {
                Some((ip, secs)) => {
                    ctx.io.done(format!("up {:.1}s", secs));
                    ts_rule_on(ctx).await;
                    ts_dns_on(ctx).await;
                    Ok(ip)
                }
                None => {
                    ctx.io.done("failed, UDP may be blocked");
                    Err(anyhow!("WireGuard: no working exit within 10 s"))
                }
            }
        }
        Tunnel::OpenVpn => {
            if !util::exists(&ovpn_conf()) {
                return Err(anyhow!("OpenVPN not configured (missing {})", ovpn_conf()));
            }
            ctx.io.step("OpenVPN | TCP");
            // No tailscale rule here: OpenVPN's redirect-gateway puts 0/1 + 128/1 into main, so tailscale's
            // lookups in main go into the OpenVPN interface by themselves.
            match ovpn_up().await {
                Ok(true) => match tunnel_check(ctx, 20).await {
                    Some((ip, secs)) => {
                        ctx.io.done(format!("up {:.1}s", secs));
                        ts_dns_on(ctx).await;
                        Ok(ip)
                    }
                    None => {
                        ctx.io.done("failed, looks like DPI recognized the protocol");
                        Err(anyhow!("OpenVPN: no working exit within 20 s"))
                    }
                },
                Ok(false) => {
                    ctx.io.done(format!("no interface within 20 s (journalctl -u {})", ovpn_unit()));
                    Err(anyhow!("OpenVPN interface did not appear"))
                }
                Err(e) => {
                    ctx.io.done(format!("failed to start: {}", e));
                    Err(e)
                }
            }
        }
        Tunnel::Wstunnel => {
            let conf = WstConf::load()?;
            let wgc = wg_conf().await?;
            let carrier = wst::active_carrier(&conf, ssid);
            wst::carrier_route_on(ctx, &conf, &carrier).await?;
            match wst::bring_up(ctx, &conf, &wgc, ssid).await {
                wst::BringUp::Up(v, ip) => {
                    ts_rule_on(ctx).await;
                    ts_dns_on(ctx).await;
                    match v {
                        wst::Variant::Clean => ctx.io.say("  wstunnel[clean]: no SNI, verified certificate"),
                        wst::Variant::Named => ctx.io.say(format!("  wstunnel[named]: SNI {}, verified certificate", conf.sni_named)),
                        wst::Variant::Disguised => {
                            ctx.io.say(format!("  wstunnel[disguised]: disguised SNI {}, certificate not verified", conf.sni_fallback));
                            ctx.io.warn("degraded variant: a man-in-the-middle on the path can obtain WST_SECRET (the inner WireGuard is still end-to-end encrypted). The watchdog tries to upgrade once a day");
                        }
                    }
                    Ok(ip)
                }
                r => {
                    wst::carrier_route_off(ctx).await;
                    let why = match r {
                        wst::BringUp::NoCarrier => "no way out at the physical layer (carrier TCP connection failed)",
                        wst::BringUp::Portal => "blocked by a captive portal (carrier certificate verification failed)",
                        _ => "all variants failed",
                    };
                    ctx.io.hint(format!("see: torii log | torii wst log | {}", WST_LOG));
                    Err(anyhow!("wstunnel: {}", why))
                }
            }
        }
    }
}

async fn mode_off(ctx: &mut Ctx) -> Result<()> {
    wst::teardown(ctx).await;
    netns::down(&ctx.nl).await;
    ts_rule_off(ctx).await;
    ts_dns_uncatchall(ctx).await; // the escape hatch itself must not be broken: with `~.` on tailscale0, nothing resolves even unprotected
    ovpn_down().await;
    wg::down(&ctx.nl).await;
    nft::flush_killswitch();
    state::write_intent(Intent::Mode(Mode::Off));
    ctx.jlog("→ off (protection removed)");
    ctx.io.warn("off | rules flushed, raw network, no protection at all");
    ctx.io.hint("to restore: torii up");
    Ok(())
}

/// portal: the kill switch stays on throughout; only a throwaway browser in a netns goes straight to the physical gateway.
async fn mode_portal(ctx: &mut Ctx) -> Result<()> {
    wst::teardown(ctx).await;
    netns::down(&ctx.nl).await;
    ovpn_down().await;
    wg::down(&ctx.nl).await;
    ts_rule_off(ctx).await;
    ts_dns_uncatchall(ctx).await;
    load_rules()?;
    repopulate_class(ctx).await;
    let phy = ctx.nl.phy_dev().await?;
    let gw = match &phy {
        Some(p) => ctx.nl.default_gw(p.index).await?,
        None => None,
    };
    let dhcp_dns = resolved_link_dns(phy.as_ref().map(|p| p.index)).await;
    let dns = netns::up(&ctx.nl, phy.as_ref().map(|p| p.name.as_str()), dhcp_dns, gw).await?;
    ctx.jlog(&format!(
        "portal netns DNS: options timeout:1 attempts:2 {}  (phy={} gw={})",
        dns.resolvers.iter().map(|r| format!("nameserver {}", r)).collect::<Vec<_>>().join(" "),
        dns.phy.as_deref().unwrap_or("none"),
        dns.gw.as_deref().unwrap_or("none")
    ));
    warn_foreign_forward_drop(ctx).await;
    state::write_intent(Intent::Mode(Mode::Portal));
    ctx.jlog("→ portal (kill switch on, only the portal netns is allowed)");
    ctx.io.ok("portal | kill switch stays on; only the throwaway browser in the portal netns can reach the network");
    ctx.io.hint("open the login page: torii portal      protection comes back automatically after login (or torii up)");
    Ok(())
}

/// First IPv4 resolver from DHCP on the physical link (read from resolved's link object).
async fn resolved_link_dns(ifindex: Option<u32>) -> Option<String> {
    let idx = ifindex?;
    let c = crate::dbus::system().await.ok()?;
    let path = crate::dbus::resolved::link_path(idx);
    let p = zbus::Proxy::new(&c, "org.freedesktop.resolve1", path, "org.freedesktop.resolve1.Link").await.ok()?;
    let v: Vec<(i32, Vec<u8>)> = p.get_property("DNS").await.ok()?;
    v.into_iter().find(|(f, _)| *f == libc::AF_INET).and_then(|(_, b)| (b.len() == 4).then(|| format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])))
}

// ── status: one screen ────────────────────────────────────────
/// Extra information supplied by the daemon (not available on the direct path).
#[derive(Default, Clone)]
pub struct StatusExtra {
    pub wst_running: bool,
    pub wst_variant: Option<String>,
    pub busy: Option<(String, u64)>,
    pub daemon_since: u64,
    pub fails: u32,
    pub probe_done: u64,
    pub probe_skipped: u64,
    pub last_action: u64,
}

fn ago(ts: u64) -> String {
    if ts == 0 {
        return "-".into();
    }
    let d = util::now().saturating_sub(ts);
    if d < 60 {
        format!("{}s ago", d)
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else {
        format!("{}h{}m ago", d / 3600, (d % 3600) / 60)
    }
}

pub async fn status_lines(nl: &Nl, extra: Option<&StatusExtra>) -> Vec<String> {
    use crate::ui::kv;
    let mut out = vec![];
    let intent = Intent::read();
    let h = state::read_health();
    let wg_up = nl.link_exists(WG_IF).await;
    let ovpn_up = nl.link_exists(&ovpn_if()).await;
    let wst_running = extra.map(|e| e.wst_running).unwrap_or_else(|| !wst::stray_pids().is_empty());

    // mode + phase
    let carrier = match intent {
        Intent::Mode(m) if m.is_tunnel() && wst_running => "WireGuard in TLS 443 via carrier server",
        Intent::Mode(m) if m.is_tunnel() && wg_up => "WireGuard/UDP",
        Intent::Mode(m) if m.is_tunnel() && ovpn_up => "OpenVPN/TCP",
        Intent::Mode(Mode::Portal) => "portal netns only",
        Intent::Mode(Mode::Off) => "unprotected",
        Intent::FailedClosed => "no tunnel (fail-closed)",
        _ => "",
    };
    let mut mode_s = intent.as_str();
    if !carrier.is_empty() {
        mode_s = format!("{} | {}", mode_s, carrier);
    }
    if wst_running {
        // A tunnel the daemon started knows its variant; an adopted one (daemon restarted) is looked up by SSID
        let mut v = extra.and_then(|e| e.wst_variant.clone());
        if v.is_none() {
            if let Some(ssid) = crate::netclass::network_id().await {
                v = wst::variant_get(&ssid).map(|x| x.as_str().to_string());
            }
        }
        if let Some(v) = v {
            mode_s = format!("{}[{}]", mode_s, v);
        }
    }
    out.push(kv("mode", &mode_s));
    let hs = wg::handshake_age().map(|a| format!("handshake {}s ago", a));
    let phase = match &h {
        Some(h) => {
            let mut p = h.phase.clone();
            if let Some(ip) = h.reason.strip_prefix("ok:").or_else(|| h.reason.split(':').nth(2)) {
                let ip = ip.split('(').next().unwrap_or(ip);
                if !ip.is_empty() && ip.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    p = format!("{} | exit {}", p, ip);
                }
            }
            if !h.healthy && !h.reason.starts_with("skip:") {
                p = format!("{} | {}", p, h.reason);
            }
            p
        }
        None => "(watchdog has not written a health file)".into(),
    };
    out.push(kv("phase", &format!("{}{}", phase, hs.map(|x| format!(" | {}", x)).unwrap_or_default())));

    // network
    let phy = nl.phy_dev().await.ok().flatten();
    let wifi = crate::wifi::state().await;
    let net_s = match (&phy, &wifi) {
        (Some(p), Some(w)) if p.name == w.dev => format!("{} ({}) | {} {} | conn {}", w.ssid.clone().unwrap_or_else(|| w.state.clone()), util::read_trim(NET_CLASS).unwrap_or("?".into()), w.dev, w.mac, h.as_ref().map(|h| h.conn.as_str()).unwrap_or("?")),
        (Some(p), _) => format!("wired {} {} | conn {}", p.name, p.mac.clone().unwrap_or_default(), h.as_ref().map(|h| h.conn.as_str()).unwrap_or("?")),
        (None, _) => "no physical interface is UP".into(),
    };
    out.push(kv("network", &net_s));
    if let Some(ssid) = wifi.as_ref().and_then(|w| w.ssid.clone()) {
        if let Some((how, when)) = state::portal_memory_get(&ssid) {
            out.push(kv("portal", &format!("last time: {} ({})", how, when.get(..10).unwrap_or(&when))));
        }
    }

    // protection
    let prot = if util::is_root() {
        let ks = nft::ks_loaded();
        let lan = nft::lan_allow_elements().map(|v| if v.is_empty() { "LAN not allowed".to_string() } else { format!("LAN allowed {}", v.iter().filter(|e| !e.starts_with("224.") && !e.starts_with("239.") && !e.starts_with("255.")).cloned().collect::<Vec<_>>().join(", ")) });
        format!("killswitch {}{}", if ks { "loaded" } else { "not loaded" }, lan.map(|l| format!(" | {}", l)).unwrap_or_default())
    } else {
        format!("killswitch {} (non-root: from health file only)", h.as_ref().map(|h| if h.ks { "loaded" } else { "not loaded" }).unwrap_or("?"))
    };
    out.push(kv("protect", &prot));

    // tailnet
    let ts_s = if !nl.link_exists("tailscale0").await {
        "tailscale0 not up".to_string()
    } else {
        let redirect = nl.rule_exists(TS_PRIO, false).await.unwrap_or(false);
        let route = nl.route_lookup_dev(Ipv4Addr::new(100, 100, 100, 100)).await.ok().flatten();
        let r = match route.as_deref() {
            Some("tailscale0") => "100.64/10 → tailscale0".to_string(),
            None => "no route found".into(),
            Some(d) => format!("**broken** 100.64/10 goes via {}", d),
        };
        format!("{} | {}", if redirect { "inside the tunnel (5200)" } else { "own bypass route" }, r)
    };
    out.push(kv("tailnet", &ts_s));

    // DNS (routing domains per link)
    let mut dns_parts = vec![];
    for name in [WG_IF, &ovpn_if(), "tailscale0"] {
        if let Ok(Some(l)) = nl.link_by_name(name).await {
            let doms = resolved::link_domains(l.index as i32).await;
            let servers = resolved_link_dns_all(l.index).await;
            if servers.is_empty() && doms.is_empty() {
                continue;
            }
            let d: Vec<String> = doms.iter().map(|(d, r)| if *r { format!("~{}", d) } else { d.clone() }).collect();
            dns_parts.push(format!("{} → {}{}", name, servers.join(","), if d.is_empty() { String::new() } else { format!(" ({})", d.join(" ")) }));
        }
    }
    if let Some(p) = &phy {
        let doms = resolved::link_domains(p.index as i32).await;
        if doms.iter().any(|(d, r)| crate::dbus::resolved::is_catchall(d, *r)) {
            dns_parts.push(format!("{} also has ~.", p.name));
        }
    }
    let dns_s = if dns_parts.is_empty() { "no link has routing domains - queries use the physical link's resolver".to_string() } else { dns_parts.join(" | ") };
    let dns_warn = matches!(intent, Intent::Mode(m) if m.is_tunnel()) && !dns_parts.iter().any(|p| p.starts_with(WG_IF) || p.starts_with(&ovpn_if()));
    out.push(kv("DNS", &format!("{}{}", dns_s, if dns_warn { "  ⚠ tunnel is up but DNS is not going through it" } else { "" })));

    // watchdog / daemon
    let wd_s = match (extra, &h) {
        (Some(e), Some(h)) => format!(
            "{} | {} failures | probes {}/cached {} | last action {} | daemon started {}{}",
            if h.healthy { "healthy" } else { "unhealthy" }, e.fails, e.probe_done, e.probe_skipped, ago(e.last_action), ago(e.daemon_since),
            e.busy.as_ref().map(|(w, t)| format!(" | busy: {} ({})", w, ago(*t))).unwrap_or_default()
        ),
        (None, Some(h)) => format!("{} | health file {} | daemon not running (systemctl status toriid)", if h.healthy { "healthy" } else { "unhealthy" }, ago(h.ts)),
        _ => "daemon not running, no health file".into(),
    };
    out.push(kv("watchdog", &wd_s));
    if let Some(h) = &h {
        if let Some(a) = &h.advice {
            out.push(kv("advice", &a.text));
        }
    }
    out
}

async fn resolved_link_dns_all(ifindex: u32) -> Vec<String> {
    let Ok(c) = crate::dbus::system().await else { return vec![] };
    let path = crate::dbus::resolved::link_path(ifindex);
    let Ok(p) = zbus::Proxy::new(&c, "org.freedesktop.resolve1", path, "org.freedesktop.resolve1.Link").await else { return vec![] };
    let Ok(v) = p.get_property::<Vec<(i32, Vec<u8>)>>("DNS").await else { return vec![] };
    v.into_iter()
        .filter_map(|(f, b)| match (f, b.len()) {
            (libc::AF_INET, 4) => Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])),
            (libc::AF_INET6, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&b);
                Some(Ipv6Addr::from(a).to_string())
            }
            _ => None,
        })
        .collect()
}

pub async fn status_text(nl: &Nl) -> String {
    status_lines(nl, None).await.join("\n") + "\n"
}
