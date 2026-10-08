//! daemon: the single executor. All mode switches and watchdog actions are serialized in one actor;
//! events (rtnetlink / iwd / logind / CLI) only wake it up. User/watchdog collisions are impossible by construction.
use crate::config::WdConf;
use crate::dbus;
use crate::journal;
use crate::modes::{self, Ctx, Io};
use crate::netclass;
use crate::nl::{self, nft, Nl};
use crate::paths::*;
use crate::policy::{self, Obs};
use crate::probe::{self, Conn};
use crate::state::{self, Health, Intent, Mode};
use crate::util;
use crate::watchdog::Watchdog;
use crate::wst;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

const TAG: &str = "toriid";
const MAX_CLIENTS: usize = 16;
const MAX_REQUEST: u64 = 16 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Request {
    pub cmd: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub automated: bool,
}

struct Job {
    req: Request,
    uid: u32,
    out: mpsc::UnboundedSender<String>,
    done: oneshot::Sender<i32>,
}

#[derive(Clone)]
pub struct Shared {
    /// (what is running, start time)
    pub busy: Arc<Mutex<Option<(String, u64)>>>,
    pub since: u64,
    /// Time of the last resume (logind signal / hook marker); lets the notifier say "just resumed, nothing to do"
    pub resumed_at: Arc<Mutex<u64>>,
}

/// Snapshot, taken once at the start of each round.
async fn observe(nl: &Nl, conn: Conn, resumed: bool) -> Obs {
    let intent = Intent::read();
    let phy = nl.phy_dev().await.ok().flatten();
    let phy_has_ip = match &phy {
        Some(p) => nl.has_ipv4(p.index).await,
        None => false,
    };
    let ssid = crate::netclass::network_id_for(phy.as_ref()).await;
    Obs {
        now: util::now(),
        intent,
        intent_age: state::intent_age(),
        manual_off: util::exists(MANUAL_OFF),
        manual_portal: util::exists(MANUAL_PORTAL),
        portal_handoff: util::exists(PORTAL_HANDOFF),
        phy: phy.as_ref().map(|p| p.name.clone()),
        phy_has_ip,
        at_home: netclass::classify(ssid.as_deref()) == netclass::Class::Trusted,
        ssid,
        conn,
        carrier_flag: state::carrier_flag_read(180),
        resumed,
        net_changed: false, // filled in by the watchdog against its own last_ssid
    }
}

pub async fn run() -> Result<()> {
    if !util::is_root() {
        return Err(anyhow!("the daemon must run as root"));
    }
    journal::notice(TAG, "toriid starting");
    let nl = Nl::new()?;
    let shared = Shared { busy: Arc::new(Mutex::new(None)), since: util::now(), resumed_at: Arc::new(Mutex::new(0)) };
    let mut ctx = Ctx { nl: nl.clone(), io: Io::default(), wst: wst::Client::default(), carrier_wait_budget: 40, automated: false };
    let mut wd = Watchdog::new();

    // -- socket --
    let _ = std::fs::remove_file(SOCK);
    let listener = UnixListener::bind(SOCK)?;
    let _ = std::fs::set_permissions(SOCK, std::os::unix::fs::PermissionsExt::from_mode(0o666));
    let (job_tx, mut job_rx) = mpsc::unbounded_channel::<Job>();
    {
        let shared = shared.clone();
        // The socket is world-connectable so `torii status` works for everyone; what a caller may do is
        // decided in serve() before anything reaches the actor. Bounded so nobody can pile up connections.
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { continue };
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                let tx = job_tx.clone();
                let sh = shared.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, tx, sh).await;
                    drop(permit);
                });
            }
        });
    }

    // -- event sources --
    let mut nl_ev = nl::subscribe().ok();
    let mut wifi_ev = crate::wifi::state_events().await.ok();
    let mut resume_ev = dbus::logind::resume_events().await.ok();
    if wifi_ev.is_none() {
        journal::notice(TAG, "iwd signal subscription failed, falling back to polling");
    }

    let cfg = WdConf::load();
    let mut tick_timer = tokio::time::interval(Duration::from_secs(cfg.tick.max(15)));
    tick_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut fast_timer = tokio::time::interval(Duration::from_secs(5));
    let mut debounce: Option<tokio::time::Instant> = None;
    let mut resumed_pending = false;
    let mut last_conn = Conn::Unknown;
    let mut last_class: Option<netclass::Class> = None;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut last_phy: Option<String> = None;
    let mut last_phy_probed: Option<String> = None;
    let mut last_conn_ts = 0u64;

    loop {
        // debounce: one run per burst of events
        let debounce_sleep = async {
            match debounce {
                Some(t) => tokio::time::sleep_until(t).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = sigterm.recv() => { shutdown(&mut ctx).await; return Ok(()); }
            _ = sigint.recv() => { shutdown(&mut ctx).await; return Ok(()); }
            Some(job) = job_rx.recv() => {
                handle_job(&mut ctx, &mut wd, &shared, job).await;
                write_health_now(&mut wd, &ctx, &shared, last_conn, None).await;
            }
            _ = tick_timer.tick() => {
                // After a 90s round, drop the ticks the timer accumulated instead of running back to back
                // (observed: two "unhealthy" entries logged in the same second)
                tick_timer.reset();
                debounce = None;
                run_tick(&mut ctx, &mut wd, &shared, &mut last_conn, &mut resumed_pending).await;
                tick_timer.reset();
            }
            _ = debounce_sleep => {
                debounce = None;
                run_tick(&mut ctx, &mut wd, &shared, &mut last_conn, &mut resumed_pending).await;
                tick_timer.reset();
            }
            _ = fast_timer.tick() => {
                // Cheap observation: connectivity + network class + notifier advice. No actions.
                let phy = nl.phy_dev().await.ok().flatten();
                let phy_name = phy.as_ref().map(|p| p.name.clone());
                if phy_name != last_phy {
                    last_phy = phy_name.clone();
                    debounce = Some(tokio::time::Instant::now() + Duration::from_secs(1));
                }
                // The connectivity probe is an outbound beacon (a 204 request to a fixed site), so not every 5s:
                // every 5 minutes while up (NM's default cadence); every 10s while down, to catch the
                // limited -> full flip quickly; immediately when the link changes.
                let due = match last_conn {
                    Conn::Full => util::now().saturating_sub(last_conn_ts) >= 300,
                    _ => util::now().saturating_sub(last_conn_ts) >= 10,
                };
                // iwd's Station object doesn't exist until the NIC is up, so the boot-time subscription fails -
                // retry every 30s
                if wifi_ev.is_none() && phy.is_some() && util::now() % 30 < 5 {
                    if let Ok(rx) = crate::wifi::state_events().await {
                        journal::notice(TAG, "iwd signal subscription succeeded (retry)");
                        wifi_ev = Some(rx);
                    }
                }
                // In tunnel modes tailscale0 must not hold `~.` (tailscaled reapplies it on reconnect)
                if shared.busy.lock().unwrap().is_none() {
                    modes::ts_dns_reconcile(&ctx, Intent::read()).await;
                }
                let conn = if phy.is_none() {
                    Conn::Limited
                } else if due || phy_name != last_phy_probed {
                    last_conn_ts = util::now();
                    last_phy_probed = phy_name.clone();
                    tokio::task::spawn_blocking(probe::connectivity_here).await.unwrap_or(Conn::Unknown)
                } else {
                    last_conn
                };
                last_conn = conn;
                // Network classification: refill lan_allow when the SSID changes, auto-protect at home
                let ssid = crate::netclass::network_id_for(phy.as_ref()).await;
                let class = netclass::classify(ssid.as_deref());
                let class_key = Some(class).filter(|_| phy.is_some());
                if class_key != last_class {
                    last_class = class_key;
                    if phy.is_some() {
                        netclass::write_class(class);
                        journal::notice("toriid-netclass", &format!("class={} iface={} ssid={}", class.as_str(), phy_name.as_deref().unwrap_or("?"), ssid.as_deref().unwrap_or("")));
                        for l in netclass::apply_lan(&nl, class, phy.as_ref().map(|p| p.index)).await { journal::notice("toriid-netclass", &l); }
                        if class == netclass::Class::Trusted && !util::exists(MANUAL_OFF) && !matches!(Intent::read(), Intent::Mode(m) if m.is_tunnel()) {
                            journal::notice("toriid-netclass", "trusted network, bringing protection up automatically");
                            let _ = run_action(&mut ctx, &mut wd, &shared, "auto-protect", |c| Box::pin(modes::apply(c, Mode::Auto))).await;
                        }
                        debounce = Some(tokio::time::Instant::now() + Duration::from_secs(1));
                    } else {
                        netclass::write_class(netclass::Class::Hostile);
                        nft::lan_clear();
                    }
                }
                write_health_now(&mut wd, &ctx, &shared, conn, None).await;
            }
            Some(_) = async { match nl_ev.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {
                debounce = Some(tokio::time::Instant::now() + Duration::from_secs(1));
            }
            Some(st) = async { match wifi_ev.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {
                journal::notice(TAG, &format!("wifi: {}", st));
                // Network changed: the previous network's connectivity is void. Caching by interface name alone
                // is wrong (both networks are wlan0) - observed: a hotspot's `full` carried over for 7s and the
                // notifier showed a false "portal passed"
                last_conn = Conn::Unknown;
                last_conn_ts = 0;
                debounce = Some(tokio::time::Instant::now() + Duration::from_secs(1));
            }
            Some(()) = async { match resume_ev.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {
                journal::notice(TAG, "logind: resumed");
                *shared.resumed_at.lock().unwrap() = util::now();
                resumed_pending = true;
                debounce = Some(tokio::time::Instant::now() + Duration::from_secs(3));
            }
        }
    }
}

/// Shutdown: remove the socket; **do not tear down the tunnel** - a daemon restart must not drop the network.
/// The wstunnel child is released (the next daemon adopts it).
async fn shutdown(ctx: &mut Ctx) {
    journal::notice(TAG, "toriid got stop signal, exiting (tunnel kept)");
    let _ = std::fs::remove_file(SOCK);
    wst::release_child(&mut ctx.wst);
}

type ActionFut<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;

async fn run_action(ctx: &mut Ctx, wd: &mut Watchdog, shared: &Shared, what: &str, f: impl FnOnce(&mut Ctx) -> ActionFut<'_>) -> Result<()> {
    let hb = begin_busy(shared, &ctx.nl, what, wd.mem.gave_up).await;
    let r = f(ctx).await;
    end_busy(shared, hb);
    r
}

/// Action start: set busy, write the health file with busy **immediately**, then start a heartbeat that
/// refreshes ts/busy/advice every 5s. Previously busy only lived during the action and the health file was
/// written afterwards - the notifier never saw "working on it, hands off", and a 200s switch made it
/// falsely report the watchdog as dead.
async fn begin_busy(shared: &Shared, nl: &Nl, what: &str, gave_up: bool) -> tokio::task::JoinHandle<()> {
    *shared.busy.lock().unwrap() = Some((what.to_string(), util::now()));
    write_busy_health(shared, nl, gave_up).await; // write once synchronously: the action may finish in ms, before the heartbeat runs
    let sh = shared.clone();
    let nl = nl.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            write_busy_health(&sh, &nl, gave_up).await;
        }
    })
}

async fn write_busy_health(sh: &Shared, nl: &Nl, gave_up: bool) {
    let h0 = state::read_health().unwrap_or_default();
    let conn = Conn::parse(&h0.conn);
    let o = observe(nl, conn, false).await;
    let busy = sh.busy.lock().unwrap().clone();
    let adv = policy::advice(&o, nft::ks_loaded(), busy.as_ref().map(|b| b.0.as_str()), busy.as_ref().map(|b| util::now().saturating_sub(b.1)).unwrap_or(0), gave_up, resumed_ago(sh));
    let h = Health {
        ts: util::now(),
        mode: o.intent.as_str(),
        ssid: o.ssid.clone().unwrap_or_default(),
        advice: adv,
        busy: busy.as_ref().map(|b| b.0.clone()),
        busy_since: busy.map(|b| b.1).unwrap_or(0),
        phase: "establishing".into(),
        ..h0
    };
    state::write_health(&h);
}

fn resumed_ago(sh: &Shared) -> Option<u64> {
    let t = *sh.resumed_at.lock().unwrap();
    (t > 0).then(|| util::now().saturating_sub(t))
}

fn end_busy(shared: &Shared, hb: tokio::task::JoinHandle<()>) {
    hb.abort();
    *shared.busy.lock().unwrap() = None;
    util::rm(STEP); // action done: the bar's "now: ..." goes away with it
}

async fn run_tick(ctx: &mut Ctx, wd: &mut Watchdog, shared: &Shared, last_conn: &mut Conn, resumed_pending: &mut bool) {
    let resumed = *resumed_pending;
    if resumed && *shared.resumed_at.lock().unwrap() == 0 {
        *shared.resumed_at.lock().unwrap() = util::now();
    }
    *resumed_pending = false;
    // Resume/event-driven rounds need fresh connectivity; timer rounds reuse fast_timer's value (it has its
    // own cadence) instead of sending another beacon
    let conn = if resumed || *last_conn == Conn::Unknown {
        let c = tokio::task::spawn_blocking(probe::connectivity_here).await.unwrap_or(Conn::Unknown);
        *last_conn = c;
        c
    } else {
        *last_conn
    };
    let o = observe(&ctx.nl, conn, resumed).await;
    let hb = begin_busy(shared, &ctx.nl, "watchdog", wd.mem.gave_up).await;
    ctx.io = Io::default();
    ctx.automated = true;
    let (healthy, reason) = wd.tick(ctx, &o).await;
    end_busy(shared, hb);
    wd.mem.dump();
    write_health_now(wd, ctx, shared, conn, Some((healthy, reason))).await;
}

async fn write_health_now(wd: &mut Watchdog, ctx: &Ctx, shared: &Shared, conn: Conn, verdict: Option<(bool, String)>) {
    let o = observe(&ctx.nl, conn, false).await;
    let prev = state::read_health().unwrap_or_default();
    let (healthy, reason) = verdict.unwrap_or((prev.healthy, prev.reason.clone()));
    let reason_for_ip = reason.clone();
    let ks = nft::ks_loaded();
    let busy = shared.busy.lock().unwrap().clone();
    let adv = policy::advice(&o, ks, busy.as_ref().map(|b| b.0.as_str()), busy.as_ref().map(|b| util::now().saturating_sub(b.1)).unwrap_or(0), wd.mem.gave_up, resumed_ago(shared));
    let h = Health {
        ts: util::now(),
        mode: o.intent.as_str(),
        phase: policy::phase(o.intent, healthy, &reason, ks).into(),
        ssid: o.ssid.clone().unwrap_or_default(),
        healthy,
        reason,
        fails: wd.mem.fails,
        last_action: wd.mem.last_action,
        ks,
        probe_done: wd.mem.probe_done,
        probe_skipped: wd.mem.probe_skipped,
        conn: conn.as_str().into(),
        advice: adv,
        busy: busy.as_ref().map(|b| b.0.clone()),
        busy_since: busy.map(|b| b.1).unwrap_or(0),
        gave_up: wd.mem.gave_up,
        class: util::read_trim(NET_CLASS).unwrap_or_default(),
        daemon_pid: std::process::id(),
        tunnel: modes::actual_tunnel(ctx).await.map(|t| t.as_str()).unwrap_or("").into(),
        variant: if ctx.wst.running() { ctx.wst.variant.map(|v| v.as_str().to_string()).unwrap_or_default() } else { String::new() },
        exit_ip: exit_ip_of(&reason_for_ip).unwrap_or(prev.exit_ip),
    };
    state::write_health(&h);
}

/// The watchdog verdict carries the measured exit as `ok:<ip>` (or `...:...:<ip>(...)`).
fn exit_ip_of(reason: &str) -> Option<String> {
    let ip = reason.strip_prefix("ok:").or_else(|| reason.split(':').nth(2))?;
    let ip = ip.split('(').next().unwrap_or(ip).trim();
    ip.parse::<std::net::IpAddr>().ok().map(|_| ip.to_string())
}

/// The operator of this machine: [daemon] operator (username) in config.toml. Unset = only root.
fn operator_uid() -> Option<u32> {
    let s = crate::settings::get();
    if !s.daemon.operator.is_empty() {
        let c = std::ffi::CString::new(s.daemon.operator.as_str()).ok()?;
        let pw = unsafe { libc::getpwnam(c.as_ptr()) };
        return (!pw.is_null()).then(|| unsafe { (*pw).pw_uid });
    }
    None
}

fn who(uid: u32) -> policy::Who {
    if uid == 0 {
        policy::Who::Root
    } else if operator_uid() == Some(uid) {
        policy::Who::Operator
    } else {
        policy::Who::Other
    }
}

fn last_conn() -> Conn {
    Conn::parse(&state::read_health().map(|h| h.conn).unwrap_or_default())
}

/// Not permitted: say what to do instead and end the request
macro_rules! deny {
    ($out:expr, $done:expr, $why:expr) => {{
        let _ = $out.send(format!("{}fail {}", crate::ui::P_STYLE, $why));
        let _ = $done.send(1);
        return;
    }};
}

/// Per-request state (where progress goes, whether this counts as automated) must not outlive the request,
/// whichever way it ends - early denials return from inside handle_job_inner.
async fn handle_job(ctx: &mut Ctx, wd: &mut Watchdog, shared: &Shared, job: Job) {
    handle_job_inner(ctx, wd, shared, job).await;
    ctx.io = Io::default();
    ctx.automated = false;
}

async fn handle_job_inner(ctx: &mut Ctx, wd: &mut Watchdog, shared: &Shared, job: Job) {
    let Job { req, uid, out, done } = job;
    let root = uid == 0;
    let caller = who(uid);
    ctx.io = Io { tx: Some(out.clone()) };
    ctx.automated = req.automated;
    let rc = match req.cmd.as_str() {
        "mode" => {
            let Some(m) = req.args.first().and_then(|s| Mode::parse(s)) else { let _ = out.send("usage: mode {auto|wireguard|openvpn|wstunnel|portal|off}".into()); let _ = done.send(2); return };
            if let Err(why) = policy::may(caller, "mode", Some(m), last_conn()) {
                deny!(out, done, why);
            }
            let at_home = {
                let ssid = crate::netclass::network_id().await;
                netclass::classify(ssid.as_deref()) == netclass::Class::Trusted
            };
            let auto_portal = WdConf::load().auto_portal && !at_home && m.is_tunnel();
            match run_action(ctx, wd, shared, &format!("torii {}", m), |c| Box::pin(async move {
                // A manual torii up must recognize portals too: carrier cert verification failing = a portal
                // impersonating the carrier -> pass the portal, then protect. Previously only the watchdog path
                // did this; a manual switch into a portal just failed and waited for the next round (up to 60s).
                if auto_portal {
                    if let Some(p) = c.nl.phy_dev().await.ok().flatten() {
                        if let Some(ep) = crate::config::WstConf::peek_server() {
                            if let Ok(ip) = ep.parse::<std::net::IpAddr>() {
                                let dev = p.name.clone();
                                let r = tokio::task::spawn_blocking(move || probe::carrier(ip, 443, Some(&dev), true)).await.unwrap_or(probe::Carrier::Ok);
                                if r == probe::Carrier::BadCert {
                                    c.io.warn("carrier cert verification failed - a captive portal is impersonating the carrier, passing it first");
                                    c.automated = true;
                                    modes::apply(c, Mode::Portal).await?;
                                    let gw = c.nl.default_gw(p.index).await.ok().flatten();
                                    let rep = crate::portal::run(gw, false).await?;
                                    for l in &rep.log {
                                        c.io.say(format!("  {}", l));
                                    }
                                    use crate::portal::Outcome::*;
                                    match rep.outcome {
                                        Passed | AlreadyOpen | OpenedByRedirect => c.io.ok("portal passed, restoring protection"),
                                        o => {
                                            c.io.fail(format!("portal not passed ({:?}). Staying in portal mode", o));
                                            c.io.hint("Accept the terms manually: torii portal (protection is restored afterwards)");
                                            return Err(anyhow!("portal not passed"));
                                        }
                                    }
                                    c.automated = false;
                                }
                            }
                        }
                    }
                }
                modes::apply(c, m).await
            })).await {
                Ok(()) => 0,
                Err(e) => {
                    journal::err("toriid", &e.to_string());
                    1
                }
            }
        }
        "kick" => {
            if let Err(why) = policy::may(caller, "kick", None, last_conn()) {
                deny!(out, done, why);
            }
            let conn = tokio::task::spawn_blocking(probe::connectivity_here).await.unwrap_or(Conn::Unknown);
            let mut rp = false;
            let mut lc = conn;
            run_tick(ctx, wd, shared, &mut lc, &mut rp).await;
            let h = state::read_health().unwrap_or_default();
            let _ = out.send(format!("{}ok watchdog ran one round: {} - {}", crate::ui::P_STYLE, if h.healthy { "healthy" } else { "unhealthy" }, h.reason));
            0
        }
        "portal-auto" => {
            if let Err(why) = policy::may(caller, "portal-auto", None, last_conn()) {
                deny!(out, done, why);
            }
            let dry = req.args.iter().any(|a| a == "--dry-run");
            let r = run_action(ctx, wd, shared, "portal-auto", |c| {
                Box::pin(async move {
                    c.automated = false;
                    modes::apply(c, Mode::Portal).await?;
                    let gw = match c.nl.phy_dev().await.ok().flatten() {
                        Some(p) => c.nl.default_gw(p.index).await.ok().flatten(),
                        None => None,
                    };
                    let rep = crate::portal::run(gw, dry).await?;
                    for l in &rep.log {
                        c.io.say(format!("  {}", l));
                    }
                    let phases: Vec<String> = rep.phases.iter().map(|(n, t)| format!("{} +{:.1}s", n, t)).collect();
                    c.io.hint(phases.join(" | "));
                    use crate::portal::Outcome::*;
                    let passed = matches!(rep.outcome, Passed | AlreadyOpen | OpenedByRedirect);
                    match rep.outcome {
                        Passed => c.io.ok("login passed (204)"),
                        AlreadyOpen => c.io.ok("already online, no portal"),
                        OpenedByRedirect => c.io.ok("let through after following the redirect"),
                        _ => {}
                    }
                    if passed {
                        // A manual portal-auto means "pass the portal, then be online": restore protection per this
                        // network's history (dry-run too - don't leave the user in portal mode)
                        let ssid = crate::netclass::network_id().await;
                        let want = state::preferred_mode(ssid.as_deref(), &WdConf::load());
                        c.io.say(format!("  restoring protection -> {}", want));
                        return modes::apply(c, want).await;
                    }
                    match rep.outcome {
                        Passed | AlreadyOpen | OpenedByRedirect => { c.io.hint("staying in portal mode; to protect: torii up"); Ok(()) }
                        NoExit => { c.io.fail("gateway unreachable - no exit, not a portal. Retry in a few seconds or switch networks"); Err(anyhow!("no exit")) }
                        NoForm => { c.io.fail("no form found (raw page in /run/toriid/portal.dump) - most likely a JS login page"); c.io.hint("manually: torii portal"); Err(anyhow!("no form")) }
                        NeedsUser => { c.io.fail("this portal wants you to log in or fill something in"); c.io.hint("open it: torii portal"); Err(anyhow!("needs the user")) }
                        StillBlocked(x) if x == "dry-run" => {
                            c.io.warn("dry-run: form parsed, not submitted. Staying in portal mode (kill switch on)");
                            c.io.hint("submit for real: torii portal-auto    by hand: torii portal    give up: torii up");
                            // the watchdog takes over after 4 minutes, not the 15 of a manual portal
                            c.automated = true;
                            util::rm(MANUAL_PORTAL);
                            Ok(())
                        }
                        StillBlocked(x) => { c.io.fail(format!("still blocked after submit ({}). Staying in portal mode", x)); c.io.hint("Accept the terms manually: torii portal (protection is restored afterwards)"); Err(anyhow!("blocked")) }
                        Error(e) => { c.io.fail(e.clone()); Err(anyhow!(e)) }
                    }
                })
            })
            .await;
            if r.is_ok() { 0 } else { 1 }
        }
        "portal-open" => {
            if let Err(why) = policy::may(caller, "portal-open", None, last_conn()) {
                deny!(out, done, why);
            }
            if !matches!(Intent::read(), Intent::Mode(Mode::Portal)) || !crate::nl::netns::exists() {
                deny!(out, done, "not in portal mode - run torii portal first (it switches automatically)");
            }
            // Which user the browser runs as: a regular user = the caller; root (sudo torii portal) = the uid argument (SUDO_UID)
            let arg = |k: &str| req.args.iter().find_map(|a| a.strip_prefix(&format!("{}=", k)).map(String::from));
            let target_uid = if root { arg("uid").and_then(|u| u.parse().ok()).or_else(operator_uid) } else { Some(uid) };
            let Some(target_uid) = target_uid.filter(|u| *u != 0) else { deny!(out, done, "don't know whose desktop to open the browser on (under sudo, SUDO_UID is required)") };
            match crate::portal_browser::open(target_uid, arg("wl").as_deref(), arg("url").as_deref()).await {
                Ok(msg) => {
                    let _ = out.send(format!("{}ok {}", crate::ui::P_STYLE, msg));
                    let _ = out.send(format!("{}hint Just accept the terms: once connectivity is up, the watchdog closes this window and restores protection", crate::ui::P_STYLE));
                    0
                }
                Err(e) => {
                    let _ = out.send(format!("{}fail failed to open the portal browser: {:#}", crate::ui::P_STYLE, e));
                    1
                }
            }
        }
        "wst-probe" => {
            if !root {
                let _ = out.send("needs root".into());
                1
            } else {
                let ssid = crate::netclass::network_id().await.unwrap_or_default();
                match crate::watchdog::wst_probe_cli(&ssid).await {
                    Ok(s) => {
                        let _ = out.send(s);
                        0
                    }
                    Err(e) => {
                        let _ = out.send(format!("{}", e));
                        1
                    }
                }
            }
        }
        "status" => {
            let extra = modes::StatusExtra {
                wst_running: ctx.wst.running(),
                wst_variant: ctx.wst.variant.map(|v| v.as_str().to_string()),
                busy: None,
                daemon_since: shared.since,
                fails: wd.mem.fails,
                probe_done: wd.mem.probe_done,
                probe_skipped: wd.mem.probe_skipped,
                last_action: wd.mem.last_action,
            };
            for l in modes::status_lines(&ctx.nl, Some(&extra)).await {
                let _ = out.send(l);
            }
            0
        }
        "wst-reload" => {
            // Restart the client after a key change (root or the operator).
            if let Err(why) = policy::may(caller, "wst-reload", None, last_conn()) {
                deny!(out, done, why);
            }
            let intent = Intent::read().mode().filter(|m| m.is_tunnel());
            if modes::actual_tunnel(ctx).await != Some(crate::state::Tunnel::Wstunnel) || intent.is_none() {
                let _ = out.send(format!("{}h not in wstunnel mode; the new key takes effect on the next connection", crate::ui::P_STYLE));
                0
            } else {
                let _ = out.send(format!("{}h reconnecting wstunnel with the new key...", crate::ui::P_STYLE));
                let m = intent.unwrap_or(Mode::Auto);
                match run_action(ctx, wd, shared, "wst-reload", |c| Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(3)).await; // wait for the server side's delayed restart
                    c.automated = true;
                    modes::apply(c, m).await
                })).await {
                    Ok(()) => 0,
                    Err(_) => 1,
                }
            }
        }
        "wst-secret-get" | "wst-secret-set" => {
            // Key rotation runs as the operator (it needs their ssh key) but the secrets live in a root-owned
            // file. The operator already owns these keys, so handing them over is no new exposure.
            if let Err(why) = policy::may(caller, "wst-secret", None, last_conn()) {
                deny!(out, done, why);
            }
            let r = if req.cmd == "wst-secret-get" {
                crate::rotate::local_read_direct().map(|l| {
                    let _ = out.send(serde_json::json!({ "cur": l.cur, "prev": l.prev, "next": l.next, "conf": crate::rotate::mgmt_conf_direct() }).to_string());
                })
            } else {
                let opt = |i: usize| req.args.get(i).cloned().filter(|s| !s.is_empty());
                match opt(0) {
                    Some(cur) => crate::rotate::local_write_direct(&crate::rotate::Local { cur, prev: opt(1), next: opt(2) }),
                    None => Err(anyhow!("missing current key")),
                }
            };
            match r {
                Ok(()) => 0,
                Err(e) => {
                    let _ = out.send(format!("{}fail {:#}", crate::ui::P_STYLE, e));
                    1
                }
            }
        }
        "wst-log" => {
            if let Err(why) = policy::may(caller, "wst-log", None, last_conn()) {
                deny!(out, done, why);
            }
            for l in ctx.wst.recent_lines(40) {
                let _ = out.send(l);
            }
            0
        }
        _ => {
            let _ = out.send(format!("unknown command {}", req.cmd));
            2
        }
    };
    ctx.io = Io::default();
    let _ = done.send(rc);
}

async fn serve(stream: UnixStream, jobs: mpsc::UnboundedSender<Job>, shared: Shared) -> Result<()> {
    let uid = stream.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);
    let (r, mut w) = stream.into_split();
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(5), BufReader::new(r.take(MAX_REQUEST)).read_line(&mut line)).await??;
    if n == 0 || !line.ends_with('\n') {
        return Ok(());
    }
    let req: Request = serde_json::from_str(&line)?;
    // Everyone else may only look; checked here, before the request can occupy the actor.
    if who(uid) == policy::Who::Other && req.cmd != "status" {
        w.write_all(format!("{}fail only root and the operator ([daemon] operator in config.toml) may control the network\n{}1\n", crate::ui::P_STYLE, crate::ui::P_DONE).as_bytes()).await?;
        return Ok(());
    }
    let busy_now = shared.busy.lock().unwrap().clone();
    if let Some((what, since)) = busy_now {
        w.write_all(format!("{}h another action is running ({}, {}s so far), queued behind it...\n", crate::ui::P_STYLE, what, util::now().saturating_sub(since)).as_bytes()).await?;
    }
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
    let (done_tx, done_rx) = oneshot::channel();
    jobs.send(Job { req, uid, out: out_tx, done: done_tx }).map_err(|_| anyhow!("actor is gone"))?;
    let mut done_rx = done_rx;
    loop {
        tokio::select! {
            Some(l) = out_rx.recv() => { w.write_all(format!("{}\n", l).as_bytes()).await?; }
            rc = &mut done_rx => {
                while let Ok(l) = out_rx.try_recv() { w.write_all(format!("{}\n", l).as_bytes()).await?; }
                let rc = rc.unwrap_or(1);
                w.write_all(format!("{}{}\n", crate::ui::P_DONE, rc).as_bytes()).await?;
                break;
            }
        }
    }
    Ok(())
}
