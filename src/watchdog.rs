//! Watchdog: orchestration of one tick. Health is judged on the data path (handshake + exit IP), not on
//! whether things exist. Three-valued verdict (up / down / don't know); "don't know" is never folded into
//! either side.
use crate::config::{WdConf, WstConf};
use crate::journal;
use crate::modes::{self, Ctx};
use crate::nl::wg;
use crate::paths::*;
use crate::policy::{self, Gate, Obs, PortalNext};
use crate::probe::{self, Conn, Reach};
use crate::state::{self, CarrierWait, Intent, Mode, Tunnel};
use crate::util;
use crate::wst;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const TAG: &str = "toriid-watchdog";
fn log(m: &str) {
    journal::notice(TAG, m);
}

/// The daemon's memory. Held in-process, with a JSON copy in /run for debugging; discarded on restart.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Memory {
    pub fails: u32,
    pub last_action: u64,
    pub actions_win: u64,
    pub actions_n: u32,
    pub last_ssid: Option<String>,
    pub last_exit_ts: u64,
    pub last_exit_ip: Option<String>,
    pub last_exit_ctx: Option<String>,
    pub probe_done: u64,
    pub probe_skipped: u64,
    pub unknown_n: u32,
    pub last_probe: u64,
    pub last_skip: Option<String>,
    pub gave_up: bool,
}
impl Memory {
    pub fn dump(&self) {
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = util::write_atomic(WD_STATE, &s, 0o600);
        }
    }
}

#[derive(Clone, Debug)]
pub enum Verdict {
    Up(String),
    Down(String),
    Unknown(String),
}

pub struct Watchdog {
    pub mem: Memory,
    pub cfg: WdConf,
    pub exit_ip: Option<String>,
    pub exit_cached: u64,
    portal_done: bool,
    /// portal-auto returned Handoff this round: a portal is there, but it needs the user
    handoff: bool,
}

impl Watchdog {
    pub fn new() -> Self {
        Watchdog { mem: Memory::default(), cfg: WdConf::load(), exit_ip: None, exit_cached: 0, portal_done: false, handoff: false }
    }

    fn wg_handshake_ok(&self) -> bool {
        matches!(wg::handshake_age(), Some(age) if age < self.cfg.hs_max_age)
    }

    /// Local signals are free (handshake timestamp); the external probe confirms every 10 minutes.
    /// The cache is trusted only while everything is healthy.
    pub async fn healthy(&mut self, ctx: &Ctx, o: &Obs, mode: Option<Mode>) -> Verdict {
        let mut local_ok = false;
        if let Some(m) = mode.filter(|m| m.is_tunnel()) {
            // Judge what is actually running, not what the intent names: in auto mode any rung may be up.
            let actual = if ctx.wst.running() {
                Some(Tunnel::Wstunnel)
            } else if ctx.nl.link_exists(WG_IF).await {
                Some(Tunnel::WireGuard)
            } else if ctx.nl.link_exists(&ovpn_if()).await {
                Some(Tunnel::OpenVpn)
            } else {
                None
            };
            match (m, actual) {
                (_, None) => return Verdict::Down(format!("{} mode but no tunnel is up", m)),
                (Mode::Only(want), Some(a)) if want != a => return Verdict::Down(format!("{} wanted but {} is up", want.as_str(), a.as_str())),
                (_, Some(Tunnel::WireGuard)) => {
                    if !self.wg_handshake_ok() {
                        return Verdict::Down("wg0 handshake timed out".into());
                    }
                    local_ok = true;
                }
                (_, Some(Tunnel::Wstunnel)) => {
                    if !ctx.nl.link_exists(WG_IF).await {
                        return Verdict::Down("wstunnel is running but wg0 is missing".into());
                    }
                    if !self.wg_handshake_ok() {
                        return Verdict::Down("wg0 handshake timed out (carrier may be down)".into());
                    }
                    local_ok = true;
                }
                (_, Some(Tunnel::OpenVpn)) => {}
            }
        }
        let ctx_key = format!("{}:{}", mode.map(|m| m.as_str()).unwrap_or("?"), o.ssid.as_deref().unwrap_or(""));
        let iv = if crate::on_battery() { self.cfg.exit_confirm_bat } else { self.cfg.exit_confirm_ac };
        if local_ok
            && self.mem.last_exit_ip.is_some()
            && self.mem.last_exit_ctx.as_deref() == Some(&ctx_key)
            && self.mem.fails == 0
            && !o.resumed
            && o.now.saturating_sub(self.mem.last_exit_ts) < iv
        {
            self.exit_ip = self.mem.last_exit_ip.clone();
            self.exit_cached = o.now - self.mem.last_exit_ts;
            self.mem.probe_skipped += 1;
            return Verdict::Up(self.exit_ip.clone().unwrap());
        }
        self.exit_cached = 0;
        let (r, ip) = tokio::task::spawn_blocking(probe::exit_ip).await.unwrap_or((Reach::NoAnswer, None));
        match r {
            Reach::NoAnswer => Verdict::Unknown("unknown: all 3 sources timed out (no answer at all)".into()),
            Reach::Bad => Verdict::Down("no exit IP from any of 3 sources".into()),
            Reach::Ok => {
                let ip = ip.unwrap();
                self.mem.last_exit_ts = o.now;
                self.mem.last_exit_ip = Some(ip.clone());
                self.mem.last_exit_ctx = Some(ctx_key);
                self.mem.probe_done += 1;
                self.exit_ip = Some(ip.clone());
                Verdict::Up(ip)
            }
        }
    }

    async fn switch(&self, ctx: &mut Ctx, m: Mode) -> bool {
        ctx.automated = true;
        // 90s used to cover a single variant: 40 carrier wait + 40 for one variant. That doesn't fit three
        // wstunnel variants - observed: at boot the second variant was killed halfway, leaving a half-built
        // wg0 behind. Budget for the worst path now:
        //   wstunnel: 40 + 3*(40+5)      normal: 10 + 20 (ovpn start) + 20 + the wstunnel chain above
        let budget = Duration::from_secs(match m {
            Mode::Only(Tunnel::Wstunnel) => 200,
            Mode::Auto => 260,
            _ => 90,
        });
        match tokio::time::timeout(budget, modes::apply(ctx, m)).await {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                // Log the cause of watchdog-initiated failures too - otherwise the journal only says "switch
                // failed" and post-mortems are guesswork
                journal::err("toriid", &format!("{} failed: {:#}", m, e));
                false
            }
            Err(_) => {
                // The cancelled apply may have left a half-built tunnel (wg0 without a working carrier, a
                // wstunnel child without wg0). Clear it; the kill switch stays, so this is offline, not leaking.
                journal::err("toriid", &format!("{} did not finish in {}s, aborted; tearing down the partial tunnel", m, budget.as_secs()));
                modes::tunnels_down(ctx).await;
                state::write_intent(Intent::FailedClosed);
                false
            }
        }
    }

    /// Automatic captive portal pass (in-process, on the portal netns thread). Enters portal mode first.
    /// Returns true = let through. On Handoff the machine stays in portal, PORTAL_HANDOFF is set and
    /// self.handoff is set; the caller must back off immediately.
    async fn portal_auto(&mut self, ctx: &mut Ctx) -> bool {
        ctx.automated = true; // otherwise the previous job's value leaks: after a manual torii portal, an automatic pass would be recorded as manual (900s strand limit)
        if modes::apply(ctx, Mode::Portal).await.is_err() {
            return false;
        }
        let gw = match ctx.nl.phy_dev().await.ok().flatten() {
            Some(p) => ctx.nl.default_gw(p.index).await.ok().flatten(),
            None => None,
        };
        let t0 = std::time::Instant::now();
        match tokio::time::timeout(Duration::from_secs(120), crate::portal::run(gw, false)).await {
            Ok(Ok(rep)) => {
                use crate::portal::Outcome::*;
                let phases: Vec<String> = rep.phases.iter().map(|(n, t)| format!("{} +{:.1}s", n, t)).collect();
                journal::notice("toriid-portal", &format!("phases: {}", phases.join(" | ")));
                for l in &rep.log {
                    journal::notice("toriid-portal", &format!("  {}", l));
                }
                let next = policy::portal_next(&rep.outcome);
                if let Some(ssid) = crate::wifi::ssid().await {
                    let how = match (&next, &rep.outcome) {
                        (PortalNext::Passed, AlreadyOpen) => None, // no portal, nothing to record
                        (PortalNext::Passed, _) => Some(if rep.method.is_empty() { "passed automatically" } else { rep.method.as_str() }),
                        (PortalNext::Handoff, NoForm) => Some("needs the user (JS login page)"),
                        (PortalNext::Handoff, NeedsUser) => Some("needs the user (login or required input)"),
                        (PortalNext::Handoff, _) => Some("needs the user (auto-submit did not pass)"),
                        (PortalNext::NotPortal, _) => None,
                    };
                    if let Some(h) = how {
                        state::portal_memory_put(&ssid, h);
                    }
                }
                let what = match &rep.outcome {
                    Passed => "captive portal passed automatically".to_string(),
                    AlreadyOpen => "no portal to pass: internet already reachable".to_string(),
                    OpenedByRedirect => "let through after following the redirect".to_string(),
                    NoExit => "network has no exit (gateway unreachable), not a portal".to_string(),
                    NoForm => "no form found (JS login page?); manually: torii portal".to_string(),
                    NeedsUser => "portal wants a login or required input; open it with: torii portal".to_string(),
                    StillBlocked(c) => format!("still blocked after submit ({}); manually: torii portal", c),
                    Error(e) => format!("error: {}", e),
                };
                journal::notice("toriid-portal", &format!("{} in {:.1}s", what, t0.elapsed().as_secs_f32()));
                if next == PortalNext::Handoff {
                    self.handoff = true;
                    util::touch(PORTAL_HANDOFF);
                    log("captive portal confirmed but can't be passed automatically - staying in portal and handing it to the user (torii portal); protection is restored after login. Not climbing the ladder: no tunnel works until the portal is passed");
                }
                next == PortalNext::Passed
            }
            Ok(Err(e)) => {
                journal::err("toriid-portal", &format!("failed to run: {}", e));
                false
            }
            Err(_) => {
                journal::err("toriid-portal", "did not finish in 120s, aborted");
                false
            }
        }
    }

    fn auto_portal_ok(&self, o: &Obs) -> bool {
        self.cfg.auto_portal && !o.at_home
    }

    /// After a failed switch: is a captive portal in the way? If so, pass it and retry the same mode once.
    async fn switch_failed_maybe_portal(&mut self, ctx: &mut Ctx, m: Mode) -> bool {
        if !matches!(state::carrier_flag_read(180), Some((CarrierWait::Portal, _))) {
            return false;
        }
        if !self.auto_portal_ok_now() || self.portal_done {
            return false;
        }
        log(&format!("{} switch failed because a captive portal is in the way (carrier cert verification failed) - passing the portal, then retrying {}", m, m));
        self.portal_done = true;
        if !self.portal_auto(ctx).await {
            log("portal-auto did not pass - maybe it's not a portal but an expired carrier cert? (6-day validity)");
            return false;
        }
        log(&format!("portal-auto succeeded, retrying -> {}", m));
        self.switch(ctx, m).await
    }
    fn auto_portal_ok_now(&self) -> bool {
        self.cfg.auto_portal
    }

    async fn try_mode(&mut self, ctx: &mut Ctx, o: &Obs, m: Mode) -> Option<String> {
        log(&format!("trying -> {}", m));
        let ok = self.switch(ctx, m).await || self.switch_failed_maybe_portal(ctx, m).await;
        if ok {
            tokio::time::sleep(Duration::from_secs(1)).await; // the switch itself already tested the tunnel; just give routes/DNS a second to settle
            match self.healthy(ctx, o, Some(m)).await {
                Verdict::Up(ip) => {
                    log(&format!("{} up (exit {})", m, ip));
                    self.mem.fails = 0;
                    self.mem.gave_up = false;
                    util::rm(GAVE_UP);
                    return Some(ip);
                }
                Verdict::Down(r) | Verdict::Unknown(r) => log(&format!("{} came up but the data path is down: {}", m, r)),
            }
        } else {
            log(&format!("{} switch itself failed", m));
        }
        None
    }

    fn note_action(&mut self, now: u64) {
        self.mem.last_action = now;
        self.mem.actions_n += 1;
    }

    /// The carrier (server:443) is explicitly allowed by the kill switch outside the tunnel. If it is
    /// unreachable, nothing gets out at the physical layer - where portals exist, that almost always means a portal.
    async fn carrier_reachable(&self, o: &Obs) -> bool {
        let Some(ep) = WstConf::peek_server() else { return true }; // can't tell, don't block what follows
        let Ok(ip) = ep.parse::<std::net::IpAddr>() else { return true };
        let dev = o.phy.clone();
        tokio::task::spawn_blocking(move || probe::carrier(ip, 443, dev.as_deref(), true) == probe::Carrier::Ok).await.unwrap_or(true)
    }

    /// One round. Returns (healthy, reason) for the health file.
    pub async fn tick(&mut self, ctx: &mut Ctx, o: &Obs) -> (bool, String) {
        let mut o2 = o.clone();
        o2.net_changed = matches!((&o.ssid, &self.mem.last_ssid), (Some(a), Some(b)) if a != b);
        let o = &o2;
        self.cfg = WdConf::load();
        self.portal_done = false;
        self.handoff = false;
        let now = o.now;

        let bootstrap = match policy::gate(o, &self.cfg) {
            Gate::Skip(why) => {
                let key: String = why.chars().filter(|c| !c.is_ascii_digit()).collect();
                if self.mem.last_skip.as_deref() != Some(&key) {
                    log(&format!("skipping this round: {}", why));
                    self.mem.last_skip = Some(key);
                }
                return (true, format!("skip:{}", why));
            }
            Gate::Proceed { bootstrap } => bootstrap,
        };
        self.mem.last_skip = None;
        if o.resumed {
            log("just resumed from suspend - skipping confirmation count, judging now");
        } else if o.net_changed {
            log(&format!("network changed ({} -> {}) - skipping confirmation count, judging now", self.mem.last_ssid.as_deref().unwrap_or("?"), o.ssid.as_deref().unwrap_or("?")));
        }
        let cur = o.intent.mode();

        // -- re-select the tunnel on network change --
        if !bootstrap {
            let profile = o.ssid.as_deref().and_then(state::profile_get);
            if let Some(want) = policy::reevaluate_target(o, &self.cfg, self.mem.last_ssid.as_deref(), profile, cur) {
                if now.saturating_sub(self.mem.last_action) >= self.cfg.cooldown {
                    log(&format!("network changed ({} -> {}), re-selecting tunnel: {} -> {}", self.mem.last_ssid.as_deref().unwrap_or("?"), o.ssid.as_deref().unwrap_or("?"), o.intent.as_str(), want));
                    self.mem.last_ssid = o.ssid.clone();
                    self.note_action(now);
                    if self.switch(ctx, want).await {
                        tokio::time::sleep(Duration::from_secs(1)).await; // the switch itself already tested the tunnel; just give routes/DNS a second to settle
                        if let Verdict::Up(ip) = self.healthy(ctx, o, Some(want)).await {
                            log(&format!("{} works on {} (exit {})", want, o.ssid.as_deref().unwrap_or("?"), ip));
                            self.mem.fails = 0;
                            return (true, format!("switched:{}:{}", want, ip));
                        }
                        log(&format!("{} down - falling back to {}", want, o.intent.as_str()));
                        if let Some(c) = cur {
                            self.switch(ctx, c).await;
                        }
                    } else {
                        log(&format!("{} switch failed, staying on {}", want, o.intent.as_str()));
                    }
                }
            }
            self.mem.last_ssid = o.ssid.clone();
        }

        // -- bootstrap: build protection from an unprotected state --
        if bootstrap && o.portal_handoff && o.conn == Conn::Full {
            if let Some(s) = &o.ssid {
                state::portal_memory_put(s, "passed by the user (torii portal)");
            }
        }
        if bootstrap {
            self.mem.last_ssid = o.ssid.clone();
            if !self.cfg.auto_bootstrap {
                return (true, format!("skip:mode={} and AUTO_BOOTSTRAP=no", o.intent.as_str()));
            }
            if now.saturating_sub(self.mem.last_action) < self.cfg.cooldown {
                return (true, "skip:bootstrap cooling down".into());
            }
            if o.conn != Conn::Full {
                if self.cfg.auto_portal && o.at_home {
                    // no portals at home, build the tunnel directly
                } else if self.cfg.auto_portal {
                    log(&format!("unprotected + connectivity {}, passing captive portal first", o.conn.as_str()));
                    if !self.portal_auto(ctx).await {
                        self.note_action(now);
                        if self.handoff {
                            return (false, "portal:needs-human".into());
                        }
                        log("automatic portal pass failed - manually: torii portal");
                        return (false, "bootstrap: portal not passed".into());
                    }
                    log("portal-auto succeeded");
                } else {
                    return (false, "bootstrap: waiting for portal (AUTO_PORTAL=no)".into());
                }
            }
            self.note_action(now);
            let want = state::preferred_mode(o.ssid.as_deref(), &self.cfg);
            log(&format!("unprotected (mode={}), establishing protection on {} -> {}", o.intent.as_str(), o.ssid.as_deref().unwrap_or("unknown network"), want));
            if self.switch(ctx, want).await || self.switch_failed_maybe_portal(ctx, want).await {
                tokio::time::sleep(Duration::from_secs(1)).await; // the switch itself already tested the tunnel; just give routes/DNS a second to settle
                match self.healthy(ctx, o, Some(want)).await {
                    Verdict::Up(ip) => {
                        log(&format!("protection established ({}, exit {})", want, ip));
                        self.mem.fails = 0;
                        return (true, format!("bootstrap:{}:{}", want, ip));
                    }
                    Verdict::Down(r) | Verdict::Unknown(r) => log(&format!("{} came up but the data path is down: {} - leaving it to the ladder next round", want, r)),
                }
            } else {
                log(&format!("{} switch failed", want));
            }
            return (false, format!("bootstrap: {} failed", want));
        }

        // -- verdict (three-valued) --
        let verdict = self.healthy(ctx, o, cur).await;
        let reason = match verdict {
            Verdict::Unknown(r) => {
                self.mem.unknown_n += 1;
                if self.mem.unknown_n < self.cfg.unknown_max && !o.resumed && !o.net_changed {
                    log(&format!("can't tell [{}/{}]: {} - not acting, waiting for next round", self.mem.unknown_n, self.cfg.unknown_max, r));
                    return (true, r);
                }
                log(&format!("{} rounds in a row without a single response - treating as down", self.mem.unknown_n));
                self.mem.unknown_n = 0;
                r
            }
            Verdict::Up(ip) => {
                self.mem.unknown_n = 0;
                if self.mem.fails != 0 {
                    log(&format!("back to normal (mode={} exit={})", o.intent.as_str(), ip));
                }
                self.mem.fails = 0;
                self.mem.gave_up = false;
                util::rm(GAVE_UP);
                if let (Some(s), Some(m)) = (&o.ssid, cur) {
                    state::profile_put(s, m);
                }
                // once a day, try to upgrade from the disguised variant back to a cert-verifying one
                let pinned = o.ssid.as_deref().map(|s| WstConf::load().map(|c| c.pins.iter().any(|(n, _)| n == s)).unwrap_or(false)).unwrap_or(false);
                if cur == Some(Mode::Only(Tunnel::Wstunnel)) && o.ssid.is_some() && !pinned && now.saturating_sub(self.mem.last_probe) >= 86400 {
                    self.mem.last_probe = now;
                    let ssid = o.ssid.clone().unwrap();
                    // Inline, not spawned: everything that touches tunnels or their memory runs on the one actor.
                    let _ = wst_probe_cli(&ssid).await;
                }
                return (true, if self.exit_cached > 0 { format!("ok:{} (cached {}s)", ip, self.exit_cached) } else { format!("ok:{}", ip) });
            }
            Verdict::Down(r) => {
                self.mem.unknown_n = 0;
                r
            }
        };

        self.mem.fails += 1;
        log(&format!("unhealthy [{}/{}] mode={}: {}", self.mem.fails, self.cfg.fail_threshold, o.intent.as_str(), reason));
        if !o.resumed && !o.net_changed && self.mem.fails < self.cfg.fail_threshold {
            return (false, reason);
        }
        // -- gates before acting --
        if now.saturating_sub(self.mem.last_action) < self.cfg.cooldown {
            return (false, reason);
        }
        if now.saturating_sub(self.mem.actions_win) > 3600 {
            self.mem.actions_win = now;
            self.mem.actions_n = 0;
        }
        if self.mem.actions_n >= self.cfg.max_actions {
            log(&format!("already acted {} times this hour, backing off - this is not something automation can fix; check `torii log`", self.mem.actions_n));
            return (false, reason);
        }
        self.note_action(now);
        let orig = cur;

        // -- first tell apart: tunnel problem, or captive portal not passed --
        if self.auto_portal_ok(o) && !self.carrier_reachable(o).await {
            log("carrier unreachable - nothing gets out at the physical layer, treating as captive portal first");
            if self.portal_auto(ctx).await {
                log("portal-auto succeeded (details: -t portal-auto)");
                self.portal_done = true;
            } else if self.handoff {
                return (false, "portal:needs-human".into());
            } else {
                log("portal-auto did not pass (or there is no portal here at all)");
            }
        }
        // Re-judge after passing the portal (the last verdict predates it). Only meaningful if the machine is
        // still in a tunnel mode - portal-auto no longer restores the original mode, so after a pass the
        // machine sits in portal, the host can't get out, and all three probe sources time out at 5s each
        // (observed: 15s wasted). In that case go straight to the ladder.
        let m = Intent::read().mode();
        if self.portal_done && m.map(|m| m.is_tunnel()).unwrap_or(false) {
            if let Verdict::Up(ip) = self.healthy(ctx, o, m).await {
                log(&format!("tunnel already up after passing the portal (mode={} exit={}) - no ladder needed", m.map(|m| m.as_str()).unwrap_or("?"), ip));
                self.mem.fails = 0;
                return (true, format!("ok:{}", ip));
            }
            log("portal passed but data path still down - continuing");
        } else if self.portal_done {
            log("portal passed, machine is in portal mode - rebuilding the tunnel directly");
        }

        // -- action ladder --
        let known = o.ssid.as_deref().map(|s| state::preferred_mode(Some(s), &self.cfg));
        if let Some(k) = known {
            if Some(k) != orig {
                log(&format!("{} last worked with {} (current {}) - trying it first", o.ssid.as_deref().unwrap_or("?"), k, o.intent.as_str()));
            }
        }
        let rungs = modes::ladder();
        let ladder = policy::ladder(orig, known, &rungs);
        for m in &ladder {
            if let Some(ip) = self.try_mode(ctx, o, *m).await {
                // The top rung stands in for auto: if the user was on auto, stay on auto.
                if orig == Some(Mode::Auto) && Some(*m) == rungs.first().map(|t| Mode::Only(*t)) {
                    state::write_intent(Intent::Mode(Mode::Auto));
                }
                return (true, format!("recovered:{}:{}", m, ip));
            }
            if self.handoff {
                return (false, "portal:needs-human".into()); // try_mode hit a portal and handed it to the user
            }
        }
        // -- last step: treat it as a captive portal (what a human would try; automation should too) --
        if self.auto_portal_ok(o) && !self.portal_done {
            log("all tunnels down - trying to treat it as a captive portal");
            if self.portal_auto(ctx).await {
                log("portal passed, retrying tunnels");
                for m in &ladder {
                    if let Some(ip) = self.try_mode(ctx, o, *m).await {
                        return (true, format!("recovered:{}:{}", m, ip));
                    }
                }
                log("still all down after passing the portal - not a portal problem");
            } else if self.handoff {
                return (false, "portal:needs-human".into());
            } else {
                log("portal-auto did not pass (or there is no portal here at all)");
            }
        }
        log(&format!("all tunnels failed (tried: {}). Staying on {}, not switching off automatically - going unprotected is worse than being offline.", ladder.iter().map(|m| m.as_str()).collect::<Vec<_>>().join(" "), o.intent.as_str()));
        self.mem.gave_up = true;
        util::touch(GAVE_UP);
        (false, "all-channels-failed".into())
    }
}

/// wst-probe: try the two cert-verifying variants on the alternate port; if one works, lift the disguised downgrade.
pub async fn wst_probe_cli(ssid: &str) -> anyhow::Result<String> {
    let mut out = String::new();
    if wst::variant_get(ssid) != Some(wst::Variant::Disguised) {
        return Ok(format!("  no disguised downgrade on {}, nothing to probe", ssid));
    }
    let conf = WstConf::load()?;
    let carrier = util::read_trim(WST_ACTIVE).unwrap_or_else(|| conf.server.clone());
    out += "  trying the two cert-verifying variants on the alternate port...\n";
    let mut up = None;
    for v in [wst::Variant::Clean, wst::Variant::Named] {
        if let Some(age) = wst::live_fail_age(ssid, v) {
            if age < wst::WST_LIVE_FAIL_TTL {
                out += &format!("    {} ... skipped (failed on the real path {} min ago)\n", v.as_str(), age / 60);
                continue;
            }
        }
        let ok = wst::probe_variant(&conf, &carrier, v).await;
        out += &format!("    {} ... {}\n", v.as_str(), if ok { "ok" } else { "failed" });
        if ok {
            up = Some(v);
            break;
        }
    }
    match up {
        Some(v) => match wst::variant_clear(ssid) {
            Ok(()) => {
                out += &format!("  {} works now - downgrade on {} lifted, the next connection will use the cert-verifying variant\n", v.as_str(), ssid);
                journal::notice("toriid", &format!("{} variant usable again on {}, disguised downgrade lifted", v.as_str(), ssid));
            }
            Err(e) => out += &format!("  {} works, but the downgrade record could not be cleared: {}\n", v.as_str(), e),
        },
        None => out += "  both failed, keeping disguised\n",
    }
    Ok(out)
}
