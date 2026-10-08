//! Decision layer: **pure functions**. No system access, no file reads; a snapshot goes in, a decision
//! comes out, so all of it is testable offline.
//! target state = f(network identity, phase, history, config).
use crate::config::WdConf;
use crate::portal::Outcome;
use crate::probe::Conn;
use crate::state::{Advice, CarrierWait, Intent, Mode, Tunnel};

/// Snapshot taken at the start of each round.
#[derive(Clone, Debug, Default)]
pub struct Obs {
    pub now: u64,
    pub intent: Intent,
    pub intent_age: Option<u64>,
    pub manual_off: bool,
    pub manual_portal: bool,
    /// The watchdog confirmed a captive portal it cannot pass automatically and handed it to the user (PORTAL_HANDOFF)
    pub portal_handoff: bool,
    pub phy: Option<String>,
    pub phy_has_ip: bool,
    pub ssid: Option<String>,
    pub conn: Conn,
    pub carrier_flag: Option<(CarrierWait, u64)>,
    pub at_home: bool,
    pub resumed: bool,
    /// The SSID differs from the previous round (last_ssid in watchdog memory). A network change is like a
    /// resume: any waiting tied to the old network is void
    pub net_changed: bool,
}
impl Default for Intent {
    fn default() -> Self {
        Intent::Unknown
    }
}
impl Default for Conn {
    fn default() -> Self {
        Conn::Unknown
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    Skip(String),
    Proceed { bootstrap: bool },
}

pub fn carrier_flag_is_portal(o: &Obs) -> bool {
    matches!(o.carrier_flag, Some((CarrierWait::Portal, _)))
}

/// Skip conditions; each one means either "not a tunnel problem" or "hands off".
/// Better to not rescue than to do harm.
pub fn gate(o: &Obs, c: &WdConf) -> Gate {
    // Manual off is an explicit escape hatch from the user; always respect it
    if o.manual_off {
        return Gate::Skip("manual off - respecting that".into());
    }
    let mut bootstrap = false;
    match o.intent {
        Intent::Mode(Mode::Portal) if o.portal_handoff => {
            // Handed to the user: as soon as they get through (connectivity full) take over and restore
            // protection; until then wait, with the manual grace period. Observed: on a JS-only login page the
            // watchdog kept climbing the ladder for 2.5 minutes while the user's portal session sat queued
            let age = o.intent_age.unwrap_or(0);
            if o.conn != Conn::Full && age < c.portal_strand_manual {
                return Gate::Skip(format!("captive portal needs a human ({}s < {}s)", age, c.portal_strand_manual));
            }
            bootstrap = true;
        }
        Intent::Mode(Mode::Portal) => {
            // Portal is never a resting state: a fresh one is left alone, a stale one is treated as an
            // abandoned unprotected state and taken over
            let age = o.intent_age.unwrap_or(0);
            let (lim, who) = if o.manual_portal { (c.portal_strand_manual, "manual") } else { (c.portal_strand, "auto") };
            if age < lim {
                return Gate::Skip(format!("captive portal in progress ({}, {}s < {}s)", who, age, lim));
            }
            bootstrap = true;
        }
        Intent::Mode(Mode::Off) | Intent::Unknown | Intent::FailedClosed => bootstrap = true,
        _ => {}
    }
    let Some(phy) = &o.phy else { return Gate::Skip("no physical link up - not a tunnel problem".into()) };
    if !o.phy_has_ip {
        return Gate::Skip(format!("{} has no IP yet", phy));
    }
    // Mode was just switched; give it time to come up. Exception: the switch was blocked by a captive
    // portal - that is not "not up yet", it is "never coming up"
    if let Some(age) = o.intent_age {
        // A handed-off portal was just passed by the user: settle exists for the tunnel, and there is none to wait for
        let handoff_passed = o.portal_handoff && o.conn == Conn::Full;
        // Don't wait after a network change either: settle is for a mode just switched on *this* network.
        // Observed: switching networks 14s after `torii up`, settle blocked the watchdog, which first looked
        // 80s later, and the portal sat unpassed the whole time
        if age < c.settle && !carrier_flag_is_portal(o) && !handoff_passed && !o.net_changed {
            return Gate::Skip(format!("mode switched {}s ago, still settling", age));
        }
    }
    if o.conn == Conn::Portal && !carrier_flag_is_portal(o) && !c.auto_portal {
        return Gate::Skip("connectivity check says portal and AUTO_PORTAL=no".into());
    }
    Gate::Proceed { bootstrap }
}

/// Which mode to switch to on a network change: whatever last worked on this SSID, else BOOTSTRAP_DEFAULT.
pub fn reevaluate_target(o: &Obs, c: &WdConf, last_ssid: Option<&str>, want_rung: Option<Tunnel>, cur: Option<Mode>, actual: Option<Tunnel>) -> Option<Mode> {
    if !c.reevaluate_on_network_change || o.conn != Conn::Full {
        return None;
    }
    let ssid = o.ssid.as_deref()?;
    let last = last_ssid?;
    if ssid == last {
        return None;
    }
    // A pin for the new network wins.
    if let Some(p) = c.mode_pins.iter().find(|(n, _)| n == ssid).and_then(|(_, m)| Mode::parse(m)).filter(|m| m.is_tunnel()) {
        return (Some(p) != cur).then_some(p);
    }
    match cur {
        // A manual single-tunnel choice was made for the previous network; on a new one go back to auto.
        Some(Mode::Only(_)) => Some(Mode::Auto),
        // Auto already: re-climb only if the running tunnel is not the one this network should start with.
        Some(Mode::Auto) => (want_rung.is_some() && actual != want_rung).then_some(Mode::Auto),
        _ => None,
    }
}

/// Recovery order: a pinned single tunnel is retried as itself first, then auto climbs the whole ladder.
pub fn ladder(orig: Option<Mode>) -> Vec<Mode> {
    match orig {
        Some(Mode::Only(t)) => vec![Mode::Only(t), Mode::Auto],
        _ => vec![Mode::Auto],
    }
}

/// Who issued the command (the daemon identifies it via SO_PEERCRED on the socket).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Who {
    Root,
    /// The user of this machine ([daemon] operator in config.toml; no operator if unset)
    Operator,
    Other,
}

/// What is allowed without sudo. Principle: **adding protection is free, removing it needs sudo**.
/// Portal is the grey zone: the kill switch stays on, but the browser in the portal netns goes out
/// unprotected - any program running as the user could use it to bypass the tunnel. So the operator may
/// enter portal / run portal-auto only when the network is already broken (connectivity not full); on a
/// working network that door stays shut. For portal-open the daemon additionally requires portal mode.
pub fn may(who: Who, cmd: &str, mode: Option<Mode>, conn: Conn) -> Result<(), String> {
    if who == Who::Root {
        return Ok(());
    }
    if who == Who::Other {
        return Err("only root and the operator ([daemon] operator in config.toml) may control the network".into());
    }
    let net_broken = conn != Conn::Full;
    match (cmd, mode) {
        ("mode", Some(m)) if m.is_tunnel() => Ok(()),
        ("mode", Some(Mode::Off)) => Err("removing protection needs sudo: sudo torii down".into()),
        ("mode", Some(Mode::Portal)) | ("portal-auto", _) if net_broken => Ok(()),
        ("mode", Some(Mode::Portal)) | ("portal-auto", _) => Err("this network works, no captive portal needed; to force portal mode: sudo torii portal".into()),
        ("kick", _) | ("portal-open", _) | ("wst-reload", _) | ("wst-log", _) | ("wst-secret", _) => Ok(()),
        _ => Err("needs sudo".into()),
    }
}

/// What to do after portal-auto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortalNext {
    /// Let through; go on building the tunnel
    Passed,
    /// Portal confirmed (probe intercepted, page fetched) but automation can't pass it - stay in portal,
    /// release the lock, ask the user. Climbing the ladder now is pointless: no tunnel works until the portal is passed
    Handoff,
    /// No portal detected (no exit / error / timeout) - climb the ladder as usual
    NotPortal,
}

pub fn portal_next(out: &Outcome) -> PortalNext {
    match out {
        Outcome::Passed | Outcome::AlreadyOpen | Outcome::OpenedByRedirect => PortalNext::Passed,
        Outcome::NoForm | Outcome::NeedsUser | Outcome::StillBlocked(_) => PortalNext::Handoff,
        Outcome::NoExit | Outcome::Error(_) => PortalNext::NotPortal,
    }
}

/// The `phase` in the health file: what is actually happening, as opposed to `mode` (the intent).
pub fn phase(intent: Intent, healthy: bool, reason: &str, ks: bool) -> &'static str {
    let p = match intent {
        Intent::Mode(Mode::Off) => "off",
        Intent::Mode(Mode::Portal) => "portal",
        // No tunnel is wanted-and-up in these states, whatever a "skip:" verdict says about this round.
        Intent::FailedClosed | Intent::Unknown => {
            if reason.starts_with("bootstrap:") && healthy {
                "up"
            } else {
                "degraded"
            }
        }
        Intent::Mode(_) => {
            if reason.starts_with("unknown:") {
                "unknown"
            } else if reason.starts_with("skip:") && reason.contains("settling") {
                "establishing"
            } else if healthy {
                "up"
            } else {
                "degraded"
            }
        }
    };
    // Without the kill switch the fail-closed promise is gone even while the tunnel happens to work: the
    // next drop leaks. A bar must not show that as protected. ("Safely offline" is degraded, not leaking.)
    if (p == "degraded" || p == "up") && !ks {
        "leaking"
    } else {
        p
    }
}

/// Message for the notifier. None = nothing worth saying.
/// title = what is happening, at a glance; text = whether the user needs to act, and how. `critical` is
/// reserved for real danger (leaking / gave up): notification daemons never expire critical notifications,
/// and one afternoon piled up 20+ cards, most of them "the watchdog is handling it, don't touch".
pub fn advice(o: &Obs, ks: bool, busy: Option<&str>, busy_for: u64, gave_up: bool, resumed_ago: Option<u64>) -> Option<Advice> {
    let wifi = o.ssid.clone().unwrap_or_default();
    let net = if wifi.is_empty() { "this network".to_string() } else { wifi.clone() };
    let mk = |key: String, title: String, text: &str, critical: bool| Some(Advice { key, title, text: text.to_string(), critical });
    if gave_up {
        return mk("gaveup".into(), "All tunnels failed - offline, not leaking".into(), "The watchdog tried every tunnel and gave up; the kill switch is still on.\nPortal needs a login: torii portal    Go unprotected on purpose: sudo torii down", true);
    }
    // No physical link, nothing to advise. Observed: wifi dropped before suspend, an advice was computed
    // anyway, the notifier's debounce carried it across the night and popped it 6s after resume
    if o.phy.is_none() {
        return None;
    }
    // Really leaking: intent is a tunnel, the kill switch is not loaded, and the data path is down.
    // The only network notification that deserves critical
    if matches!(o.intent, Intent::Mode(m) if m.is_tunnel()) && !ks && o.conn != Conn::Full {
        return mk(format!("{}:leak", wifi), "Tunnel down, kill switch not loaded - unprotected".into(), "Now: torii up    To cut off first: sudo torii down, then turn off wifi", true);
    }
    if o.conn == Conn::Full {
        return match o.intent {
            Intent::Mode(Mode::Portal) if o.portal_handoff => mk("handoff-ok".into(), format!("{} - portal passed", net), "Restoring protection automatically, nothing to do", false),
            // Only remind about protection for a *manually* entered portal; after an automatic pass the
            // watchdog rebuilds by itself (a reminder in that 2s window is misleading)
            Intent::Mode(Mode::Portal) if o.manual_portal => mk("restore".into(), format!("{} - portal passed", net), "Restore protection: torii up", false),
            _ => None,
        };
    }
    if matches!(o.intent, Intent::Mode(Mode::Portal)) && o.portal_handoff && !o.manual_portal {
        return mk(format!("{}:handoff", wifi), format!("{} - captive portal needs you", net), "Run: torii portal (no sudo needed)\nAccept the terms; the watchdog then closes the window and restores protection", false);
    }
    if matches!(o.intent, Intent::Mode(Mode::Portal)) {
        return None; // automatic portal pass in progress / user has the login page open
    }
    if let Some((st, budget)) = o.carrier_flag {
        return match st {
            CarrierWait::Waiting => mk(format!("{}:waiting", wifi), format!("{} - gateway not forwarding yet", net), "Common right after connecting or resume; auto-reconnect is waiting for it, nothing to do", false),
            CarrierWait::Unreachable => mk(format!("{}:unreachable", wifi), format!("{} - gateway not forwarding", net), &format!("Nothing forwarded for {}s; the watchdog retries every minute. If it lasts over 3 minutes: torii portal, or switch networks", budget), false),
            CarrierWait::Portal => mk(format!("{}:portal", wifi), format!("{} - captive portal is blocking again", net), "The watchdog will pass the portal and reconnect, nothing to do", false),
        };
    }
    if let Some(b) = busy {
        return mk(format!("{}:busy", wifi), format!("{} - connecting", net), &format!("The watchdog is on it: {} ({}s so far). Don't run torii portal / torii up by hand, it would collide", b, busy_for), false);
    }
    // Just resumed: the link is still coming up and the watchdog hasn't run yet. Observed: an advice popped
    // 6s after resume, while the watchdog only started 14s after resume and fully recovered within 44s.
    if let Some(ago) = resumed_ago {
        if ago < 90 {
            return mk(format!("{}:resumed", wifi), "Just resumed, network recovering".into(), &format!("Resumed {}s ago; the watchdog will pass any portal and reconnect (usually within a minute), nothing to do", ago), false);
        }
    }
    // Mode just switched (torii up / re-selection after a network change): the tunnel is being built and the
    // bar already says "connecting". Observed: 4 notifications fired in this window, and every time the
    // watchdog sorted it out on its next round
    if matches!(o.intent, Intent::Mode(m) if m.is_tunnel()) && o.intent_age.map(|a| a < 90).unwrap_or(false) {
        return None;
    }
    if o.conn == Conn::Portal {
        return mk(format!("{}:nmportal", wifi), format!("{} - captive portal detected", net), "Run: torii portal (opens the login page in an isolated browser)", false);
    }
    if o.conn == Conn::Unknown {
        return None; // can't see != no problem, and != portal; stay quiet
    }
    match o.intent {
        Intent::Mode(Mode::Off) | Intent::Unknown => mk(format!("{}:bare", wifi), format!("{} - no internet (unprotected)", net), "Most likely a captive portal: torii portal", false),
        _ => mk(format!("{}:tunnel", wifi), format!("{} - no internet", net), &format!("{} is down, kill switch is on (not leaking). The watchdog keeps retrying; for details see `torii log`", o.intent.as_str()), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn obs() -> Obs {
        Obs { now: 1000, intent: Intent::Mode(Mode::Only(Tunnel::Wstunnel)), intent_age: Some(600), phy: Some("wlan0".into()), phy_has_ip: true, ssid: Some("X".into()), conn: Conn::Full, ..Default::default() }
    }
    fn cfg() -> WdConf {
        WdConf { auto_portal: true, ..Default::default() }
    }
    #[test]
    fn manual_off_wins() {
        let mut o = obs();
        o.manual_off = true;
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(s) if s.contains("manual off")));
    }
    #[test]
    fn portal_fresh_skips_stale_bootstraps() {
        let mut o = obs();
        o.intent = Intent::Mode(Mode::Portal);
        o.intent_age = Some(10);
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(_)));
        o.intent_age = Some(300);
        assert_eq!(gate(&o, &cfg()), Gate::Proceed { bootstrap: true });
        o.manual_portal = true;
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(_)), "manual portal gets a 900s grace period");
    }
    #[test]
    fn settle_exempt_when_portal_flag() {
        let mut o = obs();
        o.intent_age = Some(20);
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(s) if s.contains("settling")));
        o.carrier_flag = Some((CarrierWait::Portal, 40));
        assert_eq!(gate(&o, &cfg()), Gate::Proceed { bootstrap: false });
    }
    #[test]
    fn failed_closed_is_bootstrap() {
        let mut o = obs();
        o.intent = Intent::FailedClosed;
        assert_eq!(gate(&o, &cfg()), Gate::Proceed { bootstrap: true });
    }
    #[test]
    fn no_phy_or_ip() {
        let mut o = obs();
        o.phy_has_ip = false;
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(s) if s.contains("no IP")));
        o.phy = None;
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(s) if s.contains("no physical")));
    }
    #[test]
    fn ladder_order() {
        assert_eq!(ladder(Some(Mode::Auto)), vec![Mode::Auto]);
        assert_eq!(ladder(None), vec![Mode::Auto]);
        let ws = Mode::Only(Tunnel::Wstunnel);
        assert_eq!(ladder(Some(ws)), vec![ws, Mode::Auto]);
    }
    #[test]
    fn reevaluate_only_on_change_with_full() {
        let o = obs();
        let c = cfg();
        let (wg, ws) = (Some(Tunnel::WireGuard), Some(Tunnel::Wstunnel));
        // new network, auto, running the wrong rung for it: re-climb
        assert_eq!(reevaluate_target(&o, &c, Some("Y"), wg, Some(Mode::Auto), ws), Some(Mode::Auto));
        // same network: nothing
        assert_eq!(reevaluate_target(&o, &c, Some("X"), wg, Some(Mode::Auto), ws), None);
        // already on the right rung
        assert_eq!(reevaluate_target(&o, &c, Some("Y"), wg, Some(Mode::Auto), wg), None);
        // manual single tunnel from the previous network: back to auto
        assert_eq!(reevaluate_target(&o, &c, Some("Y"), wg, Some(Mode::Only(Tunnel::Wstunnel)), ws), Some(Mode::Auto));
        let mut o2 = obs();
        o2.conn = Conn::Limited;
        assert_eq!(reevaluate_target(&o2, &c, Some("Y"), wg, Some(Mode::Auto), ws), None);
    }
    #[test]
    fn phase_leaking_vs_degraded() {
        assert_eq!(phase(Intent::Mode(Mode::Auto), false, "x", true), "degraded");
        assert_eq!(phase(Intent::Mode(Mode::Auto), false, "x", false), "leaking");
        assert_eq!(phase(Intent::Mode(Mode::Auto), true, "ok:192.0.2.1", false), "leaking", "working tunnel without kill switch is not protected");
        assert_eq!(phase(Intent::FailedClosed, true, "skip:bootstrap cooling down", true), "degraded", "no tunnel is never protected");
        assert_eq!(phase(Intent::Unknown, true, "skip:no physical link", true), "degraded");
        assert_eq!(phase(Intent::Mode(Mode::Auto), true, "skip:mode switched 5s ago, still settling", true), "establishing");
        assert_eq!(phase(Intent::Mode(Mode::Auto), true, "unknown: all 3", true), "unknown");
    }
    #[test]
    fn advice_busy_beats_generic() {
        let mut o = obs();
        o.conn = Conn::Limited;
        let a = advice(&o, true, Some("portal-auto"), 27, false, None).unwrap();
        assert!(a.text.contains("Don't run"), "{}", a.text);
        let b = advice(&o, true, None, 0, false, None).unwrap();
        assert!(b.text.contains("torii log"));
        o.carrier_flag = Some((CarrierWait::Waiting, 40));
        assert!(advice(&o, true, Some("x"), 1, false, None).map(|a| format!("{} {}", a.title, a.text)).unwrap().contains("gateway not forwarding yet"));
        o.carrier_flag = None;
        assert!(advice(&o, true, None, 0, false, Some(20)).map(|a| format!("{} {}", a.title, a.text)).unwrap().contains("Just resumed"));
        assert!(advice(&o, true, None, 0, false, Some(200)).map(|a| format!("{} {}", a.title, a.text)).unwrap().contains("torii log"));
    }
    #[test]
    fn advice_restore_only_manual_portal() {
        let mut o = obs();
        o.intent = Intent::Mode(Mode::Portal);
        assert!(advice(&o, true, None, 0, false, None).is_none(), "no reminder for an automatic portal");
        o.manual_portal = true;
        assert!(advice(&o, true, None, 0, false, None).map(|a| format!("{} {}", a.title, a.text)).unwrap().contains("torii up"));
        let mut o2 = obs();
        o2.conn = Conn::Limited;
        o2.phy = None;
        assert!(advice(&o2, true, None, 0, false, None).is_none(), "no link, no advice");
    }
    #[test]
    fn advice_silent_when_unknown() {
        let mut o = obs();
        o.conn = Conn::Unknown;
        assert!(advice(&o, true, None, 0, false, None).is_none());
    }
    #[test]
    fn portal_next_classifies() {
        assert_eq!(portal_next(&Outcome::Passed), PortalNext::Passed);
        assert_eq!(portal_next(&Outcome::AlreadyOpen), PortalNext::Passed);
        assert_eq!(portal_next(&Outcome::OpenedByRedirect), PortalNext::Passed);
        assert_eq!(portal_next(&Outcome::NoForm), PortalNext::Handoff, "JS-only login page");
        assert_eq!(portal_next(&Outcome::NeedsUser), PortalNext::Handoff);
        assert_eq!(portal_next(&Outcome::StillBlocked("302".into())), PortalNext::Handoff);
        assert_eq!(portal_next(&Outcome::NoExit), PortalNext::NotPortal);
        assert_eq!(portal_next(&Outcome::Error("x".into())), PortalNext::NotPortal);
    }
    fn handoff_obs() -> Obs {
        let mut o = obs();
        o.intent = Intent::Mode(Mode::Portal);
        o.portal_handoff = true;
        o.conn = Conn::Portal;
        o.intent_age = Some(300);
        o
    }
    #[test]
    fn handoff_waits_for_human_past_auto_strand() {
        let mut o = handoff_obs();
        // The 240s auto-portal grace has passed, but it was handed to the user - don't grab it back to climb the ladder
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(s) if s.contains("needs a human")));
        o.conn = Conn::Limited;
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(_)));
        o.intent_age = Some(901);
        assert_eq!(gate(&o, &cfg()), Gate::Proceed { bootstrap: true }, "user never acts; take over after the manual grace period");
    }
    #[test]
    fn handoff_resumes_as_soon_as_passed() {
        let mut o = handoff_obs();
        o.intent_age = Some(5);
        o.conn = Conn::Full;
        assert_eq!(gate(&o, &cfg()), Gate::Proceed { bootstrap: true }, "restore protection right after login, no grace wait");
        o.manual_portal = true; // same if the user ran portal again themselves
        assert_eq!(gate(&o, &cfg()), Gate::Proceed { bootstrap: true });
    }
    #[test]
    fn handoff_manual_off_still_wins() {
        let mut o = handoff_obs();
        o.manual_off = true;
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(s) if s.contains("manual off")));
    }
    #[test]
    fn advice_handoff() {
        let mut o = handoff_obs();
        let a = advice(&o, true, None, 0, false, None).unwrap();
        assert!(a.text.contains("portal") && !a.critical, "needs the user, but not dangerous: must not be a never-expiring critical  {}", a.text);
        assert!(a.title.contains("X"), "title includes the network name: {}", a.title);
        assert!(!a.text.contains("Don't run"));
        o.manual_portal = true;
        assert!(advice(&o, true, None, 0, false, None).is_none(), "user has the login page open, don't nag");
        o.conn = Conn::Full;
        let b = advice(&o, true, None, 0, false, None).unwrap();
        assert!(b.text.contains("Restoring protection automatically") && !b.text.contains("torii up"), "{}", b.text);
    }
    #[test]
    fn net_changed_skips_settle() {
        let mut o = obs();
        o.intent_age = Some(14);
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(s) if s.contains("settling")));
        o.net_changed = true;
        assert_eq!(gate(&o, &cfg()), Gate::Proceed { bootstrap: false });
        o.manual_off = true;
        assert!(matches!(gate(&o, &cfg()), Gate::Skip(s) if s.contains("manual off")), "manual off is respected across network changes too");
    }
    #[test]
    fn advice_quiet_while_establishing() {
        let mut o = obs();
        o.intent = Intent::Mode(Mode::Auto);
        o.conn = Conn::Limited;
        o.intent_age = Some(14);
        assert!(advice(&o, true, None, 0, false, None).is_none(), "14s after torii up: tunnel is being built, don't nag");
        o.intent_age = Some(120);
        assert!(advice(&o, true, None, 0, false, None).is_some());
    }
    #[test]
    fn advice_leak_is_the_critical_one() {
        let mut o = obs();
        o.intent = Intent::Mode(Mode::Auto);
        o.conn = Conn::Limited;
        o.intent_age = Some(5);
        let a = advice(&o, false, Some("x"), 3, false, None).unwrap();
        assert!(a.critical && a.title.contains("unprotected"), "{}", a.title);
        let b = advice(&o, true, Some("x"), 3, false, None).unwrap();
        assert!(!b.critical, "kill switch on = offline but not leaking, not critical");
    }
    #[test]
    fn may_rules() {
        use Conn::*;
        let op = Who::Operator;
        assert!(may(Who::Root, "mode", Some(Mode::Off), Full).is_ok());
        assert!(may(op, "mode", Some(Mode::Auto), Full).is_ok(), "adding protection needs no sudo");
        assert!(may(op, "mode", Some(Mode::Only(Tunnel::Wstunnel)), Limited).is_ok());
        assert!(may(op, "mode", Some(Mode::Off), Limited).unwrap_err().contains("sudo torii down"), "removing protection needs sudo");
        assert!(may(op, "mode", Some(Mode::Portal), Portal).is_ok(), "behind a portal: no sudo");
        assert!(may(op, "mode", Some(Mode::Portal), Limited).is_ok());
        assert!(may(op, "mode", Some(Mode::Portal), Full).is_err(), "no unprotected door on a working network");
        assert!(may(op, "portal-auto", None, Full).is_err());
        assert!(may(op, "kick", None, Full).is_ok());
        assert!(may(op, "portal-open", None, Full).is_ok(), "daemon separately checks for portal mode");
        assert!(may(Who::Other, "kick", None, Full).is_err());
        assert!(may(op, "something-new", None, Limited).is_err(), "anything unlisted needs sudo");
    }
}
