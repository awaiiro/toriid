//! Public status interface for status bars and scripts.
//!
//! `torii status --json` prints one [`Status`] object; `torii watch` prints one per change (inotify on
//! the runtime directory, no polling, no root, never touches the network). `torii bar <kind>` renders
//! the same data in the native format of a bar. The JSON schema is versioned: fields are only ever
//! added within a version.
use crate::paths::*;
use crate::state::{self, Health};
use crate::util;
use serde::Serialize;
use std::io::Write;

pub const SCHEMA_VERSION: u32 = 1;
/// A heartbeat older than this means the daemon is not watching any more. A stale green light is
/// worse than a red one, so the state becomes `unknown`.
pub const STALE_AFTER: u64 = 150;

/// Coarse state a bar can switch on. Exactly one applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// Tunnel verified working.
    Protected,
    /// Daemon is bringing a tunnel up or re-checking.
    Connecting,
    /// Tunnel intended but not working; kill switch holds (no network, no leak).
    Blocked,
    /// Tunnel intended but kill switch not loaded and traffic flows outside the tunnel.
    Leaking,
    /// Captive portal mode: only the isolated portal browser can reach the network.
    Portal,
    /// User turned protection off.
    Off,
    /// Daemon not running or heartbeat stale.
    Unknown,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Protected => "protected",
            State::Connecting => "connecting",
            State::Blocked => "blocked",
            State::Leaking => "leaking",
            State::Portal => "portal",
            State::Off => "off",
            State::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Network {
    pub ssid: String,
    /// trusted / hostile
    pub class: String,
    /// full / limited / portal / unknown, as measured by the daemon
    pub connectivity: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Busy {
    pub action: String,
    pub since: u64,
    /// Step currently running inside the action, if any (e.g. "WireGuard / UDP 51820")
    pub step: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Advice {
    pub title: String,
    pub text: String,
    pub critical: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub version: u32,
    pub state: State,
    /// What the user asked for: auto / wireguard / openvpn / wstunnel / portal / off / failed-closed / unknown
    pub mode: String,
    /// wireguard / openvpn / wstunnel, or empty when no tunnel is up
    pub tunnel: String,
    pub variant: String,
    pub exit_ip: String,
    pub killswitch: bool,
    pub network: Network,
    pub busy: Option<Busy>,
    pub advice: Option<Advice>,
    /// Unix time of the daemon heartbeat this was built from (0 = none)
    pub updated: u64,
}

fn step() -> Option<String> {
    let t = util::read_trim(STEP)?;
    t.split_once('\t').map(|(_, l)| l.to_string())
}

pub fn classify(h: &Health, fresh: bool) -> State {
    if !fresh {
        return State::Unknown;
    }
    if h.busy.is_some() {
        return State::Connecting;
    }
    match h.phase.as_str() {
        "up" => State::Protected,
        "establishing" => State::Connecting,
        "leaking" => State::Leaking,
        "portal" => State::Portal,
        "off" => State::Off,
        "degraded" => State::Blocked,
        _ if h.mode == "failed-closed" => State::Blocked,
        _ => State::Unknown,
    }
}

/// Build a status snapshot from the runtime files. Cheap; safe to call from a bar every second.
pub fn snapshot() -> Status {
    let h = state::read_health();
    let fresh = h.as_ref().map(|h| util::now().saturating_sub(h.ts) <= STALE_AFTER).unwrap_or(false);
    let h = h.unwrap_or_default();
    let st = classify(&h, fresh);
    Status {
        version: SCHEMA_VERSION,
        state: st,
        mode: if h.mode.is_empty() { state::Intent::read().as_str() } else { h.mode.clone() },
        tunnel: if st == State::Protected || st == State::Connecting { h.tunnel.clone() } else { String::new() },
        variant: h.variant.clone(),
        exit_ip: if st == State::Protected { h.exit_ip.clone() } else { String::new() },
        killswitch: h.ks,
        network: Network { ssid: h.ssid.clone(), class: h.class.clone(), connectivity: h.conn.clone() },
        busy: h.busy.clone().map(|a| Busy { action: a, since: h.busy_since, step: step() }),
        advice: h.advice.as_ref().map(|a| Advice { title: a.title.clone(), text: a.text.clone(), critical: a.critical }),
        updated: h.ts,
    }
}

// ── Rendering ───────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icons {
    /// Nerd Font glyphs
    Nerd,
    Emoji,
    /// Plain ASCII, works everywhere
    Text,
}

impl Icons {
    pub fn parse(s: &str) -> Option<Icons> {
        Some(match s {
            "nerd" => Icons::Nerd,
            "emoji" => Icons::Emoji,
            "text" | "ascii" => Icons::Text,
            _ => return None,
        })
    }
    pub fn of(self, s: State) -> &'static str {
        match (self, s) {
            // Font Awesome 4 codepoints: present in every Nerd Font and stable across versions
            (Icons::Nerd, State::Protected) => "\u{f132}", // shield
            (Icons::Nerd, State::Connecting) => "\u{f021}", // refresh
            (Icons::Nerd, State::Blocked) => "\u{f05e}", // ban
            (Icons::Nerd, State::Leaking) => "\u{f071}", // warning
            (Icons::Nerd, State::Portal) => "\u{f0ac}", // globe
            (Icons::Nerd, State::Off) => "\u{f09c}", // unlock
            (Icons::Nerd, State::Unknown) => "\u{f128}", // question
            (Icons::Emoji, State::Protected) => "🛡️",
            (Icons::Emoji, State::Connecting) => "⏳",
            (Icons::Emoji, State::Blocked) => "⛔",
            (Icons::Emoji, State::Leaking) => "⚠️",
            (Icons::Emoji, State::Portal) => "🌐",
            (Icons::Emoji, State::Off) => "🔓",
            (Icons::Emoji, State::Unknown) => "❔",
            (Icons::Text, State::Protected) => "[VPN]",
            (Icons::Text, State::Connecting) => "[..]",
            (Icons::Text, State::Blocked) => "[X]",
            (Icons::Text, State::Leaking) => "[!!]",
            (Icons::Text, State::Portal) => "[P]",
            (Icons::Text, State::Off) => "[off]",
            (Icons::Text, State::Unknown) => "[?]",
        }
    }
}

/// Default colors per state (used by bars that take colors inline). Overridable from the CLI.
pub fn color(s: State) -> &'static str {
    match s {
        State::Protected => "#a6e3a1",
        State::Connecting => "#f9e2af",
        State::Blocked => "#fab387",
        State::Leaking => "#f38ba8",
        State::Portal => "#89b4fa",
        State::Off => "#9399b2",
        State::Unknown => "#6c7086",
    }
}

/// Short human label: what a bar shows next to the icon.
pub fn label(s: &Status) -> String {
    match s.state {
        State::Protected => match (s.tunnel.as_str(), s.variant.is_empty()) {
            ("wstunnel", false) => format!("wstunnel/{}", s.variant),
            ("", _) => s.mode.clone(),
            (t, _) => t.to_string(),
        },
        State::Connecting => s.busy.as_ref().and_then(|b| b.step.clone()).unwrap_or_else(|| "connecting".into()),
        st => st.as_str().to_string(),
    }
}

/// Multi-line tooltip text.
pub fn tooltip(s: &Status) -> String {
    let mut t = vec![format!("state: {}  (mode {})", s.state.as_str(), s.mode)];
    if !s.tunnel.is_empty() {
        t.push(format!("tunnel: {}{}", s.tunnel, if s.variant.is_empty() { String::new() } else { format!(" [{}]", s.variant) }));
    }
    if !s.exit_ip.is_empty() {
        t.push(format!("exit: {}", s.exit_ip));
    }
    if !s.network.ssid.is_empty() || !s.network.class.is_empty() {
        t.push(format!("network: {} ({}, {})", if s.network.ssid.is_empty() { "wired" } else { &s.network.ssid }, s.network.class, s.network.connectivity));
    }
    t.push(format!("kill switch: {}", if s.killswitch { "on" } else { "off" }));
    if let Some(b) = &s.busy {
        t.push(format!("busy: {}{}", b.action, b.step.as_ref().map(|x| format!(" / {}", x)).unwrap_or_default()));
    }
    if let Some(a) = &s.advice {
        t.push(String::new());
        t.push(a.title.clone());
        t.push(a.text.clone());
    }
    t.join("\n")
}

/// Expand `{icon} {label} {state} {mode} {tunnel} {variant} {exit_ip} {ssid} {class}` in a user format.
pub fn format(fmt: &str, s: &Status, icons: Icons) -> String {
    fmt.replace("{icon}", icons.of(s.state))
        .replace("{label}", &label(s))
        .replace("{state}", s.state.as_str())
        .replace("{mode}", &s.mode)
        .replace("{tunnel}", &s.tunnel)
        .replace("{variant}", &s.variant)
        .replace("{exit_ip}", &s.exit_ip)
        .replace("{ssid}", &s.network.ssid)
        .replace("{class}", &s.network.class)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    /// Raw status JSON (eww deflisten, ags, quickshell, anything scriptable)
    Json,
    /// waybar custom module, `return-type: json`
    Waybar,
    /// polybar `custom/script` with `tail = true`
    Polybar,
    /// i3blocks / i3status-rust custom block (full_text, short_text, color lines)
    I3blocks,
    /// Plain formatted line (yambar, lemonbar, sfwbar, tmux, ...)
    Plain,
}

impl Bar {
    pub fn parse(s: &str) -> Option<Bar> {
        Some(match s {
            "json" | "eww" | "ags" | "quickshell" => Bar::Json,
            "waybar" => Bar::Waybar,
            "polybar" => Bar::Polybar,
            "i3blocks" => Bar::I3blocks,
            "plain" | "text" | "yambar" | "lemonbar" | "tmux" => Bar::Plain,
            _ => return None,
        })
    }
}

pub struct RenderOpts {
    pub icons: Icons,
    pub format: String,
}

pub fn render(bar: Bar, s: &Status, o: &RenderOpts) -> String {
    let text = format(&o.format, s, o.icons);
    match bar {
        Bar::Json => serde_json::to_string(s).unwrap_or_default(),
        Bar::Waybar => {
            let mut classes = vec![s.state.as_str().to_string()];
            if !s.tunnel.is_empty() {
                classes.push(s.tunnel.clone());
            }
            if s.advice.as_ref().map(|a| a.critical).unwrap_or(false) {
                classes.push("critical".into());
            }
            serde_json::json!({
                "text": text,
                "alt": s.state.as_str(),
                "tooltip": tooltip(s),
                "class": classes,
                "percentage": match s.state { State::Protected => 100, State::Connecting => 50, _ => 0 },
            })
            .to_string()
        }
        Bar::Polybar => format!("%{{F{}}}{}%{{F-}}", color(s.state), text),
        Bar::I3blocks => format!("{}\n{}\n{}", text, o.icons.of(s.state), color(s.state)),
        Bar::Plain => text,
    }
}

// ── Watching ────────────────────────────────────────────────────

/// Call `emit` once now and again whenever the runtime state changes (deduplicated). Also re-emits
/// every `STALE_AFTER`/3 seconds so a dead daemon turns into `unknown` without any file changing.
pub fn watch(mut emit: impl FnMut(&Status) -> bool) -> anyhow::Result<()> {
    use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
    use std::os::fd::AsFd;
    let ino = Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK)?;
    let mut watching = false;
    let mut last = String::new();
    loop {
        if !watching {
            // The directory appears when the daemon starts; until then keep polling slowly.
            watching = ino.add_watch(RUN_DIR, AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_DELETE | AddWatchFlags::IN_CREATE).is_ok();
        }
        let s = snapshot();
        let key = serde_json::to_string(&Status { updated: 0, ..s.clone() }).unwrap_or_default();
        if key != last {
            if !emit(&s) {
                return Ok(());
            }
            last = key;
        }
        let mut fds = [nix::poll::PollFd::new(ino.as_fd(), nix::poll::PollFlags::POLLIN)];
        let timeout = if watching { (STALE_AFTER / 3 * 1000) as u16 } else { 5000 };
        let _ = nix::poll::poll(&mut fds, nix::poll::PollTimeout::from(timeout));
        while let Ok(ev) = ino.read_events() {
            if ev.is_empty() {
                break;
            }
        }
        // Writers rename into place in bursts; coalesce them.
        std::thread::sleep(std::time::Duration::from_millis(50));
        while let Ok(ev) = ino.read_events() {
            if ev.is_empty() {
                break;
            }
        }
    }
}

/// Print `render(bar)` for every change; stops when stdout goes away (bar restarted).
pub fn watch_print(bar: Bar, o: &RenderOpts) -> anyhow::Result<()> {
    let out = std::io::stdout();
    watch(|s| {
        let mut l = out.lock();
        writeln!(l, "{}", render(bar, s, o)).and_then(|_| l.flush()).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn health(phase: &str) -> Health {
        Health { ts: util::now(), mode: "auto".into(), phase: phase.into(), tunnel: "wireguard".into(), exit_ip: "203.0.113.9".into(), ks: true, ..Default::default() }
    }
    #[test]
    fn stale_is_unknown() {
        assert_eq!(classify(&health("up"), false), State::Unknown);
        assert_eq!(classify(&health("up"), true), State::Protected);
    }
    #[test]
    fn busy_wins() {
        let mut h = health("up");
        h.busy = Some("watchdog".into());
        assert_eq!(classify(&h, true), State::Connecting);
    }
    #[test]
    fn phases() {
        assert_eq!(classify(&health("leaking"), true), State::Leaking);
        assert_eq!(classify(&health("degraded"), true), State::Blocked);
        assert_eq!(classify(&health("portal"), true), State::Portal);
        let mut h = health("whatever");
        h.mode = "failed-closed".into();
        assert_eq!(classify(&h, true), State::Blocked);
    }
    fn st() -> Status {
        Status {
            version: 1,
            state: State::Protected,
            mode: "auto".into(),
            tunnel: "wstunnel".into(),
            variant: "clean".into(),
            exit_ip: "203.0.113.9".into(),
            killswitch: true,
            network: Network { ssid: "Cafe".into(), class: "hostile".into(), connectivity: "full".into() },
            busy: None,
            advice: None,
            updated: 1,
        }
    }
    #[test]
    fn waybar_is_valid_json() {
        let o = RenderOpts { icons: Icons::Text, format: "{icon} {label}".into() };
        let v: serde_json::Value = serde_json::from_str(&render(Bar::Waybar, &st(), &o)).unwrap();
        assert_eq!(v["text"], "[VPN] wstunnel/clean");
        assert_eq!(v["alt"], "protected");
        assert_eq!(v["class"][1], "wstunnel");
    }
    #[test]
    fn polybar_and_i3blocks() {
        let o = RenderOpts { icons: Icons::Text, format: "{label} {ssid}".into() };
        assert_eq!(render(Bar::Polybar, &st(), &o), "%{F#a6e3a1}wstunnel/clean Cafe%{F-}");
        assert_eq!(render(Bar::I3blocks, &st(), &o).lines().count(), 3);
    }
}
