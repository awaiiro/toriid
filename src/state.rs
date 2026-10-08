//! Intent (mode), phase, per-SSID memory, health file. Every on-disk format here is a public interface.
use crate::paths::*;
use crate::util::{self, write_atomic, Tsv};
use serde::{Deserialize, Serialize};
use std::fmt;

/// One rung of the tunnel ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tunnel {
    /// WireGuard over UDP
    WireGuard,
    /// OpenVPN over TCP (usually 443)
    OpenVpn,
    /// WireGuard wrapped in TLS/WebSocket via wstunnel and your own carrier server
    Wstunnel,
}
impl Tunnel {
    pub fn as_str(self) -> &'static str {
        match self {
            Tunnel::WireGuard => "wireguard",
            Tunnel::OpenVpn => "openvpn",
            Tunnel::Wstunnel => "wstunnel",
        }
    }
    pub fn parse(s: &str) -> Option<Tunnel> {
        Some(match s {
            "wireguard" | "wg" => Tunnel::WireGuard,
            "openvpn" | "ovpn" | "tcp" => Tunnel::OpenVpn,
            "wstunnel" | "wst" => Tunnel::Wstunnel,
            _ => return None,
        })
    }
}

/// What the user (or the watchdog) asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// Climb the configured ladder from the top until a tunnel works
    Auto,
    /// Exactly this tunnel, no fallback
    Only(Tunnel),
    /// Kill switch on, only the isolated portal namespace may reach the network
    Portal,
    /// No protection at all
    Off,
}
impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::Only(t) => t.as_str(),
            Mode::Portal => "portal",
            Mode::Off => "off",
        }
    }
    /// Accepts the pre-1.0 names too (`normal`, `tcp`), so remembered per-network modes keep working.
    pub fn parse(s: &str) -> Option<Mode> {
        Some(match s {
            "auto" | "normal" => Mode::Auto,
            "portal" => Mode::Portal,
            "off" => Mode::Off,
            t => Mode::Only(Tunnel::parse(t)?),
        })
    }
    pub fn is_tunnel(self) -> bool {
        matches!(self, Mode::Auto | Mode::Only(_))
    }
}
impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Contents of the mode state file. failed-closed is a **state**, not a mode name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    Mode(Mode),
    FailedClosed,
    Unknown,
}
impl Intent {
    pub fn read() -> Intent {
        match util::read_trim(STATE).as_deref() {
            Some("failed-closed") => Intent::FailedClosed,
            Some(s) => Mode::parse(s).map(Intent::Mode).unwrap_or(Intent::Unknown),
            None => Intent::Unknown,
        }
    }
    pub fn as_str(self) -> String {
        match self {
            Intent::Mode(m) => m.as_str().to_string(),
            Intent::FailedClosed => "failed-closed".into(),
            Intent::Unknown => "unknown".into(),
        }
    }
    pub fn mode(self) -> Option<Mode> {
        match self {
            Intent::Mode(m) => Some(m),
            _ => None,
        }
    }
}

pub fn write_intent(i: Intent) {
    let _ = write_atomic(STATE, &i.as_str(), 0o644);
}
pub fn intent_age() -> Option<u64> {
    util::mtime(STATE).map(|m| util::now().saturating_sub(m))
}

// ── per-SSID memory (TSV, public format) ─────────────────────
/// The rung that last worked on this network. Auto starts climbing there.
pub fn remembered_rung(ssid: &str) -> Option<Tunnel> {
    Tsv::get(MODE_PROFILE, ssid).and_then(|(v, _)| Tunnel::parse(&v))
}

pub fn remember_rung(ssid: &str, t: Tunnel) {
    let _ = Tsv::put(MODE_PROFILE, ssid, t.as_str());
}

/// Which mode this network should use: pin ([networks.pin]) > default_mode. The single place that decides.
/// (What worked last time is not a mode: auto starts from it, see `remembered_rung`.)
pub fn preferred_mode(ssid: Option<&str>, cfg: &crate::config::WdConf) -> Mode {
    if let Some(s) = ssid {
        if let Some((_, m)) = cfg.mode_pins.iter().find(|(n, _)| n == s) {
            if let Some(m) = Mode::parse(m).filter(|m| m.is_tunnel()) {
                return m;
            }
        }
    }
    Mode::parse(&cfg.bootstrap_default).filter(|m| m.is_tunnel()).unwrap_or(Mode::Auto)
}

/// How this network's captive portal was passed last time ("form auto-submitted", "Meraki auto-accept",
/// "needed a click", ...). A human-readable record only.
pub fn portal_memory_get(ssid: &str) -> Option<(String, String)> {
    Tsv::get(PORTAL_MEMORY, ssid)
}
pub fn portal_memory_put(ssid: &str, how: &str) {
    let _ = Tsv::put(PORTAL_MEMORY, ssid, how);
}

// ── carrier-wait flag (legacy interface; the notifier now reads the same-named field in health) ──
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CarrierWait {
    Waiting,
    Unreachable,
    Portal,
}
pub fn carrier_flag_write(s: CarrierWait, budget: u64) {
    let w = match s {
        CarrierWait::Waiting => "waiting",
        CarrierWait::Unreachable => "unreachable",
        CarrierWait::Portal => "portal",
    };
    let _ = write_atomic(CARRIER_WAIT, &format!("{} {} {}\n", w, util::now(), budget), 0o644);
}
pub fn carrier_flag_read(max_age: u64) -> Option<(CarrierWait, u64)> {
    let s = util::read_trim(CARRIER_WAIT)?;
    let mut it = s.split_whitespace();
    let st = match it.next()? {
        "waiting" => CarrierWait::Waiting,
        "unreachable" => CarrierWait::Unreachable,
        "portal" => CarrierWait::Portal,
        _ => return None,
    };
    let ts: u64 = it.next()?.parse().ok()?;
    let budget: u64 = it.next().and_then(|b| b.parse().ok()).unwrap_or(45);
    (util::now().saturating_sub(ts) <= max_age).then_some((st, budget))
}
pub fn carrier_flag_clear() {
    util::rm(CARRIER_WAIT);
}

// ── health file ──────────────────────────────────────────────
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Health {
    pub ts: u64,
    pub mode: String,
    pub phase: String,
    pub ssid: String,
    pub healthy: bool,
    pub reason: String,
    pub fails: u32,
    pub last_action: u64,
    pub ks: bool,
    pub probe_done: u64,
    pub probe_skipped: u64,
    // ── newer fields (older consumers ignore unknown keys) ──
    /// Connectivity (measured by the daemon): full / limited / portal / unknown
    pub conn: String,
    /// Message for the notifier. None = nothing to say.
    pub advice: Option<Advice>,
    /// What the daemon is doing right now (while busy, the notifier should say "hold on")
    pub busy: Option<String>,
    pub busy_since: u64,
    pub gave_up: bool,
    pub class: String,
    pub daemon_pid: u32,
    /// Which carrier is actually up: wireguard / openvpn / wstunnel / "" (none)
    #[serde(default)]
    pub tunnel: String,
    /// wstunnel variant when tunnel == wstunnel
    #[serde(default)]
    pub variant: String,
    /// Last exit IP the watchdog measured through the tunnel
    #[serde(default)]
    pub exit_ip: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Advice {
    /// Dedup key: re-notify only when it changes
    pub key: String,
    /// One-line title (notification summary / bar banner). Missing in older health files
    #[serde(default)]
    pub title: String,
    pub text: String,
    pub critical: bool,
}

pub fn write_health(h: &Health) {
    if let Ok(s) = serde_json::to_string(h) {
        let _ = write_atomic(HEALTH, &(s + "\n"), 0o644);
    }
}
pub fn read_health() -> Option<Health> {
    serde_json::from_str(&std::fs::read_to_string(HEALTH).ok()?).ok()
}
