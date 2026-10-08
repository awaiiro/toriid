//! /etc/toriid/config.toml: the single user-edited config file. Missing keys take their defaults;
//! unknown keys are an error (a typo is harder to track down than a missing setting).
//! No restart needed after editing: the file is cached by mtime and re-read when it changes.
//! The path can be overridden with TORIID_CONFIG (tests / non-standard installs).
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

pub const DEFAULT_PATH: &str = "/etc/toriid/config.toml";

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub daemon: Daemon,
    pub networks: Networks,
    pub watchdog: Watchdog,
    pub tunnels: Tunnels,
    pub wifi: WifiSettings,
    pub wireguard: WireGuard,
    pub openvpn: OpenVpn,
    pub wstunnel: Wstunnel,
    pub killswitch: Killswitch,
    pub tailscale: Tailscale,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Daemon {
    /// The user (login name) who operates this machine. This user can run `torii up` / `torii portal`
    /// without sudo, and the portal browser and notifications open in their session.
    pub operator: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Networks {
    /// Trusted networks (SSIDs). LAN access is allowed only on these; every other network is
    /// treated as hostile.
    pub trusted: Vec<String>,
    /// Pin a mode per network, e.g. `"Guest-WiFi" = "wstunnel"`. A pinned network ignores its
    /// history and never tries other modes.
    pub pin: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Watchdog {
    /// Bring protection up automatically when unprotected after boot or a network change.
    pub auto_bootstrap: bool,
    /// Try to get through a detected captive portal automatically (click-through portals only).
    pub auto_portal: bool,
    /// Mode to try first on a network with no history.
    pub default_mode: String,
    /// After a network change, re-pick the mode based on what worked on the new network before.
    pub reevaluate_on_network_change: bool,
    /// Number of consecutive inconclusive connectivity checks before treating the network as
    /// having no way out.
    pub unknown_max: u32,
}
impl Default for Watchdog {
    fn default() -> Self {
        Watchdog { auto_bootstrap: true, auto_portal: false, default_mode: "auto".into(), reevaluate_on_network_change: true, unknown_max: 3 }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WifiSettings {
    /// "auto" (iwd if it is running, else NetworkManager), "iwd" or "networkmanager"
    pub backend: String,
}
impl Default for WifiSettings {
    fn default() -> Self {
        WifiSettings { backend: "auto".into() }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tunnels {
    /// The fallback ladder `torii up` climbs, top first. Rungs that are not configured are skipped.
    /// Known rungs: "wireguard" (UDP), "openvpn" (TCP 443), "wstunnel" (WireGuard inside TLS, own server).
    pub ladder: Vec<String>,
}
impl Default for Tunnels {
    fn default() -> Self {
        Tunnels { ladder: vec!["wireguard".into(), "openvpn".into(), "wstunnel".into()] }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WireGuard {
    /// WireGuard config in wg-quick format. toriid parses it and configures the interface itself;
    /// PostUp/PostDown commands are not executed.
    pub config: String,
}
impl Default for WireGuard {
    fn default() -> Self {
        WireGuard { config: "/etc/wireguard/wg0.conf".into() }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpenVpn {
    /// OpenVPN config for the TCP 443 fallback. If the file does not exist, this rung is skipped.
    pub config: String,
    /// systemd unit that starts/stops the OpenVPN client.
    pub unit: String,
    /// Interface name, as set by `dev` in the OpenVPN config.
    pub interface: String,
}
impl Default for OpenVpn {
    fn default() -> Self {
        OpenVpn { config: "/etc/openvpn/client/torii-tcp.conf".into(), unit: "openvpn-client@torii-tcp".into(), interface: "torii-tcp".into() }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Wstunnel {
    /// Parameters for the WireGuard-over-TLS rung (KEY=VALUE; contains secrets, keep it 0600).
    /// If the file does not exist, this rung is skipped.
    pub config: String,
    /// Path to the wstunnel client binary.
    pub client: String,
}
impl Default for Wstunnel {
    fn default() -> Self {
        Wstunnel { config: "/etc/toriid/wstunnel.conf".into(), client: "/usr/bin/wstunnel".into() }
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Killswitch {
    /// Extra interfaces to allow (VM bridges etc.). Their outbound traffic is allowed; forwarded
    /// traffic from them may only leave through the tunnel interface.
    pub vm_bridges: Vec<String>,
    /// Extra interfaces whose outbound traffic is allowed unconditionally. Only list interfaces
    /// you know send their traffic into a tunnel themselves (e.g. the inner side of another VPN).
    pub allow_interfaces: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tailscale {
    /// When tailscale0 exists, route its outer (encapsulated) traffic through the tunnel and send
    /// MagicDNS queries via tailscale0.
    pub integrate: bool,
}
impl Default for Tailscale {
    fn default() -> Self {
        Tailscale { integrate: true }
    }
}

pub fn path() -> String {
    std::env::var("TORIID_CONFIG").unwrap_or_else(|_| DEFAULT_PATH.into())
}

impl Settings {
    pub fn parse(text: &str) -> Result<Settings> {
        Ok(toml::from_str(text)?)
    }
    fn read(p: &str) -> Result<Settings> {
        if crate::util::euid_is_root() && std::path::Path::new(p).exists() {
            crate::util::root_trusted(p)?;
        }
        match std::fs::read_to_string(p) {
            Ok(t) => Self::parse(&t).with_context(|| format!("error in {}", p)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", p)),
        }
    }
}

static CACHE: Mutex<Option<(Option<SystemTime>, Arc<Settings>)>> = Mutex::new(None);

/// Current config. If the file is broken, log once to the journal and keep using the last good
/// one (or the defaults): a single mistyped key must not make the daemon drop protection.
pub fn get() -> Arc<Settings> {
    let p = path();
    let mtime = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
    let mut g = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((t, s)) = g.as_ref() {
        if *t == mtime {
            return s.clone();
        }
    }
    let s = match Settings::read(&p) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            crate::journal::err("toriid", &format!("cannot read config, keeping the previous one: {:#}", e));
            g.as_ref().map(|(_, s)| s.clone()).unwrap_or_default()
        }
    };
    *g = Some((mtime, s.clone()));
    s
}

/// `toriid check-config`: show errors to the user verbatim
pub fn check() -> Result<Settings> {
    let s = Settings::read(&path())?;
    for t in &s.tunnels.ladder {
        if crate::state::Tunnel::parse(t).is_none() {
            anyhow::bail!("[tunnels] ladder: unknown tunnel \"{}\" (known: wireguard, openvpn, wstunnel)", t);
        }
    }
    for (net, m) in &s.networks.pin {
        if crate::state::Mode::parse(m).map(|m| !m.is_tunnel()).unwrap_or(true) {
            anyhow::bail!("[networks.pin] \"{}\" = \"{}\": not a tunnel mode (auto, wireguard, openvpn, wstunnel)", net, m);
        }
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_overrides() {
        let s = Settings::parse("[networks]\ntrusted = [\"Home\"]\npin = { \"Guest WiFi\" = \"wstunnel\" }\n[watchdog]\nauto_portal = true\n").unwrap();
        assert_eq!(s.networks.trusted, vec!["Home"]);
        assert_eq!(s.networks.pin.get("Guest WiFi").map(String::as_str), Some("wstunnel"));
        assert!(s.watchdog.auto_portal);
        assert!(s.watchdog.auto_bootstrap);
        assert_eq!(s.wireguard.config, "/etc/wireguard/wg0.conf");
    }
    #[test]
    fn unknown_key_is_error() {
        assert!(Settings::parse("[watchdog]\nauto_portl = true\n").is_err());
    }
    #[test]
    fn empty_is_default() {
        let s = Settings::parse("").unwrap();
        assert_eq!(s.openvpn.interface, "torii-tcp");
    }
}
