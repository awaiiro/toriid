//! Runtime config views. The main config is config.toml (settings.rs); wstunnel.conf is a separate
//! KEY=VALUE file (holds secrets, rewritten by key rotation). It is parsed here, never sourced:
//! nothing in it is executed.
use crate::paths;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fs;

/// Read a file root is about to act on; as root, only if `util::root_trusted` passes.
pub fn read_trusted(path: &str) -> Option<String> {
    if !std::path::Path::new(path).exists() {
        return None; // not configured: nothing to say
    }
    if crate::util::euid_is_root() {
        if let Err(e) = crate::util::root_trusted(path) {
            crate::journal::err("toriid", &format!("{:#}", e));
            return None;
        }
    }
    fs::read_to_string(path).ok()
}

pub fn parse_kv(text: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").unwrap_or(l);
        if let Some((k, v)) = l.split_once('=') {
            let k = k.trim();
            if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let raw = v.trim();
            let v = match raw.chars().next() {
                Some(q @ ('"' | '\'')) => match raw[1..].find(q) {
                    Some(end) => raw[1..1 + end].to_string(), // quoted value verbatim; everything after the closing quote (incl. comments) dropped
                    None => raw[1..].to_string(),
                },
                _ => match raw.find(" #") {
                    Some(i) => raw[..i].trim().to_string(),
                    None => raw.to_string(),
                },
            };
            m.insert(k.to_string(), v);
        }
    }
    m
}

/// wstunnel.conf. A missing key is fatal; never silently fall back to a default (a silent default
/// once took the tunnel down on a restrictive network).
pub const WST_REQUIRED_KEYS: &[&str] = &[
    "WST_SERVER", "WST_PORT", "WST_SECRET", "WST_UPSTREAM", "WST_LOCAL_PORT", "WST_SNI_FALLBACK", "WST_SNI_NAMED",
    "WST_VERIFY",
];

#[derive(Clone, Debug)]
pub struct WstConf {
    pub servers: Vec<String>,
    pub server: String, // the configured default; the one picked at runtime is tracked separately
    pub port: String,
    pub secret: String,
    /// WireGuard endpoint the carrier server forwards to (host:port)
    pub upstream: String,
    pub local_port: String,
    pub sni_fallback: String,
    pub sni_named: String,
    pub verify: bool,
    /// Per-network variant pin (optional key WST_PIN="SSID=disguised;Other=clean"): a pinned network
    /// only tries that variant, no rotation, no daily upgrade probe. Some networks RST every clean/named
    /// handshake, so trying them first each time is wasted time.
    pub pins: Vec<(String, String)>,
}

impl WstConf {
    pub fn load() -> Result<WstConf> {
        Self::load_from(&paths::wst_conf())
    }
    pub fn load_from(path: &str) -> Result<WstConf> {
        if crate::util::euid_is_root() && std::path::Path::new(path).exists() {
            crate::util::root_trusted(path)?;
        }
        let text = fs::read_to_string(path).map_err(|_| anyhow!("missing {}", path))?;
        Self::parse(&text, path)
    }
    pub fn parse(text: &str, path: &str) -> Result<WstConf> {
        let m = parse_kv(text);
        let missing: Vec<&str> = WST_REQUIRED_KEYS.iter().copied().filter(|k| !m.contains_key(*k)).collect();
        if !missing.is_empty() {
            return Err(anyhow!(
                "{} is missing keys: {} - config and code are out of sync. Add them from {}.example; refusing to guess defaults",
                path,
                missing.join(" "),
                path
            ));
        }
        let server = m["WST_SERVER"].clone();
        let mut servers: Vec<String> =
            m.get("WST_SERVERS").map(|s| s.split_whitespace().map(String::from).collect()).unwrap_or_default();
        if servers.is_empty() {
            servers.push(server.clone());
        }
        Ok(WstConf {
            servers,
            server,
            port: m["WST_PORT"].clone(),
            secret: m["WST_SECRET"].clone(),
            upstream: m["WST_UPSTREAM"].clone(),
            local_port: m["WST_LOCAL_PORT"].clone(),
            sni_fallback: m["WST_SNI_FALLBACK"].clone(),
            sni_named: m["WST_SNI_NAMED"].clone(),
            verify: m["WST_VERIFY"] == "yes",
            pins: m
                .get("WST_PIN")
                .map(|v| v.split(';').filter_map(|e| e.split_once('=').map(|(a, b)| (a.trim().to_string(), b.trim().to_string()))).filter(|(a, b)| !a.is_empty() && !b.is_empty()).collect())
                .unwrap_or_default(),
        })
    }
    /// Reads only WST_SERVER without validating other keys, for callers like carrier_reachable that fail open.
    pub fn peek_server() -> Option<String> {
        let m = parse_kv(&read_trusted(&paths::wst_conf())?);
        m.get("WST_SERVER").cloned().filter(|s| !s.is_empty())
    }
    pub fn peek_servers_all() -> Vec<String> {
        let m = read_trusted(&paths::wst_conf()).map(|t| parse_kv(&t)).unwrap_or_default();
        let mut v: Vec<String> = m
            .get("WST_SERVERS")
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default();
        if let Some(s) = m.get("WST_SERVER") {
            if !s.is_empty() && !v.contains(s) {
                v.push(s.clone());
            }
        }
        v
    }
}

/// Watchdog parameters: user-tunable ones come from config.toml [watchdog], the rest are constants
#[derive(Clone, Debug)]
pub struct WdConf {
    pub auto_bootstrap: bool,
    pub auto_portal: bool,
    pub bootstrap_default: String,
    pub reevaluate_on_network_change: bool,
    // constants (kept here so tests can override them)
    pub fail_threshold: u32,
    pub cooldown: u64,
    pub max_actions: u32,
    pub portal_strand: u64,
    pub portal_strand_manual: u64,
    pub hs_max_age: u64,
    pub settle: u64,
    pub exit_confirm_ac: u64,
    pub exit_confirm_bat: u64,
    pub unknown_max: u32,
    pub tick: u64,
    /// Per-network mode pin ([networks.pin]): ignores history and alternatives; used by `torii up`, bootstrap and re-evaluation on network change
    pub mode_pins: Vec<(String, String)>,
}

impl Default for WdConf {
    fn default() -> Self {
        WdConf {
            auto_bootstrap: true,
            auto_portal: false,
            bootstrap_default: "auto".into(),
            reevaluate_on_network_change: true,
            fail_threshold: 2,
            cooldown: 120,
            max_actions: 6,
            portal_strand: 240,
            portal_strand_manual: 900,
            hs_max_age: 180,
            settle: 60,
            exit_confirm_ac: 600,
            exit_confirm_bat: 900,
            unknown_max: 3,
            tick: 60,
            mode_pins: vec![],
        }
    }
}

impl WdConf {
    pub fn load() -> WdConf {
        let mut c = WdConf::default();
        c.apply(&crate::settings::get());
        c
    }
    pub fn apply(&mut self, s: &crate::settings::Settings) {
        let w = &s.watchdog;
        self.auto_bootstrap = w.auto_bootstrap;
        self.auto_portal = w.auto_portal;
        self.reevaluate_on_network_change = w.reevaluate_on_network_change;
        if !w.default_mode.is_empty() {
            self.bootstrap_default = w.default_mode.clone();
        }
        self.unknown_max = w.unknown_max;
        self.mode_pins = s.networks.pin.iter().map(|(a, b)| (a.clone(), b.clone())).collect();
    }
}

/// SSIDs of trusted networks ([networks] trusted)
pub fn home_ssids() -> Vec<String> {
    crate::settings::get().networks.trusted.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kv_quotes_and_comments() {
        let m = parse_kv("# c\nA=1\nB=\"two words\" \nC='x' # tail\nD=v # tail\nexport E=5\n");
        assert_eq!(m["A"], "1");
        assert_eq!(m["B"], "two words");
        assert_eq!(m["C"], "x");
        assert_eq!(m["D"], "v");
        assert_eq!(m["E"], "5");
    }
    #[test]
    fn wst_missing_key_is_fatal() {
        let e = WstConf::parse("WST_SERVER=1.2.3.4\n", "x").unwrap_err().to_string();
        assert!(e.contains("WST_SECRET"), "{}", e);
    }
    #[test]
    fn wst_pin_parses() {
        let t = "WST_SERVER=1.1.1.1\nWST_PORT=443\nWST_SECRET=s\nWST_UPSTREAM=2.2.2.2:1\nWST_LOCAL_PORT=51822\nWST_SNI_FALLBACK=a\nWST_SNI_NAMED=b\nWST_VERIFY=yes\nWST_PIN=\"Guest Net=disguised; Cafe Wifi=clean\"\n";
        let c = WstConf::parse(t, "x").unwrap();
        assert_eq!(c.pins, vec![("Guest Net".to_string(), "disguised".to_string()), ("Cafe Wifi".to_string(), "clean".to_string())]);
    }
    #[test]
    fn wst_servers_fallback_to_server() {
        let t = "WST_SERVER=1.1.1.1\nWST_PORT=443\nWST_SECRET=s\nWST_UPSTREAM=2.2.2.2:1\nWST_LOCAL_PORT=51822\nWST_SNI_FALLBACK=a\nWST_SNI_NAMED=b\nWST_VERIFY=yes\n";
        let c = WstConf::parse(t, "x").unwrap();
        assert_eq!(c.upstream, "2.2.2.2:1");
        assert_eq!(c.servers, vec!["1.1.1.1"]);
        assert!(c.verify);
    }
}
