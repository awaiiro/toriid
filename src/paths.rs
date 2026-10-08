//! All file paths live here. User-configurable ones (tunnel config locations, OpenVPN unit name) come from
//! config.toml; this module provides accessors for them.
//! health.json / step / mode under /run/toriid are a **public interface** read by status bars and scripts -
//! think before changing their format.

pub const STATE: &str = "/run/toriid/mode"; // mode name (intent)
pub const STEP: &str = "/run/toriid/step"; // step the current action is on: "epoch\tlabel". Removed when the action ends; shown live by the bar
pub const HEALTH: &str = "/run/toriid/health.json"; // watchdog verdict + everything the bar needs
pub const WD_STATE: &str = "/run/toriid/watchdog.json"; // daemon's own memory (for debugging, discarded on restart)
pub const LOCK: &str = "/run/toriid/lock"; // mode-switch mutex (direct path; the daemon serializes internally)
pub const SOCK: &str = "/run/toriid/sock"; // CLI ↔ daemon
pub const MANUAL_OFF: &str = "/run/toriid/manual-off"; // user explicitly turned it off
pub const MANUAL_PORTAL: &str = "/run/toriid/manual-portal";
pub const GAVE_UP: &str = "/run/toriid/gave-up";
pub const PORTAL_HANDOFF: &str = "/run/toriid/portal-handoff"; // captive portal confirmed but could not be passed automatically, handed to the user; cleared on leaving portal mode
pub const CARRIER_WAIT: &str = "/run/toriid/carrier-wait"; // waiting|unreachable|portal <ts> <budget>
pub const FWD_SAVED: &str = "/run/toriid/forwarding-was";
pub const NET_CLASS: &str = "/run/toriid/class"; // trusted|hostile
pub const WST_ACTIVE: &str = "/run/toriid/wst-carrier";
pub const WST_LOG: &str = "/run/toriid/wstunnel.log";

pub const MODE_PROFILE: &str = "/var/lib/toriid/mode-profile"; // SSID\tmode\tts
pub const PORTAL_MEMORY: &str = "/var/lib/toriid/portal-method"; // SSID\thow the portal was passed\tts
pub const WST_VARIANT_DB: &str = "/var/lib/toriid/wst-variant"; // SSID\tvariant\tts
pub const WST_LIVE_FAIL_DB: &str = "/var/lib/toriid/wst-live-fail"; // SSID\tvariant\tts
pub const WST_PREF_DB: &str = "/var/lib/toriid/wst-carrier-pref"; // SSID\tcarrier\tts

pub const WG_IF: &str = "wg0";
pub const PORTAL_NS: &str = "portal";
pub const PORTAL_IP: &str = "10.99.98.5";
pub const PORTAL_HOST_IP: &str = "10.99.98.4";

pub const TS_MARK: &str = "0x80000/0xff0000";
pub const TS_PRIO: u32 = 5200;
pub const TS_NET4: &str = "100.64.0.0/10";
pub const TS_NET6: &str = "fd7a:115c:a1e0::/48";
pub const TS_TABLE: u32 = 52;
pub const TS_NET_PRIO: u32 = 5100;
pub const WST_CARRIER_PRIO: u32 = 90;

pub const RUN_DIR: &str = "/run/toriid";

// -- from config.toml --
pub fn wg_conf() -> String {
    crate::settings::get().wireguard.config.clone()
}
pub fn ovpn_conf() -> String {
    crate::settings::get().openvpn.config.clone()
}
pub fn ovpn_if() -> String {
    crate::settings::get().openvpn.interface.clone()
}
pub fn ovpn_unit() -> String {
    crate::settings::get().openvpn.unit.clone()
}
pub fn wst_conf() -> String {
    crate::settings::get().wstunnel.config.clone()
}
pub fn wst_client() -> String {
    crate::settings::get().wstunnel.client.clone()
}
