//! Wi-Fi backend facade: iwd or NetworkManager, picked by `[wifi] backend` in config.toml.
//! Everything outside this module asks here, never a backend directly.
use crate::dbus::{iwd, nm};
pub use crate::dbus::iwd::Wifi;
use anyhow::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Iwd,
    NetworkManager,
}

/// `auto`: iwd when it is running (it is the lower layer even when NetworkManager drives it), else
/// NetworkManager.
pub async fn backend() -> Backend {
    match crate::settings::get().wifi.backend.as_str() {
        "iwd" => Backend::Iwd,
        "networkmanager" | "nm" => Backend::NetworkManager,
        _ => {
            if crate::dbus::systemd::is_active("iwd.service").await || !nm::present().await {
                Backend::Iwd
            } else {
                Backend::NetworkManager
            }
        }
    }
}

pub async fn state() -> Option<Wifi> {
    match backend().await {
        Backend::Iwd => iwd::state().await,
        Backend::NetworkManager => nm::state().await,
    }
}

pub async fn scan_list(rescan: bool) -> Result<Vec<(String, String, i16, bool)>> {
    match backend().await {
        Backend::Iwd => iwd::scan_list(rescan).await,
        Backend::NetworkManager => nm::scan_list(rescan).await,
    }
}

pub async fn connect(name: &str) -> Result<()> {
    match backend().await {
        Backend::Iwd => iwd::connect(name).await,
        Backend::NetworkManager => nm::connect(name).await,
    }
}

pub async fn disconnect() -> Result<()> {
    match backend().await {
        Backend::Iwd => iwd::disconnect().await,
        Backend::NetworkManager => nm::disconnect().await,
    }
}

pub async fn state_events() -> Result<tokio::sync::mpsc::UnboundedReceiver<String>> {
    match backend().await {
        Backend::Iwd => iwd::state_events().await,
        Backend::NetworkManager => nm::state_events().await,
    }
}

pub async fn autoconnect(name: &str, on: bool) -> Result<String> {
    match backend().await {
        Backend::Iwd => iwd::autoconnect(name, on).await,
        Backend::NetworkManager => nm::autoconnect(name, on).await,
    }
}

pub async fn forget(name: &str) -> Result<String> {
    match backend().await {
        Backend::Iwd => iwd::forget(name).await,
        Backend::NetworkManager => nm::forget(name).await,
    }
}
