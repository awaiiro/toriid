//! D-Bus side: iwd and NetworkManager (Wi-Fi), systemd-resolved (DNS), systemd (units), logind (sleep signals), notifications.
pub mod iwd;
pub mod logind;
pub mod nm;
pub mod notify;
pub mod resolved;
pub mod systemd;

use std::sync::OnceLock;
use tokio::sync::OnceCell;

static SYSTEM: OnceLock<OnceCell<zbus::Connection>> = OnceLock::new();

/// System bus connection, one shared per process.
pub async fn system() -> zbus::Result<zbus::Connection> {
    SYSTEM.get_or_init(OnceCell::new).get_or_try_init(zbus::Connection::system).await.cloned()
}
