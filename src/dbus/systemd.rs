//! systemd unit control (the OpenVPN client is still a systemd unit).
use zbus::proxy;

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait Manager {
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
    fn reset_failed_unit(&self, name: &str) -> zbus::Result<()>;
    fn get_unit(&self, name: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

#[proxy(interface = "org.freedesktop.systemd1.Unit", default_service = "org.freedesktop.systemd1")]
trait Unit {
    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
}

/// Unit names over D-Bus need a suffix (`systemctl` appends .service automatically,
/// org.freedesktop.systemd1 does not). Without it the call fails with `<unit> is not valid` and the
/// OpenVPN fallback never starts.
fn unit_name(name: &str) -> String {
    if name.contains('.') { name.to_string() } else { format!("{}.service", name) }
}

pub async fn is_active(name: &str) -> bool {
    let name = &unit_name(name);
    let Ok(c) = super::system().await else { return false };
    let Ok(m) = ManagerProxy::new(&c).await else { return false };
    let Ok(path) = m.get_unit(name).await else { return false };
    let Ok(u) = UnitProxy::builder(&c).path(path).unwrap().build().await else { return false };
    u.active_state().await.map(|s| s == "active").unwrap_or(false)
}

pub async fn start(name: &str) -> anyhow::Result<()> {
    let name = &unit_name(name);
    let c = super::system().await?;
    ManagerProxy::new(&c).await?.start_unit(name, "replace").await?;
    Ok(())
}

pub async fn stop(name: &str) {
    let name = &unit_name(name);
    if let Ok(c) = super::system().await {
        if let Ok(m) = ManagerProxy::new(&c).await {
            let _ = m.stop_unit(name, "replace").await;
        }
    }
}
