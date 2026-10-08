//! NetworkManager Wi-Fi backend. Reads (state, scan results, state changes) go over D-Bus; the rare
//! write operations (connect, disconnect, autoconnect, forget) use `nmcli`, NetworkManager's own stable
//! interface for them, so saved secrets and profile flags are handled exactly as NM expects.
use super::iwd::Wifi;
use anyhow::{anyhow, Result};
use futures::StreamExt;
use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

#[proxy(interface = "org.freedesktop.NetworkManager", default_service = "org.freedesktop.NetworkManager", default_path = "/org/freedesktop/NetworkManager")]
trait Manager {
    fn get_devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}

#[proxy(interface = "org.freedesktop.NetworkManager.Device", default_service = "org.freedesktop.NetworkManager")]
trait Device {
    #[zbus(property)]
    fn device_type(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn interface(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn state(&self) -> zbus::Result<u32>;
    // Named explicitly: the `State` property already claims `receive_state_changed` in zbus' generated API.
    #[zbus(signal, name = "StateChanged")]
    fn device_state_changed(&self, new_state: u32, old_state: u32, reason: u32) -> zbus::Result<()>;
}

#[proxy(interface = "org.freedesktop.NetworkManager.Device.Wireless", default_service = "org.freedesktop.NetworkManager")]
trait Wireless {
    #[zbus(property)]
    fn hw_address(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn active_access_point(&self) -> zbus::Result<OwnedObjectPath>;
    fn get_all_access_points(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    fn request_scan(&self, options: std::collections::HashMap<String, zbus::zvariant::Value<'_>>) -> zbus::Result<()>;
    #[zbus(property)]
    fn last_scan(&self) -> zbus::Result<i64>;
}

#[proxy(interface = "org.freedesktop.NetworkManager.AccessPoint", default_service = "org.freedesktop.NetworkManager")]
trait AccessPoint {
    #[zbus(property)]
    fn ssid(&self) -> zbus::Result<Vec<u8>>;
    #[zbus(property)]
    fn strength(&self) -> zbus::Result<u8>;
    #[zbus(property)]
    fn flags(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn wpa_flags(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn rsn_flags(&self) -> zbus::Result<u32>;
}

const DEVICE_TYPE_WIFI: u32 = 2;

/// Is NetworkManager on the bus?
pub async fn present() -> bool {
    let Ok(c) = super::system().await else { return false };
    let Ok(p) = ManagerProxy::new(&c).await else { return false };
    p.get_devices().await.is_ok()
}

async fn wifi_device() -> Result<(zbus::Connection, OwnedObjectPath)> {
    let c = super::system().await?;
    for path in ManagerProxy::new(&c).await?.get_devices().await? {
        let d = DeviceProxy::builder(&c).path(path.clone())?.build().await?;
        if d.device_type().await.unwrap_or(0) == DEVICE_TYPE_WIFI {
            return Ok((c, path));
        }
    }
    Err(anyhow!("no Wi-Fi device managed by NetworkManager"))
}

/// NM device states (NMDeviceState) folded into the same words the iwd backend uses.
pub fn state_word(s: u32) -> &'static str {
    match s {
        100 => "connected",
        40..=90 => "connecting",
        110 => "disconnecting",
        30 => "disconnected",
        _ => "unavailable",
    }
}

fn ssid_string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

pub async fn state() -> Option<Wifi> {
    let (c, path) = wifi_device().await.ok()?;
    let d = DeviceProxy::builder(&c).path(path.clone()).ok()?.build().await.ok()?;
    let w = WirelessProxy::builder(&c).path(path).ok()?.build().await.ok()?;
    let st = d.state().await.unwrap_or(0);
    let mut out = Wifi { dev: d.interface().await.unwrap_or_default(), mac: w.hw_address().await.unwrap_or_default().to_lowercase(), state: state_word(st).into(), ssid: None };
    if st == 100 {
        if let Ok(ap) = w.active_access_point().await {
            if ap.as_str() != "/" {
                if let Ok(a) = AccessPointProxy::builder(&c).path(ap).ok()?.build().await {
                    out.ssid = a.ssid().await.ok().map(|b| ssid_string(&b));
                }
            }
        }
    }
    Some(out)
}

/// Security type in iwd's words: open / psk / 8021x.
pub fn security(flags: u32, wpa: u32, rsn: u32) -> &'static str {
    const KEY_MGMT_8021X: u32 = 0x200;
    if (wpa | rsn) & KEY_MGMT_8021X != 0 {
        "8021x"
    } else if wpa | rsn != 0 || flags & 0x1 != 0 {
        "psk"
    } else {
        "open"
    }
}

/// Visible networks: (name, type, approximate signal in dBm, connected). NM reports strength in
/// percent; it is mapped back to a dBm-like number so both backends print the same column.
pub async fn scan_list(rescan: bool) -> Result<Vec<(String, String, i16, bool)>> {
    let (c, path) = wifi_device().await?;
    let w = WirelessProxy::builder(&c).path(path)?.build().await?;
    if rescan {
        let before = w.last_scan().await.unwrap_or(0);
        let _ = w.request_scan(Default::default()).await;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if w.last_scan().await.unwrap_or(0) != before {
                break;
            }
        }
    }
    let active = w.active_access_point().await.ok();
    let mut out: Vec<(String, String, i16, bool)> = vec![];
    for ap in w.get_all_access_points().await? {
        let is_active = active.as_ref().map(|a| a == &ap).unwrap_or(false);
        let a = AccessPointProxy::builder(&c).path(ap)?.build().await?;
        let name = ssid_string(&a.ssid().await.unwrap_or_default());
        if name.is_empty() {
            continue;
        }
        let dbm = a.strength().await.unwrap_or(0) as i16 / 2 - 100;
        let ty = security(a.flags().await.unwrap_or(0), a.wpa_flags().await.unwrap_or(0), a.rsn_flags().await.unwrap_or(0));
        match out.iter_mut().find(|e| e.0 == name) {
            Some(e) => {
                e.2 = e.2.max(dbm);
                e.3 |= is_active;
            }
            None => out.push((name, ty.into(), dbm, is_active)),
        }
    }
    out.sort_by(|a, b| b.2.cmp(&a.2));
    Ok(out)
}

async fn nmcli(args: &[&str]) -> Result<String> {
    let o = tokio::process::Command::new("nmcli").args(args).output().await.map_err(|e| anyhow!("nmcli: {}", e))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        Err(anyhow!("nmcli {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim()))
    }
}

/// Connect using a saved profile; for networks without one, only open networks work here (secrets come
/// from your desktop's NetworkManager agent, never from this tool).
pub async fn connect(name: &str) -> Result<()> {
    if nmcli(&["--wait", "30", "connection", "up", "id", name]).await.is_ok() {
        return Ok(());
    }
    nmcli(&["--wait", "30", "device", "wifi", "connect", name]).await.map(|_| ())
}

pub async fn disconnect() -> Result<()> {
    let w = state().await.ok_or_else(|| anyhow!("no Wi-Fi device"))?;
    nmcli(&["device", "disconnect", &w.dev]).await.map(|_| ())
}

pub async fn state_events() -> Result<tokio::sync::mpsc::UnboundedReceiver<String>> {
    let (c, path) = wifi_device().await?;
    let d = DeviceProxy::builder(&c).path(path)?.build().await?;
    let mut s = d.receive_device_state_changed().await?;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(sig) = s.next().await {
            let word = sig.args().map(|a| state_word(a.new_state)).unwrap_or("unknown");
            if tx.send(word.to_string()).is_err() {
                break;
            }
        }
    });
    Ok(rx)
}

pub async fn autoconnect(name: &str, on: bool) -> Result<String> {
    nmcli(&["connection", "modify", "id", name, "connection.autoconnect", if on { "yes" } else { "no" }]).await?;
    Ok(format!("NetworkManager: {} autoconnect={}", name, on))
}

pub async fn forget(name: &str) -> Result<String> {
    nmcli(&["connection", "delete", "id", name]).await?;
    Ok(format!("NetworkManager: forgot {}", name))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn security_words() {
        assert_eq!(security(0, 0, 0), "open");
        assert_eq!(security(1, 0, 0x188), "psk");
        assert_eq!(security(1, 0, 0x288), "8021x");
    }
    #[test]
    fn states() {
        assert_eq!(state_word(100), "connected");
        assert_eq!(state_word(70), "connecting");
        assert_eq!(state_word(30), "disconnected");
        assert_eq!(state_word(20), "unavailable");
    }
}
