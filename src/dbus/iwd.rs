//! iwd: WiFi state, scanning, connecting. NetworkManager is not involved.
use anyhow::{anyhow, Result};
use iwdrs::session::Session;
use iwdrs::station::State;

#[derive(Clone, Debug, Default)]
pub struct Wifi {
    pub dev: String,
    pub mac: String,
    pub state: String,
    pub ssid: Option<String>,
}

async fn session() -> Result<Session> {
    Ok(Session::new().await?)
}

/// First NIC in station mode. None = iwd not running or no WiFi NIC.
pub async fn state() -> Option<Wifi> {
    let s = session().await.ok()?;
    let st = s.stations().await.ok()?.into_iter().next()?;
    let mut w = Wifi::default();
    w.state = match st.state().await.ok()? {
        State::Connected => "connected",
        State::Disconnected => "disconnected",
        State::Connecting => "connecting",
        State::Disconnecting => "disconnecting",
        State::Roaming => "roaming",
    }
    .into();
    let mut dev = None;
    if let Ok(Some(n)) = st.connected_network().await {
        w.ssid = n.name().await.ok();
        dev = n.device().await.ok();
    }
    if dev.is_none() {
        dev = s.devices().await.ok()?.into_iter().next();
    }
    if let Some(d) = dev {
        w.dev = d.name().await.unwrap_or_default();
        w.mac = d.address().await.unwrap_or_default();
    }
    Some(w)
}

/// Visible networks: (name, type, signal dBm, connected)
pub async fn scan_list(rescan: bool) -> Result<Vec<(String, String, i16, bool)>> {
    let s = session().await?;
    let st = s.stations().await?.into_iter().next().ok_or_else(|| anyhow!("no WiFi NIC"))?;
    if rescan {
        let _ = st.scan().await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), st.wait_for_scan_complete()).await;
    }
    let mut out = vec![];
    for (n, sig) in st.discovered_networks().await? {
        out.push((n.name().await?, format!("{:?}", n.network_type().await?).to_lowercase(), sig / 100, n.connected().await.unwrap_or(false)));
    }
    Ok(out)
}

/// Connect to a known/visible network. Passphrases come from an iwd agent or a saved known network;
/// none are taken here.
pub async fn connect(name: &str) -> Result<()> {
    let s = session().await?;
    let st = s.stations().await?.into_iter().next().ok_or_else(|| anyhow!("no WiFi NIC"))?;
    for (n, _) in st.discovered_networks().await? {
        if n.name().await? == name {
            n.connect().await.map_err(|e| anyhow!("connecting to {} failed: {:?}", name, e))?;
            return Ok(());
        }
    }
    Err(anyhow!("network {} not visible (run `torii wifi scan` first)", name))
}

pub async fn disconnect() -> Result<()> {
    let s = session().await?;
    let st = s.stations().await?.into_iter().next().ok_or_else(|| anyhow!("no WiFi NIC"))?;
    st.disconnect().await.map_err(|e| anyhow!("{:?}", e))?;
    Ok(())
}

/// Station.State changes -> events. Returns Err if iwd is not running; the caller falls back to polling.
pub async fn state_events() -> Result<tokio::sync::mpsc::UnboundedReceiver<String>> {
    use futures::StreamExt;
    let s = session().await?;
    let st = s.stations().await?.into_iter().next().ok_or_else(|| anyhow!("no WiFi NIC"))?;
    let mut stream = st.state_stream().await?;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(v) = stream.next().await {
            let s = match v {
                Ok(st) => format!("{:?}", st).to_lowercase(),
                Err(_) => "unknown".into(),
            };
            if tx.send(s).is_err() {
                break;
            }
        }
    });
    Ok(rx)
}

/// Toggle autoconnect for / forget a known network. If NetworkManager is running, its connection
/// profile is changed too (otherwise it would connect anyway).
pub async fn autoconnect(name: &str, on: bool) -> Result<String> {
    let s = session().await?;
    let mut hit = false;
    for k in s.known_networks().await? {
        if k.name().await? == name {
            k.set_autoconnect(on).await?;
            hit = true;
        }
    }
    let mut msg = if hit { format!("iwd: {} autoconnect={}", name, on) } else { format!("iwd: no known network {}", name) };
    if crate::dbus::systemd::is_active("NetworkManager").await {
        let r = tokio::process::Command::new("nmcli").args(["connection", "modify", name, "connection.autoconnect", if on { "yes" } else { "no" }]).output().await;
        msg += match r {
            Ok(o) if o.status.success() => " - NM: synced",
            _ => " - NM: no such connection profile (or modify failed)",
        };
    }
    Ok(msg)
}

pub async fn forget(name: &str) -> Result<String> {
    let s = session().await?;
    let mut hit = false;
    for k in s.known_networks().await? {
        if k.name().await? == name {
            k.forget().await?;
            hit = true;
        }
    }
    let mut msg = if hit { format!("iwd: forgot {}", name) } else { format!("iwd: no known network {}", name) };
    if crate::dbus::systemd::is_active("NetworkManager").await {
        let r = tokio::process::Command::new("nmcli").args(["connection", "delete", name]).output().await;
        msg += match r {
            Ok(o) if o.status.success() => " - NM: profile deleted",
            _ => " - NM: no such connection profile",
        };
    }
    Ok(msg)
}
