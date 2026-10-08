//! Network classification: home (trusted network) / hostile, default hostile.
//! Any network not seen before is treated as a hostile network, not as neutral.
//! Warning: SSIDs can be spoofed and classification is by name. The only reliable gate is a
//! WPA-Enterprise certificate, which is iwd configuration.
use crate::config;
use crate::nl::{nft, Nl};
use crate::paths;
use crate::util::write_atomic;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Home,
    Hostile,
}
impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Home => "home",
            Class::Hostile => "hostile",
        }
    }
}

/// Compare whole entries, **never split on spaces**: splitting "My Home WiFi" into three tokens would classify
/// an open network named "My" as home, and mDNS would then broadcast the hostname and service list to
/// everyone there. This is the only misclassification in the design that fails open.
pub fn classify(ssid: Option<&str>) -> Class {
    match ssid {
        Some(s) if config::home_ssids().iter().any(|h| h == s) => Class::Home,
        _ => Class::Hostile,
    }
}

pub fn write_class(c: Class) {
    let _ = write_atomic(paths::NET_CLASS, c.as_str(), 0o644);
}

pub fn network_of(ip: Ipv4Addr, len: u8) -> String {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
    let net = Ipv4Addr::from(u32::from(ip) & mask);
    format!("{}/{}", net, len)
}

/// Fill lan_allow by class. Only the subnet **this NIC is actually on** is allowed, not all of RFC1918.
/// Does nothing when the killswitch isn't loaded (the set doesn't exist).
pub async fn apply_lan(nl: &Nl, class: Class, phy_index: Option<u32>) -> Vec<String> {
    let mut logs = vec![];
    if !nft::ks_loaded() {
        return logs;
    }
    nft::lan_clear();
    if class != Class::Home {
        return logs;
    }
    let Some(idx) = phy_index else { return logs };
    let Ok(addrs) = nl.ipv4_addrs(idx).await else { return logs };
    if let Some((ip, len)) = addrs.first() {
        let net = network_of(*ip, *len);
        match nft::lan_allow(&net) {
            Ok(()) => logs.push(format!("LAN allowed: {} + multicast/broadcast (mDNS / SSDP / LocalSend discovery)", net)),
            Err(e) => logs.push(format!("LAN allow failed: {}", e)),
        }
    }
    logs
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn net_of() {
        assert_eq!(network_of("192.0.2.37".parse().unwrap(), 24), "192.0.2.0/24");
        assert_eq!(network_of("203.0.113.9".parse().unwrap(), 22), "203.0.112.0/22");
    }
}
