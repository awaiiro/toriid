//! systemd-resolved: per-link DNS servers and routing domains. Does what resolvectl does, directly via
//! org.freedesktop.resolve1. `~domain` is a routing domain (takes part in query routing), plain `domain`
//! is only a search domain; the bool here is that `~`.
use std::net::IpAddr;
use zbus::proxy;

#[proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
trait Manager {
    // zbus would map set_link_dns to SetLinkDns, but resolved's real name is SetLinkDNS. One letter of
    // case and the call fails with UnknownMethod; observed: wg0's DNS and tailscale0's routing domain
    // both silently went unset because of this.
    #[zbus(name = "SetLinkDNS")]
    fn set_link_dns(&self, ifindex: i32, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;
    fn set_link_domains(&self, ifindex: i32, domains: Vec<(String, bool)>) -> zbus::Result<()>;
    fn set_link_default_route(&self, ifindex: i32, enable: bool) -> zbus::Result<()>;
    fn revert_link(&self, ifindex: i32) -> zbus::Result<()>;
}

fn addr_tuple(a: &IpAddr) -> (i32, Vec<u8>) {
    match a {
        IpAddr::V4(v) => (libc::AF_INET, v.octets().to_vec()),
        IpAddr::V6(v) => (libc::AF_INET6, v.octets().to_vec()),
    }
}

/// A domain starting with `~` is a routing domain.
fn domain_tuple(d: &str) -> (String, bool) {
    match d.strip_prefix('~') {
        Some(rest) => (rest.to_string(), true),
        None => (d.to_string(), false),
    }
}

pub async fn set_link_dns(ifindex: i32, dns: &[IpAddr], domains: &[&str]) -> anyhow::Result<()> {
    let c = super::system().await?;
    let p = ManagerProxy::new(&c).await?;
    p.set_link_dns(ifindex, dns.iter().map(addr_tuple).collect()).await?;
    p.set_link_domains(ifindex, domains.iter().map(|d| domain_tuple(d)).collect()).await?;
    Ok(())
}

pub async fn set_link_default_route(ifindex: i32, on: bool) -> anyhow::Result<()> {
    let c = super::system().await?;
    ManagerProxy::new(&c).await?.set_link_default_route(ifindex, on).await?;
    Ok(())
}

pub async fn set_link_domains(ifindex: i32, domains: &[&str]) -> anyhow::Result<()> {
    let c = super::system().await?;
    ManagerProxy::new(&c).await?.set_link_domains(ifindex, domains.iter().map(|d| domain_tuple(d)).collect()).await?;
    Ok(())
}

pub async fn revert_link(ifindex: i32) {
    if let Ok(c) = super::system().await {
        if let Ok(p) = ManagerProxy::new(&c).await {
            let _ = p.revert_link(ifindex).await;
        }
    }
}

pub async fn active() -> bool {
    match super::system().await {
        Ok(c) => ManagerProxy::new(&c).await.is_ok(),
        Err(_) => false,
    }
}

/// Routing domains currently on a link (read from resolved's Link object). Used to check whether
/// tailscale0 holds `~.`.
#[proxy(interface = "org.freedesktop.resolve1.Link", default_service = "org.freedesktop.resolve1")]
trait Link {
    #[zbus(property)]
    fn domains(&self) -> zbus::Result<Vec<(String, bool)>>;
}

/// Object path of resolved's Link: every decimal digit of the ifindex is escaped as `_3X` per sd-bus
/// rules. A hardcoded `_3{}` only works for single digits: ifindex 12 would become `_312` instead of `_31_32`.
pub fn link_path(ifindex: impl std::fmt::Display) -> String {
    let esc: String = ifindex.to_string().chars().map(|c| format!("_3{}", c)).collect();
    format!("/org/freedesktop/resolve1/link/{}", esc)
}

/// Whether this is the "all queries are mine" routing domain `~.`. resolved reports it over D-Bus as
/// ".", not an empty string. Checking only for "" meant `~.` was never removed, and behind a captive
/// portal all DNS went into MagicDNS and deadlocked.
pub fn is_catchall(d: &str, routing: bool) -> bool {
    routing && (d.is_empty() || d == ".")
}

pub async fn link_domains(ifindex: i32) -> Vec<(String, bool)> {
    let Ok(c) = super::system().await else { return vec![] };
    let path = link_path(ifindex);
    let Ok(p) = LinkProxy::builder(&c).path(path).and_then(|b| Ok(b)) else { return vec![] };
    match p.build().await {
        Ok(p) => p.domains().await.unwrap_or_default(),
        Err(_) => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn link_path_escapes_each_digit() {
        assert_eq!(link_path(5), "/org/freedesktop/resolve1/link/_35");
        assert_eq!(link_path(12), "/org/freedesktop/resolve1/link/_31_32");
    }
    #[test]
    fn catchall_is_dot() {
        assert!(is_catchall(".", true), "this is what resolved actually reports");
        assert!(is_catchall("", true));
        assert!(!is_catchall(".", false), "search domain . is not a routing domain");
        assert!(!is_catchall("tail0000.ts.net", true));
    }
}
