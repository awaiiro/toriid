//! WireGuard, configured directly over genetlink instead of wg-quick.
//!
//! Everything wg-quick does is done explicitly here, and **we choose the priorities**:
//!   5150  lookup main suppress_prefixlength 0     <- the only way out for LAN / direct tailscale / main-table summary routes
//!   5300  not fwmark 0xca6c lookup 51820          <- catch-all into the tunnel
//! 5100 (tailnet) and 5200 (tailscale outer) in between are added by the modes layer.
//! wg-quick lets the kernel allocate its two rules at min-1, which lands them at 88/89 and races
//! the portal rule at 98. That race is gone: no rule priority is ever picked by the kernel.
//!
//! `up` is a **transaction**: if any step fails, everything done so far is undone in reverse order
//! and the error is returned.
use super::{Nl, RuleSpec};
use crate::dbus::resolved;
use crate::paths::{wg_conf, WG_IF};
use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

pub const WG_TABLE: u32 = 51820;
pub const WG_MARK: u32 = 0xca6c; // = 51820; killswitch.nft's prerouting_mark uses this value
pub const PRIO_SUPPRESS: u32 = 5150;
pub const PRIO_CATCHALL: u32 = 5300;

#[derive(Clone, Debug)]
pub struct WgConf {
    pub private_key: String,
    pub addresses: Vec<(IpAddr, u8)>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u32>,
    pub peer_public: String,
    pub preshared: Option<String>,
    pub endpoint: String, // host:port (verbatim; may be a hostname)
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub keepalive: Option<u16>,
    /// Routing domains (`~.` etc.). Defaults to ["~."] when DNS= is set; taken from
    /// `resolvectl domain %i ...` in PostUp if present.
    pub dns_domains: Vec<String>,
    /// PostUp/PostDown commands we did **not** run (wg-quick would; we never run arbitrary shell).
    /// These get logged.
    pub ignored_hooks: Vec<String>,
}

impl WgConf {
    pub fn load() -> Result<WgConf> {
        if crate::util::euid_is_root() {
            crate::util::root_trusted(&wg_conf())?;
        }
        let t = std::fs::read_to_string(&wg_conf()).with_context(|| format!("read {}", &wg_conf()))?;
        Self::parse(&t)
    }
    pub fn parse(t: &str) -> Result<WgConf> {
        let mut c = WgConf {
            private_key: String::new(),
            addresses: vec![],
            dns: vec![],
            mtu: None,
            peer_public: String::new(),
            preshared: None,
            endpoint: String::new(),
            allowed_ips: vec![],
            keepalive: None,
            dns_domains: vec![],
            ignored_hooks: vec![],
        };
        let mut section = "";
        for line in t.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if l.starts_with('[') {
                section = if l.eq_ignore_ascii_case("[interface]") { "if" } else { "peer" };
                continue;
            }
            let Some((k, v)) = l.split_once('=') else { continue };
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            match (section, k.as_str()) {
                ("if", "privatekey") => c.private_key = v.into(),
                ("if", "address") => c.addresses.extend(v.split(',').filter_map(|s| parse_cidr(s.trim()))),
                ("if", "dns") => c.dns.extend(v.split(',').filter_map(|s| s.trim().parse::<IpAddr>().ok())),
                ("if", "mtu") => c.mtu = v.parse().ok(),
                // wg-quick runs these via sh -c. We run nothing; we only understand the resolvectl dns/domain shapes and record the rest
                ("if", "postup") | ("if", "predown") | ("if", "postdown") | ("if", "preup") => {
                    for cmd in v.split(';').map(str::trim).filter(|c| !c.is_empty()) {
                        // wg-quick hands these to sh, so quoted args like `'~.'` are common; the quotes belong to the shell, not the domain
                        let w: Vec<&str> = cmd.split_whitespace().map(|a| a.trim_matches(|c| c == '\'' || c == '"')).collect();
                        match (k.as_str(), w.first().copied(), w.get(1).copied()) {
                            ("postup", Some("resolvectl"), Some("dns")) => c.dns.extend(w.iter().skip(3).filter_map(|a| a.parse::<IpAddr>().ok())),
                            ("postup", Some("resolvectl"), Some("domain")) => c.dns_domains.extend(w.iter().skip(3).map(|a| a.to_string())),
                            ("postup", Some("resolvectl"), Some("default-route")) => {}
                            ("postdown", _, _) | ("predown", _, _) => {} // on teardown we RevertLink, which is equivalent
                            _ => c.ignored_hooks.push(cmd.to_string()),
                        }
                    }
                }
                ("peer", "publickey") => c.peer_public = v.into(),
                ("peer", "presharedkey") => c.preshared = Some(v.into()),
                ("peer", "endpoint") => c.endpoint = v.into(),
                ("peer", "allowedips") => c.allowed_ips.extend(v.split(',').filter_map(|s| parse_cidr(s.trim()))),
                ("peer", "persistentkeepalive") => c.keepalive = v.parse().ok(),
                _ => {}
            }
        }
        if c.private_key.is_empty() || c.peer_public.is_empty() || c.endpoint.is_empty() {
            return Err(anyhow!("{} is missing PrivateKey / PublicKey / Endpoint", &wg_conf()));
        }
        if c.addresses.is_empty() {
            return Err(anyhow!("{} has no Address", &wg_conf()));
        }
        if !c.dns.is_empty() && c.dns_domains.is_empty() {
            c.dns_domains.push("~.".into()); // wg-quick + resolved default: with DNS= set, all queries go over this link
        }
        Ok(c)
    }
    pub fn endpoint_addr(&self) -> Result<SocketAddr> {
        self.endpoint.to_socket_addrs().with_context(|| format!("resolve Endpoint {}", self.endpoint))?.next().ok_or_else(|| anyhow!("Endpoint resolved to no addresses"))
    }
    /// Whether the interface has any IPv6 address.
    pub fn has_v6(&self) -> bool {
        self.addresses.iter().any(|(a, _)| a.is_ipv6())
    }
}

pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, l) = s.split_once('/')?;
    Some((a.parse().ok()?, l.parse().ok()?))
}

fn ifname() -> InterfaceName {
    WG_IF.parse().unwrap()
}

/// Handshake age in seconds. None = no interface / no peer / never handshaked (the interface exists
/// but the peer was never reached, which is exactly the state we want to catch).
pub fn handshake_age() -> Option<u64> {
    let d = Device::get(&ifname(), Backend::Kernel).ok()?;
    let hs = d.peers.first()?.stats.last_handshake_time?;
    Some(hs.elapsed().map(|e| e.as_secs()).unwrap_or(0))
}

/// Bring up wg0. `endpoint_override` is for wstunnel (points at 127.0.0.1:<local port>).
pub async fn up(nl: &Nl, conf: &WgConf, endpoint_override: Option<SocketAddr>) -> Result<()> {
    // Re-entrant: tear down first. Any leftover (half-configured interface, stale rules) is the next
    // "looks like it's running but nothing gets through".
    down(nl).await;

    let mut done = Vec::<Undo>::new();
    match up_inner(nl, conf, endpoint_override, &mut done).await {
        Ok(()) => Ok(()),
        Err(e) => {
            for u in done.into_iter().rev() {
                u.apply(nl).await;
            }
            Err(e)
        }
    }
}

enum Undo {
    Link(u32),
    Rule(u32, bool),
    Dns(i32),
}
impl Undo {
    async fn apply(self, nl: &Nl) {
        match self {
            Undo::Link(i) => {
                let _ = nl.link_del(i).await;
            }
            Undo::Rule(p, v6) => {
                let _ = nl.rule_del_prio(p, v6).await;
            }
            Undo::Dns(i) => resolved::revert_link(i).await,
        }
    }
}

async fn up_inner(nl: &Nl, conf: &WgConf, endpoint_override: Option<SocketAddr>, done: &mut Vec<Undo>) -> Result<()> {
    nl.wg_link_add(WG_IF).await.context("create wg0")?;
    let idx = nl.link_index(WG_IF).await?;
    done.push(Undo::Link(idx));

    let priv_key = Key::from_base64(&conf.private_key).map_err(|_| anyhow!("PrivateKey is not valid base64"))?;
    let pub_key = Key::from_base64(&conf.peer_public).map_err(|_| anyhow!("PublicKey is not valid base64"))?;
    let ep = match endpoint_override {
        Some(e) => e,
        None => conf.endpoint_addr()?,
    };
    let mut peer = PeerConfigBuilder::new(&pub_key).set_endpoint(ep).replace_allowed_ips();
    for (a, l) in &conf.allowed_ips {
        peer = peer.add_allowed_ip(*a, *l);
    }
    if let Some(k) = &conf.preshared {
        peer = peer.set_preshared_key(Key::from_base64(k).map_err(|_| anyhow!("PresharedKey is not valid"))?);
    }
    peer = peer.set_persistent_keepalive_interval(conf.keepalive.unwrap_or(25));
    DeviceUpdate::new()
        .set_private_key(priv_key)
        .set_fwmark(WG_MARK)
        .replace_peers()
        .add_peer(peer)
        .apply(&ifname(), Backend::Kernel)
        .context("write WireGuard config (genetlink)")?;

    for (a, l) in &conf.addresses {
        nl.addr_add(idx, *a, *l).await.with_context(|| format!("add address {}/{} to wg0", a, l))?;
    }
    nl.link_mtu(idx, conf.mtu.unwrap_or(1420)).await?;
    nl.link_up(idx).await.context("wg0 up")?;

    // Routes: the default route in table 51820 goes via wg0
    nl.route_replace(Ipv4Addr::UNSPECIFIED, 0, None, idx, WG_TABLE).await.context("table 51820 default route")?;
    if conf.has_v6() {
        let _ = nl.route6_replace_default(idx, WG_TABLE).await;
    }
    // Rules: explicit priorities
    for v6 in [false, true] {
        if v6 && !conf.has_v6() {
            continue;
        }
        nl.rule_add(RuleSpec { prio: PRIO_SUPPRESS, table: 254, v6, suppress_prefixlen: Some(0), ..Default::default() })
            .await
            .context("rule suppress_prefixlength")?;
        done.push(Undo::Rule(PRIO_SUPPRESS, v6));
        nl.rule_add(RuleSpec { prio: PRIO_CATCHALL, table: WG_TABLE, v6, fwmark: Some((WG_MARK, 0xffffffff)), invert: true, ..Default::default() })
            .await
            .context("rule catch-all")?;
        done.push(Undo::Rule(PRIO_CATCHALL, v6));
    }
    // DNS: routing domain (default `~.`) -> all queries go to the VPN's resolver inside the tunnel (same effect as wg-quick + resolvconf)
    if !conf.dns.is_empty() {
        let doms: Vec<&str> = conf.dns_domains.iter().map(String::as_str).collect();
        resolved::set_link_dns(idx as i32, &conf.dns, &doms).await.context("set wg0 DNS in resolved")?;
        let _ = resolved::set_link_default_route(idx as i32, true).await;
        done.push(Undo::Dns(idx as i32));
    } else {
        // No DNS means DNS goes over the physical link: in plaintext to the router at home, dropped by the
        // killswitch on a hostile network. Must be loud.
        crate::journal::err("toriid", "⚠ wg0.conf has no DNS= (and no PostUp resolvectl dns): the tunnel is up but DNS does not go through the VPN");
    }
    for h in &conf.ignored_hooks {
        crate::journal::notice("toriid", &format!("wg0.conf hook not executed (toriid does not run arbitrary commands): {}", h));
    }
    Ok(())
}

/// Tear down wg0. Idempotent; removing something that does not exist is not an error.
pub async fn down(nl: &Nl) {
    for v6 in [false, true] {
        let _ = nl.rule_del_prio(PRIO_CATCHALL, v6).await;
        let _ = nl.rule_del_prio(PRIO_SUPPRESS, v6).await;
    }
    if let Ok(Some(l)) = nl.link_by_name(WG_IF).await {
        resolved::revert_link(l.index as i32).await;
        let _ = nl.link_del(l.index).await; // deleting the interface also removes its routes in table 51820
    }
    let _ = Ipv6Addr::UNSPECIFIED; // (the v6 default route goes away with the interface)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_typical_provider_config() {
        let t = "[Interface]\nPrivateKey = abc=\nAddress = 10.77.0.2/32\nDNS = 10.77.0.1\n\n[Peer]\nPublicKey = def=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n";
        let c = WgConf::parse(t).unwrap();
        assert_eq!(c.addresses, vec![("10.77.0.2".parse().unwrap(), 32)]);
        assert_eq!(c.dns.len(), 1);
        assert_eq!(c.endpoint, "203.0.113.10:51820");
        assert!(!c.has_v6());
    }
    #[test]
    fn postup_resolvectl_is_understood() {
        let t = "[Interface]\nPrivateKey = a\nAddress = 10.77.0.2/32\nPostUp = resolvectl dns %i 10.77.0.1\nPostUp = resolvectl domain %i '~.'\nPostDown = resolvectl revert %i\n[Peer]\nPublicKey = b\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";
        let c = WgConf::parse(t).unwrap();
        assert_eq!(c.dns, vec!["10.77.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(c.dns_domains, vec!["~."]);
        assert!(c.ignored_hooks.is_empty());
        let t2 = "[Interface]\nPrivateKey = a\nAddress = 10.77.0.2/32\nDNS = 10.77.0.1\nPostUp = iptables -A FOO\n[Peer]\nPublicKey = b\nEndpoint = 192.0.2.1:51820\n";
        let c2 = WgConf::parse(t2).unwrap();
        assert_eq!(c2.dns_domains, vec!["~."]);
        assert_eq!(c2.ignored_hooks, vec!["iptables -A FOO"]);
    }
    #[test]
    fn missing_endpoint_fails() {
        assert!(WgConf::parse("[Interface]\nPrivateKey=a\nAddress=10.0.0.1/32\n[Peer]\nPublicKey=b\n").is_err());
    }
}
