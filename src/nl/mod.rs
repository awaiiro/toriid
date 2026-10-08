//! rtnetlink: links / addresses / routes / rules, plus kernel multicast events.
//! No text parsing anywhere: everything is netlink messages.
pub mod netns;
pub mod nft;
pub mod wg;

use anyhow::{anyhow, Context, Result};
use futures::TryStreamExt;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::{LinkAttribute, State};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType};
use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleFlags, RuleMessage};
use netlink_packet_route::AddressFamily;
use rtnetlink::{Handle, IpVersion, LinkUnspec, LinkVeth, LinkWireguard, RouteMessageBuilder};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;

#[derive(Clone, Debug)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub oper_up: bool,
    pub mac: Option<String>,
}

/// Interfaces that are never the physical uplink: tunnels, overlays, bridges, our own veths.
pub fn is_virtual(name: &str) -> bool {
    let ovpn = crate::paths::ovpn_if();
    name == "lo"
        || name == ovpn
        || ["wg", "tun", "tap", "tailscale", "to-portal", "from-portal", "virbr", "docker", "br-", "veth", "vnet", "zt", "dummy"].iter().any(|p| name.starts_with(p))
}

#[derive(Clone)]
pub struct Nl {
    pub h: Handle,
}

impl Nl {
    pub fn new() -> Result<Nl> {
        let (conn, h, _) = rtnetlink::new_connection().context("cannot open rtnetlink socket")?;
        tokio::spawn(conn);
        Ok(Nl { h })
    }

    // ── links ──────────────────────────────────────────────────
    pub async fn links(&self) -> Result<Vec<Link>> {
        let mut s = self.h.link().get().execute();
        let mut out = vec![];
        while let Some(m) = s.try_next().await? {
            let mut name = String::new();
            let mut oper_up = false;
            let mut mac = None;
            for a in &m.attributes {
                match a {
                    LinkAttribute::IfName(n) => name = n.clone(),
                    LinkAttribute::OperState(st) => oper_up = matches!(st, State::Up),
                    LinkAttribute::Address(b) if b.len() == 6 => {
                        mac = Some(b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(":"))
                    }
                    _ => {}
                }
            }
            out.push(Link { index: m.header.index, name, oper_up, mac });
        }
        Ok(out)
    }

    pub async fn link_by_name(&self, name: &str) -> Result<Option<Link>> {
        Ok(self.links().await?.into_iter().find(|l| l.name == name))
    }

    pub async fn link_index(&self, name: &str) -> Result<u32> {
        self.link_by_name(name).await?.map(|l| l.index).ok_or_else(|| anyhow!("no such interface {}", name))
    }

    pub async fn link_exists(&self, name: &str) -> bool {
        matches!(self.link_by_name(name).await, Ok(Some(_)))
    }

    /// First physical NIC with operstate=UP (wl*/en*/eth*). The single definition used project-wide.
    /// The physical uplink: the UP, non-virtual interface that holds the main table's default route.
    /// Falls back to the first UP wl*/en*/eth* interface (no default route yet, e.g. right after association).
    /// Name prefixes alone are not enough: usb0 / wwan0 tethering has no such prefix, and a second NIC
    /// (management, docking station) can be UP without being the way out.
    pub async fn phy_dev(&self) -> Result<Option<Link>> {
        let links: Vec<Link> = self.links().await?.into_iter().filter(|l| l.oper_up && !is_virtual(&l.name)).collect();
        let mut default_oifs = vec![];
        for m in self.routes_v4(254).await? {
            if m.header.destination_prefix_length == 0 {
                for a in &m.attributes {
                    if let RouteAttribute::Oif(i) = a {
                        default_oifs.push(*i);
                    }
                }
            }
        }
        if let Some(l) = links.iter().find(|l| default_oifs.contains(&l.index)) {
            return Ok(Some(l.clone()));
        }
        Ok(links.into_iter().find(|l| l.name.starts_with("wl") || l.name.starts_with("en") || l.name.starts_with("eth")))
    }

    pub async fn link_up(&self, index: u32) -> Result<()> {
        self.h.link().set(LinkUnspec::new_with_index(index).up().build()).execute().await?;
        Ok(())
    }
    pub async fn link_mtu(&self, index: u32, mtu: u32) -> Result<()> {
        self.h.link().set(LinkUnspec::new_with_index(index).mtu(mtu).build()).execute().await?;
        Ok(())
    }
    pub async fn link_del(&self, index: u32) -> Result<()> {
        self.h.link().del(index).execute().await?;
        Ok(())
    }
    pub async fn link_del_by_name(&self, name: &str) -> Result<bool> {
        match self.link_by_name(name).await? {
            Some(l) => {
                self.link_del(l.index).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
    pub async fn veth_add(&self, name: &str, peer: &str) -> Result<()> {
        self.h.link().add(LinkVeth::new(name, peer).build()).execute().await?;
        Ok(())
    }
    pub async fn wg_link_add(&self, name: &str) -> Result<()> {
        self.h.link().add(LinkWireguard::new(name).build()).execute().await?;
        Ok(())
    }
    pub async fn link_set_netns_fd(&self, index: u32, fd: RawFd) -> Result<()> {
        self.h.link().set(LinkUnspec::new_with_index(index).setns_by_fd(fd).build()).execute().await?;
        Ok(())
    }

    // ── addresses ──────────────────────────────────────────────────
    pub async fn ipv4_addrs(&self, index: u32) -> Result<Vec<(Ipv4Addr, u8)>> {
        let mut s = self.h.address().get().set_link_index_filter(index).execute();
        let mut out = vec![];
        while let Some(m) = s.try_next().await? {
            if m.header.family != AddressFamily::Inet {
                continue;
            }
            for a in &m.attributes {
                if let AddressAttribute::Address(IpAddr::V4(ip)) = a {
                    out.push((*ip, m.header.prefix_len));
                }
            }
        }
        Ok(out)
    }
    pub async fn has_ipv4(&self, index: u32) -> bool {
        self.ipv4_addrs(index).await.map(|v| !v.is_empty()).unwrap_or(false)
    }
    pub async fn addr_add(&self, index: u32, ip: IpAddr, len: u8) -> Result<()> {
        match self.h.address().add(index, ip, len).execute().await {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::EEXIST => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    // ── routes ──────────────────────────────────────────────────
    /// `ip route get <dst>`: the kernel's actual route choice. Returns (egress ifindex, gateway).
    pub async fn route_lookup(&self, dst: Ipv4Addr) -> Result<Option<(u32, Option<Ipv4Addr>)>> {
        let msg = RouteMessageBuilder::<Ipv4Addr>::new().destination_prefix(dst, 32).build();
        let mut s = self.h.route().get(msg).execute();
        match s.try_next().await {
            Ok(Some(m)) => {
                let mut oif = None;
                let mut gw = None;
                for a in &m.attributes {
                    match a {
                        RouteAttribute::Oif(i) => oif = Some(*i),
                        RouteAttribute::Gateway(RouteAddress::Inet(g)) => gw = Some(*g),
                        _ => {}
                    }
                }
                Ok(oif.map(|o| (o, gw)))
            }
            Ok(None) => Ok(None),
            Err(rtnetlink::Error::NetlinkError(_)) => Ok(None), // ENETUNREACH: no route
            Err(e) => Err(e.into()),
        }
    }
    pub async fn route_lookup_dev(&self, dst: Ipv4Addr) -> Result<Option<String>> {
        let Some((oif, _)) = self.route_lookup(dst).await? else { return Ok(None) };
        Ok(self.links().await?.into_iter().find(|l| l.index == oif).map(|l| l.name))
    }

    async fn routes_v4(&self, table: u32) -> Result<Vec<RouteMessage>> {
        let msg = RouteMessageBuilder::<Ipv4Addr>::new().table_id(table).build();
        let mut s = self.h.route().get(msg).execute();
        let mut out = vec![];
        while let Some(m) = s.try_next().await? {
            if route_table(&m) == table {
                out.push(m);
            }
        }
        Ok(out)
    }

    /// Default gateway of this NIC in the main table.
    pub async fn default_gw(&self, oif: u32) -> Result<Option<Ipv4Addr>> {
        for m in self.routes_v4(254).await? {
            if m.header.destination_prefix_length != 0 {
                continue;
            }
            let mut o = None;
            let mut gw = None;
            for a in &m.attributes {
                match a {
                    RouteAttribute::Oif(i) => o = Some(*i),
                    RouteAttribute::Gateway(RouteAddress::Inet(g)) => gw = Some(*g),
                    _ => {}
                }
            }
            if o == Some(oif) {
                return Ok(gw);
            }
        }
        Ok(None)
    }

    pub async fn route_exists(&self, dst: Ipv4Addr, len: u8, table: u32) -> Result<bool> {
        for m in self.routes_v4(table).await? {
            if m.header.destination_prefix_length != len {
                continue;
            }
            let d = m.attributes.iter().find_map(|a| match a {
                RouteAttribute::Destination(RouteAddress::Inet(d)) => Some(*d),
                _ => None,
            });
            if (len == 0 && d.is_none()) || d == Some(dst) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `ip route replace <dst>/<len> [via gw] dev <oif> table <t>`
    pub async fn route_replace(&self, dst: Ipv4Addr, len: u8, gw: Option<Ipv4Addr>, oif: u32, table: u32) -> Result<()> {
        let mut b = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(dst, len)
            .output_interface(oif)
            .table_id(table)
            .protocol(RouteProtocol::Static)
            .kind(RouteType::Unicast);
        b = match gw {
            Some(g) => b.gateway(g).scope(RouteScope::Universe),
            None => b.scope(RouteScope::Link),
        };
        self.h.route().add(b.build()).replace().execute().await?;
        Ok(())
    }
    pub async fn route6_replace_default(&self, oif: u32, table: u32) -> Result<()> {
        let b = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .output_interface(oif)
            .table_id(table)
            .protocol(RouteProtocol::Static)
            .kind(RouteType::Unicast);
        self.h.route().add(b.build()).replace().execute().await?;
        Ok(())
    }
    /// Deleting a route that does not exist is harmless: returns Ok(false).
    pub async fn route_del(&self, dst: Ipv4Addr, len: u8, table: u32) -> Result<bool> {
        let mut any = false;
        for m in self.routes_v4(table).await? {
            if m.header.destination_prefix_length != len {
                continue;
            }
            let d = m.attributes.iter().find_map(|a| match a {
                RouteAttribute::Destination(RouteAddress::Inet(d)) => Some(*d),
                _ => None,
            });
            if (len == 0 && d.is_none()) || d == Some(dst) {
                self.h.route().del(m).execute().await?;
                any = true;
            }
        }
        Ok(any)
    }

    // ── rules ──────────────────────────────────────────────────
    pub async fn rules(&self, v6: bool) -> Result<Vec<RuleMessage>> {
        let mut s = self.h.rule().get(if v6 { IpVersion::V6 } else { IpVersion::V4 }).execute();
        let mut out = vec![];
        while let Some(m) = s.try_next().await? {
            out.push(m);
        }
        Ok(out)
    }
    pub async fn rule_exists(&self, prio: u32, v6: bool) -> Result<bool> {
        Ok(self.rules(v6).await?.iter().any(|r| rule_prio(r) == Some(prio)))
    }
    pub async fn rule_del_prio(&self, prio: u32, v6: bool) -> Result<usize> {
        let mut n = 0;
        for r in self.rules(v6).await? {
            if rule_prio(&r) == Some(prio) {
                self.h.rule().del(r).execute().await?;
                n += 1;
            }
        }
        Ok(n)
    }
    /// Add a rule. Every field is explicit and the priority always is: the kernel never gets a chance
    /// to allocate min-1.
    pub async fn rule_add(&self, spec: RuleSpec) -> Result<()> {
        if self.rule_exists(spec.prio, spec.v6).await? {
            return Ok(());
        }
        let mut req = self.h.rule().add().priority(spec.prio).table_id(spec.table).action(RuleAction::ToTable);
        if let Some((m, mask)) = spec.fwmark {
            req = req.fw_mark(m);
            req.message_mut().attributes.push(RuleAttribute::FwMask(mask));
        }
        if let Some(l) = spec.suppress_prefixlen {
            req.message_mut().attributes.push(RuleAttribute::SuppressPrefixLen(l));
        }
        if spec.invert {
            req.message_mut().header.flags |= RuleFlags::Invert;
        }
        if spec.v6 {
            let mut r = req.v6();
            if let Some((IpAddr::V6(a), l)) = spec.src {
                r = r.source_prefix(a, l);
            }
            if let Some((IpAddr::V6(a), l)) = spec.dst {
                r = r.destination_prefix(a, l);
            }
            r.execute().await?;
        } else {
            let mut r = req.v4();
            if let Some((IpAddr::V4(a), l)) = spec.src {
                r = r.source_prefix(a, l);
            }
            if let Some((IpAddr::V4(a), l)) = spec.dst {
                r = r.destination_prefix(a, l);
            }
            r.execute().await?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuleSpec {
    pub prio: u32,
    pub table: u32,
    pub v6: bool,
    pub fwmark: Option<(u32, u32)>,
    pub invert: bool,
    pub suppress_prefixlen: Option<u32>,
    pub src: Option<(IpAddr, u8)>,
    pub dst: Option<(IpAddr, u8)>,
}

fn route_table(m: &RouteMessage) -> u32 {
    m.attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Table(t) => Some(*t),
            _ => None,
        })
        .unwrap_or(m.header.table as u32)
}

fn rule_prio(r: &RuleMessage) -> Option<u32> {
    r.attributes.iter().find_map(|a| match a {
        RuleAttribute::Priority(p) => Some(*p),
        _ => None,
    })
}

// ── events ──────────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NlEvent {
    Link,
    Addr,
    Route,
}

/// Subscribe to link/address/route multicast. The content does not matter, only that "something
/// changed": consumers debounce and take a fresh snapshot instead of interpreting each message.
pub fn subscribe() -> Result<tokio::sync::mpsc::UnboundedReceiver<NlEvent>> {
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_route::RouteNetlinkMessage as R;
    use rtnetlink::MulticastGroup as G;
    let groups = [G::Link, G::Ipv4Ifaddr, G::Ipv4Route, G::Ipv6Ifaddr, G::Ipv6Route];
    let (conn, _h, mut msgs) = rtnetlink::new_multicast_connection(&groups).context("subscribe to rtnetlink multicast")?;
    tokio::spawn(conn);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some((m, _)) = futures::StreamExt::next(&mut msgs).await {
            let ev = match m.payload {
                NetlinkPayload::InnerMessage(R::NewLink(_) | R::DelLink(_)) => NlEvent::Link,
                NetlinkPayload::InnerMessage(R::NewAddress(_) | R::DelAddress(_)) => NlEvent::Addr,
                NetlinkPayload::InnerMessage(R::NewRoute(_) | R::DelRoute(_)) => NlEvent::Route,
                _ => continue,
            };
            if tx.send(ev).is_err() {
                break;
            }
        }
    });
    Ok(rx)
}

#[cfg(test)]
mod phy_tests {
    #[test]
    fn virtual_names() {
        for v in ["lo", "wg0", "tailscale0", "to-portal", "virbr0", "docker0", "veth1a2b", "tun0"] {
            assert!(super::is_virtual(v), "{}", v);
        }
        for p in ["wlan0", "wlp2s0", "enp1s0", "eth0", "usb0", "wwan0"] {
            assert!(!super::is_virtual(p), "{}", p);
        }
    }
}
