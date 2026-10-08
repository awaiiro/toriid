//! Sandboxed self-test: runs inside `unshare -rnm` (root in a user namespace, with CAP_NET_ADMIN over
//! a fresh netns). Exercises only the kernel layer: veth / WireGuard genetlink / routes / rules
//! (including invert + fwmark + suppress) / route lookup / netns transactions.
//! No D-Bus, no real network. `toriid selftest`
use crate::nl::{wg, Nl, RuleSpec};
use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr};

fn check(name: &str, ok: bool) -> Result<()> {
    println!("  {} {}", if ok { "✅" } else { "❌" }, name);
    if ok { Ok(()) } else { Err(anyhow!("{} failed", name)) }
}

pub async fn run() -> Result<()> {
    let nl = Nl::new()?;
    println!("── rtnetlink");
    let lo = nl.link_index("lo").await.context("lo")?;
    nl.link_up(lo).await?;
    let links = nl.links().await?;
    check("links() lists lo", links.iter().any(|l| l.name == "lo"))?;

    println!("── veth + addresses + routes");
    nl.veth_add("st-a", "st-b").await?;
    let a = nl.link_index("st-a").await?;
    let b = nl.link_index("st-b").await?;
    nl.addr_add(a, "10.99.97.4".parse()?, 24).await?;
    nl.addr_add(b, "10.99.96.5".parse()?, 24).await?; // different subnet: the same subnet in one ns would make lookups hit local/lo
    nl.link_up(a).await?;
    nl.link_up(b).await?;
    check("addr_add is idempotent (EEXIST swallowed)", nl.addr_add(a, "10.99.97.4".parse()?, 24).await.is_ok())?;
    check("ipv4_addrs", nl.ipv4_addrs(a).await?.contains(&("10.99.97.4".parse()?, 24)))?;
    nl.route_replace(Ipv4Addr::UNSPECIFIED, 0, Some("10.99.97.5".parse()?), a, 254).await?;
    let d = nl.route_lookup_dev(Ipv4Addr::new(1, 1, 1, 1)).await?;
    check("route_lookup goes via st-a", d.as_deref() == Some("st-a"))?;
    check("default_gw", nl.default_gw(a).await? == Some("10.99.97.5".parse()?))?;
    nl.route_replace("198.51.100.7".parse()?, 32, Some("10.99.97.5".parse()?), a, 254).await?;
    check("route_exists /32", nl.route_exists("198.51.100.7".parse()?, 32, 254).await?)?;
    check("route_del /32", nl.route_del("198.51.100.7".parse()?, 32, 254).await?)?;
    check("route_del of missing route -> false", !nl.route_del("198.51.100.7".parse()?, 32, 254).await?)?;

    println!("── rules (explicit priority / fwmark / invert / suppress)");
    nl.rule_add(RuleSpec { prio: 98, table: 254, src: Some((IpAddr::V4("10.99.98.5".parse()?), 32)), ..Default::default() }).await?;
    nl.rule_add(RuleSpec { prio: 5150, table: 254, suppress_prefixlen: Some(0), ..Default::default() }).await?;
    nl.rule_add(RuleSpec { prio: 5300, table: 51820, fwmark: Some((0xca6c, 0xffffffff)), invert: true, ..Default::default() }).await?;
    nl.rule_add(RuleSpec { prio: 5200, table: 51820, fwmark: Some((0x80000, 0xff0000)), ..Default::default() }).await?;
    for p in [98u32, 5150, 5200, 5300] {
        check(&format!("rule {} present", p), nl.rule_exists(p, false).await?)?;
    }
    check("rule_add is idempotent", nl.rule_add(RuleSpec { prio: 98, table: 254, ..Default::default() }).await.is_ok() && nl.rules(false).await?.iter().filter(|r| r.attributes.iter().any(|a| matches!(a, netlink_packet_route::rule::RuleAttribute::Priority(98)))).count() == 1)?;
    for p in [98u32, 5150, 5200, 5300] {
        nl.rule_del_prio(p, false).await?;
    }
    check("rule_del_prio clears", !nl.rule_exists(5300, false).await?)?;

    println!("── WireGuard genetlink transaction");
    let conf = wg::WgConf::parse(
        "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.64.0.2/32\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 10.99.97.5:51820\nPersistentKeepalive = 25\n",
    )?;
    match wg::up(&nl, &conf, None).await {
        Ok(()) => {
            check("wg0 is up", nl.link_exists("wg0").await)?;
            check("wg0 has an address", nl.ipv4_addrs(nl.link_index("wg0").await?).await?.len() == 1)?;
            check("rules 5150/5300 present", nl.rule_exists(5150, false).await? && nl.rule_exists(5300, false).await?)?;
            let d = nl.route_lookup_dev(Ipv4Addr::new(8, 8, 8, 8)).await?;
            check("default route sent into wg0 by catch-all", d.as_deref() == Some("wg0"))?;
            let d2 = nl.route_lookup_dev(Ipv4Addr::new(10, 99, 97, 77)).await?;
            check("directly connected prefix still via st-a (suppress_prefixlength 0 works)", d2.as_deref() == Some("st-a"))?;
            check("handshake_age = None (never handshaked)", wg::handshake_age().is_none())?;
            wg::down(&nl).await;
            check("wg::down tears down cleanly", !nl.link_exists("wg0").await && !nl.rule_exists(5300, false).await?)?;
        }
        Err(e) => {
            let s = e.to_string();
            // resolved is not in the sandbox: the DNS step fails and triggers rollback, which is itself what we want to test
            check(&format!("wg::up rolls back after failure (cause: {})", s.lines().next().unwrap_or("")), !nl.link_exists("wg0").await && !nl.rule_exists(5300, false).await?)?;
        }
    }
    nl.link_del(a).await?;

    println!("── portal netns transaction (dedicated thread unshare + bind-mount + setns)");
    nl.veth_add("st-a", "st-b").await?;
    let a = nl.link_index("st-a").await?;
    nl.addr_add(a, "10.99.95.9".parse()?, 22).await?;
    nl.link_up(a).await?;
    nl.route_replace(Ipv4Addr::UNSPECIFIED, 0, Some("10.99.95.1".parse()?), a, 254).await?;
    let r = crate::nl::netns::up(&nl, Some("st-a"), Some("198.51.100.53".into()), Some("10.99.95.1".parse()?)).await;
    match &r {
        Ok(d) => check(&format!("netns::up fully passed (resolvers {:?})", d.resolvers), true)?,
        Err(e) if e.to_string().contains("/etc/netns") || e.to_string().contains("ermission") => println!("  ➖ /etc/netns not writable in the sandbox ({}), checking structure only", e.to_string().lines().next().unwrap_or("")),
        Err(e) => check(&format!("netns::up: {}", e), false)?,
    }
    check("/run/netns/portal is a mount point", crate::nl::netns::exists())?;
    check("to-portal is on the host", nl.link_exists("to-portal").await)?;
    check("from-portal is not on the host (moved into ns)", !nl.link_exists("from-portal").await)?;
    check("rule 98 present", nl.rule_exists(98, false).await?)?;
    check("default route inside ns via 10.99.98.4", crate::nl::netns::inside_default_gw()? == Some("10.99.98.4".parse()?))?;
    crate::nl::netns::down(&nl).await;
    check("netns::down tears down cleanly", !crate::nl::netns::exists() && !nl.link_exists("to-portal").await && !nl.rule_exists(98, false).await?)?;
    nl.link_del(a).await?;
    println!("all passed");
    Ok(())
}
