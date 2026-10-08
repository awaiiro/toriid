//! portal netns: an isolated network namespace used only for captive-portal login.
//!
//! The host kill switch stays on throughout; only this netns may reach the physical gateway unprotected.
//! What lets it out is **not** ip rule 98 but the 0xca6c mark that killswitch.nft's prerouting_mark sets
//! for PORTAL_IP (see the comments in killswitch.nft). Rule 98 is a second layer of safety.
//!
//! setns/unshare are **per-thread**: everything done inside the netns runs on a dedicated OS thread that
//! starts a current_thread runtime for rtnetlink and exits when done. Tokio workers never enter the netns.
//! /run/netns/portal is a bind-mounted ns file, so `ip netns exec portal` works as usual.
use super::Nl;
use crate::paths::*;
use anyhow::{anyhow, Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{setns, unshare, CloneFlags};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

fn ns_path() -> String {
    format!("/run/netns/{}", PORTAL_NS)
}

pub fn exists() -> bool {
    // The file exists and is a mount point (nsfs). Checking existence alone is fooled by a stale empty file.
    let p = ns_path();
    if !Path::new(&p).exists() {
        return false;
    }
    fs::read_to_string("/proc/self/mountinfo").map(|m| m.lines().any(|l| l.split(' ').nth(4) == Some(p.as_str()))).unwrap_or(false)
}

fn open_ns() -> Result<OwnedFd> {
    let f = fs::File::open(ns_path()).context("opening netns file")?;
    Ok(f.into())
}

/// Run `f` inside the ns on a new thread. The thread exiting doesn't affect the ns (the bind mount pins it).
fn in_ns<T: Send + 'static>(fd: OwnedFd, f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    std::thread::spawn(move || -> Result<T> {
        setns(&fd, CloneFlags::CLONE_NEWNET).context("setns")?;
        f()
    })
    .join()
    .map_err(|_| anyhow!("netns thread panicked"))?
}

fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(fut)
}

/// Enter the host's (PID 1) mount namespace.
/// toriid.service has ProtectSystem/PrivateTmp, so systemd gives it a private mount ns (a slave of the host's).
/// Bind mounts made in there are invisible to the host: observed, /run/netns/portal was just an empty file
/// on the host and every `ip netns exec portal` failed with EINVAL. A VM smoke test missed it because the
/// daemon was started by hand there. So netns mounts must be created/removed in the **host's** mount ns:
/// the host is the master, so mounts propagate into the daemon's ns, but not the other way round. If we
/// can't get in (sandbox / hand-started daemon), stay in the current ns; then the two are the same anyway.
///
/// Note: setns(CLONE_NEWNS) requires that the calling thread not share its fs struct with other threads
/// (setns(2): EINVAL), and all threads of a tokio process share it. An earlier version swallowed that
/// error with `let _`, so the fix never took effect. unshare(CLONE_FS) on this dedicated thread first so
/// setns can succeed, and report failures.
fn enter_host_mnt() {
    let r = unshare(CloneFlags::CLONE_FS)
        .map_err(|e| anyhow!("unshare(CLONE_FS): {}", e))
        .and_then(|_| fs::File::open("/proc/1/ns/mnt").map_err(|e| anyhow!("opening /proc/1/ns/mnt: {}", e)))
        .and_then(|f| setns(&f, CloneFlags::CLONE_NEWNS).map_err(|e| anyhow!("setns(mnt): {}", e)));
    if let Err(e) = r {
        crate::journal::err("toriid", &format!("cannot enter host mount ns ({}); /run/netns/portal may be invisible to the host and the portal browser will fail with EINVAL", e));
    }
}

/// Create the ns + bind mount: unshare on a dedicated thread, then bind-mount that thread's /proc/thread-self/ns/net onto /run/netns/portal.
fn create() -> Result<()> {
    fs::create_dir_all("/run/netns")?;
    let p = ns_path();
    fs::File::create(&p)?;
    std::thread::spawn(move || -> Result<()> {
        enter_host_mnt();
        unshare(CloneFlags::CLONE_NEWNET).context("unshare(CLONE_NEWNET)")?;
        // Must be thread-self: /proc/self refers to the thread group leader (the whole process), which is
        // still in the host ns. Mounting /proc/self/ns/net makes the "portal" ns the host ns (caught by a
        // sandbox self-test: from-portal was still on the host after being moved in).
        mount(Some("/proc/thread-self/ns/net"), p.as_str(), None::<&str>, MsFlags::MS_BIND, None::<&str>).context("bind-mount netns")?;
        // Still in the new ns: bring lo up and disable IPv6 (this path is unprotected; v6 would be one more leak surface)
        block_on(async {
            let nl = Nl::new()?;
            let lo = nl.link_index("lo").await?;
            nl.link_up(lo).await?;
            Ok::<(), anyhow::Error>(())
        })?;
        fs::write("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1").ok();
        fs::write("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1").ok();
        Ok(())
    })
    .join()
    .map_err(|_| anyhow!("netns creation thread panicked"))?
}

pub struct PortalDns {
    pub resolvers: Vec<String>,
    pub phy: Option<String>,
    pub gw: Option<String>,
}

/// Bring up the portal netns (idempotent). `dhcp_dns` / `gw` are the physical link's resolver and gateway, used as fallbacks.
pub async fn up(nl: &Nl, phy: Option<&str>, dhcp_dns: Option<String>, gw: Option<Ipv4Addr>) -> Result<PortalDns> {
    if !exists() {
        create()?;
        nl.veth_add("to-portal", "from-portal").await.context("creating veth")?;
        let host_idx = nl.link_index("to-portal").await?;
        let peer_idx = nl.link_index("from-portal").await?;
        let fd = open_ns()?;
        nl.link_set_netns_fd(peer_idx, fd.as_raw_fd()).await.context("moving from-portal into netns")?;
        nl.addr_add(host_idx, PORTAL_HOST_IP.parse::<IpAddr>()?, 31).await?;
        nl.link_up(host_idx).await?;
        // inside the ns: address + default route
        let fd2 = open_ns()?;
        in_ns(fd2, move || {
            block_on(async {
                let nl = Nl::new()?;
                let i = nl.link_index("from-portal").await?;
                nl.addr_add(i, PORTAL_IP.parse::<IpAddr>()?, 31).await?;
                nl.link_up(i).await?;
                nl.route_replace(Ipv4Addr::UNSPECIFIED, 0, Some(PORTAL_HOST_IP.parse()?), i, 254).await?;
                // The portal worker runs as nobody; let it ping the gateway with an unprivileged ICMP socket.
                // Per-netns sysctl, so this only affects the portal namespace.
                let _ = fs::write("/proc/sys/net/ipv4/ping_group_range", "0 2147483647");
                Ok::<(), anyhow::Error>(())
            })
        })?;
    }
    // forwarding: save the original value first; down() restores it
    if !Path::new(FWD_SAVED).exists() {
        if let Ok(v) = fs::read_to_string("/proc/sys/net/ipv4/conf/all/forwarding") {
            let _ = fs::write(FWD_SAVED, v.trim());
        }
    }
    fs::write("/proc/sys/net/ipv4/conf/all/forwarding", "1").context("enabling ip_forward")?;
    nl.rule_add(super::RuleSpec { prio: 98, table: 254, src: Some((PORTAL_IP.parse()?, 32)), ..Default::default() }).await?;

    // DNS for the netns. Public resolvers first (glibc only moves on after a timeout, so a bad gateway would stall it); DHCP DNS / gateway as fallback.
    let mut resolvers = vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()];
    if let Some(d) = &dhcp_dns {
        if !resolvers.contains(d) {
            resolvers.push(d.clone());
        }
    }
    if let Some(g) = gw {
        let g = g.to_string();
        if !resolvers.contains(&g) {
            resolvers.push(g);
        }
    }
    let dir = format!("/etc/netns/{}", PORTAL_NS);
    fs::create_dir_all(&dir)?;
    let mut rc = String::from("options timeout:1 attempts:2\n");
    for r in &resolvers {
        rc.push_str(&format!("nameserver {}\n", r));
    }
    fs::write(format!("{}/resolv.conf", dir), &rc)?;
    // Force NSS to query via the dns module directly, not resolved (it would query from the host network context, which is dead behind a portal)
    fs::write(format!("{}/nsswitch.conf", dir), "hosts: files dns\n")?;
    Ok(PortalDns { resolvers, phy: phy.map(String::from), gw: gw.map(|g| g.to_string()) })
}

/// Run a blocking closure inside the ns (used by the portal flow: the whole HTTP session runs on the ns thread).
pub fn in_ns_blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    let fd = open_ns()?;
    in_ns(fd, f)
}

/// For self-checks: read the default route's gateway from inside the ns.
pub fn inside_default_gw() -> Result<Option<Ipv4Addr>> {
    let fd = open_ns()?;
    in_ns(fd, || {
        block_on(async {
            let nl = Nl::new()?;
            let i = nl.link_index("from-portal").await?;
            nl.default_gw(i).await
        })
    })
}

pub async fn down(nl: &Nl) {
    let _ = nl.rule_del_prio(98, false).await;
    let _ = nl.link_del_by_name("to-portal").await; // the veth peer goes away with it
    let p = ns_path();
    if Path::new(&p).exists() {
        // Unmount in the host's mount ns too (an umount in the slave doesn't propagate back to the master)
        let p2 = p.clone();
        let _ = std::thread::spawn(move || {
            enter_host_mnt();
            let _ = umount2(p2.as_str(), MntFlags::MNT_DETACH);
            let _ = fs::remove_file(&p2);
        })
        .join();
        let _ = umount2(p.as_str(), MntFlags::MNT_DETACH); // in case entering the host ns failed, also tear down in the current ns
        let _ = fs::remove_file(&p);
    }
    let _ = fs::remove_dir_all(format!("/etc/netns/{}", PORTAL_NS));
    if let Ok(v) = fs::read_to_string(FWD_SAVED) {
        let _ = fs::write("/proc/sys/net/ipv4/conf/all/forwarding", v.trim());
        let _ = fs::remove_file(FWD_SAVED);
    }
}
