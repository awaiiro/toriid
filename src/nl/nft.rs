//! Direct libnftables binding. The ruleset stays declarative (killswitch.nft); this only does atomic
//! loading and JSON queries. The unsafe surface is these 8 symbols; switching back to an `nft -j`
//! subprocess would only touch this file.
use crate::paths;
use anyhow::{anyhow, Result};
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};

const NFT_CTX_OUTPUT_JSON: c_uint = 1 << 4;

#[link(name = "nftables")]
extern "C" {
    fn nft_ctx_new(flags: u32) -> *mut c_void;
    fn nft_ctx_free(ctx: *mut c_void);
    fn nft_ctx_set_dry_run(ctx: *mut c_void, dry: bool);
    fn nft_ctx_output_set_flags(ctx: *mut c_void, flags: c_uint);
    fn nft_ctx_buffer_output(ctx: *mut c_void) -> c_int;
    fn nft_ctx_buffer_error(ctx: *mut c_void) -> c_int;
    fn nft_ctx_get_output_buffer(ctx: *mut c_void) -> *const c_char;
    fn nft_ctx_get_error_buffer(ctx: *mut c_void) -> *const c_char;
    fn nft_run_cmd_from_buffer(ctx: *mut c_void, buf: *const c_char) -> c_int;
}

struct Ctx(*mut c_void);
impl Ctx {
    fn new(json: bool, dry: bool) -> Result<Ctx> {
        let p = unsafe { nft_ctx_new(0) };
        if p.is_null() {
            return Err(anyhow!("nft_ctx_new failed"));
        }
        unsafe {
            nft_ctx_buffer_output(p);
            nft_ctx_buffer_error(p);
            if json {
                nft_ctx_output_set_flags(p, NFT_CTX_OUTPUT_JSON);
            }
            nft_ctx_set_dry_run(p, dry);
        }
        Ok(Ctx(p))
    }
    fn run(&self, cmd: &str) -> Result<String> {
        let c = CString::new(cmd)?;
        let rc = unsafe { nft_run_cmd_from_buffer(self.0, c.as_ptr()) };
        self.result(rc, cmd)
    }
    fn result(&self, rc: c_int, what: &str) -> Result<String> {
        let out = unsafe { CStr::from_ptr(nft_ctx_get_output_buffer(self.0)) }.to_string_lossy().into_owned();
        if rc != 0 {
            let e = unsafe { CStr::from_ptr(nft_ctx_get_error_buffer(self.0)) }.to_string_lossy().into_owned();
            return Err(anyhow!("nft `{}` failed: {}", what, e.trim()));
        }
        Ok(out)
    }
}
impl Drop for Ctx {
    fn drop(&mut self) {
        unsafe { nft_ctx_free(self.0) }
    }
}

const TEMPLATE: &str = include_str!("killswitch.nft");
pub const BOOT_RULESET: &str = "/var/lib/toriid/killswitch.nft";

/// One pinned hole for a tunnel carrier.
#[derive(Clone, Debug, PartialEq)]
pub struct Carrier {
    pub addr: std::net::IpAddr,
    pub port: u16,
    pub tcp: bool,
    pub comment: &'static str,
}

/// Everything the ruleset depends on, gathered from config. Kept separate from rendering so it is testable.
#[derive(Clone, Debug, Default)]
pub struct Inputs {
    pub tunnel_ifs: Vec<String>,
    pub extra_ifs: Vec<String>,
    pub vm_bridges: Vec<String>,
    pub carriers: Vec<Carrier>,
    pub tailscale: bool,
}

fn quoted(v: &[String]) -> String {
    v.iter().map(|i| format!("\"{}\"", i)).collect::<Vec<_>>().join(", ")
}

pub fn render(i: &Inputs) -> String {
    let mut extra = String::new();
    let mut ifs = i.extra_ifs.clone();
    if i.tailscale {
        // tailscale0 is not a leak: tailscaled re-encapsulates the inner traffic as fwmarked UDP,
        // which the daemon routes into the tunnel table. Without this the tailnet and MagicDNS die.
        ifs.push("tailscale0".into());
    }
    for f in &ifs {
        extra.push_str(&format!("        oifname \"{}\" accept\n", f));
    }
    let mut carriers = String::new();
    for c in &i.carriers {
        let fam = if c.addr.is_ipv4() { "ip" } else { "ip6" };
        let proto = if c.tcp { "tcp" } else { "udp" };
        carriers.push_str(&format!("        {} daddr {} {} dport {} accept comment \"{}\"\n", fam, c.addr, proto, c.port, c.comment));
    }
    let (mut vm_out, mut vm_fwd, mut vm_in) = (String::new(), String::new(), String::new());
    if !i.vm_bridges.is_empty() {
        let br = quoted(&i.vm_bridges);
        let tun = quoted(&i.tunnel_ifs);
        vm_out = format!("        oifname {{ {} }} accept comment \"vm-bridge\"\n", br);
        // VMs must use the tunnel too. Pin the egress interface: a rule that only says
        // "from the bridge" lets guests leave through the physical NIC with the real IP.
        // Consequence (intended): no tunnel, no network for VMs either.
        vm_fwd = format!(
            "        iifname {{ {br} }} oifname {{ {tun} }} accept comment \"vm-out-tunnel\"\n        iifname {{ {tun} }} oifname {{ {br} }} ct state established,related accept comment \"vm-in-tunnel\"\n        iifname {{ {br} }} oifname {{ {br} }} accept comment \"vm-to-vm\"\n"
        );
        vm_in = format!("        iifname {{ {} }} accept\n", br);
    }
    let ts_in = if i.tailscale { "        iifname \"tailscale0\" accept\n".to_string() } else { String::new() };
    TEMPLATE
        .replace("@@NO_PORTAL_IFS@@", &quoted(&[i.tunnel_ifs.clone(), i.vm_bridges.clone(), vec!["tailscale0".to_string(), "lo".to_string()]].concat()))
        .replace("@@TUNNEL_IFS@@", &quoted(&i.tunnel_ifs))
        .replace("@@EXTRA_IFS@@\n", &extra)
        .replace("@@CARRIERS@@\n", &carriers)
        .replace("@@VM_OUT@@\n", &vm_out)
        .replace("@@VM_FORWARD@@\n", &vm_fwd)
        .replace("@@VM_IN@@\n", &vm_in)
        .replace("@@TAILSCALE_IN@@\n", &ts_in)
        .replace("@@PORTAL_IP@@", paths::PORTAL_IP)
        .replace("@@PORTAL_HOST_IP@@", paths::PORTAL_HOST_IP)
        .replace("@@WG_MARK@@", &format!("{:#x}", super::wg::WG_MARK))
        .replace("@@WG_IF@@", paths::WG_IF)
}

/// `remote <host> [port] [proto]` lines of an OpenVPN config. Hostnames are resolved now, while
/// there is still a way to resolve them; the ruleset can only pin addresses.
fn ovpn_remotes(text: &str) -> Vec<(String, u16)> {
    let default_port = text.lines().find_map(|l| l.trim().strip_prefix("port ").and_then(|p| p.trim().parse().ok())).unwrap_or(1194);
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some("remote")).then(|| ())?;
            let host = it.next()?.to_string();
            let port = it.next().and_then(|p| p.parse().ok()).unwrap_or(default_port);
            Some((host, port))
        })
        .collect()
}

fn resolve(host: &str, port: u16) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    if let Ok(ip) = host.parse() {
        return vec![ip];
    }
    (host, port).to_socket_addrs().map(|a| a.map(|s| s.ip()).collect()).unwrap_or_default()
}

/// Collect the ruleset inputs from config.toml and the tunnel configs it points at.
pub fn inputs() -> Result<Inputs> {
    let s = crate::settings::get();
    let mut i = Inputs {
        tunnel_ifs: vec![paths::WG_IF.into(), s.openvpn.interface.clone()],
        extra_ifs: s.killswitch.allow_interfaces.clone(),
        vm_bridges: s.killswitch.vm_bridges.clone(),
        tailscale: s.tailscale.integrate,
        carriers: vec![],
    };
    if let Ok(wg) = super::wg::WgConf::load() {
        let (host, port) = wg.endpoint.rsplit_once(':').map(|(h, p)| (h.trim_matches(|c| c == '[' || c == ']').to_string(), p.parse().unwrap_or(51820))).unwrap_or((wg.endpoint.clone(), 51820));
        let ips = resolve(&host, port);
        if ips.is_empty() {
            return Err(anyhow!("cannot resolve the WireGuard endpoint {}; use an IP address in {}", wg.endpoint, paths::wg_conf()));
        }
        for addr in ips {
            i.carriers.push(Carrier { addr, port, tcp: false, comment: "wireguard" });
        }
    }
    if let Some(t) = crate::config::read_trusted(&paths::ovpn_conf()) {
        for (host, port) in ovpn_remotes(&t) {
            for addr in resolve(&host, port) {
                i.carriers.push(Carrier { addr, port, tcp: true, comment: "openvpn" });
            }
        }
    }
    if let Ok(w) = crate::config::WstConf::load() {
        let port = w.port.parse().unwrap_or(443);
        for srv in crate::config::WstConf::peek_servers_all() {
            for addr in resolve(&srv, port) {
                i.carriers.push(Carrier { addr, port, tcp: true, comment: "wstunnel" });
            }
        }
    }
    i.carriers.dedup();
    Ok(i)
}

/// Dry-run first, then load for real. A broken ruleset loaded here means instant loss of
/// connectivity that is hard to diagnose.
pub fn load_killswitch() -> Result<()> {
    let rules = render(&inputs()?);
    Ctx::new(false, true)?.run(&rules).map_err(|e| anyhow!("ruleset failed the syntax check, refusing to load (network untouched): {}", e))?;
    Ctx::new(false, false)?.run(&rules).map_err(|e| anyhow!("loading the ruleset failed: {}", e))?;
    // Only a ruleset that actually loaded is kept for toriid-killswitch-boot.service: at boot there is
    // no DNS to resolve endpoints with, so the boot unit replays the last good copy.
    let _ = crate::util::write_atomic(BOOT_RULESET, &rules, 0o600);
    Ok(())
}

pub fn flush_killswitch() {
    if let Ok(c) = Ctx::new(false, false) {
        let _ = c.run("delete table inet ks");
        let _ = c.run("delete table ip ksnat");
    }
}

pub fn ks_loaded() -> bool {
    Ctx::new(true, false).and_then(|c| c.run("list table inet ks")).is_ok()
}

fn list_json(cmd: &str) -> Option<serde_json::Value> {
    let out = Ctx::new(true, false).ok()?.run(cmd).ok()?;
    serde_json::from_str(&out).ok()
}

fn items(v: &serde_json::Value) -> impl Iterator<Item = &serde_json::Value> {
    v.get("nftables").and_then(|x| x.as_array()).map(|a| a.iter()).into_iter().flatten()
}

/// Tables other than ks with a policy-drop forward hook (this is how Docker's ip filter strangles the portal netns).
pub fn foreign_forward_drop_tables() -> Vec<String> {
    let Some(v) = list_json("list ruleset") else { return vec![] };
    let mut out = vec![];
    for it in items(&v) {
        let Some(c) = it.get("chain") else { continue };
        let s = |k: &str| c.get(k).and_then(|x| x.as_str()).unwrap_or("");
        if s("hook") == "forward" && s("policy") == "drop" && !(s("family") == "inet" && s("table") == "ks") {
            let n = format!("{} {}", s("family"), s("table"));
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

/// Current elements of the lan_allow set (human-readable). None = unreadable (table not loaded).
pub fn lan_allow_elements() -> Option<Vec<String>> {
    let v = list_json("list set inet ks lan_allow")?;
    let mut out = vec![];
    for it in items(&v) {
        let Some(s) = it.get("set") else { continue };
        for e in s.get("elem").and_then(|e| e.as_array()).map(|a| a.iter()).into_iter().flatten() {
            if let Some(p) = e.get("prefix") {
                out.push(format!(
                    "{}/{}",
                    p.get("addr").and_then(|x| x.as_str()).unwrap_or("?"),
                    p.get("len").and_then(|x| x.as_u64()).unwrap_or(0)
                ));
            } else if let Some(a) = e.as_str() {
                out.push(a.to_string());
            }
        }
    }
    Some(out)
}

/// LAN allowance: flush both sets, then on a home network fill in the current subnet + multicast.
pub fn lan_clear() {
    if let Ok(c) = Ctx::new(false, false) {
        let _ = c.run("flush set inet ks lan_allow");
        let _ = c.run("flush set inet ks lan_allow6");
    }
}
pub fn lan_allow(net: &str) -> Result<()> {
    let c = Ctx::new(false, false)?;
    c.run(&format!("add element inet ks lan_allow {{ {} }}", net))?;
    // 224.0.0.0/24 mDNS; 239.0.0.0/8 SSDP; limited broadcast. Home only: allowing this on a public
    // network is announcing yourself to everyone on it.
    c.run("add element inet ks lan_allow { 224.0.0.0/24, 239.0.0.0/8, 255.255.255.255 }")?;
    c.run("add element inet ks lan_allow6 { ff02::/16 }")?;
    Ok(())
}

#[cfg(test)]
mod render_tests {
    use super::*;
    #[test]
    fn renders_all_holes() {
        let i = Inputs {
            tunnel_ifs: vec!["wg0".into(), "torii-tcp".into()],
            extra_ifs: vec![],
            vm_bridges: vec!["virbr0".into()],
            carriers: vec![
                Carrier { addr: "198.51.100.7".parse().unwrap(), port: 51820, tcp: false, comment: "wireguard" },
                Carrier { addr: "2001:db8::1".parse().unwrap(), port: 443, tcp: true, comment: "wstunnel" },
            ],
            tailscale: true,
        };
        let r = render(&i);
        assert!(!r.contains("@@"), "{}", r);
        assert!(r.contains("ip daddr 198.51.100.7 udp dport 51820 accept"));
        assert!(r.contains("ip6 daddr 2001:db8::1 tcp dport 443 accept"));
        assert!(r.contains("oifname { \"wg0\", \"torii-tcp\" } accept"));
        assert!(r.contains("iifname { \"virbr0\" } oifname { \"wg0\", \"torii-tcp\" }"));
        assert!(r.contains("oifname \"tailscale0\" accept"));
        assert!(r.contains("meta mark set 0xca6c"));
    }
    /// `TORIID_DUMP_RULESET=path cargo test dump_full_ruleset` writes a fully populated ruleset for `nft -c`.
    #[test]
    fn dump_full_ruleset() {
        if let Ok(p) = std::env::var("TORIID_DUMP_RULESET") {
            let i = Inputs {
                tunnel_ifs: vec!["wg0".into(), "torii-tcp".into()],
                extra_ifs: vec!["extra0".into()],
                vm_bridges: vec!["virbr0".into()],
                carriers: vec![
                    Carrier { addr: "198.51.100.7".parse().unwrap(), port: 51820, tcp: false, comment: "wireguard" },
                    Carrier { addr: "2001:db8::1".parse().unwrap(), port: 443, tcp: true, comment: "wstunnel" },
                ],
                tailscale: true,
            };
            std::fs::write(p, render(&i)).unwrap();
        }
    }
    #[test]
    fn minimal_has_no_optional_holes() {
        let r = render(&Inputs { tunnel_ifs: vec!["wg0".into()], ..Default::default() });
        assert!(!r.contains("@@"));
        assert!(!r.contains("oifname \"tailscale0\" accept"));
        assert!(!r.contains("iifname \"tailscale0\" accept"));
        assert!(!r.contains("vm-"));
    }
    #[test]
    fn ovpn_remote_lines() {
        let r = ovpn_remotes("client\nport 443\nremote 203.0.113.5\nremote vpn.example 8443 tcp\n");
        assert_eq!(r, vec![("203.0.113.5".to_string(), 443), ("vpn.example".to_string(), 8443)]);
    }
}
