//! toriid: one binary for both the daemon and the command line.
//!   torii         what you type (symlink to toriid)
//!   toriid daemon the daemon itself (started by systemd)
mod browser;
mod client;
mod config;
mod daemon;
mod dbus;
mod journal;
mod modes;
mod netclass;
mod nl;
mod notifier;
mod paths;
mod policy;
mod portal;
mod portal_browser;
mod probe;
mod rotate;
mod selftest;
mod settings;
mod state;
mod status;
mod tailscale;
mod ui;
mod util;
mod watchdog;
mod wifi;
mod wst;

use state::Mode;

pub fn on_battery() -> bool {
    std::fs::read_dir("/sys/class/power_supply")
        .map(|d| {
            d.flatten().any(|e| {
                e.file_name().to_string_lossy().starts_with("BAT")
                    && std::fs::read_to_string(e.path().join("status")).map(|s| s.trim() == "Discharging").unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

const HELP: &str = "\
usage: torii <command> [args]

  torii                          status screen (same as `torii status`)
  torii status [--json]          status; --json for machine-readable output
  torii watch                    stream status as JSON lines (for status bars)
  torii bar <json|waybar|polybar|i3blocks|plain> [--once] [--icons nerd|emoji|text] [--format FMT]
                                 status-bar output
  torii up [MODE]                bring protection up, no sudo needed
                                 (default: what last worked on this network, else auto)
  torii down                     unprotected escape hatch: no protection at all (needs sudo)
  torii portal [URL]             captive portal: enter portal mode and open an isolated browser on
                                 your desktop; protection comes back up automatically afterwards
  torii portal-auto [--dry-run]  pass the captive portal automatically (follow redirects, submit
                                 the form, re-check); stays in portal mode, then run torii up
  torii check                    run one watchdog round now
  torii check-config             validate config.toml
  torii log [-f] [-n N]          related journal entries
  torii dns                      DNS servers / routing domains per link
  torii wifi status|list|scan|connect <ssid>|disconnect
  torii wifi autoconnect <ssid> on|off
  torii wifi forget <ssid>       (iwd known network and NM profile together)
  torii browser status|clean|kill
                                 browser identity policy: on an unprotected hostile network, kill
                                 Firefox with your identity and open a clean throwaway profile
  torii wst probe|log            wstunnel side-channel probe / client log
  torii wst keys                 which keys each side accepts (fingerprints only); finishes a
                                 half-done rotation
  torii wst rotate               rotate keys: old and new coexist, no restart, no disconnect
                                 (safe to run over wstunnel)
  torii wst retire               retire the old key (only when not on wstunnel; forced even
                                 during the grace period)
  torii wst audit [DAYS]         server-side summary of recent connections by source IP;
                                 set WST_KNOWN_NETS to flag unknown sources
  torii wst migrate [--force]    one-time: migrate the server to the multi-key layout
                                 (restarts it, drops the tunnel for a few seconds)
  torii help

modes:
  auto       climb [tunnels] ladder in config.toml until a tunnel works (default:
             wireguard > openvpn > wstunnel)
  wireguard  WireGuard over UDP only
  openvpn    OpenVPN over TCP only (for networks known to block UDP)
  wstunnel   WireGuard inside TLS/WebSocket on 443 via your own carrier server
             (for networks whose DPI blocks even OpenVPN)";

fn usage() -> ! {
    eprintln!("{}", HELP);
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("status");
    let rest = &args[1.min(args.len())..];
    let automated = std::env::var("TORIID_AUTOMATED").is_ok();
    let rc = match cmd {
        "daemon" => report(daemon::run().await, "toriid"),
        "notify" => report(notifier::run().await, "notify"),
        "selftest" => report(selftest::run().await, "selftest"),
        "portal-worker" => portal::worker_main(rest),
        "--required-keys" => {
            println!("{}", config::WST_REQUIRED_KEYS.join(" "));
            0
        }
        "help" | "-h" | "--help" => {
            println!("{}", HELP);
            0
        }
        "status" | "st" if rest.iter().any(|a| a == "--json") => {
            println!("{}", serde_json::to_string_pretty(&status::snapshot()).unwrap_or_default());
            0
        }
        "watch" => bar(&[&["json".to_string()], rest].concat()),
        "bar" => bar(rest),
        "check-config" => match settings::check() {
            Ok(_) => {
                println!("{}: ok", settings::path());
                0
            }
            Err(e) => {
                eprintln!("{:#}", e);
                1
            }
        },
        "status" | "st" => status().await,
        // ── commands that used to be separate scripts (old names still work) ──
        "up" => match rest.first().map(String::as_str) {
            None => {
                let ssid = crate::wifi::ssid().await;
                let m = state::preferred_mode(ssid.as_deref(), &config::WdConf::load());
                mode(m, automated).await
            }
            Some(s) => match Mode::parse(s) {
                Some(m) if m.is_tunnel() => mode(m, automated).await,
                _ => usage(),
            },
        },
        "down" => mode(Mode::Off, automated).await,
        "portal" => portal_cmd(rest, automated).await,
        "check" => via_daemon("kick").await,
        "portal-auto" => {
            let dry = rest.iter().any(|a| a == "--dry-run");
            match client::send(daemon::Request { cmd: "portal-auto".into(), args: if dry { vec!["--dry-run".into()] } else { vec![] }, automated: false }).await {
                Ok(rc) => rc,
                Err(e) => {
                    ui::render(&format!("{}fail daemon not running ({}): systemctl status toriid", ui::P_STYLE, e), ui::is_tty());
                    1
                }
            }
        }
        "log" => log(rest),
        "dns" => dns().await,
        "browser" => match rest.first().map(String::as_str) {
            Some("status") | None => { print!("{}", browser::status_text()); 0 }
            Some("clean") => {
                let p = browser::policy();
                let ssid = crate::wifi::ssid().await.unwrap_or_else(|| "manual".into());
                match browser::on_hostile(&p, &ssid).await {
                    Ok(m) => { ui::render(&format!("{}ok {}", ui::P_STYLE, m), ui::is_tty()); 0 }
                    Err(e) => { ui::render(&format!("{}fail {:#}", ui::P_STYLE, e), ui::is_tty()); 1 }
                }
            }
            Some("kill") => {
                let killed = browser::kill_identity(&[]).await;
                println!("{}", if killed.is_empty() { "no Firefox with an identity is running".into() } else { format!("closed {}", killed.join(" ")) });
                0
            }
            _ => usage(),
        },
        "portal-probe" => {
            for l in tokio::task::spawn_blocking(portal::host_selfcheck).await.unwrap_or_default() {
                println!("{}", l);
            }
            0
        }
        "wifi" => wifi(rest).await,
        "wst" => match rest.first().map(String::as_str) {
            Some("probe") => via_daemon("wst-probe").await,
            Some("log") => via_daemon("wst-log").await,
            Some("rotate") => report_text(rotate::rotate("manual").await),
            Some("retire") => report_text(rotate::retire(true).await),
            Some("keys") => report_text(rotate::keys_status().await),
            Some("migrate") => report_text(rotate::migrate(rest.iter().any(|a| a == "--force")).await),
            Some("audit") => {
                let days = rest.get(1).and_then(|d| d.parse().ok()).unwrap_or(7);
                match tokio::task::spawn_blocking(move || rotate::audit(days)).await.unwrap_or_else(|e| Err(anyhow::anyhow!(e))) {
                    Ok((t, foreign)) => {
                        print!("{}", t);
                        if !foreign.is_empty() {
                            let ips: Vec<&str> = foreign.iter().map(|(ip, _)| ip.as_str()).collect();
                            ui::render(&format!("{}warn unknown sources {:?} - if they are your own networks, add them to WST_KNOWN_NETS; otherwise run torii wst rotate", ui::P_STYLE, ips), ui::is_tty());
                        }
                        0
                    }
                    Err(e) => { ui::render(&format!("{}fail {:#}", ui::P_STYLE, e), ui::is_tty()); 1 }
                }
            }
            Some("scheduled") => match rotate::scheduled().await {
                Ok(s) => { print!("{}", s); 0 }
                Err(e) => { eprintln!("{:#}", e); 1 }
            },
            _ => usage(),
        },
        // ── short forms: <mode> / off / kick / wst-probe / wst-log ──
        "off" => mode(Mode::Off, automated).await,
        "kick" => via_daemon("kick").await,
        "wst-probe" => via_daemon("wst-probe").await,
        "wst-log" => via_daemon("wst-log").await,
        "failed-closed" => {
            eprintln!("failed-closed is a state, not a mode: all three paths failed. Retry with torii up, or go unprotected with torii down");
            2
        }
        m => match Mode::parse(m) {
            Some(mode_) => mode(mode_, automated).await,
            None => usage(),
        },
    };
    std::process::exit(rc);
}

fn report(r: anyhow::Result<()>, what: &str) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{}: {}", what, e);
            1
        }
    }
}

async fn mode(m: Mode, automated: bool) -> i32 {
    // NETD_MANAGED=1: when portal-auto is launched by the daemon, entering/leaving portal mode is the daemon's job; do nothing here
    if std::env::var("NETD_MANAGED").is_ok() {
        return 0;
    }
    if client::daemon_alive().await {
        return client::send(daemon::Request { cmd: "mode".into(), args: vec![m.as_str().into()], automated }).await.unwrap_or(1);
    }
    match client::direct_mode(m, automated).await {
        Ok(rc) => rc,
        Err(e) => {
            ui::render(&format!("{}fail {}", ui::P_STYLE, e), ui::is_tty());
            1
        }
    }
}

async fn via_daemon(cmd: &str) -> i32 {
    match client::send(daemon::Request { cmd: cmd.into(), args: vec![], automated: false }).await {
        Ok(rc) => rc,
        Err(e) => {
            ui::render(&format!("{}fail daemon not running ({}): systemctl status toriid", ui::P_STYLE, e), ui::is_tty());
            1
        }
    }
}

async fn status() -> i32 {
    if client::daemon_alive().await {
        return client::send(daemon::Request { cmd: "status".into(), args: vec![], automated: false }).await.unwrap_or(1);
    }
    match nl::Nl::new() {
        Ok(nl) => {
            print!("{}", modes::status_text(&nl).await);
            0
        }
        Err(e) => {
            eprintln!("{}", e);
            1
        }
    }
}

/// The journal is the right viewer; this just saves remembering the tags.
fn log(rest: &[String]) -> i32 {
    let mut c = std::process::Command::new("journalctl");
    c.args(["-t", "toriid", "-t", "toriid-watchdog", "-t", "toriid-netclass", "-t", "toriid-wst", "-t", "toriid-portal", "-o", "short-iso", "--no-pager"]);
    let mut n = "60".to_string();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "-f" => {
                c.arg("-f");
            }
            "-n" => {
                i += 1;
                n = rest.get(i).cloned().unwrap_or(n);
            }
            other => {
                c.arg(other);
            }
        }
        i += 1;
    }
    c.args(["-n", &n]);
    match c.status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("journalctl: {}", e);
            1
        }
    }
}

async fn dns() -> i32 {
    let Ok(nl) = nl::Nl::new() else { return 1 };
    let color = ui::is_tty();
    let suffix = tailscale::magicdns_suffix().await;
    ui::render(&format!("{}h MagicDNS suffix: {}", ui::P_STYLE, suffix.as_deref().unwrap_or("(unavailable - tailscaled local API did not answer)")), color);
    for l in nl.links().await.unwrap_or_default() {
        if l.name == "lo" {
            continue;
        }
        let doms = dbus::resolved::link_domains(l.index as i32).await;
        let d: Vec<String> = doms.iter().map(|(d, r)| if *r { format!("~{}", d) } else { d.clone() }).collect();
        println!("{:<12} {}", l.name, if d.is_empty() { "(no routing domains)".to_string() } else { d.join(" ") });
    }
    ui::render(&format!("{}hint `~.` is the global routing domain: all queries go to whichever link carries it. In tunnel modes it should only be on the tunnel interface.", ui::P_STYLE), color);
    0
}

async fn wifi(args: &[String]) -> i32 {
    let sub = args.first().map(String::as_str).unwrap_or("status");
    let r: anyhow::Result<()> = async {
        match sub {
            "status" => match crate::wifi::state().await {
                Some(w) => println!("{} {} {} {}", w.dev, w.mac, w.state, w.ssid.unwrap_or_default()),
                None => println!("iwd not running or no WiFi device"),
            },
            "list" | "scan" => {
                for (name, ty, sig, conn) in crate::wifi::scan_list(sub == "scan").await? {
                    println!("{} {:<32} {:<6} {:>4} dBm", if conn { "*" } else { " " }, name, ty, sig);
                }
            }
            "connect" => {
                let ssid = args.get(1).ok_or_else(|| anyhow::anyhow!("SSID required"))?;
                crate::wifi::connect(ssid).await?;
                println!("connection to {} requested", ssid);
            }
            "disconnect" => crate::wifi::disconnect().await?,
            "autoconnect" => {
                let ssid = args.get(1).ok_or_else(|| anyhow::anyhow!("SSID required"))?;
                let on = match args.get(2).map(String::as_str) { Some("on") => true, Some("off") => false, _ => anyhow::bail!("expected on|off") };
                println!("{}", crate::wifi::autoconnect(ssid, on).await?);
            }
            "forget" => {
                let ssid = args.get(1).ok_or_else(|| anyhow::anyhow!("SSID required"))?;
                println!("{}", crate::wifi::forget(ssid).await?);
            }
            _ => usage(),
        }
        Ok(())
    }
    .await;
    report(r, "wifi")
}

fn report_text(r: anyhow::Result<String>) -> i32 {
    match r {
        Ok(s) => { ui::render(&format!("{}ok {}", ui::P_STYLE, s.replace('\n', "\n   ")), ui::is_tty()); 0 }
        Err(e) => { ui::render(&format!("{}fail {:#}", ui::P_STYLE, e), ui::is_tty()); 1 }
    }
}

/// `torii portal [URL]`: enter portal mode if not already in it (no sudo needed), then have the daemon open
/// the portal browser on your desktop.
async fn portal_cmd(rest: &[String], automated: bool) -> i32 {
    if !matches!(state::Intent::read(), state::Intent::Mode(Mode::Portal)) {
        let rc = mode(Mode::Portal, automated).await;
        if rc != 0 {
            return rc;
        }
    }
    let mut args = vec![];
    if let Ok(w) = std::env::var("WAYLAND_DISPLAY") {
        args.push(format!("wl={}", w));
    }
    if let Ok(u) = std::env::var("SUDO_UID") {
        args.push(format!("uid={}", u)); // sudo torii portal: open the browser on the invoking user's desktop, not root's
    }
    if let Some(u) = rest.iter().find(|a| a.starts_with("http://") || a.starts_with("https://")) {
        args.push(format!("url={}", u));
    }
    match client::send(daemon::Request { cmd: "portal-open".into(), args, automated }).await {
        Ok(rc) => rc,
        Err(e) => {
            ui::render(&format!("{}fail daemon not running ({}): systemctl status toriid", ui::P_STYLE, e), ui::is_tty());
            1
        }
    }
}

/// `torii bar <kind> [--once] [--icons nerd|emoji|text] [--format FMT]`
fn bar(args: &[String]) -> i32 {
    let Some(kind) = args.first().and_then(|k| status::Bar::parse(k)) else {
        eprintln!("usage: torii bar json|waybar|polybar|i3blocks|plain [--once] [--icons nerd|emoji|text] [--format '{{icon}} {{label}}']");
        return 2;
    };
    let mut o = status::RenderOpts { icons: status::Icons::Nerd, format: "{icon} {label}".into() };
    let mut once = false;
    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--once" => once = true,
            "--icons" => match it.next().and_then(|v| status::Icons::parse(v)) {
                Some(i) => o.icons = i,
                None => return 2,
            },
            "--format" => match it.next() {
                Some(f) => o.format = f.clone(),
                None => return 2,
            },
            _ => return 2,
        }
    }
    if once {
        println!("{}", status::render(kind, &status::snapshot(), &o));
        return 0;
    }
    match status::watch_print(kind, &o) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("watch: {:#}", e);
            1
        }
    }
}
