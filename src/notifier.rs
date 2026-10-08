//! User-side notifier. Only reads /run/net-health.json; never touches the network and makes no decisions.
//! All decisions live in the daemon (it has the live state). This just pops up the advice and
//! shouts if the watchdog dies.
use crate::dbus::notify;
use crate::journal;
use crate::state;
use crate::util;
use std::time::Duration;

const POLL: u64 = 2;
const RENOTIFY: u64 = 300; // while still offline, remind again this often
/// Same threshold as the status bar interface, so the notifier and the bar never disagree about a dead daemon.
const WD_MAX_AGE: u64 = crate::status::STALE_AFTER;
const DEBOUNCE: u64 = 6; // the same advice must persist this long before we speak; filters roaming transients
const OK_CARD_SECS: u64 = 6; // how long the "Protected" card stays

/// Action key of the "Open login page" button (used only by our portal notifications)
const ACT_PORTAL: &str = "toriid-portal";

/// Portal-type advice (needs a click / portal detected / unprotected and probably a portal): the card
/// gets a button that runs `torii portal`
fn wants_portal_button(key: &str) -> bool {
    key.ends_with(":handoff") || key.ends_with(":nmportal") || key.ends_with(":bare") || key == "gaveup"
}

pub async fn run() -> anyhow::Result<()> {
    let conn = wait_bus().await?;
    // Button clicked: run `torii portal` as this user (the daemon identifies callers via SO_PEERCRED; no sudo behind a portal)
    if let Ok(acts) = notify::actions(&conn).await {
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut acts = Box::pin(acts);
            while let Some((_id, key)) = acts.next().await {
                if key == ACT_PORTAL {
                    journal::notice("toriid-portal", "\"Open login page\" clicked on notification -> torii portal");
                    let _ = tokio::process::Command::new(std::env::current_exe().unwrap_or_else(|_| "torii".into())).arg("portal").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
                }
            }
        });
    }
    let mut last_key: Option<String> = None;
    let mut last_notify = 0u64;
    let mut key_since: Option<(String, u64)> = None;
    let mut dead_notified = 0u64;
    // Network notices use a single card: updates replace it in place and it is withdrawn once resolved
    // (otherwise twenty-odd cards pile up in an afternoon)
    let mut slot: u32 = 0;
    // The "Protected" card shown after resolution is withdrawn after a few seconds (some notification
    // daemons ignore expire_timeout, so it would otherwise stay in the notification center forever)
    let mut ok_card: Option<(u32, u64)> = None;
    // Browser identity policy: run once per (class, SSID), also across restarts (installing a new
    // version restarts the notifier; it must not kill the browser on every install). The last key
    // is persisted in ~/.local/state/toriid/browser-net.
    let net_state = util::user_state_dir().join("browser-net");
    let mut last_net: Option<(String, String)> = std::fs::read_to_string(&net_state).ok().and_then(|t| t.trim().split_once('\t').map(|(a, b)| (a.to_string(), b.to_string())));
    loop {
        let now = util::now();
        match state::read_health() {
            None => {
                if now.saturating_sub(dead_notified) >= RENOTIFY && uptime() > 90 {
                    if notify::send(&conn, "Watchdog heartbeat missing: if the tunnel drops, nothing will recover it. Check: systemctl status toriid", true).await.is_ok() {
                        dead_notified = now;
                    }
                }
            }
            Some(h) => {
                // ── browser policy: arrived on a hostile network ──
                if !h.ssid.is_empty() && !h.class.is_empty() {
                    let key = (crate::browser::exposure_class(&h.class, &h.mode, &h.phase), h.ssid.clone());
                    if last_net.as_ref() != Some(&key) {
                        let was_hostile = matches!(&last_net, Some((c, _)) if c.starts_with("hostile"));
                        last_net = Some(key.clone());
                        let _ = std::fs::create_dir_all(std::path::Path::new(&net_state).parent().unwrap());
                        let _ = std::fs::write(&net_state, format!("{}\t{}", key.0, key.1));
                        let p = crate::browser::policy();
                        if p.enabled && key.0 == crate::browser::HOSTILE_BARE {
                            match crate::browser::on_hostile(&p, &h.ssid).await {
                                Ok(m) => {
                                    journal::notice("toriid-portal", &format!("browser policy: {}", m));
                                    let _ = notify::show(&conn, 0, &format!("{} - Unprotected, switched to clean Firefox", h.ssid), m.split_once(": ").map(|(_, r)| r.trim()).unwrap_or(&m), false).await;
                                }
                                Err(e) => {
                                    let _ = notify::send(&conn, &format!("Browser policy failed: {:#}", e), true).await;
                                }
                            }
                        } else if p.enabled && h.class == "home" && was_hostile {
                            let _ = notify::send(&conn, "Back on the home network. The clean Firefox is still open (left as is); your main profile is safe to open now", false).await;
                        }
                    }
                }
                let age = now.saturating_sub(h.ts);
                if age > WD_MAX_AGE {
                    if now.saturating_sub(dead_notified) >= RENOTIFY {
                        if notify::send(&conn, &format!("Watchdog silent for {}s: if the tunnel drops, nothing will recover it. Check: journalctl -u toriid", age), true).await.is_ok() {
                            dead_notified = now;
                        }
                    }
                } else {
                    dead_notified = 0;
                }
                match &h.advice {
                    Some(a) => {
                        // Debounce: speak only after the same key has persisted for DEBOUNCE seconds
                        let since = match &key_since {
                            Some((k, t)) if *k == a.key => *t,
                            _ => {
                                key_since = Some((a.key.clone(), now));
                                now
                            }
                        };
                        if now.saturating_sub(since) >= DEBOUNCE && (last_key.as_deref() != Some(&a.key) || now.saturating_sub(last_notify) >= RENOTIFY) {
                            // Record the dedup timestamp only on delivery. An undelivered warning was never sent.
                            let title = if a.title.is_empty() { "Network" } else { a.title.as_str() };
                            let buttons: &[(&str, &str)] = if wants_portal_button(&a.key) { &[(ACT_PORTAL, "Open login page")] } else { &[] };
                            if let Ok(id) = notify::show_with(&conn, slot, title, &a.text, a.critical, buttons).await {
                                slot = id;
                                journal::notice("toriid-portal", &format!("{} - {}", title, a.text.replace('\n', " / ")));
                                last_key = Some(a.key.clone());
                                last_notify = now;
                            }
                        }
                    }
                    None => {
                        key_since = None;
                        // We spoke and now all is well: replace the card with an "OK" that is withdrawn after a few seconds.
                        // If it is not actually OK (e.g. the user switched off manually), just withdraw it.
                        if last_key.take().is_some() && slot != 0 {
                            if h.phase == "up" {
                                let title = if h.ssid.is_empty() { "Protected".to_string() } else { format!("{} - Protected", h.ssid) };
                                if let Ok(id) = notify::show(&conn, slot, &title, &format!("Tunnel {} is up", h.mode), false).await {
                                    ok_card = Some((id, now));
                                    journal::notice("toriid-portal", &title);
                                }
                            } else {
                                notify::close(&conn, slot).await;
                            }
                            slot = 0;
                        }
                    }
                }
            }
        }
        if let Some((id, t)) = ok_card {
            if now.saturating_sub(t) >= OK_CARD_SECS {
                notify::close(&conn, id).await;
                ok_card = None;
            }
        }
        tokio::time::sleep(Duration::from_secs(POLL)).await;
    }
}

fn uptime() -> u64 {
    std::fs::read_to_string("/proc/uptime").ok().and_then(|s| s.split('.').next()?.parse().ok()).unwrap_or(999)
}

/// At boot the notification bus is not up yet. Wait for it rather than shouting the first messages into the void.
async fn wait_bus() -> anyhow::Result<zbus::Connection> {
    for i in 1..=60 {
        if let Ok(c) = zbus::Connection::session().await {
            if let Ok(d) = zbus::fdo::DBusProxy::new(&c).await {
                if d.name_has_owner("org.freedesktop.Notifications".try_into().unwrap()).await.unwrap_or(false) {
                    journal::notice("toriid-portal", &format!("notification bus ready (after {} tries)", i));
                    return Ok(c);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    journal::notice("toriid-portal", "notification bus never appeared: messages will only go to the journal, no popups");
    Ok(zbus::Connection::session().await?)
}
