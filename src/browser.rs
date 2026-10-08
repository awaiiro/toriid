//! Browser identity policy (user side): when the machine is **unprotected** on a hostile network
//! (mode off, or the kill switch is not loaded), an identity-bearing Firefox (logged-in sessions,
//! history, cookies) should not stay open. Kill it and open a clean, throwaway profile instead.
//! This layer (identity isolation) is orthogonal to the tunnel layers: the tunnel hides you from
//! observers on the path; this keeps your own logged-in state from being active on an untrusted network.
//!
//! Config in ~/.config/toriid/browser.conf:
//!   BROWSER_POLICY=yes             on/off switch
//!   HOSTILE_KILL="<profile> ..."   profile names to kill on a hostile network; empty = every non-clean Firefox
//!   HOSTILE_OPEN=clean             clean | none
//!   CLEAN_TEMPLATE=<dir>           optional: copied into the clean profile on every launch (extensions/prefs)
use crate::config::parse_kv;
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn home() -> PathBuf {
    crate::util::home()
}
fn conf_path() -> PathBuf {
    home().join(".config/toriid/browser.conf")
}
pub fn clean_dir() -> PathBuf {
    home().join(".cache/toriid/firefox-clean")
}

/// The state where the real IP is exposed on a hostile network: the only time identity-bearing
/// Firefox gets closed. While the tunnel is up (kill switch loaded) it is left alone; killing it on
/// every switch to a hostile network was too noisy. In portal mode the host is also locked by the
/// kill switch, so the identity Firefox cannot get out and does not need killing either.
pub const HOSTILE_BARE: &str = "hostile-bare";

/// The class part of the notifier's "has the browser policy already run" key. Only HOSTILE_BARE
/// triggers killing the browser. off = the user explicitly chose unprotected; leaking = the intent
/// is a tunnel but the kill switch is not loaded (actually leaking).
pub fn exposure_class(class: &str, mode: &str, phase: &str) -> String {
    if class == "hostile" && (mode == "off" || phase == "leaking") {
        HOSTILE_BARE.to_string()
    } else {
        class.to_string()
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub enabled: bool,
    pub kill: Vec<String>,
    pub open_clean: bool,
    pub template: Option<PathBuf>,
}

pub fn policy() -> Policy {
    let m = std::fs::read_to_string(conf_path()).ok().map(|t| parse_kv(&t)).unwrap_or_default();
    let expand = |s: &str| PathBuf::from(s.replace('~', &home().to_string_lossy()));
    Policy {
        enabled: m.get("BROWSER_POLICY").map(|v| v == "yes").unwrap_or(false),
        kill: m.get("HOSTILE_KILL").map(|v| v.split_whitespace().map(String::from).collect()).unwrap_or_default(),
        open_clean: m.get("HOSTILE_OPEN").map(|v| v != "none").unwrap_or(true),
        template: m.get("CLEAN_TEMPLATE").map(|s| expand(s)).filter(|p| p.is_dir()),
    }
}

#[derive(Clone, Debug)]
pub struct Ff {
    pub pid: i32,
    pub profile: String, // name from "-P xxx", dir from "--profile <dir>", or "(default)"
    pub is_clean: bool,
}

/// Firefox main processes of the current uid: argv[0] is firefox and it is not a contentproc.
pub fn running() -> Vec<Ff> {
    let uid = unsafe { libc::getuid() };
    let clean = clean_dir();
    let mut out = vec![];
    let Ok(d) = std::fs::read_dir("/proc") else { return out };
    for e in d.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(st) = std::fs::metadata(e.path()) else { continue };
        if std::os::unix::fs::MetadataExt::uid(&st) != uid {
            continue;
        }
        let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else { continue };
        let args: Vec<String> = cmd.split(|b| *b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
        let Some(a0) = args.first() else { continue };
        let base = Path::new(a0).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        if !(base == "firefox" || base == "firefox-bin" || base == "firefox-nightly") {
            continue;
        }
        if args.iter().any(|a| a == "-contentproc" || a.starts_with("-childID")) {
            continue;
        }
        let mut profile = "(default)".to_string();
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-P" | "--P" | "-p" => {
                    profile = args.get(i + 1).cloned().unwrap_or_default();
                    i += 1;
                }
                "--profile" | "-profile" => {
                    profile = args.get(i + 1).cloned().unwrap_or_default();
                    i += 1;
                }
                _ => {}
            }
            i += 1;
        }
        let is_clean = Path::new(&profile) == clean || profile.starts_with("/tmp/toriid-portal-");
        out.push(Ff { pid, profile, is_clean });
    }
    out
}

/// Kill identity-bearing Firefox. Empty `which` = every non-clean one. SIGTERM first (Firefox saves
/// its session and exits), SIGKILL if still alive after 5s.
pub async fn kill_identity(which: &[String]) -> Vec<String> {
    let victims: Vec<Ff> = running().into_iter().filter(|f| !f.is_clean && (which.is_empty() || which.iter().any(|w| *w == f.profile))).collect();
    for f in &victims {
        unsafe {
            libc::kill(f.pid, libc::SIGTERM);
        }
    }
    if !victims.is_empty() {
        tokio::time::sleep(Duration::from_secs(5)).await;
        for f in &victims {
            if Path::new(&format!("/proc/{}", f.pid)).exists() {
                unsafe {
                    libc::kill(f.pid, libc::SIGKILL);
                }
            }
        }
    }
    victims.iter().map(|f| format!("{}({})", f.profile, f.pid)).collect()
}

/// Launch the clean profile: wipe the dir (optionally copy the template in), then
/// `--no-remote --profile <dir>`.
pub fn open_clean(template: Option<&Path>) -> Result<i32> {
    let dir = clean_dir();
    if dir.exists() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("wipe {}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir)?;
    if let Some(t) = template {
        copy_dir(t, &dir)?;
    }
    // Baseline prefs that do not depend on the template
    let userjs = dir.join("user.js");
    let mut prefs = std::fs::read_to_string(&userjs).unwrap_or_default();
    prefs.push_str(
        "\n// toriid clean profile\nuser_pref(\"datareporting.healthreport.uploadEnabled\", false);\nuser_pref(\"toolkit.telemetry.enabled\", false);\nuser_pref(\"dom.security.https_only_mode\", true);\nuser_pref(\"privacy.resistFingerprinting\", true);\nuser_pref(\"browser.shell.checkDefaultBrowser\", false);\nuser_pref(\"browser.startup.homepage\", \"about:blank\");\nuser_pref(\"datareporting.policy.dataSubmissionPolicyBypassNotification\", true);\n\
// Fresh profile every time: suppress the first-run wizard\n\
user_pref(\"browser.aboutwelcome.enabled\", false);\n\
user_pref(\"trailhead.firstrun.didSeeAboutWelcome\", true);\n\
user_pref(\"browser.startup.homepage_override.mstone\", \"ignore\");\n\
user_pref(\"startup.homepage_welcome_url\", \"\");\n\
user_pref(\"startup.homepage_welcome_url.additional\", \"\");\n\
user_pref(\"browser.newtabpage.activity-stream.feeds.section.topstories\", false);\n\
user_pref(\"browser.messaging-system.whatsNewPanel.enabled\", false);\n\
user_pref(\"datareporting.policy.firstRunURL\", \"\");\n",
    );
    std::fs::write(&userjs, prefs)?;
    let child = std::process::Command::new("firefox")
        .args(["--no-remote", "--profile", &dir.to_string_lossy()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("launch firefox")?;
    Ok(child.id() as i32)
}

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            std::fs::create_dir_all(&to)?;
            copy_dir(&e.path(), &to)?;
        } else {
            std::fs::copy(e.path(), &to)?;
        }
    }
    Ok(())
}

/// The full "arrived on a hostile network" action. Returns one line for the notification/CLI.
pub async fn on_hostile(p: &Policy, ssid: &str) -> Result<String> {
    let killed = kill_identity(&p.kill).await;
    let mut msg = if killed.is_empty() { "no identity-bearing Firefox running".to_string() } else { format!("closed {}", killed.join(" ")) };
    if p.open_clean {
        let pid = open_clean(p.template.as_deref())?;
        msg += &format!(" - opened clean Firefox (pid {})", pid);
    }
    Ok(format!("{}: {}", ssid, msg))
}

pub fn status_text() -> String {
    let p = policy();
    let mut s = format!(
        "Policy: {} - on hostile kill: {} - open clean: {} - template: {}\n",
        if p.enabled { "on" } else { "off (set BROWSER_POLICY=yes in ~/.config/toriid/browser.conf)" },
        if p.kill.is_empty() { "all non-clean".to_string() } else { p.kill.join(" ") },
        if p.open_clean { "yes" } else { "no" },
        p.template.as_ref().map(|t| t.display().to_string()).unwrap_or("none".into())
    );
    let r = running();
    if r.is_empty() {
        s += "No Firefox running\n";
    }
    for f in r {
        s += &format!("  pid {:<7} {} {}\n", f.pid, if f.is_clean { "clean   " } else { "identity" }, f.profile);
    }
    s += &format!("Clean dir: {}\n", clean_dir().display());
    let _ = anyhow!("");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exposure_only_when_bare() {
        assert_eq!(exposure_class("hostile", "auto", "up"), "hostile", "tunnel up: do not kill");
        assert_eq!(exposure_class("hostile", "portal", "portal"), "hostile", "portal: host is locked");
        assert_eq!(exposure_class("hostile", "wstunnel", "degraded"), "hostile", "no connectivity but kill switch loaded: not leaking");
        assert_eq!(exposure_class("hostile", "off", "off"), HOSTILE_BARE);
        assert_eq!(exposure_class("hostile", "auto", "leaking"), HOSTILE_BARE);
        assert_eq!(exposure_class("home", "off", "off"), "home", "unprotected at home: ignored");
    }
}
