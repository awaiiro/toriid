//! Portal browser: a throwaway-profile Firefox running in the portal netns, as the user, on the user's desktop.
//! Launched by the daemon (previously a shell script that needed sudo and a terminal):
//! - No sudo: the daemon identifies the caller via SO_PEERCRED (policy::may) and only opens it in portal mode.
//! - Started by systemd as a transient unit (systemd-run), not as a daemon child: the daemon lives in a
//!   private mount namespace (ProtectHome/PrivateTmp), so its children can't write ~/.cache and see a fake /tmp.
//! - Enters the netns with `ip netns exec` (which also bind-mounts /etc/netns/portal/resolv.conf over
//!   /etc/resolv.conf; DNS behind the portal depends on that), then runuser back to the user.
//! - Fixed unit name: opening again closes the old one first; the daemon closes it (close) once login
//!   succeeds or portal mode is left.
use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::Command;

pub const UNIT: &str = "toriid-portal-browser.service";
const DEFAULT_URL: &str = "http://neverssl.com/";

/// Pitfalls of a fresh profile behind a portal: HTTPS-First upgrades http to https (the portal can't hijack
/// 443, so it just hangs); DoH bypasses the netns resolv.conf (and can't get out before login); the
/// first-run wizard steals the first tab.
const USER_JS: &str = r#"user_pref("dom.security.https_first", false);
user_pref("dom.security.https_only_mode", false);
user_pref("network.trr.mode", 5);
user_pref("doh-rollout.disable-heuristics", true);
user_pref("network.captive-portal-service.enabled", true);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("trailhead.firstrun.didSeeAboutWelcome", true);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
"#;

struct Pw {
    name: String,
    home: String,
}

fn getpw(uid: u32) -> Option<Pw> {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return None;
    }
    let s = |p: *const libc::c_char| unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned();
    Some(unsafe { Pw { name: s((*pw).pw_name), home: s((*pw).pw_dir) } })
}

/// The user's Wayland socket: the given one if it exists, otherwise the first wayland-N in the runtime dir
/// (the variable can get lost, e.g. sudo strips it; the socket doesn't lie).
fn wayland_socket(rt: &str, wl: Option<&str>) -> Option<String> {
    use std::os::unix::fs::FileTypeExt;
    let is_sock = |n: &str| std::fs::metadata(format!("{}/{}", rt, n)).map(|m| m.file_type().is_socket()).unwrap_or(false);
    if let Some(w) = wl.filter(|w| !w.contains('/') && is_sock(w)) {
        return Some(w.to_string());
    }
    let mut names: Vec<String> = std::fs::read_dir(rt).ok()?.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with("wayland-") && !n.ends_with(".lock")).collect();
    names.sort();
    names.into_iter().find(|n| is_sock(n))
}

/// Only plain http(s) URLs: it is passed as a sh positional parameter, not spliced into the script, but there's no reason to let odd things through.
pub fn url_ok(u: &str) -> bool {
    (u.starts_with("http://") || u.starts_with("https://")) && u.len() < 2048 && !u.chars().any(|c| c.is_whitespace() || c.is_control())
}

pub async fn open(uid: u32, wl: Option<&str>, url: Option<&str>) -> Result<String> {
    let pw = getpw(uid).ok_or_else(|| anyhow!("no such uid {}", uid))?;
    let rt = format!("/run/user/{}", uid);
    let wl = wayland_socket(&rt, wl).ok_or_else(|| anyhow!("no Wayland socket in {}; is a graphical session running?", rt))?;
    let url = url.unwrap_or(DEFAULT_URL);
    if !url_ok(url) {
        return Err(anyhow!("invalid URL: {}", url));
    }
    close();
    let dir = format!("/tmp/toriid-portal-{}", uid);
    // fixed directory, removed when the unit stops (ExecStopPost, as root); sh removes it then mkdir -m 700,
    // so if someone else pre-created the directory we fail instead of using it
    let script = format!(
        "d={dir}; rm -rf \"$d\" 2>/dev/null; mkdir -m 700 \"$d\" || exit 1\ncat > \"$d/user.js\" <<'TORIID_EOF'\n{js}TORIID_EOF\nexec firefox --no-remote --profile \"$d\" \"$1\"\n",
        dir = dir,
        js = USER_JS
    );
    let out = Command::new("systemd-run")
        .args(["--unit", UNIT, "--collect", "--quiet", "--no-block"])
        .args(["-p", &format!("ExecStopPost=/bin/rm -rf {}", dir)])
        .args(["-p", "KillMode=control-group", "-p", "TimeoutStopSec=5"])
        .args([crate::util::tool("ip").as_str(), "netns", "exec", "portal", crate::util::tool("runuser").as_str(), "-u", &pw.name, "--", crate::util::tool("env").as_str(), "-i"])
        .arg(format!("HOME={}", pw.home))
        .arg(format!("USER={}", pw.name))
        .arg("PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .arg(format!("WAYLAND_DISPLAY={}", wl))
        .arg(format!("XDG_RUNTIME_DIR={}", rt))
        .arg(format!("DBUS_SESSION_BUS_ADDRESS=unix:path={}/bus", rt))
        .arg("MOZ_ENABLE_WAYLAND=1")
        .args(["/bin/sh", "-c", &script, "sh", url])
        .output()
        .context("running systemd-run")?;
    if !out.status.success() {
        return Err(anyhow!("systemd-run: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    crate::journal::notice("toriid", &format!("portal browser opened ({} @ {}, {})", pw.name, wl, url));
    Ok(format!("portal browser opened on {}'s desktop (portal netns, throwaway profile)", pw.name))
}

/// Close the portal browser (no-op if not open). Called when leaving portal mode or after login succeeds.
pub fn close() {
    if Path::new(&format!("/run/systemd/transient/{}", UNIT)).exists() || is_active() {
        let _ = Command::new("systemctl").args(["stop", "--no-block", UNIT]).output();
    }
}

pub fn is_active() -> bool {
    Command::new("systemctl").args(["is-active", "--quiet", UNIT]).status().map(|s| s.success()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn urls() {
        assert!(url_ok("http://neverssl.com/"));
        assert!(url_ok("https://portal.example.com/?a=b&c=d"));
        assert!(!url_ok("file:///etc/shadow"));
        assert!(!url_ok("javascript:alert(1)"));
        assert!(!url_ok("http://x/ y"));
        assert!(!url_ok("http://x/\n"));
    }
    #[test]
    fn user_js_has_no_heredoc_terminator() {
        assert!(!USER_JS.lines().any(|l| l == "TORIID_EOF"));
    }
}
