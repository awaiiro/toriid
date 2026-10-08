//! Running external commands, logging, atomic file writes, the TSV memory store.
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn iso_now() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
}

pub fn read_trim(p: &str) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub fn exists(p: &str) -> bool {
    Path::new(p).exists()
}

pub fn mtime(p: &str) -> Option<u64> {
    fs::metadata(p).ok()?.modified().ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

pub fn touch(p: &str) {
    let _ = fs::OpenOptions::new().create(true).write(true).truncate(true).open(p);
}

pub fn rm(p: &str) {
    let _ = fs::remove_file(p);
}

/// Atomic write: temp file in the same dir + rename. Readers never see a partial file.
pub fn write_atomic(p: &str, content: &str, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = Path::new(p);
    let dir = path.parent().ok_or_else(|| anyhow!("{} has no parent directory", p))?;
    fs::create_dir_all(dir).ok();
    let tmp = dir.join(format!(".{}.{}.tmp", path.file_name().unwrap().to_string_lossy(), std::process::id()));
    {
        let mut f = fs::File::create(&tmp).with_context(|| format!("write {}", tmp.display()))?;
        f.write_all(content.as_bytes())?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    fs::rename(&tmp, path).with_context(|| format!("rename -> {}", p))?;
    Ok(())
}

/// Three-column memory store: SSID<TAB>value<TAB>iso-ts. A stable external format; other tools may read it.
pub struct Tsv;
impl Tsv {
    pub fn get(path: &str, key: &str) -> Option<(String, String)> {
        let s = fs::read_to_string(path).ok()?;
        s.lines()
            .filter_map(|l| {
                let c: Vec<&str> = l.split('\t').collect();
                (c.len() >= 2 && c[0] == key).then(|| (c[1].to_string(), c.get(2).unwrap_or(&"").to_string()))
            })
            .last()
    }
    /// Two-level-key variant: key\tsub\tts
    pub fn get2(path: &str, key: &str, sub: &str) -> Option<String> {
        let s = fs::read_to_string(path).ok()?;
        s.lines()
            .filter_map(|l| {
                let c: Vec<&str> = l.split('\t').collect();
                (c.len() >= 3 && c[0] == key && c[1] == sub).then(|| c[2].to_string())
            })
            .last()
    }
    pub fn put(path: &str, key: &str, val: &str) -> Result<()> {
        let mut lines: Vec<String> = fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.split('\t').next() != Some(key))
            .map(String::from)
            .collect();
        lines.push(format!("{}\t{}\t{}", key, val, iso_now()));
        write_atomic(path, &(lines.join("\n") + "\n"), 0o644)
    }
    pub fn put2(path: &str, key: &str, sub: &str) -> Result<()> {
        let mut lines: Vec<String> = fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| {
                let c: Vec<&str> = l.split('\t').collect();
                !(c.len() >= 2 && c[0] == key && c[1] == sub)
            })
            .map(String::from)
            .collect();
        lines.push(format!("{}\t{}\t{}", key, sub, iso_now()));
        write_atomic(path, &(lines.join("\n") + "\n"), 0o644)
    }
    pub fn del(path: &str, key: &str) -> Result<()> {
        if !exists(path) {
            return Ok(());
        }
        let lines: Vec<String> = fs::read_to_string(path)?
            .lines()
            .filter(|l| l.split('\t').next() != Some(key))
            .map(String::from)
            .collect();
        write_atomic(path, &(lines.join("\n") + "\n"), 0o644)
    }
    pub fn del2(path: &str, key: &str, sub: &str) -> Result<()> {
        if !exists(path) {
            return Ok(());
        }
        let lines: Vec<String> = fs::read_to_string(path)?
            .lines()
            .filter(|l| {
                let c: Vec<&str> = l.split('\t').collect();
                !(c.len() >= 2 && c[0] == key && c[1] == sub)
            })
            .map(String::from)
            .collect();
        write_atomic(path, &(lines.join("\n") + "\n"), 0o644)
    }
}

/// Parse a `date -Is` style timestamp into epoch seconds.
pub fn parse_iso(ts: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(ts).ok().map(|d| d.timestamp().max(0) as u64)
}

pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// The invoking user's home. No guessing: without $HOME there is no sensible place for per-user state.
pub fn home() -> std::path::PathBuf {
    std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_else(|| "/nonexistent".into())
}

/// $XDG_STATE_HOME/toriid, falling back to ~/.local/state/toriid.
pub fn user_state_dir() -> std::path::PathBuf {
    std::env::var_os("XDG_STATE_HOME").map(std::path::PathBuf::from).unwrap_or_else(|| home().join(".local/state")).join("toriid")
}

/// May root trust this path? Owned by root, not writable by group/other, and the same for every parent
/// directory (otherwise someone could swap the file out from under it). Applies to anything root reads
/// as configuration or executes.
pub fn root_trusted(p: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut cur = Some(Path::new(p));
    while let Some(c) = cur {
        if c.as_os_str().is_empty() {
            break;
        }
        let m = fs::metadata(c).with_context(|| format!("stat {}", c.display()))?;
        if !trust_ok(m.uid(), m.mode()) {
            return Err(anyhow!("refusing to trust {}: {} must be owned by root and not writable by group/other", p, c.display()));
        }
        cur = c.parent();
    }
    Ok(())
}

pub fn trust_ok(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

pub fn euid_is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(test)]
mod trust_tests {
    use super::*;
    #[test]
    fn trust_rules() {
        assert!(trust_ok(0, 0o100600));
        assert!(trust_ok(0, 0o040755));
        assert!(!trust_ok(1000, 0o100600));
        assert!(!trust_ok(0, 0o100620));
        assert!(!trust_ok(0, 0o040777));
    }
}
