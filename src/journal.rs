//! Writes straight to the systemd journal (native protocol on /run/systemd/journal/socket), no logger.
//! SYSLOG_IDENTIFIER uses stable tags, so `journalctl -t toriid` / `-t toriid-watchdog` work as expected.
use std::os::unix::net::UnixDatagram;
use std::sync::OnceLock;

const SOCK: &str = "/run/systemd/journal/socket";

fn sock() -> Option<&'static UnixDatagram> {
    static S: OnceLock<Option<UnixDatagram>> = OnceLock::new();
    S.get_or_init(|| {
        let s = UnixDatagram::unbound().ok()?;
        s.connect(SOCK).ok()?;
        Some(s)
    })
    .as_ref()
}

/// Binary field format: NAME\n + u64 LE length + value + \n. Safe for values containing newlines.
fn field(buf: &mut Vec<u8>, k: &str, v: &str) {
    buf.extend_from_slice(k.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
    buf.extend_from_slice(v.as_bytes());
    buf.push(b'\n');
}

pub fn send(tag: &str, priority: u8, msg: &str) {
    let mut buf = Vec::with_capacity(msg.len() + 64);
    field(&mut buf, "MESSAGE", msg);
    field(&mut buf, "SYSLOG_IDENTIFIER", tag);
    field(&mut buf, "PRIORITY", &priority.to_string());
    if let Some(s) = sock() {
        if s.send(&buf).is_ok() {
            return;
        }
    }
    eprintln!("[{}] {}", tag, msg);
}

pub fn notice(tag: &str, msg: &str) {
    send(tag, 5, msg)
}
pub fn err(tag: &str, msg: &str) {
    send(tag, 3, msg)
}
