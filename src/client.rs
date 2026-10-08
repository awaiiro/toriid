//! CLI side: send requests to the daemon and render progress per the line protocol. If the daemon is not
//! running, mode commands execute directly (the escape hatch must not depend on the daemon being alive).
use crate::daemon::Request;
use crate::modes::{self, Ctx, Io};
use crate::nl::Nl;
use crate::paths::*;
use crate::state::Mode;
use crate::ui;
use crate::util;
use crate::wst;
use anyhow::{anyhow, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub async fn send(req: Request) -> Result<i32> {
    let stream = UnixStream::connect(SOCK).await?;
    let (r, mut w) = stream.into_split();
    w.write_all((serde_json::to_string(&req)? + "\n").as_bytes()).await?;
    let color = ui::is_tty();
    let mut lines = BufReader::new(r).lines();
    while let Some(l) = lines.next_line().await? {
        if let Some(rc) = ui::render(&l, color) {
            return Ok(rc);
        }
    }
    Err(anyhow!("daemon closed the connection without an end marker"))
}

/// Send a request and collect the raw output lines instead of rendering them. Blocking (callers in rotate
/// run outside the async context's hot path).
pub fn capture(req: Request) -> Result<(i32, Vec<String>)> {
    use std::io::{BufRead, Write};
    let mut s = std::os::unix::net::UnixStream::connect(SOCK).map_err(|e| anyhow!("daemon not reachable ({}): systemctl status toriid", e))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(60)))?;
    s.write_all((serde_json::to_string(&req)? + "\n").as_bytes())?;
    let mut lines = vec![];
    for l in std::io::BufReader::new(s).lines() {
        let l = l?;
        if let Some(rc) = l.strip_prefix(ui::P_DONE) {
            return Ok((rc.trim().parse().unwrap_or(1), lines));
        }
        lines.push(l);
    }
    Err(anyhow!("daemon closed the connection without an end marker"))
}

/// Is the daemon up (socket connectable)? If the unit is active but the socket is not bound yet (just
/// restarted), wait up to 5 s - otherwise `systemctl restart toriid && torii up` would take the direct path
/// and race the daemon that is starting.
pub async fn daemon_alive() -> bool {
    for i in 0..25 {
        if UnixStream::connect(SOCK).await.is_ok() {
            return true;
        }
        if i == 0 && !unit_active("toriid.service").await {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    false
}

async fn unit_active(name: &str) -> bool {
    crate::dbus::systemd::is_active(name).await
}

/// Apply a mode directly (daemon not running). Needs root; takes the flock; first kills orphaned wstunnel
/// processes that may belong to a dead daemon.
pub async fn direct_mode(m: Mode, automated: bool) -> Result<i32> {
    let color = ui::is_tty();
    if !util::is_root() {
        return Err(anyhow!("needs root: sudo torii {}", verb(m)));
    }
    let lock = std::fs::OpenOptions::new().create(true).write(true).open(LOCK)?;
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        ui::render(&format!("{}h another torii command is running, waiting for it... (up to 120 s; Ctrl-C to give up)", ui::P_STYLE), color);
        let r = tokio::task::spawn_blocking(move || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }).await?;
        if r != 0 {
            return Err(anyhow!("could not acquire lock"));
        }
    }
    ui::render(&format!("{}h daemon not running, executing directly (see systemctl status toriid)", ui::P_STYLE), color);
    kill_stray_wstunnel();
    let nl = Nl::new()?;
    // Direct path: progress goes through a local channel, rendered exactly as when going through the daemon
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let printer = tokio::spawn(async move {
        while let Some(l) = rx.recv().await {
            ui::render(&l, color);
        }
    });
    let mut ctx = Ctx { nl, io: Io { tx: Some(tx) }, wst: wst::Client::default(), carrier_wait_budget: 40, automated };
    let r = modes::apply(&mut ctx, m).await;
    if let Err(e) = &r {
        ctx.io.fail(format!("{:#}", e));
    }
    ctx.io = Io::default();
    let _ = printer.await;
    Ok(if r.is_ok() { 0 } else { 1 })
}

/// Mode -> the verb the user types (for error hints).
pub fn verb(m: Mode) -> String {
    match m {
        Mode::Off => "down".into(),
        Mode::Portal => "portal".into(),
        m => format!("up {}", m),
    }
}

pub fn kill_stray_wstunnel() {
    for pid in wst::stray_pids() {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}
