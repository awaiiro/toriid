//! tailscaled's local API (HTTP over a unix socket). Does not shell out to `tailscale status`.
use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const SOCK: &str = "/var/run/tailscale/tailscaled.sock";

pub async fn status() -> Result<serde_json::Value> {
    let mut s = tokio::time::timeout(std::time::Duration::from_secs(5), UnixStream::connect(SOCK)).await??;
    s.write_all(b"GET /localapi/v0/status HTTP/1.1\r\nHost: local-tailscaled.sock\r\nSec-Tailscale: localapi\r\nConnection: close\r\n\r\n").await?;
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_end(&mut buf)).await??;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).ok_or_else(|| anyhow!("tailscaled response has no body"))?;
    // May be chunked; with Connection: close the localapi usually sends Content-Length. Handle both.
    let body = if text.to_ascii_lowercase().contains("transfer-encoding: chunked") { dechunk(body) } else { body.to_string() };
    Ok(serde_json::from_str(&body)?)
}

fn dechunk(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some((len_line, after)) = rest.split_once("\r\n") {
        let Ok(n) = usize::from_str_radix(len_line.trim(), 16) else { break };
        if n == 0 {
            break;
        }
        out.push_str(&after[..n.min(after.len())]);
        rest = after.get(n + 2..).unwrap_or("");
    }
    out
}

pub async fn magicdns_suffix() -> Option<String> {
    status().await.ok()?.get("MagicDNSSuffix")?.as_str().map(String::from).filter(|s| !s.is_empty())
}

/// The exit node's tailnet IP, if an exit node is in use.
pub async fn exit_node() -> Option<String> {
    let s = status().await.ok()?;
    let en = s.get("ExitNodeStatus")?;
    if en.is_null() {
        return None;
    }
    en.get("TailscaleIPs")?.as_array()?.first()?.as_str().map(String::from)
}
