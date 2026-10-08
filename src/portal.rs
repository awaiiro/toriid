//! Automatic captive-portal pass-through. Runs inside the daemon, on a dedicated thread in the portal netns.
//!
//! Heuristics (each one learned on a real portal):
//!   - "Is there a portal": three probes in parallel; any real HTTP status counts. Only all-000 is 000.
//!   - 000 != portal: gateway reachable (TCP 80/443/9997) = portal silently dropping, carry on;
//!     gateway unreachable = no exit, no form to fill.
//!   - If names don't resolve, probe the gateway IP directly (it usually is the portal device).
//!   - Follow redirects hop by hop looking for a <form>; no form may still mean we were let through (re-probe 204).
//!   - Form scoring: password field disqualifies; submit button, accept/agree/continue keywords and
//!     hidden fields add points.
//!   - `<button type="text" name="ok">` (Ruckus): not a text box; value-less fields are still submitted as `ok=`.
//!   - After submitting, re-check 5 times, 2s apart.
//!
//! Compared with the old shell implementation: no 5-6s "is the internet up" pre-check (the caller already
//! knows the carrier is unreachable and the mode is portal); the three 204 probes run in parallel instead
//! of serially (15s -> 4s when the portal drops packets); no child processes, cookies never touch disk.
//!
//! DNS: the host's resolved can't be used inside the netns (it runs in the host network context and dies
//! behind a portal), so we send A queries ourselves to the resolvers in /etc/netns/portal/resolv.conf.
use crate::nl::netns;
use crate::paths::*;
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use ureq::ResponseExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum Outcome {
    /// Form submitted, 204 re-check passed
    Passed,
    /// First probe returned 204; already open
    AlreadyOpen,
    /// Let through while following redirects (some portals open on first visit)
    OpenedByRedirect,
    /// Gateway unreachable: no exit, not a portal
    NoExit,
    /// No form on the page (JS-driven login page)
    NoForm,
    /// Form wants a password or other required input: the user logs in themselves
    NeedsUser,
    /// Submitted, but re-check still fails
    StillBlocked(String),
    Error(String),
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Report {
    pub outcome: Outcome,
    /// How we got through, if we did (human-readable, recorded per SSID):
    /// "form auto-submit" / "Meraki auto-grant" / "opened by redirect"
    pub method: String,
    /// Raw pages seen while following redirects; written to /run/toriid/portal.dump by the daemon
    #[serde(default)]
    pub dump: String,
    /// Phase timings: (phase name, cumulative seconds)
    pub phases: Vec<(String, f32)>,
    pub log: Vec<String>,
}

struct Phase {
    t0: Instant,
    phases: Vec<(String, f32)>,
    log: Vec<String>,
}
impl Phase {
    fn mark(&mut self, name: &str) {
        self.phases.push((name.to_string(), self.t0.elapsed().as_secs_f32()));
    }
    fn say(&mut self, s: impl Into<String>) {
        self.log.push(s.into());
    }
}

const PROBE_URL: &str = "http://neverssl.com/";
const MAX_HOPS: usize = 3;
const UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

// ── DNS: minimal A query ──────────────────────────────────────────
fn dns_query_packet(host: &str, id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, QDCOUNT=1
    for label in host.trim_end_matches('.').split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    p
}

fn dns_parse_a(buf: &[u8], id: u16) -> Vec<Ipv4Addr> {
    let mut out = vec![];
    if buf.len() < 12 || u16::from_be_bytes([buf[0], buf[1]]) != id {
        return out;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut i = 12;
    // skip the question section
    let skip_name = |i: &mut usize| {
        while *i < buf.len() {
            let l = buf[*i] as usize;
            if l == 0 {
                *i += 1;
                break;
            }
            if l & 0xC0 == 0xC0 {
                *i += 2;
                break;
            }
            *i += 1 + l;
        }
    };
    for _ in 0..qd {
        skip_name(&mut i);
        i += 4;
    }
    for _ in 0..an {
        skip_name(&mut i);
        if i + 10 > buf.len() {
            break;
        }
        let ty = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let len = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        i += 10;
        if ty == 1 && len == 4 && i + 4 <= buf.len() {
            out.push(Ipv4Addr::new(buf[i], buf[i + 1], buf[i + 2], buf[i + 3]));
        }
        i += len;
    }
    out
}

/// Ask **all** resolvers at once and take the first valid answer, waiting at most 2.5s.
/// Observed on a network that blocks public UDP 53: asking serially (1.1.1.1 -> 9.9.9.9 -> the local
/// resolver) burned 2s on each of the first two, the probe's 4s budget ran out before the one that could
/// answer was tried, all three probes came back 000, and a working network was classified as "no exit".
fn dns_a(host: &str, resolvers: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return vec![ip];
    }
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else { return vec![] };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
    static SEQ: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0x4e44);
    let id: u16 = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) ^ (std::process::id() as u16);
    let pkt = dns_query_packet(host, id);
    let deadline = Instant::now() + Duration::from_millis(2500);
    let mut buf = [0u8; 1500];
    let mut resent = false;
    for r in resolvers {
        let _ = sock.send_to(&pkt, (*r, 53));
    }
    while Instant::now() < deadline {
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            let v = dns_parse_a(&buf[..n], id);
            if !v.is_empty() {
                return v;
            }
            continue; // a resolver answered without an A record (hijacked / NXDOMAIN); wait for others
        }
        if !resent && Instant::now() > deadline - Duration::from_millis(1200) {
            resent = true; // nobody answered in 1.3s; send another round
            for r in resolvers {
                let _ = sock.send_to(&pkt, (*r, 53));
            }
        }
    }
    vec![]
}

/// Resolver for ureq: uses our own DNS client (inside the netns).
#[derive(Debug)]
struct NsResolver {
    resolvers: Vec<Ipv4Addr>,
    cache: Mutex<HashMap<String, Vec<Ipv4Addr>>>,
}
impl ureq::unversioned::resolver::Resolver for NsResolver {
    fn resolve(&self, uri: &ureq::http::Uri, _config: &ureq::config::Config, _timeout: ureq::unversioned::transport::NextTimeout) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let host = uri.host().ok_or(ureq::Error::HostNotFound)?.to_string();
        let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
        let ips = {
            let cached = self.cache.lock().unwrap().get(&host).cloned();
            match cached {
                Some(v) => v,
                None => {
                    let v = dns_a(&host, &self.resolvers);
                    self.cache.lock().unwrap().insert(host.clone(), v.clone());
                    v
                }
            }
        };
        if ips.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        let mut out = self.empty();
        for ip in ips.into_iter().take(8) {
            out.push(SocketAddr::new(IpAddr::V4(ip), port));
        }
        Ok(out)
    }
}

#[derive(Debug, Clone)]
struct SharedResolver(Arc<NsResolver>);
impl ureq::unversioned::resolver::Resolver for SharedResolver {
    fn resolve(&self, uri: &ureq::http::Uri, config: &ureq::config::Config, timeout: ureq::unversioned::transport::NextTimeout) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        self.0.resolve(uri, config, timeout)
    }
}

fn resolver(resolvers: &[Ipv4Addr]) -> SharedResolver {
    SharedResolver(Arc::new(NsResolver { resolvers: resolvers.to_vec(), cache: Mutex::new(HashMap::new()) }))
}

fn agent_with(res: &SharedResolver, timeout: Duration, redirects: u32) -> ureq::Agent {
    let cfg = ureq::Agent::config_builder().timeout_global(Some(timeout)).max_redirects(redirects).http_status_as_error(false).user_agent(UA).build();
    ureq::Agent::with_parts(cfg, ureq::unversioned::transport::DefaultConnector::default(), res.clone())
}

fn agent(resolvers: &[Ipv4Addr], timeout: Duration, redirects: u32) -> ureq::Agent {
    agent_with(&resolver(resolvers), timeout, redirects)
}

// ── probes ──────────────────────────────────────────────────────
/// Three probes in parallel. Some(204) = open; Some(other) = something served a page = portal; None = all 000.
fn probe204(resolvers: &[Ipv4Addr]) -> Option<u16> {
    let urls = ["http://connectivitycheck.gstatic.com/generate_204", "http://www.msftconnecttest.com/connecttest.txt", "http://captive.apple.com/hotspot-detect.html"];
    let res = resolver(resolvers);
    let (tx, rx) = std::sync::mpsc::channel::<Option<u16>>();
    for u in urls {
        let tx = tx.clone();
        let res = res.clone();
        std::thread::spawn(move || {
            // DNS has its own budget (up to 2.5s), HTTP gets 4s on top: slow resolution must not eat the HTTP budget
            let a = agent_with(&res, Duration::from_secs(4), 0);
            let r = a.get(u).call().ok().map(|r| r.status().as_u16());
            let _ = tx.send(r);
        });
    }
    drop(tx);
    let mut best: Option<u16> = None;
    for r in rx {
        match r {
            Some(204) => return Some(204),
            Some(c) => best = best.or(Some(c)),
            None => {}
        }
    }
    best
}

/// Is the gateway alive: ICMP echo first (the daemon has CAP_NET_RAW), then TCP ports it may have open.
/// Observed: the default gateway can be a plain router that is not the portal device itself (the portal
/// controller lives at another address), with 80/443 and the controller port all closed. Trying only TCP misclassified a working
/// network as "no exit".
fn gateway_alive(gw: Ipv4Addr) -> bool {
    if icmp_echo(gw, Duration::from_millis(1500)) {
        return true;
    }
    [80u16, 443, 9997].iter().any(|p| TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(gw), *p), Duration::from_secs(2)).is_ok())
}

fn icmp_echo(dst: Ipv4Addr, timeout: Duration) -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    // The worker runs unprivileged: datagram ICMP (ping_group_range is opened in the portal netns).
    if let Ok(sock) = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
        return icmp_echo_dgram(sock, dst, timeout);
    }
    let Ok(sock) = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) else { return false };
    let _ = sock.set_read_timeout(Some(timeout));
    let ident = (std::process::id() & 0xffff) as u16;
    let mut pkt = vec![8u8, 0, 0, 0, (ident >> 8) as u8, ident as u8, 0, 1];
    pkt.extend_from_slice(b"toriid-portal-echo");
    let mut sum: u32 = 0;
    for c in pkt.chunks(2) {
        sum += ((c[0] as u32) << 8) | (*c.get(1).unwrap_or(&0) as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let ck = !(sum as u16);
    pkt[2] = (ck >> 8) as u8;
    pkt[3] = ck as u8;
    if sock.send_to(&pkt, &SocketAddr::new(IpAddr::V4(dst), 0).into()).is_err() {
        return false;
    }
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 512];
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let Ok((n, _)) = sock.recv_from(&mut buf) else { return false };
        // raw sockets receive the IP header too: ICMP starts at IHL*4; type 0 = echo reply, ident must match
        let b: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if n < 20 {
            continue;
        }
        let ihl = ((b[0] & 0x0f) as usize) * 4;
        if n >= ihl + 8 && b[ihl] == 0 && b[ihl + 4] == (ident >> 8) as u8 && b[ihl + 5] == ident as u8 {
            return true;
        }
    }
    false
}

/// Datagram ICMP: the kernel fills in ident and checksum, and replies arrive without the IP header.
fn icmp_echo_dgram(sock: socket2::Socket, dst: Ipv4Addr, timeout: Duration) -> bool {
    let _ = sock.set_read_timeout(Some(timeout));
    let mut pkt = vec![8u8, 0, 0, 0, 0, 0, 0, 1];
    pkt.extend_from_slice(b"toriid-portal-echo");
    if sock.send_to(&pkt, &SocketAddr::new(IpAddr::V4(dst), 0).into()).is_err() {
        return false;
    }
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 512];
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let Ok((n, _)) = sock.recv_from(&mut buf) else { return false };
        let b: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if n >= 8 && b[0] == 0 {
            return true;
        }
    }
    false
}

// ── HTML forms ─────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct Field {
    tag: String,
    ty: String,
    name: Option<String>,
    value: String,
    /// `required` attribute present
    required: bool,
    /// Visible text of a <button> (what the user would read: "Log in", "Connect")
    label: String,
}

/// Words on a button or link that mean "let me online". Includes common non-English portal wording.
const GO_WORDS: &[&str] = &[
    "accept", "agree", "continue", "connect", "login", "log in", "log-in", "get online", "go online", "start browsing",
    "free wi", "proceed",
    // Chinese: agree, accept, log in, connect; Japanese: agree, connect, log in; Spanish/French/German: accept, connect
    "\u{540c}\u{610f}", "\u{63a5}\u{53d7}", "\u{767b}\u{5f55}", "\u{8fde}\u{63a5}", "\u{540c}\u{610f}\u{3059}\u{308b}", "\u{63a5}\u{7d9a}",
    "\u{30ed}\u{30b0}\u{30a4}\u{30f3}", "aceptar", "conectar", "accepter", "connexion", "akzeptieren", "verbinden",
];
/// Words that mean the opposite; a control or link carrying them is never clicked.
const STOP_WORDS: &[&str] = &["decline", "cancel", "reject", "logout", "log out", "sign up", "register", "privacy", "terms of", "disagree", "back"];

fn has_word(hay: &str, words: &[&str]) -> bool {
    let h = hay.to_lowercase();
    words.iter().any(|w| h.contains(w))
}

fn is_control(f: &Field) -> bool {
    f.tag == "button" || matches!(f.ty.as_str(), "submit" | "button" | "image" | "reset")
}

fn control_text(f: &Field) -> String {
    format!("{} {} {}", f.name.clone().unwrap_or_default(), f.value, f.label)
}

/// Fields that a person would have to type into: visible text-like inputs that are required and empty.
/// Such a form is handed to the user instead of being submitted empty.
fn needs_user(f: &Form) -> bool {
    f.fields.iter().any(|x| x.ty == "password")
        || f.fields.iter().any(|x| {
            x.required
                && x.value.is_empty()
                && (x.tag == "textarea" || x.tag == "select" || (x.tag == "input" && matches!(x.ty.as_str(), "" | "text" | "email" | "tel" | "number" | "date")))
        })
}

/// What a browser would send when the user clicks the one "go" button: every data field, plus only that
/// button (never a second "Decline" button that would cancel the first).
fn submission(f: &Form) -> Vec<(String, String)> {
    let go = f.fields.iter().filter(|x| is_control(x) && x.name.is_some() && !has_word(&control_text(x), STOP_WORDS)).max_by_key(|x| has_word(&control_text(x), GO_WORDS) as i32);
    f.fields
        .iter()
        .filter(|x| !is_control(x) || go.map(|g| std::ptr::eq(*x, g)).unwrap_or(false))
        .filter(|x| x.ty != "reset")
        .filter_map(|x| x.name.clone().map(|n| (n, x.value.clone())))
        .collect()
}
#[derive(Debug, Clone)]
struct Form {
    action: String,
    method: String,
    fields: Vec<Field>,
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">")
}

/// Lenient tag scanner: only understands <form> / <input> / <button> / <select> / <textarea> and their attributes.
fn parse_forms(src: &str) -> Vec<Form> {
    let mut forms: Vec<Form> = vec![];
    let mut cur: Option<Form> = None;
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        // <form inside comments / scripts doesn't count
        if src[i..].starts_with("<!--") {
            i = src[i..].find("-->").map(|e| i + e + 3).unwrap_or(bytes.len());
            continue;
        }
        let Some(end) = src[i..].find('>') else { break };
        let tag_src = &src[i + 1..i + end];
        i += end + 1;
        let closing = tag_src.starts_with('/');
        let body = tag_src.trim_start_matches('/');
        let name_end = body.find(|c: char| c.is_whitespace() || c == '/').unwrap_or(body.len());
        let tag = body[..name_end].to_ascii_lowercase();
        if tag == "script" && !closing {
            i = src[i..].to_ascii_lowercase().find("</script").map(|e| i + e).unwrap_or(bytes.len());
            continue;
        }
        if closing {
            if tag == "form" {
                if let Some(f) = cur.take() {
                    forms.push(f);
                }
            }
            continue;
        }
        let attrs = parse_attrs(&body[name_end..]);
        match tag.as_str() {
            "form" => {
                if let Some(f) = cur.take() {
                    forms.push(f);
                }
                cur = Some(Form { action: attrs.get("action").cloned().unwrap_or_default(), method: attrs.get("method").map(|m| m.to_ascii_lowercase()).unwrap_or_else(|| "get".into()), fields: vec![] });
            }
            "input" | "button" | "select" | "textarea" => {
                if let Some(f) = cur.as_mut() {
                    // <button>Log in</button>: the visible text up to </button>, tags stripped
                    let label = if tag == "button" {
                        let rest = &src[i..];
                        let end = rest.to_ascii_lowercase().find("</button").unwrap_or(0);
                        strip_tags(&rest[..end])
                    } else {
                        String::new()
                    };
                    let ty = attrs.get("type").map(|t| t.to_ascii_lowercase()).unwrap_or_else(|| if tag == "button" { "submit".into() } else { String::new() });
                    f.fields.push(Field { tag: tag.clone(), ty, name: attrs.get("name").cloned(), value: attrs.get("value").cloned().unwrap_or_default(), required: attrs.contains_key("required"), label });
                }
            }
            _ => {}
        }
    }
    if let Some(f) = cur.take() {
        forms.push(f);
    }
    forms
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    html_unescape(out.split_whitespace().collect::<Vec<_>>().join(" ").trim())
}

/// `<a href>` links with their visible text, outside scripts and comments.
fn parse_links(src: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let lower = src.to_ascii_lowercase();
    let mut i = 0;
    while let Some(p) = lower[i..].find("<a") {
        let start = i + p;
        let Some(gt) = src[start..].find('>') else { break };
        let attrs = parse_attrs(&src[start + 2..start + gt]);
        let body_start = start + gt + 1;
        let end = lower[body_start..].find("</a").map(|e| body_start + e).unwrap_or(src.len());
        if let Some(h) = attrs.get("href") {
            if !h.starts_with('#') && !h.to_ascii_lowercase().starts_with("javascript:") && !h.starts_with("mailto:") {
                out.push((h.clone(), strip_tags(&src[body_start..end])));
            }
        }
        i = end.max(start + 2);
    }
    out
}

/// The one link a person would click to get online, if the page is just a "Log in" / "Connect" link.
fn go_link(src: &str) -> Option<String> {
    let links: Vec<(String, String)> = parse_links(src).into_iter().filter(|(_, t)| !t.is_empty() && has_word(t, GO_WORDS) && !has_word(t, STOP_WORDS)).collect();
    // Ambiguous pages (several candidate links) are left to the user.
    (links.len() == 1).then(|| links[0].0.clone())
}

fn parse_attrs(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let ks = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' && b[i] != b'/' {
            i += 1;
        }
        if ks == i {
            break;
        }
        let key = s[ks..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            let val = if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                i += 1;
                let vs = i;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                let v = &s[vs..i.min(b.len())];
                i += 1;
                v.to_string()
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() {
                    i += 1;
                }
                s[vs..i].to_string()
            };
            out.insert(key, html_unescape(&val));
        } else {
            out.insert(key, String::new());
        }
    }
    out
}

/// Pick the form most likely to be the "agree / continue" one.
fn score(f: &Form) -> i32 {
    let mut s = 0;
    let text: String = f.fields.iter().map(control_text).collect::<Vec<_>>().join(" ").to_lowercase() + " " + &f.action.to_lowercase();
    if needs_user(f) {
        s -= 100;
    }
    if f.fields.iter().any(is_control) {
        s += 10;
    }
    for kw in GO_WORDS {
        if text.contains(kw) {
            s += 5;
        }
    }
    s += f.fields.iter().filter(|x| x.ty == "hidden").count() as i32;
    s
}

fn absolutize(base: &str, action: &str) -> String {
    if action.is_empty() {
        return base.to_string();
    }
    match url::Url::parse(base).and_then(|b| b.join(action)) {
        Ok(u) => u.to_string(),
        Err(_) => action.to_string(),
    }
}

/// Cisco Meraki click-through splash. The portal page URL carries `base_grant_url`; the button on the page
/// just navigates to `base_grant_url?continue_url=...&duration=...`. The page itself is rendered by JS and
/// has no form. Mirrors an observed splash page's button handler: only an https *.network-auth.com grant
/// URL is accepted (anything else is left alone); duration uses the page's own 28800 (8 hours).
pub(crate) fn meraki_grant_url(page_url: &str) -> Option<String> {
    let u = url::Url::parse(page_url).ok()?;
    let q = |k: &str| u.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.into_owned());
    let base = q("base_grant_url")?;
    let mut g = url::Url::parse(&base).ok()?;
    let host = g.host_str()?.to_ascii_lowercase();
    if g.scheme() != "https" || !(host == "network-auth.com" || host.ends_with(".network-auth.com")) {
        return None;
    }
    let cont = q("user_continue_url").filter(|c| c.starts_with("http")).unwrap_or_else(|| "http://neverssl.com/".into());
    g.query_pairs_mut().append_pair("continue_url", &cont).append_pair("duration", "28800");
    Some(g.to_string())
}

/// Target of `<meta http-equiv="refresh" content="0; url=...">`.
fn meta_refresh(page: &str) -> Option<String> {
    let low = page.to_ascii_lowercase();
    let i = low.find("http-equiv=\"refresh\"").or_else(|| low.find("http-equiv='refresh'")).or_else(|| low.find("http-equiv=refresh"))?;
    let tag_start = low[..i].rfind('<')?;
    let tag_end = i + low[i..].find('>')?;
    let attrs = parse_attrs(&page[tag_start..tag_end]);
    let content = attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case("content")).map(|(_, v)| v.clone())?;
    let (_, u) = content.split_once(|c| c == ';' || c == ',')?;
    let u = u.trim();
    let u = u.strip_prefix("url=").or_else(|| u.strip_prefix("URL=")).unwrap_or(u).trim_matches(|c| c == '\'' || c == '"' || c == ' ');
    (!u.is_empty()).then(|| html_unescape(u))
}

/// Re-check after a grant action: 5 attempts, 2 seconds apart.
fn recheck(resolvers: &[Ipv4Addr], mut ph: Phase, method: &'static str) -> Report {
    let mut last = None;
    for i in 1..=5 {
        let c = probe204(resolvers);
        if c == Some(204) {
            ph.mark(&format!("re-check {} passed", i));
            return Report { method: method.into(), dump: String::new(), outcome: Outcome::Passed, phases: ph.phases, log: ph.log };
        }
        last = c;
        ph.say(format!("attempt {}: {:?}, retrying in 2s", i, c));
        std::thread::sleep(Duration::from_secs(2));
    }
    ph.mark("re-check");
    Report { method: "".into(), dump: String::new(), outcome: Outcome::StillBlocked(format!("{:?}", last)), phases: ph.phases, log: ph.log }
}

// ── main flow (on the netns thread, fully blocking) ─────────────────────────────
fn run_inside(gw: Option<Ipv4Addr>, resolvers: Vec<Ipv4Addr>, dry: bool) -> Report {
    let mut ph = Phase { t0: Instant::now(), phases: vec![], log: vec![] };
    let mut dump = String::new();

    // ── are we really being blocked ──
    let code = probe204(&resolvers);
    ph.mark("204 probes");
    let mut probe_url = PROBE_URL.to_string();
    match code {
        Some(204) => {
            ph.say("already open (204), no login needed");
            return Report { method: "".into(), dump: String::new(), outcome: Outcome::AlreadyOpen, phases: ph.phases, log: ph.log };
        }
        Some(c) => ph.say(format!("probe returned {}: something served a page, portal is intercepting", c)),
        None => {
            // 000: gateway reachable = portal silently dropping; gateway unreachable = no exit
            let Some(gw) = gw else {
                ph.say("no probe response (000) and no known gateway: no exit");
                return Report { method: "".into(), dump: String::new(), outcome: Outcome::NoExit, phases: ph.phases, log: ph.log };
            };
            if !gateway_alive(gw) {
                ph.mark("gateway check");
                ph.say(format!("no probe response (000) and default gateway {} is unreachable: no exit, not a portal", gw));
                return Report { method: "".into(), dump: String::new(), outcome: Outcome::NoExit, phases: ph.phases, log: ph.log };
            }
            ph.mark("gateway check");
            ph.say(format!("no probe response (000) but gateway {} is reachable: portal is silently dropping (or DNS is blocked), following redirects anyway", gw));
            if dns_a("neverssl.com", &resolvers).is_empty() {
                ph.say(format!("cannot resolve neverssl.com in the netns: probing the gateway IP instead (no DNS needed)"));
                probe_url = format!("http://{}/", gw);
            }
        }
    }

    // ── follow redirects hop by hop, looking for a form ──
    // We follow redirects ourselves (max_redirects 0): Xfinity puts the whole User-Agent verbatim into the
    // Location query, spaces and parentheses included, and the HTTP library rejects it as a malformed header.
    // Browsers tolerate it, so we must too: take it, percent-encode the illegal characters, then follow.
    let a = agent(&resolvers, Duration::from_secs(12), 0);
    let mut url = probe_url;
    let mut page = String::new();
    let mut final_url = url.clone();
    let mut found = false;
    for hop in 1..=MAX_HOPS {
        ph.say(format!("hop {}: {}", hop, url));
        match fetch_following(&a, &url, 10) {
            Ok((eff, body, chain)) => {
                final_url = eff;
                page = body;
                dump.push_str(&format!("===== hop {}  url={}  effective={}  chain={} =====\n{}\n", hop, url, final_url, chain.join(" > "), page));
                ph.say(format!("     -> {} ({} bytes{})", final_url, page.len(), if chain.len() > 1 { format!(", {} redirects", chain.len() - 1) } else { String::new() }));
                if chain.len() > 1 {
                    let hosts: Vec<String> = chain.iter().map(|u| url::Url::parse(u).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_else(|| "?".into())).collect();
                    ph.say(format!("     chain: {}", hosts.join(" -> ")));
                }
            }
            Err(e) => {
                ph.say(format!("     request failed: {}", e));
                dump.push_str(&format!("===== hop {}  url={}  error={} =====\n", hop, url, e));
            }
        }
        if page.to_ascii_lowercase().contains("<form") {
            found = true;
            break;
        }
        // no form may still mean we were let through
        if probe204(&resolvers) == Some(204) {
            ph.mark(&format!("open after hop {}", hop));
            write_dump(&dump);
            return Report { outcome: Outcome::OpenedByRedirect, method: "opened by redirect".into(), dump: String::new(), phases: ph.phases, log: ph.log };
        }
        url = final_url.clone();
    }
    ph.mark("follow redirects");
    write_dump(&dump);
    if !found {
        if let Some(g) = meraki_grant_url(&final_url) {
            ph.say(format!("no form, but this is a Meraki click-through splash (has base_grant_url): requesting the grant URL directly: {}", g));
            if dry {
                ph.say("dry-run: stopping here, grant URL not requested");
                return Report { method: "".into(), dump: String::new(), outcome: Outcome::StillBlocked("dry-run".into()), phases: ph.phases, log: ph.log };
            }
            // Must reuse the agent that followed the redirects: its cookie jar holds the session cookies set
            // along the portal chain. With a fresh agent Meraki answered 400 "error parsing the required
            // information", exactly as for a request from outside. Send a Referer like a browser would (the
            // button lives on the splash page; the default referrer policy sends only the origin).
            let a2 = a.clone();
            let referer = url::Url::parse(&final_url).ok().map(|u| format!("{}/", u.origin().ascii_serialization())).unwrap_or_default();
            match fetch_with_referer(&a2, &g, &referer, 10) {
                Ok((eff, body, chain)) => {
                    ph.say(format!("grant request done -> {} ({} redirects, {} bytes)", eff, chain.len().saturating_sub(1), body.len()));
                    // Observed: the grant returned 200 + a page (not a 302) and access was not granted. Dump the
                    // page; if it holds a meta refresh or an (auto-submitting) form, take one more step like a browser
                    dump.push_str(&format!("===== meraki grant  url={}  effective={}  chain={} =====\n{}\n", g, eff, chain.join(" > "), body));
                    write_dump(&dump);
                    if let Some(next) = meta_refresh(&body).map(|u| absolutize(&eff, &u)) {
                        ph.say(format!("grant page is a meta refresh -> {}", next));
                        if let Err(e) = fetch_following(&a2, &next, 10) {
                            ph.say(format!("  following refresh failed: {}", e));
                        }
                    } else if let Some(f) = parse_forms(&body).into_iter().filter(|f| !needs_user(f)).max_by_key(score) {
                        let action = absolutize(&eff, &f.action);
                        let fields = submission(&f);
                        ph.say(format!("grant page has a form -> {} {} ({} fields), submitting", f.method, action, fields.len()));
                        let r = if f.method == "post" {
                            a2.post(&action).send_form(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                        } else {
                            a2.get(&action).query_pairs(fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))).call()
                        };
                        match r {
                            Ok(r) => ph.say(format!("  submitted (HTTP {})", r.status().as_u16())),
                            Err(e) => ph.say(format!("  submit failed: {}", e)),
                        }
                    } else {
                        let text: String = body.chars().filter(|c| !c.is_control()).take(300).collect();
                        ph.say(format!("grant page has neither refresh nor form, starts with: {}", text));
                    }
                }
                Err(e) => ph.say(format!("grant request failed: {} (re-checking anyway)", e)),
            }
            ph.mark("Meraki grant");
            return recheck(&resolvers, ph, "Meraki auto-grant");
        }
        if let Some(link) = go_link(&page).map(|l| absolutize(&final_url, &l)) {
            if dry {
                ph.say(format!("dry-run: would follow the login link {}", link));
                return Report { method: "".into(), dump: String::new(), outcome: Outcome::StillBlocked("dry-run".into()), phases: ph.phases, log: ph.log };
            }
            ph.say(format!("no form, but a single login link: following {}", link));
            if let Err(e) = fetch_following(&a, &link, 10) {
                ph.say(format!("  following the link failed: {} (re-checking anyway)", e));
            }
            ph.mark("follow login link");
            return recheck(&resolvers, ph, "login link");
        }
        ph.say(format!("no form found. Raw content is in {}; most likely a JS-driven login page", "/run/toriid/portal.dump"));
        return Report { method: "".into(), dump: String::new(), outcome: Outcome::NoForm, phases: ph.phases, log: ph.log };
    }

    // ── parse the form ──
    let forms = parse_forms(&page);
    let Some(best) = forms.iter().max_by_key(|f| score(f)).cloned() else {
        ph.say("form parsing failed");
        return Report { method: "".into(), dump: String::new(), outcome: Outcome::NoForm, phases: ph.phases, log: ph.log };
    };
    let action = absolutize(&final_url, &best.action);
    let has_pw = needs_user(&best);
    // only look at <input>, not <button>: Ruckus writes its button as <button type="text" name="ok">
    let has_text = best.fields.iter().any(|x| x.tag == "input" && matches!(x.ty.as_str(), "text" | "email" | "tel") && x.name.is_some());
    ph.say(format!("found {} form(s), selected: action {}, method {}", forms.len(), action, best.method));
    let fields = submission(&best);
    for (k, v) in &fields {
        ph.say(format!("    field: {} = {}", k, v));
    }
    ph.mark("parse form");
    if has_pw {
        ph.say("form wants a password or required input: leaving it to the user");
        return Report { method: "".into(), dump: String::new(), outcome: Outcome::NeedsUser, phases: ph.phases, log: ph.log };
    }
    if has_text {
        ph.say("form has optional text fields: submitting them empty");
    }
    if dry {
        ph.say("dry-run: stopping here, nothing submitted");
        return Report { method: "".into(), dump: String::new(), outcome: Outcome::StillBlocked("dry-run".into()), phases: ph.phases, log: ph.log };
    }

    // ── submit ──
    let a2 = agent(&resolvers, Duration::from_secs(15), 0); // no need to follow the post-submit 3xx: the re-check looks for 204
    let r = if best.method == "post" {
        a2.post(&action).send_form(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    } else {
        a2.get(&action).query_pairs(fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))).call()
    };
    match r {
        Ok(r) => ph.say(format!("submitted (HTTP {})", r.status().as_u16())),
        Err(e) => ph.say(format!("submit request failed: {} (re-checking anyway; some portals drop the connection after submit)", e)),
    }
    ph.mark("submit");
    recheck(&resolvers, ph, "form auto-submit")
}

/// `torii portal-probe`: run the DNS and the three probes on the **host**, to verify the heuristics themselves (no netns, no state changes).
pub fn host_selfcheck() -> Vec<String> {
    let t0 = Instant::now();
    let mut out = vec![];
    let rs = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)];
    let a = dns_a("neverssl.com", &rs);
    out.push(format!("dns_a neverssl.com -> {:?} ({:.2}s)", a, t0.elapsed().as_secs_f32()));
    let t1 = Instant::now();
    let c = probe204(&rs);
    out.push(format!("probe204 -> {:?} ({:.2}s)", c, t1.elapsed().as_secs_f32()));
    let t2 = Instant::now();
    out.push(format!("icmp_echo 1.1.1.1 -> {} ({:.2}s)", icmp_echo(Ipv4Addr::new(1, 1, 1, 1), Duration::from_millis(1500)), t2.elapsed().as_secs_f32()));
    let t2 = Instant::now();
    let ag = agent(&rs, Duration::from_secs(8), 10);
    match ag.get(PROBE_URL).call() {
        Ok(mut r) => {
            let u = r.get_uri().to_string();
            let body = r.body_mut().read_to_string().unwrap_or_default();
            out.push(format!("GET {} -> {} {} ({} bytes, {} forms, {:.2}s)", PROBE_URL, r.status().as_u16(), u, body.len(), parse_forms(&body).len(), t2.elapsed().as_secs_f32()));
        }
        Err(e) => out.push(format!("GET {} failed: {}", PROBE_URL, e)),
    }
    out
}

/// Percent-encode characters in a Location that browsers tolerate but the spec forbids (spaces, quotes, braces, non-ASCII).
fn sanitize_location(loc: &str) -> String {
    let mut out = String::with_capacity(loc.len() + 16);
    for c in loc.trim().chars() {
        match c {
            ' ' => out.push_str("%20"),
            '"' => out.push_str("%22"),
            '<' => out.push_str("%3C"),
            '>' => out.push_str("%3E"),
            '{' => out.push_str("%7B"),
            '}' => out.push_str("%7D"),
            '|' => out.push_str("%7C"),
            '\\' => out.push_str("%5C"),
            '^' => out.push_str("%5E"),
            '`' => out.push_str("%60"),
            c if (c as u32) < 0x21 || (c as u32) > 0x7e => {
                let mut b = [0u8; 4];
                for byte in c.encode_utf8(&mut b).bytes() {
                    out.push_str(&format!("%{:02X}", byte));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// GET and follow redirects ourselves (at most `max`). Returns (final URL, body, URL chain).
fn fetch_following(a: &ureq::Agent, start: &str, max: usize) -> Result<(String, String, Vec<String>)> {
    let mut url = start.to_string();
    let mut chain = vec![url.clone()];
    for _ in 0..=max {
        let mut r = a.get(&url).call().map_err(|e| anyhow!("{}", e))?;
        let st = r.status().as_u16();
        if (300..400).contains(&st) {
            let Some(loc) = r.headers().get("location").and_then(|v| v.to_str().ok()).map(sanitize_location) else {
                let body = r.body_mut().read_to_string().unwrap_or_default();
                return Ok((url, body, chain));
            };
            url = absolutize(&url, &loc);
            chain.push(url.clone());
            continue;
        }
        let body = r.body_mut().read_to_string().unwrap_or_default();
        return Ok((url, body, chain));
    }
    Err(anyhow!("more than {} redirects", max))
}

/// Like fetch_following, but the first hop carries a Referer (browsers send one on link clicks; some portal grant endpoints check it).
fn fetch_with_referer(a: &ureq::Agent, start: &str, referer: &str, max: usize) -> Result<(String, String, Vec<String>)> {
    if referer.is_empty() {
        return fetch_following(a, start, max);
    }
    let mut r = a.get(start).header("Referer", referer).call().map_err(|e| anyhow!("{}", e))?;
    let st = r.status().as_u16();
    if (300..400).contains(&st) {
        if let Some(loc) = r.headers().get("location").and_then(|v| v.to_str().ok()).map(sanitize_location) {
            let next = absolutize(start, &loc);
            let (eff, body, mut chain) = fetch_following(a, &next, max)?;
            chain.insert(0, start.to_string());
            return Ok((eff, body, chain));
        }
    }
    let body = r.body_mut().read_to_string().unwrap_or_default();
    Ok((start.to_string(), body, vec![start.to_string()]))
}

fn write_dump(dump: &str) {
    *DUMP.lock().unwrap_or_else(|e| e.into_inner()) = dump.to_string();
}

/// Entry point. Requires the portal netns to exist (the caller does apply(Portal) first).
///
/// The page fetching and HTML parsing runs in a separate process: `toriid portal-worker`, inside the portal
/// netns, as nobody, with no_new_privs. Portal pages are hostile input; a parser bug there must not be a
/// bug in a root process with CAP_NET_ADMIN.
pub async fn run(gw: Option<Ipv4Addr>, dry: bool) -> Result<Report> {
    if !netns::exists() {
        return Err(anyhow!("portal netns does not exist"));
    }
    let resolvers: Vec<Ipv4Addr> = std::fs::read_to_string(format!("/etc/netns/{}/resolv.conf", PORTAL_NS))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver ").and_then(|s| s.trim().parse().ok()))
        .collect();
    let resolvers = if resolvers.is_empty() { vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)] } else { resolvers };
    let args = vec![
        "portal-worker".to_string(),
        gw.map(|g| g.to_string()).unwrap_or_else(|| "-".into()),
        if dry { "dry".into() } else { "live".into() },
        resolvers.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(","),
    ];
    let ns = std::fs::File::open(format!("/run/netns/{}", PORTAL_NS)).context("open portal netns")?;
    let exe = std::env::current_exe()?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(&args).env_clear().stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).kill_on_drop(true);
    let nsfd = std::os::fd::AsRawFd::as_raw_fd(&ns);
    unsafe {
        cmd.pre_exec(move || drop_into_portal(nsfd));
    }
    let child = cmd.spawn().context("starting portal worker")?;
    let out = tokio::time::timeout(Duration::from_secs(110), child.wait_with_output()).await.map_err(|_| anyhow!("portal worker timed out"))??;
    drop(ns);
    let mut rep: Report = serde_json::from_slice(&out.stdout).map_err(|e| anyhow!("portal worker failed ({}): {}", out.status, e))?;
    if !rep.dump.is_empty() {
        let _ = crate::util::write_atomic("/run/toriid/portal.dump", &std::mem::take(&mut rep.dump), 0o600);
    }
    Ok(rep)
}

/// Runs in the forked child before exec: enter the portal netns, then become nobody for good.
/// Only async-signal-safe calls (raw syscalls via libc).
fn drop_into_portal(nsfd: i32) -> std::io::Result<()> {
    unsafe {
        let ok = |r: i32| if r == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) };
        ok(libc::setns(nsfd, libc::CLONE_NEWNET))?;
        ok(libc::setgroups(0, std::ptr::null()))?;
        ok(libc::setresgid(NOBODY, NOBODY, NOBODY))?;
        ok(libc::setresuid(NOBODY, NOBODY, NOBODY))?;
        ok(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
    }
    Ok(())
}
const NOBODY: u32 = 65534;

static DUMP: Mutex<String> = Mutex::new(String::new());

/// `toriid portal-worker <gw|-> <dry|live> <resolver,...>`: internal, started by `run`. Prints one Report as JSON.
pub fn worker_main(args: &[String]) -> i32 {
    if nix::unistd::geteuid().is_root() {
        eprintln!("portal-worker must not run as root");
        return 2;
    }
    crate::journal::notice("toriid-portal", &format!("portal worker running as uid {} in the portal netns", nix::unistd::getuid()));
    let gw = args.first().and_then(|g| g.parse().ok());
    let dry = args.get(1).map(|d| d == "dry").unwrap_or(true);
    let resolvers: Vec<Ipv4Addr> = args.get(2).map(|r| r.split(',').filter_map(|x| x.parse().ok()).collect()).unwrap_or_default();
    let mut rep = run_inside(gw, resolvers, dry);
    rep.dump = std::mem::take(&mut *DUMP.lock().unwrap_or_else(|e| e.into_inner()));
    println!("{}", serde_json::to_string(&rep).unwrap_or_default());
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn login_button_text_counts() {
        let f = &parse_forms(r#"<form action="/a" method="post"><input type="hidden" name="t" value="1"><button name="go">Log in</button></form>"#)[0];
        assert!(score(f) > 10);
        assert!(!needs_user(f));
        assert_eq!(submission(f), vec![("t".to_string(), "1".to_string()), ("go".to_string(), "".to_string())]);
    }
    #[test]
    fn only_the_go_button_is_sent() {
        let f = &parse_forms(r#"<form action="/a"><input type="submit" name="decline" value="Decline"><input type="submit" name="ok" value="Connect"></form>"#)[0];
        assert_eq!(submission(f), vec![("ok".to_string(), "Connect".to_string())]);
    }
    #[test]
    fn required_input_goes_to_the_user() {
        let f = &parse_forms(r#"<form action="/a"><input type="email" name="email" required><input type="submit" value="Connect"></form>"#)[0];
        assert!(needs_user(f));
        let g = &parse_forms(r#"<form action="/a"><input type="email" name="email"><input type="submit" value="Connect"></form>"#)[0];
        assert!(!needs_user(g), "optional field: still a click-through");
        let h = &parse_forms(r#"<form action="/a"><input name="room" required value=""><input type="password" name="p"></form>"#)[0];
        assert!(needs_user(h));
    }
    #[test]
    fn single_login_link_is_followed() {
        let page = r#"<p>Welcome</p><a href="/terms">Terms of use</a> <a href="/grant?x=1"><span>Connect to Wi-Fi</span></a>"#;
        assert_eq!(go_link(page).as_deref(), Some("/grant?x=1"));
        let ambiguous = r#"<a href="/a">Log in</a><a href="/b">Connect</a>"#;
        assert_eq!(go_link(ambiguous), None, "two candidates: leave it to the user");
        assert_eq!(go_link(r#"<a href="javascript:go()">Log in</a>"#), None);
    }
    const RUCKUS: &str = r#"<html><head><script>function accept_terms(){document.getElementById("tF1").submit();}</script></head><body>
<form method="post" action="/forms/guest_toued" id="tF1">
<input type="hidden" name="origurl" value="http%3a%2f%2fneverssl%2ecom%2f">
<textarea id="tou" rows="15" readonly="true">Terms</textarea>
<a id="accept_terms" onClick="accept_terms();"><button type="text" name="ok">Accept and Continue</button></a>
</form></body></html>"#;
    #[test]
    fn ruckus_form() {
        let forms = parse_forms(RUCKUS);
        assert_eq!(forms.len(), 1);
        let f = &forms[0];
        assert_eq!(f.action, "/forms/guest_toued");
        assert_eq!(f.method, "post");
        let names: Vec<_> = f.fields.iter().filter_map(|x| x.name.clone()).collect();
        assert_eq!(names, vec!["origurl", "ok"]);
        assert!(!f.fields.iter().any(|x| x.tag == "input" && x.ty == "text"), "button type=text is not a text box");
        assert_eq!(absolutize("http://192.0.2.220:9997/user/guest_tou.asp?x=1", &f.action), "http://192.0.2.220:9997/forms/guest_toued");
    }
    #[test]
    fn scoring_prefers_no_password() {
        let src = r#"<form action="/login"><input type="text" name="user"><input type="password" name="pw"><input type="submit"></form>
<form action="/accept"><input type="hidden" name="t" value="1"><input type="submit" name="agree" value="I agree"></form>"#;
        let forms = parse_forms(src);
        let best = forms.iter().max_by_key(|f| score(f)).unwrap();
        assert_eq!(best.action, "/accept");
    }
    #[test]
    fn attrs_quotes_and_bare() {
        let a = parse_attrs(r#" type=hidden name="a b" value='x&amp;y' disabled"#);
        assert_eq!(a["type"], "hidden");
        assert_eq!(a["name"], "a b");
        assert_eq!(a["value"], "x&y");
        assert_eq!(a["disabled"], "");
    }
    #[test]
    fn location_with_spaces() {
        let l = sanitize_location("https://cp.example.com/x?ua=Mozilla/5.0 (X11; Linux) Gecko&cm=aa:bb");
        assert_eq!(l, "https://cp.example.com/x?ua=Mozilla/5.0%20(X11;%20Linux)%20Gecko&cm=aa:bb");
        assert!(url::Url::parse(&l).is_ok());
    }
    #[test]
    fn dns_roundtrip_packet() {
        let p = dns_query_packet("neverssl.com", 0x1234);
        assert_eq!(&p[..2], &[0x12, 0x34]);
        assert_eq!(p[12], 8); // "neverssl"
        // hand-built answer: header + question + one A record
        let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(&p[12..]);
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 34, 223, 124, 45]);
        assert_eq!(dns_parse_a(&r, 0x1234), vec![Ipv4Addr::new(34, 223, 124, 45)]);
    }
    #[test]
    fn meraki_splash() {
        // shape of a real Meraki splash URL (identifiers replaced with placeholders)
        let u = "https://splash.example.com/?base_grant_url=https%3A%2F%2Fna.network-auth.com%2Fsplash%2FAbCdEfGh.0.1234%2Fgrant&gateway_id=100000000000001&node_id=100000000000001&user_continue_url=http%3A%2F%2Fneverssl.com%2F&client_ip=192.0.2.127&client_mac=00:00:00:00:00:00&node_mac=00:00:5e:00:53:01";
        let g = meraki_grant_url(u).unwrap();
        assert_eq!(g, "https://na.network-auth.com/splash/AbCdEfGh.0.1234/grant?continue_url=http%3A%2F%2Fneverssl.com%2F&duration=28800");
    }
    #[test]
    fn meraki_rejects_foreign_grant_host() {
        let u = "https://x.example/?base_grant_url=https%3A%2F%2Fevil.example%2Fgrant";
        assert!(meraki_grant_url(u).is_none());
        let u = "https://x.example/?base_grant_url=http%3A%2F%2Fna.network-auth.com%2Fgrant";
        assert!(meraki_grant_url(u).is_none(), "non-https is left alone");
        let u = "https://x.example/?base_grant_url=https%3A%2F%2Fnetwork-auth.com.evil.example%2Fgrant";
        assert!(meraki_grant_url(u).is_none(), "suffix spoofing");
        assert!(meraki_grant_url("https://x.example/?a=b").is_none());
    }
    #[test]
    fn meraki_default_continue() {
        let u = "https://x.example/?base_grant_url=https%3A%2F%2Fn123.network-auth.com%2Fsplash%2Fgrant";
        assert_eq!(meraki_grant_url(u).unwrap(), "https://n123.network-auth.com/splash/grant?continue_url=http%3A%2F%2Fneverssl.com%2F&duration=28800");
    }
    #[test]
    fn meta_refresh_parses() {
        assert_eq!(meta_refresh(r#"<html><meta http-equiv="refresh" content="0; url=http://neverssl.com/?a=1&amp;b=2"></html>"#).as_deref(), Some("http://neverssl.com/?a=1&b=2"));
        assert_eq!(meta_refresh(r#"<META HTTP-EQUIV="Refresh" CONTENT="2;URL='/next'">"#).as_deref(), Some("/next"));
        assert!(meta_refresh("<p>hi</p>").is_none());
        assert!(meta_refresh(r#"<meta http-equiv="refresh" content="30">"#).is_none(), "interval only, no target");
    }
}
