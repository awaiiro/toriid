//! Three probes:
//!   carrier(): bound to the physical NIC, TLS to the carrier server on 443. Three states: can't get out /
//!              TCP works but the certificate is wrong (a portal is impersonating it) / ok
//!   exit_ip(): exit IP via the default route, from several sources
//!   connectivity(): the NetworkManager-style 204 check, done ourselves (NetworkManager is not used)
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    Unreachable, // can't resolve / can't connect / timeout: nothing gets out on the physical link
    BadCert,     // TCP connected but the cert isn't the Let's Encrypt cert for this IP: a portal's transparent proxy is impersonating the carrier
    Ok,          // otherwise: the TLS handshake completed
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
}

/// Blocking; callers run it in spawn_blocking.
pub fn carrier(ip: IpAddr, port: u16, bind_dev: Option<&str>, verify: bool) -> Carrier {
    let addr = SocketAddr::new(ip, port);
    let sock = match Socket::new(if ip.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 }, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(_) => return Carrier::Unreachable,
    };
    if let Some(d) = bind_dev {
        let _ = sock.bind_device(Some(d.as_bytes()));
    }
    if sock.connect_timeout(&addr.into(), Duration::from_secs(2)).is_err() {
        return Carrier::Unreachable;
    }
    let mut tcp: TcpStream = sock.into();
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(3)));
    if !verify {
        return Carrier::Ok; // self-signed phase: the cert can't be verified, TCP only
    }
    let server_name = match rustls::pki_types::ServerName::try_from(ip.to_string()) {
        Ok(n) => n,
        Err(_) => return Carrier::Ok,
    };
    let mut conn = match rustls::ClientConnection::new(tls_config(), server_name) {
        Ok(c) => c,
        Err(_) => return Carrier::Ok,
    };
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    // write something to drive the handshake to completion
    match tls.write_all(b"GET / HTTP/1.0\r\n\r\n").and_then(|_| tls.flush()) {
        Ok(()) => {}
        Err(e) => return classify_tls_err(&e),
    }
    let mut buf = [0u8; 64];
    // Any successful read, even EOF, proves the handshake completed; the byte count is irrelevant.
    #[allow(clippy::unused_io_amount)]
    match tls.read(&mut buf) {
        Ok(_) => Carrier::Ok,
        Err(e) => classify_tls_err(&e),
    }
}

fn classify_tls_err(e: &std::io::Error) -> Carrier {
    let s = e.to_string().to_ascii_lowercase();
    if s.contains("certificate") || s.contains("invalidcertificate") || s.contains("unknownissuer") || s.contains("notvalidforname") {
        Carrier::BadCert
    } else if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        Carrier::Unreachable
    } else {
        // e.g. peer closed after the handshake: TCP and TLS got through, so this isn't "can't get out"
        Carrier::Ok
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    Ok,
    NoAnswer, // everything timed out / failed to connect: **unknown**
    Bad,      // got responses, but none was a valid answer
}

/// Exit IP from three sources. Blocking. Returns (verdict, IP).
pub fn exit_ip() -> (Reach, Option<String>) {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .ip_family(ureq::config::IpFamily::Ipv4Only)
        .build()
        .new_agent();
    let mut any_answer = false;
    for u in ["https://ipinfo.io/ip", "https://icanhazip.com", "https://ifconfig.me/ip"] {
        match agent.get(u).call() {
            Ok(mut r) => {
                any_answer = true;
                if let Ok(body) = r.body_mut().read_to_string() {
                    let ip = body.trim();
                    if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                        return (Reach::Ok, Some(ip.to_string()));
                    }
                }
            }
            Err(ureq::Error::StatusCode(_)) => any_answer = true,
            Err(_) => {}
        }
    }
    (if any_answer { Reach::Bad } else { Reach::NoAnswer }, None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conn {
    Full,
    Portal,  // got a page / redirect instead of 204
    Limited, // can't connect / timeout
    Unknown,
}
impl Conn {
    pub fn as_str(self) -> &'static str {
        match self {
            Conn::Full => "full",
            Conn::Portal => "portal",
            Conn::Limited => "limited",
            Conn::Unknown => "unknown",
        }
    }
    pub fn parse(s: &str) -> Conn {
        match s {
            "full" => Conn::Full,
            "portal" => Conn::Portal,
            "limited" => Conn::Limited,
            _ => Conn::Unknown,
        }
    }
}

/// Test connectivity from the place that will actually be let through. In portal mode the host is locked
/// down by the kill switch, so testing on the host always says limited, even after the user has clicked
/// through the portal page. In that case test inside the portal netns, the same path the portal browser uses.
pub fn connectivity_here() -> Conn {
    use crate::state::{Intent, Mode};
    if matches!(Intent::read(), Intent::Mode(Mode::Portal)) && crate::nl::netns::exists() {
        return crate::nl::netns::in_ns_blocking(|| Ok(connectivity())).unwrap_or(Conn::Unknown);
    }
    connectivity()
}

/// Connectivity check (plain HTTP, so a portal can intercept it). Blocking.
/// Two sites **in parallel**, 3s each: when a portal drops HTTP, the old serial 2x5s took 10s (10s of a
/// measured 45s resume); worst case is now 3s. Any 204 = full; any non-204 answer = portal.
pub fn connectivity() -> Conn {
    let urls = ["http://connectivitycheck.gstatic.com/generate_204", "http://www.msftconnecttest.com/connecttest.txt"];
    let (tx, rx) = std::sync::mpsc::channel::<Conn>();
    for u in urls {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(3))).max_redirects(0).http_status_as_error(false).build().new_agent();
            let r = match agent.get(u).call() {
                Ok(r) => {
                    let st = r.status().as_u16();
                    if st == 204 || (u.ends_with("connecttest.txt") && st == 200) {
                        Conn::Full
                    } else {
                        Conn::Portal
                    }
                }
                Err(_) => Conn::Limited,
            };
            let _ = tx.send(r);
        });
    }
    drop(tx);
    let mut seen_portal = false;
    for r in rx {
        match r {
            Conn::Full => return Conn::Full,
            Conn::Portal => seen_portal = true,
            _ => {}
        }
    }
    if seen_portal { Conn::Portal } else { Conn::Limited }
}

