#!/usr/bin/env bash
# toriid carrier server: wstunnel behind Caddy, for the TLS rung of the tunnel ladder.
#
#   sudo ./install.sh --upstream 198.51.100.20:51820 --domain notes.example.org
#   sudo ./install.sh --upstream 198.51.100.20:51820 --sslip            # no domain: <ip>.sslip.io
#
# What it builds:
#
#   Caddy :443   real Let's Encrypt certificate (TLS-ALPN-01, so only 443 needs to be open)
#     ├─ /<key>/*   → wstunnel on 127.0.0.1:8080 → UDP, only to --upstream
#     └─ anything else → a small static site
#
# An active prober sees an ordinary website with a valid certificate whose name matches the IP.
# The server is a relay only: WireGuard stays end-to-end between the laptop and the upstream
# endpoint, so this machine never sees plaintext and needs no WireGuard, routing or NAT.
#
# Safe to re-run. If a previous deployment exists, it is backed up and an automatic rollback is
# armed before anything changes; the rollback is cancelled only after the new setup passes a
# self-test through Caddy with a real wstunnel client. (Your own ssh session may be riding this
# very tunnel; if the new setup is broken you could not log back in to fix it.)
set -euo pipefail

# The version the client side is tested with; client and server must speak the same protocol.
WSTUNNEL_VERSION=10.6.2
LISTEN=127.0.0.1:8080
ROLLBACK_AFTER=420

UPSTREAM="" DOMAIN="" SSLIP=0 IP_CERT=0 DECOY=""
usage() {
    cat <<EOF
usage: sudo $0 --upstream HOST:PORT (--domain NAME | --sslip) [options]

  --upstream IP:PORT     WireGuard endpoint the relay may forward to (and nothing else)
  --domain NAME          a domain whose A record points at this server; pick a boring name
  --sslip                use <public-ip>.sslip.io instead of your own domain
  --ip-cert              also get a certificate for the bare IP (needed by the "clean" variant:
                         no SNI + verified certificate). Requires Caddy >= 2.10; experimental
  --decoy DIR            serve this directory as the decoy site instead of the built-in page
  --wstunnel-version V   default $WSTUNNEL_VERSION
EOF
    exit 2
}
while [ $# -gt 0 ]; do
    case "$1" in
        --upstream) UPSTREAM=${2:?}; shift 2 ;;
        --domain) DOMAIN=${2:?}; shift 2 ;;
        --sslip) SSLIP=1; shift ;;
        --ip-cert) IP_CERT=1; shift ;;
        --decoy) DECOY=${2:?}; shift 2 ;;
        --wstunnel-version) WSTUNNEL_VERSION=${2:?}; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

G='\033[32m'; R='\033[31m'; Y='\033[33m'; B='\033[1m'; N='\033[0m'
ok()   { printf "  ${G}ok${N}   %s\n" "$*"; }
warn() { printf "  ${Y}warn${N} %s\n" "$*"; }
die()  { printf "  ${R}fail${N} %s\n" "$*" >&2; exit 1; }
hdr()  { printf "\n${B}%s${N}\n" "$*"; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[[ "$UPSTREAM" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}$ ]] || die "--upstream must be IPv4:PORT (the kill switch and the relay both pin addresses)"
[ -n "$DOMAIN" ] || [ "$SSLIP" = 1 ] || usage
command -v systemctl >/dev/null || die "systemd is required"

HERE=$(cd "$(dirname "$0")" && pwd)
D=/etc/wstunnel
CF=/etc/caddy/Caddyfile
UNIT=/etc/systemd/system/wstunnel-server.service
WST=/usr/local/bin/wstunnel
STAMP=$(date +%Y%m%d-%H%M%S)

hdr "1. Preflight"
PUBLIC_IP=$(curl -4 -s --max-time 8 https://api.ipify.org || true)
[[ "$PUBLIC_IP" =~ ^[0-9.]+$ ]] || die "could not determine this server's public IPv4"
ok "public IP $PUBLIC_IP"
if [ "$SSLIP" = 1 ]; then
    DOMAIN="${PUBLIC_IP//./-}.sslip.io"
fi
resolved=$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}')
[ "$resolved" = "$PUBLIC_IP" ] || die "$DOMAIN resolves to '${resolved:-nothing}', not $PUBLIC_IP; fix DNS first"
ok "$DOMAIN -> $PUBLIC_IP"
if ss -Htlnp 'sport = :443' | grep -qv caddy; then
    die "port 443 is taken by something other than Caddy: $(ss -Htlnp 'sport = :443' | head -1)"
fi

hdr "2. Packages"
if ! command -v caddy >/dev/null; then
    if command -v apt-get >/dev/null; then
        apt-get update -qq && apt-get install -y -qq caddy
    elif command -v pacman >/dev/null; then
        pacman -S --noconfirm --needed caddy
    elif command -v dnf >/dev/null; then
        dnf install -y caddy
    else
        die "install Caddy yourself (https://caddyserver.com/docs/install), then re-run"
    fi
fi
ok "$(caddy version | head -1)"
if [ "$IP_CERT" = 1 ]; then
    cv=$(caddy version | grep -oE '^v?[0-9]+\.[0-9]+' | tr -d v)
    [ "$(printf '%s\n2.10\n' "$cv" | sort -V | head -1)" = 2.10 ] || die "--ip-cert needs Caddy >= 2.10 (have $cv)"
fi

have=$("$WST" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
if [ "$have" != "$WSTUNNEL_VERSION" ]; then
    case "$(uname -m)" in x86_64) A=amd64 ;; aarch64) A=arm64 ;; *) die "unsupported arch $(uname -m)" ;; esac
    url="https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}/wstunnel_${WSTUNNEL_VERSION}_linux_${A}.tar.gz"
    tmp=$(mktemp -d)
    curl -fsSL "$url" -o "$tmp/w.tgz" || die "download failed: $url"
    tar -xzf "$tmp/w.tgz" -C "$tmp" wstunnel
    install -m 0755 "$tmp/wstunnel" "$WST"
    ok "wstunnel $WSTUNNEL_VERSION (sha256 $(sha256sum "$tmp/w.tgz" | cut -c1-16)...; compare with the release page)"
    rm -rf "$tmp"
else
    ok "wstunnel $have already installed"
fi
install -m 0755 "$HERE/wst-keys.sh" /usr/local/sbin/wst-keys
ok "/usr/local/sbin/wst-keys"

hdr "3. Backup and rollback guard"
ARMED=0
backup() { [ -e "$1" ] && cp -a "$1" "$1.bak.$STAMP" || true; }
for f in "$CF" "$UNIT" "$D/keys" "$D/target" "$D/restrict.yaml" /etc/caddy/wst-paths.caddy; do backup "$f"; done
if systemctl is-active --quiet wstunnel-server || systemctl is-active --quiet caddy; then
    cat > "$D/.rollback-$STAMP" <<EOF
#!/bin/bash
for f in "$CF" "$UNIT" "$D/keys" "$D/target" "$D/restrict.yaml" /etc/caddy/wst-paths.caddy; do
    [ -e "\$f.bak.$STAMP" ] && cp -a "\$f.bak.$STAMP" "\$f"
done
systemctl daemon-reload; systemctl restart wstunnel-server; systemctl reload-or-restart caddy
logger -t toriid-server "install $STAMP rolled back"
EOF
    chmod 700 "$D/.rollback-$STAMP"
    systemd-run --quiet --on-active="$ROLLBACK_AFTER" --unit="toriid-rollback-$STAMP" "$D/.rollback-$STAMP"
    ARMED=1
    ok "existing deployment found: automatic rollback in ${ROLLBACK_AFTER}s unless the self-test passes"
else
    ok "fresh install, nothing to roll back"
fi

hdr "4. Keys"
mkdir -p "$D"; chmod 700 "$D"
if [ ! -s "$D/keys" ]; then
    ( umask 077; tr -dc 'A-Za-z0-9_-' </dev/urandom | head -c 32 > "$D/keys"; echo >> "$D/keys" )
    ok "generated a new access key"
else
    ok "keeping existing keys ($(grep -c . "$D/keys"))"
fi
printf '%s\n' "$UPSTREAM" > "$D/target"; chmod 600 "$D/target"
/usr/local/sbin/wst-keys init

hdr "5. wstunnel service"
cat > "$UNIT" <<EOF
[Unit]
Description=wstunnel relay for toriid (Caddy -> ${LISTEN} -> ${UPSTREAM})
After=network-online.target
Wants=network-online.target

[Service]
# Loopback only: nothing reaches wstunnel except through Caddy, and Caddy only forwards known key paths.
# restrict.yaml limits each key to UDP towards the upstream endpoint; reloaded automatically on change.
ExecStart=${WST} server --restrict-config ${D}/restrict.yaml ws://${LISTEN}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=${D}

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --quiet wstunnel-server
systemctl restart wstunnel-server
ok "wstunnel-server listening on $LISTEN"

hdr "6. Decoy site"
mkdir -p /var/www/decoy
if [ -n "$DECOY" ]; then
    cp -a "$DECOY"/. /var/www/decoy/
elif [ ! -f /var/www/decoy/index.html ]; then
    cat > /var/www/decoy/index.html <<'HTML'
<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>notes</title>
<style>
 body{font:16px/1.7 system-ui,sans-serif;max-width:34rem;margin:6rem auto;padding:0 1.2rem;color:#222;background:#fafafa}
 h1{font-size:1.3rem;font-weight:600}
 footer{margin-top:3rem;font-size:.85rem;color:#888}
</style>
<h1>notes</h1>
<p>A small place for reading notes and half-finished thoughts.</p>
<p>Nothing here is organised yet.</p>
<footer>static, no tracking</footer>
HTML
fi
chown -R caddy:caddy /var/www/decoy 2>/dev/null || true
ok "/var/www/decoy"

hdr "7. Caddy"
site_body() {
    cat <<EOF
    import /etc/caddy/wst-paths.caddy
    handle @wst {
        reverse_proxy ${LISTEN}
    }
    handle {
        root * /var/www/decoy
        file_server
    }
    # No access log: a relay should not keep a record of who connected when.
    log {
        output discard
    }
EOF
}
{
    echo "# generated by toriid server/install.sh"
    echo "{"
    echo "    # Only 443 is needed: certificates via TLS-ALPN-01, no port-80 redirect listener."
    echo "    auto_https disable_redirects"
    echo "    # Clients that send no SNI get the real certificate instead of a TLS alert."
    echo "    default_sni ${DOMAIN}"
    echo "}"
    echo
    echo "${DOMAIN} {"
    site_body
    echo "}"
    if [ "$IP_CERT" = 1 ]; then
        echo
        echo "# Same content on the bare IP, so the name and the address can never disagree."
        echo "https://${PUBLIC_IP} {"
        echo "    tls {"
        echo "        issuer acme {"
        echo "            profile shortlived"
        echo "        }"
        echo "    }"
        site_body
        echo "}"
    fi
} > "$CF.new"
caddy validate --adapter caddyfile --config "$CF.new" >/dev/null 2>&1 || { caddy validate --adapter caddyfile --config "$CF.new" || true; rm -f "$CF.new"; die "generated Caddyfile is invalid"; }
mv -f "$CF.new" "$CF"
systemctl enable --quiet caddy
systemctl reload-or-restart caddy
ok "Caddy serving $DOMAIN"

hdr "8. Self-test"
ok_cert=0
for i in $(seq 1 30); do
    if curl -s --max-time 5 -o /dev/null "https://${DOMAIN}/"; then ok_cert=1; break; fi
    sleep 3
done
[ "$ok_cert" = 1 ] || die "no valid certificate for $DOMAIN after 90s (journalctl -u caddy); rollback is armed"
ok "certificate valid"
/usr/local/sbin/wst-keys selftest || die "tunnel self-test through Caddy failed; rollback is armed"
if [ "$ARMED" = 1 ]; then
    systemctl stop "toriid-rollback-$STAMP.timer" 2>/dev/null || true
    rm -f "$D/.rollback-$STAMP"
    ok "rollback cancelled"
fi

hdr "Done. Client side (/etc/toriid/wstunnel.conf):"
cat <<EOF

WST_SERVERS="${PUBLIC_IP}"
WST_SERVER=${PUBLIC_IP}
WST_PORT=443
WST_SECRET=<run: sudo tail -n1 ${D}/keys>
WST_UPSTREAM=${UPSTREAM}
WST_LOCAL_PORT=51822
WST_VERIFY=yes
WST_SNI_NAMED=${DOMAIN}
WST_SNI_FALLBACK=www.example.com

EOF
[ "$IP_CERT" = 1 ] || warn "without --ip-cert the 'clean' variant (no SNI, verified) cannot verify; the client falls back to 'named'"
