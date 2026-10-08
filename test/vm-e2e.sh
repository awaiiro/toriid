#!/usr/bin/env bash
# End-to-end test on a DISPOSABLE VM (it rewires the VM's networking). Run as root from the source tree
# after `cargo build --release`:
#
#   sudo test/vm-e2e.sh                 # detaches itself; results in /root/toriid-e2e.log
#
# It cuts ssh while the kill switch is up, so it runs detached and always ends with `torii down`
# (plus a 15-minute safety timer that flushes nftables no matter what).
#
# Simulated world, all inside the VM:
#
#   [root ns = laptop, toriid]  eth1 192.0.2.2 ──── isp-l 192.0.2.1  [isp netns]  ── wan (macvlan on the
#                                                   isp-u 198.51.100.1             VM's NIC, NAT to the
#                                                       │                          real internet)
#                                                   up-i 198.51.100.20  [vpn netns]: WireGuard server,
#                                                                         NAT for tunnel clients
#
# The isp can (a) block UDP to the VPN, (b) act as a captive portal: HTTP from clients that have not
# accepted the terms is redirected to a click-through page, everything else except DNS is dropped.
set -uo pipefail
SRC=$(cd "$(dirname "$0")/.." && pwd)
LOG=/root/toriid-e2e.log

if [ "${1:-}" != --inner ]; then
    [ "$(id -u)" = 0 ] || { echo "run as root on a disposable VM" >&2; exit 1; }
    [ -x "$SRC/target/release/toriid" ] || { echo "build first: cargo build --release" >&2; exit 1; }
    systemd-run --quiet --on-active=900 --unit toriid-e2e-safety /usr/sbin/nft flush ruleset
    systemd-run --quiet --unit toriid-e2e --property=StandardOutput=file:$LOG --property=StandardError=file:$LOG "$0" --inner
    echo "started; results in $LOG (ssh drops while the kill switch is up, reconnect in ~5 min)"
    exit 0
fi

pass=0 fail=0
ok()  { echo "  pass $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
not() { ! "$@"; }
state_is_not() { [ "$(st "['state']")" != "$1" ]; }
isp() { ip netns exec isp "$@"; }
vpn() { ip netns exec vpn "$@"; }
st() { torii status --json | python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
wait_state() { # wait_state <state> <seconds>
    for _ in $(seq 1 "$2"); do [ "$(st "['state']")" = "$1" ] && return 0; sleep 1; done
    return 1
}
direct_out() { curl -4 -s -m 4 --interface eth1 -o /dev/null http://1.1.1.1/; }   # bypassing the tunnel; no DNS involved
via_default() { curl -4 -s -m 8 -o /dev/null https://icanhazip.com/; }

echo "== setup $(date -u +%FT%TZ)"
# leftovers from a previous run
pkill -f "ThreadingHTTPServer" 2>/dev/null; systemctl stop toriid 2>/dev/null; nft flush ruleset 2>/dev/null
rm -rf /run/toriid /var/lib/toriid      # a fresh boot: no "manually turned off" flag, no per-network memory
ip netns del isp 2>/dev/null; ip netns del vpn 2>/dev/null; ip link del eth1 2>/dev/null
if ! ip route show default | grep -q .; then ip route add default via "$(ip -4 route show proto dhcp | awk '/scope link/ && $1 !~ /\// {print $1; exit}')" 2>/dev/null; fi
PHY=$(ip -o route show default | awk '{print $5; exit}')
PHYGW=$(ip -o route show default | awk '{print $3; exit}')
WAN_IP=$(ip -o -4 addr show "$PHY" | awk '{print $4}' | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3".200"}')

ip netns add isp; ip netns add vpn
isp ip link set lo up; vpn ip link set lo up
ip link add link "$PHY" name wan type macvlan mode bridge; ip link set wan netns isp
isp ip addr add "$WAN_IP/24" dev wan; isp ip link set wan up; isp ip route add default via "$PHYGW"
ip link add eth1 type veth peer name isp-l; ip link set isp-l netns isp
ip addr add 192.0.2.2/24 dev eth1; ip link set eth1 up
isp ip addr add 192.0.2.1/24 dev isp-l; isp ip link set isp-l up
ip link add isp-u type veth peer name up-i; ip link set isp-u netns isp; ip link set up-i netns vpn
isp ip addr add 198.51.100.1/24 dev isp-u; isp ip link set isp-u up
vpn ip addr add 198.51.100.20/24 dev up-i; vpn ip link set up-i up; vpn ip route add default via 198.51.100.1
isp sysctl -qw net.ipv4.ip_forward=1; vpn sysctl -qw net.ipv4.ip_forward=1

# the laptop's way out is now eth1; its management NIC keeps only the LAN route (for ssh afterwards)
ip route del default; ip route add default via 192.0.2.1 dev eth1

isp nft -f - <<'EOF'
table ip isp {
    set granted { type ipv4_addr; }
    chain pre {
        type nat hook prerouting priority dstnat;
        # captive portal (enabled by adding the element "on" to portal_on)
        iifname "isp-l" ip saddr != @granted ip daddr != 192.0.2.1 tcp dport 80 meta mark 0x1 dnat to 192.0.2.1:8080
    }
    chain filt {
        type filter hook forward priority filter; policy accept;
        iifname "isp-l" meta mark 0x1 ip saddr != @granted udp dport != 53 drop
        iifname "isp-l" meta mark 0x1 ip saddr != @granted tcp dport != 53 drop
        iifname "isp-l" udp dport 51820 meta mark 0x2 drop
    }
    chain mark_in {
        type filter hook prerouting priority mangle;
        iifname "isp-l" meta mark set 0x0
    }
    chain post {
        type nat hook postrouting priority srcnat;
        oifname "wan" masquerade
    }
}
EOF
portal_on()  { isp nft add rule ip isp mark_in iifname "isp-l" meta mark set meta mark or 0x1 comment \"portal\"; }
udp_block()  { isp nft add rule ip isp mark_in iifname "isp-l" meta mark set meta mark or 0x2 comment \"udpblock\"; }
isp_reset()  { isp nft flush chain ip isp mark_in; isp nft add rule ip isp mark_in iifname "isp-l" meta mark set 0x0; isp nft flush set ip isp granted; }

# captive portal web server in the isp
isp python3 - <<'PY' >/dev/null 2>&1 &
import http.server, subprocess
FORM = b"""<html><body><h1>Guest Wi-Fi</h1><form method="post" action="/accept">
<input type="hidden" name="token" value="t0k3n"><input type="checkbox" name="agree" value="1" checked> I accept the terms
<input type="submit" value="Accept and Continue"></form></body></html>"""
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/login"):
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(FORM)
        else:
            self.send_response(302); self.send_header("Location", "http://192.0.2.1:8080/login"); self.end_headers()
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        subprocess.run(["nft", "add", "element", "ip", "isp", "granted", "{", self.client_address[0], "}"])
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(b"Welcome")
http.server.ThreadingHTTPServer(("192.0.2.1", 8080), H).serve_forever()
PY

vpn nft -f - <<'EOF'
table ip vpn {
    chain post {
        type nat hook postrouting priority srcnat;
        ip saddr 10.77.0.0/24 oifname "up-i" masquerade
    }
}
EOF
umask 022
mkdir -p /etc/toriid; chmod 755 /etc/toriid
umask 077
SK=$(wg genkey); SP=$(echo "$SK" | wg pubkey); CK=$(wg genkey); CP=$(echo "$CK" | wg pubkey)
vpn ip link add wg0 type wireguard
vpn wg set wg0 listen-port 51820 private-key <(echo "$SK") peer "$CP" allowed-ips 10.77.0.2/32
vpn ip addr add 10.77.0.1/24 dev wg0; vpn ip link set wg0 up
mkdir -p /etc/wireguard /etc/toriid
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $CK
Address = 10.77.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = $SP
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.20:51820
PersistentKeepalive = 25
EOF
cat > /etc/toriid/config.toml <<EOF
[daemon]
operator = "ubuntu"
[tunnels]
ladder = ["wireguard"]
[watchdog]
auto_portal = true
[tailscale]
integrate = false
EOF
chmod 644 /etc/toriid/config.toml
id guest >/dev/null 2>&1 || useradd -M guest

install -m755 "$SRC/target/release/toriid" /usr/bin/toriid; ln -sf toriid /usr/bin/torii
install -m644 "$SRC"/dist/systemd/*.service /etc/systemd/system/
install -Dm644 "$SRC/dist/tmpfiles/toriid.conf" /etc/tmpfiles.d/toriid.conf; systemd-tmpfiles --create toriid.conf
# resolved binds each query to the link that owns the DNS server; give the new uplink its own
resolvectl dns eth1 1.1.1.1; resolvectl domain eth1 "~."; resolvectl dns "$PHY" ""; resolvectl domain "$PHY" ""
systemctl daemon-reload
echo "check-config: $(torii check-config 2>&1)"
check "outside world reachable before toriid" direct_out

echo "== A: open network, protection comes up by itself"
systemctl start toriid
check "reaches protected" wait_state protected 90
check "tunnel is wireguard" test "$(st "['tunnel']")" = wireguard
check "exit IP reported" test -n "$(st "['exit_ip']")"
check "traffic through the tunnel works" via_default
check "direct traffic around the tunnel is blocked" not direct_out
check "kill switch persisted for boot" test -s /var/lib/toriid/killswitch.nft

echo "== B: network blocks UDP, kill switch holds"
udp_block
vpn ip link set wg0 down; vpn ip link set wg0 up      # force a fresh handshake
torii up wireguard >/dev/null 2>&1
check "status says blocked, not protected" state_is_not protected
check "nothing leaks around the tunnel while blocked" not direct_out
check "nothing leaks via the default route while blocked" not curl -4 -s -m 4 -o /dev/null http://1.1.1.1/
isp_reset
torii up >/dev/null 2>&1
check "recovers once UDP is allowed again" wait_state protected 60

echo "== C: captive portal"
portal_on
torii up wireguard >/dev/null 2>&1
check "tunnel cannot come up behind the portal" state_is_not protected
torii portal-auto >/tmp/portal-auto.out 2>&1; echo "  portal-auto rc=$?"; sed 's/^/    /' /tmp/portal-auto.out | tail -15
check "portal granted the laptop" bash -c 'ip netns exec isp nft list set ip isp granted | grep -q 192.0.2.2'
torii up >/dev/null 2>&1
check "protected after the portal" wait_state protected 60
check "portal HTML was parsed by an unprivileged worker (uid 65534)" bash -c 'journalctl -t toriid-portal --no-pager | grep -q "portal worker running as uid 65534"'
isp_reset

echo "== D: permissions"
check "operator may bring protection up without sudo" runuser -u ubuntu -- torii up
check "operator may not remove protection" not runuser -u ubuntu -- torii down
check "any user may read status" runuser -u guest -- torii status --json
check "other users may not control the daemon" not runuser -u guest -- torii check
check "other users may not read the wstunnel log" not runuser -u guest -- torii wst log

echo "== E: daemon restart keeps protection"
systemctl restart toriid
check "protected again after restart" wait_state protected 60

echo "== F: boot without auto_portal comes up by itself"
sed -i '/^\[watchdog\]/a auto_portal = false' /etc/toriid/config.toml
systemctl stop toriid; rm -f /run/toriid/mode /run/toriid/health.json; nft -f /var/lib/toriid/killswitch.nft
ip link del wg0 2>/dev/null
systemctl start toriid
check "protected after a restart with only the boot kill switch loaded" wait_state protected 150
sed -i '/^auto_portal = false$/d' /etc/toriid/config.toml

echo "== teardown"
torii down >/dev/null 2>&1
check "down removes the kill switch" not nft list table inet ks
systemctl stop toriid
ip route del default; ip route add default via "$PHYGW" dev "$PHY"
resolvectl revert "$PHY"; resolvectl dns "$PHY" 1.1.1.1 9.9.9.9
systemctl stop toriid-e2e-safety.timer 2>/dev/null
journalctl -u toriid --no-pager -o short-iso > /root/toriid-e2e.journal
echo
echo "$pass passed, $fail failed"
