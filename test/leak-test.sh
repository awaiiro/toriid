#!/usr/bin/env bash
# Kill switch leak test: loads the real rendered ruleset into an isolated network namespace and checks,
# with real packets, that nothing leaves except through the pinned holes.
#
#   test/leak-test.sh                 # unprivileged, via user namespaces (needs unshare + iproute2 + nft + python3)
#   sudo TORIID_RULES=ks.nft test/leak-test.sh --as-root   # where unprivileged user namespaces are blocked
#
# Topology, all inside throwaway namespaces:
#
#   "laptop" netns  ──vh/vi──  "inet" netns: 192.0.2.1, plus 198.51.100.7 (the carrier) and 203.0.113.9 (anything else)
#        └──torii-tcp/tp──────┘   a stand-in tunnel interface, routed explicitly
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" != "--inner" ]; then
    rules=$(mktemp)
    if [ -n "${TORIID_RULES:-}" ]; then
        cp "$TORIID_RULES" "$rules"        # pre-rendered (CI renders as the user, then runs this as root)
    else
        TORIID_DUMP_RULESET="$rules" cargo test --quiet dump_full_ruleset >/dev/null
    fi
    if [ "${1:-}" = "--as-root" ]; then
        exec unshare -nm --propagation private "$0" --inner "$rules"
    fi
    exec unshare -rnm --propagation private "$0" --inner "$rules"
fi
RULES=$2

pass=0 fail=0
ok()  { printf '  \033[32mpass\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }
expect() { # expect allow|block "description" command...
    local want=$1 what=$2; shift 2
    if "$@" >/dev/null 2>&1; then got=allow; else got=block; fi
    [ "$got" = "$want" ] && ok "$what ($got)" || bad "$what: expected $want, got $got"
}

mount -t tmpfs none /run
mkdir -p /run/netns
ip link set lo up
ip netns add inet
IN="ip netns exec inet"

ip link add vh type veth peer name vi
ip link set vi netns inet
ip addr add 192.0.2.2/24 dev vh; ip link set vh up
ip route add default via 192.0.2.1
$IN ip link set lo up
$IN ip addr add 192.0.2.1/24 dev vi; $IN ip link set vi up
$IN ip addr add 198.51.100.7/32 dev lo
$IN ip addr add 203.0.113.9/32 dev lo
$IN ip route add 192.0.2.0/24 dev vi 2>/dev/null || true

# stand-in tunnel: an interface whose name the ruleset trusts
ip link add torii-tcp type veth peer name tp
ip link set tp netns inet
ip addr add 10.66.0.2/30 dev torii-tcp; ip link set torii-tcp up
$IN ip addr add 10.66.0.1/30 dev tp; $IN ip link set tp up
$IN ip route add 10.66.0.0/30 dev tp 2>/dev/null || true

# servers in "inet": TCP echo-ish sink on :80 and :443, UDP sink on :51820/:51821; they log what they receive
LOG=$(mktemp -d)
$IN python3 - "$LOG" <<'PY' &
import socket, sys, threading, os
log = sys.argv[1]
def tcp(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(16)
    while True:
        c, _ = s.accept()
        def h(c=c):
            while True:
                d = c.recv(4096)
                if not d: break
                with open(f"{log}/tcp{port}", "ab") as f: f.write(d)
        threading.Thread(target=h, daemon=True).start()
def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", port))
    while True:
        d, _ = s.recvfrom(4096)
        with open(f"{log}/udp{port}", "ab") as f: f.write(d)
for p in (80, 443): threading.Thread(target=tcp, args=(p,), daemon=True).start()
for p in (51820, 51821): threading.Thread(target=udp, args=(p,), daemon=True).start()
threading.Event().wait()
PY
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$LOG" "$RULES"' EXIT
sleep 0.5

tcp_to() { timeout 2 python3 -c "import socket,sys; s=socket.create_connection((sys.argv[1], int(sys.argv[2])), 1.5); s.sendall(b'x')" "$1" "$2"; }
udp_seen() { # udp_seen host port: send a datagram, succeed if the server logged it
    rm -f "$LOG/udp$2"
    python3 -c "import socket,sys; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'probe', (sys.argv[1], int(sys.argv[2])))" "$1" "$2" || return 1
    sleep 0.3; [ -s "$LOG/udp$2" ]
}

echo "before the kill switch"
expect allow "TCP to an arbitrary host" tcp_to 203.0.113.9 80

nft -f "$RULES"
echo "kill switch loaded"
expect block "TCP to an arbitrary host" tcp_to 203.0.113.9 80
expect block "TCP to the gateway (LAN not trusted)" tcp_to 192.0.2.1 80
expect allow "UDP to the WireGuard carrier, pinned port" udp_seen 198.51.100.7 51820
expect block "UDP to the carrier, other port" udp_seen 198.51.100.7 51821
expect block "TCP to the carrier (hole is UDP only)" tcp_to 198.51.100.7 443
expect block "UDP to an arbitrary host" udp_seen 203.0.113.9 51820

echo "through the tunnel interface"
ip route add 203.0.113.9/32 via 10.66.0.1 dev torii-tcp
$IN ip route add 192.0.2.0/24 dev vi 2>/dev/null || true
expect allow "TCP to an arbitrary host via the tunnel" tcp_to 203.0.113.9 80

echo "tunnel drops mid-connection"
rm -f "$LOG/tcp443"
python3 - <<'PY' &
import socket, time
s = socket.create_connection(("203.0.113.9", 443), 2)
for i in range(30):
    try: s.send(b"tick\n")
    except OSError: break
    time.sleep(0.1)
PY
CL=$!
sleep 0.8
ip route del 203.0.113.9/32 via 10.66.0.1 dev torii-tcp      # tunnel route gone: traffic falls back to vh
before=$(stat -c %s "$LOG/tcp443" 2>/dev/null || echo 0)
sleep 1.5
after=$(stat -c %s "$LOG/tcp443" 2>/dev/null || echo 0)
wait $CL 2>/dev/null || true
if [ "$before" -gt 0 ] && [ "$after" = "$before" ]; then
    ok "established connection stops when the tunnel route disappears (no cleartext fallback)"
else
    bad "established connection: ${before} bytes before the drop, ${after} after (must not grow)"
fi

echo "trusted LAN"
nft add element inet ks lan_allow '{ 192.0.2.0/24 }'
expect allow "TCP to the gateway once the LAN is trusted" tcp_to 192.0.2.1 80
expect block "still no TCP to an arbitrary host" tcp_to 203.0.113.9 80
nft flush set inet ks lan_allow

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
