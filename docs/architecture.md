# How toriid works

Only one process may change the network: the root daemon `toriid daemon`. Everything else either asks
it over a socket or reads the state files it writes. All numbers below (rule priorities, intervals,
addresses, limits) come from the source.

- [Processes and channels](#processes-and-channels)
- [The tunnel ladder](#the-tunnel-ladder)
- [A packet's path through the laptop](#a-packets-path-through-the-laptop)
- [Watchdog](#watchdog)
- [Captive portals](#captive-portals)
- [Who may do what](#who-may-do-what)
- [Files](#files)

## Processes and channels

```mermaid
flowchart TB
  subgraph user["user session"]
    cli["torii (CLI)"]
    bar["status bar<br/>torii watch / bar"]
    notify["toriid-notify"]
    ff["portal browser<br/>throwaway Firefox profile"]
  end
  subgraph root["toriid daemon (root, toriid.service)"]
    sock["socket server<br/>/run/toriid/sock<br/>SO_PEERCRED, auth before queueing"]
    actor["actor: one action at a time<br/>modes / watchdog / portal"]
    events["events<br/>tick 60s, fast tick 5s,<br/>netlink, Wi-Fi, resume"]
  end
  subgraph helpers["helpers started by the daemon"]
    worker["portal-worker<br/>nobody, no_new_privs, portal netns"]
    wst["wstunnel client<br/>root child, key via env"]
    ovpn["openvpn-client@…<br/>systemd unit"]
  end
  subgraph kernel["kernel"]
    nft["nftables table inet ks"]
    rules["ip rules / tables"]
    ifs["wg0, OpenVPN interface"]
    ns["portal netns"]
  end
  dbus["D-Bus: iwd or NetworkManager, systemd-resolved,<br/>logind, systemd; tailscaled local API"]

  cli -- "one JSON line in, progress lines out" --> sock
  sock --> actor
  events --> actor
  actor -- "writes /run/toriid/*" --> bar
  actor -- "health.json" --> notify
  actor -- "systemd-run + runuser in netns" --> ff
  actor -- "fork, setns, setuid nobody" --> worker
  actor -- spawn --> wst
  actor -- "start / stop" --> ovpn
  actor -- "rtnetlink, WireGuard genetlink, libnftables" --> kernel
  actor -- "calls + signals" --> dbus
```

Untrusted input (captive portal HTML) is parsed by `portal-worker`, which enters the portal namespace and
drops to `nobody` before reading anything.

## The tunnel ladder

```mermaid
flowchart LR
  laptop["laptop<br/>kill switch opens only these holes"]
  subgraph net["the network you are on (sees only encrypted traffic)"]
    direction TB
    r1["1 · wireguard<br/>UDP 51820"]
    r2["2 · openvpn<br/>TCP 443"]
    r3["3 · wstunnel<br/>TLS 443, looks like HTTPS"]
  end
  carrier["your carrier server<br/>Caddy :443 → wstunnel<br/>anything else → a plain site"]
  vpn["VPN endpoint<br/>inner WireGuard is end-to-end"]
  inet["internet"]
  laptop --> r1 --> vpn
  laptop --> r2 --> vpn
  laptop --> r3 --> carrier -- "UDP, only to the VPN endpoint" --> vpn
  vpn --> inet
```

`auto` starts at the rung that last worked on this network (`/var/lib/toriid/mode-profile`) and falls
through the rest of `[tunnels] ladder`. A rung counts as up only after a real exit IP is measured
through it. `[networks.pin]` fixes a network to one mode.

The wstunnel rung has three TLS variants, tried most secure first:

| Variant | SNI | Certificate verified |
|---|---|---|
| `clean` | none | yes |
| `named` | real name | yes |
| `disguised` | fake name | no (last resort; the inner WireGuard stays encrypted) |

## A packet's path through the laptop

```mermaid
flowchart LR
  app["application"] --> rules
  subgraph rules["ip rules (priorities set by toriid, never by the kernel)"]
    direction TB
    p90["90: carrier server /32 → main"]
    p5100["5100: tailnet 100.64/10 → main"]
    p5150["5150: main without its default route"]
    p5200["5200: tailscale outer packets → 51820"]
    p5300["5300: not fwmark 0xca6c → table 51820"]
  end
  rules --> wg0["wg0<br/>default route in table 51820"]
  wg0 -- "encapsulated, fwmark 0xca6c → main" --> ks
  subgraph ks["nftables inet ks · output · policy drop"]
    direction TB
    allow["accept: tunnel interfaces, tailscale0,<br/>pinned carriers (IP + port + protocol),<br/>DHCP, neighbour discovery, @lan_allow, portal veth"]
    drop["everything else: drop<br/>(no 'ct state established accept')"]
  end
  allow --> phy["physical interface"]
```

When the tunnel goes down, rule 5300 has nowhere to send packets and they fall back to the main table,
but the output chain only accepts tunnel interfaces and the pinned holes, so they are dropped instead of
leaving in cleartext. Established connections die with the tunnel; `test/leak-test.sh` checks this with
real packets.

The ruleset is rendered from config on every mode change and replaced atomically. The last one that
loaded is kept in `/var/lib/toriid/killswitch.nft`, which `toriid-killswitch-boot.service` loads at boot
before any network comes up.

## Watchdog

```mermaid
flowchart LR
  trig["triggers<br/>every 60s, link or Wi-Fi change,<br/>resume, torii check"] --> gate
  gate["gate<br/>manually off? just switched?<br/>no physical link? → skip this round"] --> verdict
  verdict["verdict<br/>which tunnel actually runs,<br/>handshake under 180s,<br/>exit IP from 3 sources"]
  verdict -- healthy --> ok["protected<br/>remember this rung for the network"]
  verdict -- unhealthy --> fix
  subgraph fix["fix, in order (cooldown 120s, max 6 per hour)"]
    direction TB
    f1["1 retry the pinned tunnel"] --> f2["2 auto climbs the ladder"] --> f3["3 treat it as a captive portal"] --> f4["4 give up: offline, not leaking"]
  end
```

The exit IP is cached for 10 minutes on AC and 15 on battery while everything stays healthy. Every
5 seconds the daemon also writes a heartbeat to `health.json`, measures connectivity (inside the portal
namespace when the host cannot reach anything), puts back the DNS routing domain if tailscaled grabbed
`~.`, and brings protection up on a trusted network that has none.

## Captive portals

```mermaid
flowchart LR
  subgraph host["host: kill switch on, tunnel torn down"]
    apps["your apps<br/>all blocked"]
    subgraph ns["portal netns 10.99.98.5"]
      worker["portal-worker (nobody)<br/>clicks Accept / Log in"]
      ff["isolated Firefox<br/>for logins"]
    end
  end
  ns -- "veth + NAT; physical network only,<br/>never the tunnel, tailnet or VM bridges" --> lan["local network<br/>portal page (untrusted)"]
```

Passed automatically: a form with an Accept / Log in / Connect button and nothing to fill in (only that
button is submitted), a page with a single login link, Meraki grant links. Handed to you: password
fields, required inputs (room number, email), several candidate links. Once the portal lets you
through, protection comes back on its own.

## Who may do what

Adding protection needs no sudo; removing it does.

| Caller | Allowed |
|---|---|
| any local user | `torii status`, `torii watch`, reading the state files |
| operator (`[daemon] operator`) | `up` in any tunnel mode, `check`, wstunnel log and key rotation; portal mode while the network is broken |
| root | everything, including `down` |

Status states for bars: `protected`, `connecting`, `blocked` (no network, no leak), `leaking` (kill
switch not loaded), `portal`, `off`, `unknown` (daemon not reporting for 150 s).
See [status-json.md](status-json.md) and [security.md](security.md).

## Files

| Path | What | Written / read by |
|---|---|---|
| `/etc/toriid/config.toml` | main config | you / daemon (must be root-owned) |
| `/etc/toriid/wstunnel.conf` | carrier servers, keys, variants (0600) | daemon (key rotation writes through it) |
| `/etc/wireguard/wg0.conf` | your VPN's WireGuard config (PostUp not executed) | daemon |
| `/run/toriid/health.json` | heartbeat, verdict, advice; every 5 s | daemon / bars, notifier, `torii` |
| `/run/toriid/mode`, `step`, `class` | intent, current step, network class | daemon / bars |
| `/run/toriid/sock` | control socket | `torii` ↔ daemon |
| `/var/lib/toriid/killswitch.nft` | last loaded ruleset, replayed at boot | daemon / boot unit |
| `/var/lib/toriid/mode-profile` and friends | per-network rung, wstunnel variant, how portals were passed | daemon |
