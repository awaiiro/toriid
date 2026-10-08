# Security model

## What toriid protects against

The adversary is **the network you are connected to**: whoever runs the access point, the captive
portal, the DPI middlebox, or anyone else on the path or on the same LAN. toriid's job is that this
adversary sees only tunnel carriers (encrypted WireGuard, OpenVPN or TLS to servers you chose), and
that a failing tunnel results in *no traffic*, never in *cleartext traffic*.

Not in scope:

- Your VPN provider or your carrier server. They see what any VPN endpoint sees.
- Anonymity. toriid is not Tor; your VPN account and timing are visible to the provider.
- Malware already running as root on your machine.
- Hiding that you use a VPN. The `wstunnel` rung makes the tunnel look like HTTPS to a plain website,
  which defeats protocol-based blocking, but a determined observer can still notice long-lived TLS
  sessions to one host.

## Fail-closed, concretely

- The kill switch is a default-drop nftables ruleset. It is loaded at boot by
  `toriid-killswitch-boot.service` *before* any network comes up, from the last ruleset the daemon
  successfully loaded (`/var/lib/toriid/killswitch.nft`).
- Outbound holes are pinned to specific carrier addresses, ports and protocols. Hostnames are resolved
  when the ruleset is rendered, never at packet time.
- There is deliberately no `ct state established accept` in the output chain: when a tunnel drops, the
  connections that were inside it die instead of continuing over the physical interface.
  `test/leak-test.sh` checks this with real packets, including a mutation that re-adds the rule.
- Every mode change starts by loading the ruleset; there is no state where a tunnel is being rebuilt
  without the kill switch. Only `sudo torii down` removes it.
- If every rung of the ladder fails, toriid stays fail-closed and says so. It never decides on its own
  to go unprotected.

## Captive portals

Portal mode keeps the kill switch on. A separate network namespace gets a veth pair and NAT to the
physical network; only traffic from that namespace's single address may leave unprotected, and never
into a tunnel, the tailnet or a VM bridge. Pages loaded there cannot reach services on the host
(only replies are accepted on the host side of the veth).

Automatic portal passing fetches and parses hostile HTML. That runs in a separate process,
`toriid portal-worker`, which enters the portal namespace and then drops to `nobody` with
`no_new_privs` before touching the page.

**Known limitation:** the portal *browser* runs as your user, so other processes of yours could use
it as an unprotected path while portal mode is on. This is why a non-root operator can only enter
portal mode when the network is already broken (no full connectivity).

## Who may do what

The daemon listens on `/run/toriid/sock` (world-connectable, so status works for everyone). Callers are
identified with `SO_PEERCRED` before a request is queued; requests are limited in size and number.

| Caller | Allowed |
|---|---|
| any local user | `status` (read-only snapshot) |
| operator (`[daemon] operator` in config.toml) | everything that *adds* protection: `up` in any tunnel mode, `check`, `portal` and `portal-auto` only while connectivity is not full, reading the wstunnel log, reading and storing wstunnel keys for rotation |
| root | everything, including `down` (removing protection) and forcing portal mode |

There is no implicit operator: if `[daemon] operator` is empty, only root can control the network.

## Files root trusts

Everything the root daemon reads as configuration or executes must be owned by root and not writable by
group or others, including every parent directory: `config.toml`, `wstunnel.conf`, the WireGuard and
OpenVPN configs it parses, and the `wstunnel` binary. Anything else is refused (with a log entry), so a
non-root user cannot widen the kill switch or get code executed as root by editing a file.

Key rotation runs as the operator (it needs their ssh key) and hands the new keys to the daemon over the
socket; the daemon writes the root-owned file.

WireGuard `PostUp`/`PostDown` hooks are never executed.

## Network classification

LAN access is granted per trusted SSID. An SSID can be cloned; on a cloned "trusted" network, LAN hosts
become reachable (the tunnel and kill switch are unaffected). Keep the trusted list short.

## Reporting

Please report vulnerabilities privately through GitHub's security advisories for this repository.
