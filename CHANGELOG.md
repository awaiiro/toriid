# Changelog

## 0.1.2

Documentation only.

- `docs/architecture.md`: processes and channels, the tunnel ladder, a packet's path through routing
  rules and the kill switch, the watchdog, captive portals, permissions and files, with diagrams.
- README: an overview diagram and a link to the architecture page.

## 0.1.1

Fixes from a full review after the first release.

- Protection now comes up by itself after boot on any network. Before, with the default config, the
  watchdog waited for a captive portal forever because the kill switch blocks its own connectivity probe.
- A non-root operator could inject extra lines into the root-owned wstunnel config through key rotation
  and open holes in the kill switch. Keys are now validated.
- `auto` no longer pins itself to a fallback tunnel; it remembers per network where to start instead.
- The status no longer shows `protected` while no tunnel is up (failed-closed).
- A trusted Wi-Fi no longer grants LAN access to a wired uplink on the same machine.
- Key rotation works as the operator (the daily user timer used to fail).
- Debian/Ubuntu: boot unit and portal browser no longer assume tools live in /usr/bin.
- `auto_portal` is on by default (click-through pages only; login pages are always left to you).
- Carrier server: clients send the right Host header; Caddy serves the real certificate for any SNI.
- Config check validates `default_mode` and `[wifi] backend`; network class is reported as `trusted`.

## 0.1.0

First release.

- nftables kill switch, rendered from config, loaded at boot
- tunnel ladder: WireGuard → OpenVPN over TCP → WireGuard in TLS (wstunnel), configurable
- per-network memory of what worked; per-network pins
- captive portals in an isolated network namespace: click-through pages passed automatically,
  login pages handed to the user in an isolated browser; page parsing runs as `nobody`
- watchdog: suspend/resume, network changes, tunnel drops
- Wi-Fi via iwd or NetworkManager
- status JSON (`torii watch`) and bar output for waybar, polybar, i3blocks, eww/ags, Quickshell
- carrier server setup script (`server/install.sh`), wstunnel key rotation
- tests: unit, kill switch leak test with real packets, end-to-end VM test

The prebuilt binary is built on Ubuntu 24.04 (needs glibc 2.39+ and libnftables). On other systems,
build from source or use `dist/arch/PKGBUILD` on Arch.

The carrier server script (`server/install.sh`) has not been run against a fresh VPS yet.
