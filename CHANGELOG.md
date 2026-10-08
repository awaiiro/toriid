# Changelog

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
