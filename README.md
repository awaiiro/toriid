# toriid

[English](README.md) · [日本語](README.ja.md)

VPN kill switch and tunnel manager for Linux laptops on untrusted networks.

If the tunnel is down, nothing goes out. If WireGuard is blocked, it falls back to OpenVPN over
TCP 443, then to WireGuard inside TLS ([wstunnel](https://github.com/erebe/wstunnel)). Captive portals
are handled in an isolated namespace without turning the kill switch off.

```
$ torii
mode      auto | WireGuard/UDP
phase     up | exit 198.51.100.20 | handshake 12s ago
network   Cafe-Guest (hostile) | wlan0 | connectivity full
protect   killswitch loaded | LAN blocked
```

## Features

- nftables kill switch, loaded at boot, holes only for your VPN servers
- fallback: WireGuard → OpenVPN/TCP → WireGuard in TLS; remembers what worked per network
- click-through captive portals passed automatically; login portals open in an isolated browser
- watchdog: reconnects after suspend, network changes and drops
- Tailscale keeps working inside the tunnel
- iwd or NetworkManager
- status output for waybar, polybar, i3blocks, eww/ags, Quickshell

Works with any WireGuard provider or your own server. The TLS fallback needs a VPS;
[`server/`](server) sets one up.

## In practice

What it does on the networks it's used on day to day:

| Network | What happens |
|---|---|
| Home (listed in `trusted`) | WireGuard; LAN devices (printer, NAS, ssh) reachable |
| Cafe | WireGuard; LAN blocked |
| Guest Wi-Fi that blocks UDP | WireGuard times out, OpenVPN on TCP 443 takes over |
| Network with DPI that kills OpenVPN too | falls through to WireGuard in TLS; next time it starts there |
| Hotel with an "Accept" page | portal passed automatically, then back to WireGuard |
| Portal that wants a room number or password | notification; `torii portal` opens the page in an isolated browser |
| Laptop wakes up on a different network | watchdog notices, picks the mode that worked there last time |

In every case nothing leaves the laptop outside the tunnel, including while it is switching.
The bar shows what's going on; you only act when it asks you to.

## Install

```sh
cargo build --release
sudo install -m755 target/release/toriid /usr/bin/toriid
sudo ln -s toriid /usr/bin/torii
sudo install -Dm644 dist/config.toml /etc/toriid/config.toml
sudo install -m644 dist/systemd/*.service /etc/systemd/system/
sudo install -Dm644 dist/tmpfiles/toriid.conf /etc/tmpfiles.d/toriid.conf
sudo systemd-tmpfiles --create toriid.conf
sudo systemctl enable --now toriid-killswitch-boot toriid
```

Arch: [`dist/arch/PKGBUILD`](dist/arch/PKGBUILD).

Then put your WireGuard config at `/etc/wireguard/wg0.conf`, set `operator` to your username in
`/etc/toriid/config.toml`, and run `torii up`. All options: [`dist/config.toml`](dist/config.toml).

`sudo torii down` turns everything off.

## Usage

```
torii                    status
torii up [MODE]          auto | wireguard | openvpn | wstunnel
torii down               remove protection (sudo)
torii portal             open the captive portal page
torii log [-f]           logs
torii wifi list|connect
torii watch              status as JSON, one line per change
torii bar waybar         status for a bar (also polybar, i3blocks, plain, json)
```

Bar configs: [`examples/`](examples). JSON format: [`docs/status-json.md`](docs/status-json.md).

## Security

It protects you from the network you're on, not from your VPN provider. Details and what non-root
users can do: [`docs/security.md`](docs/security.md).

Tests: `cargo test`, `test/leak-test.sh` (kill switch with real packets, no root needed),
`test/vm-e2e.sh` (full run on a throwaway VM).

## License

MIT
