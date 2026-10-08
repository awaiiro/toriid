# Carrier server

The TLS rung of toriid's tunnel ladder needs a small server you control: any VPS with a public IPv4
and port 443 open. It runs [wstunnel](https://github.com/erebe/wstunnel) behind
[Caddy](https://caddyserver.com) and relays WireGuard packets to your VPN's endpoint. It never sees
plaintext: WireGuard stays end-to-end between your laptop and the upstream endpoint.

```sh
git clone https://github.com/awaiiro/toriid && cd toriid/server
sudo ./install.sh --upstream <wireguard-endpoint-ip>:<port> --domain <a boring domain pointing here>
# or, without a domain:
sudo ./install.sh --upstream <ip>:<port> --sslip
```

The script prints the client-side `wstunnel.conf` values at the end.

| File | Purpose |
|---|---|
| `install.sh` | idempotent setup: wstunnel (loopback only), Caddy with a real certificate, a decoy site, automatic rollback if a re-run breaks a working deployment |
| `wst-keys.sh` | key management, installed as `/usr/local/sbin/wst-keys`; driven by `torii wst rotate / retire / keys / audit` over ssh |

Key rotation from the laptop needs `WST_SSH` and `WST_SSH_KEY` in the client's `wstunnel.conf`, and
that ssh user needs passwordless `sudo` (the client pushes the current `wst-keys.sh` before each call, so both ends always run the same version).

**Choosing a domain:** an active prober should see an ordinary small website. Avoid names containing
vpn, proxy, tunnel and the like.
