# Status JSON (schema version 1)

`torii status --json` prints one object; `torii watch` prints one per line whenever something changes. It
also re-checks every 50 seconds, so a dead daemon turns into `unknown` even though no file changes. Neither needs root or touches the
network. Within a schema version, fields are only ever added, never renamed or removed.

```json
{
  "version": 1,
  "state": "protected",
  "mode": "auto",
  "tunnel": "wireguard",
  "variant": "",
  "exit_ip": "198.51.100.20",
  "killswitch": true,
  "network": { "ssid": "Cafe-Guest", "class": "hostile", "connectivity": "full" },
  "busy": null,
  "advice": null,
  "updated": 1791392400
}
```

| Field | Meaning |
|---|---|
| `state` | one of `protected`, `connecting`, `blocked`, `leaking`, `portal`, `off`, `unknown` (see below) |
| `mode` | what was asked for: `auto`, `wireguard`, `openvpn`, `wstunnel`, `portal`, `off`, `failed-closed`, `unknown` |
| `tunnel` | the tunnel actually carrying traffic (`wireguard`, `openvpn`, `wstunnel`), empty when none |
| `variant` | wstunnel TLS variant: `clean`, `named`, `disguised` |
| `exit_ip` | last exit address measured through the tunnel; only set while `protected` |
| `killswitch` | whether the kill switch ruleset is loaded |
| `network.class` | `trusted` or `hostile` |
| `network.connectivity` | `full`, `limited`, `portal`, `unknown`, as measured by the daemon |
| `busy` | `{ "action", "since", "step" }` while the daemon is working, e.g. step `"WireGuard \| UDP 51820"` |
| `advice` | `{ "title", "text", "critical" }` when the user should know or do something |
| `updated` | Unix time of the daemon heartbeat this was built from; 0 if there is none |

States:

| State | Meaning | Suggested look |
|---|---|---|
| `protected` | a tunnel is verified working and the kill switch is loaded | calm |
| `connecting` | the daemon is bringing a tunnel up or re-checking | in progress |
| `blocked` | a tunnel is wanted but not working; the kill switch holds: no network, no leak | warning |
| `leaking` | a tunnel is wanted but the kill switch is not loaded | alarm |
| `portal` | captive portal mode | info |
| `off` | protection removed by the user | muted |
| `unknown` | daemon not running, or its heartbeat is older than 150 s | muted |

## Bar adapters

`torii bar <kind>` renders the same data natively:

| Kind | Output |
|---|---|
| `json` | the object above (eww `deflisten`, ags, Quickshell, scripts) |
| `waybar` | `{"text", "alt", "tooltip", "class", "percentage"}`; `class` holds the state, the tunnel and `critical` |
| `polybar` | one line with `%{F#color}` formatting, for `tail = true` |
| `i3blocks` | full_text / short_text / color lines |
| `plain` | the formatted line only (yambar, lemonbar, tmux, ...) |

Options: `--once` (print and exit instead of following), `--icons nerd|emoji|text`, and
`--format` with the placeholders `{icon} {label} {state} {mode} {tunnel} {variant} {exit_ip} {ssid} {class}`.
