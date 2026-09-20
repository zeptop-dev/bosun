# Bosun

Single-server node agent. Runs upstream proxy cores as child processes and is
driven either by its own built-in web panel (`panel.driver: local`, the
default) or headless by a management panel (Captain, or Xboard's UniProxy
API). Changes per release: [CHANGELOG.md](CHANGELOG.md).

## Status

Verified end to end against the manifest's tested releases (sing-box
1.14.1, Xray 26.3.27, mita 3.37.0, Hysteria 2.12.3; see the table under
"Run"):

- Panel drivers: Captain (`bosun/pkg/agentproto`: one-time pairing, ETag state, one combined report per interval, immediate pull when the panel signals a change) and Xboard's UniProxy v1 API.
- Per-inbound user lists (`spec.Inbound.ScopedUsers`): an inbound restricted to a user group only provisions that group; the mita adapter runs one instance per inbound because mita users are global to a process.
- sing-box adapter: renders VLESS, VMess, Trojan, Shadowsocks (incl. 2022), Hysteria2, TUIC, AnyTLS, SOCKS, HTTP, Naive; TLS, REALITY, ws/grpc/httpupgrade/http transports, multiplex, custom outbounds with chaining, route rules.
- Xray adapter: VLESS, VMess, Trojan, Shadowsocks (AEAD), SOCKS, HTTP over raw/ws/grpc/httpupgrade/xhttp, TLS and REALITY; **hot user add/remove** on VLESS/VMess/Trojan through HandlerService, restart otherwise; per-user stats via StatsService; config validated with `xray run -test`. Verified e2e: REALITY traffic, hot add and hot remove, per-user push.
- Hysteria adapter (official Hysteria 2 server): users live in bosun, not in the config. Hysteria calls bosun's HTTP auth endpoint per connection, so adds are instant and removals are enforced with a kick through the traffic stats API; only listener changes restart the process. Per-user stats from `/traffic?clear=1`. One hysteria2 inbound per node with this core; sing-box serves several. Verified e2e with the official client.
- mita adapter (official mieru server): config file + `mita run` as a child, gRPC over a unix socket for hot user reload, proxy restart on port change, and per-user counters (deltas computed by bosun). Verified with the official mieru client. Inbounds carry the client knobs too: `mieru_mtu` (server `mtu` and the link's `mtu=`), `mieru_multiplexing` (`MULTIPLEXING_OFF|LOW|MIDDLE|HIGH`), `mieru_handshake` (`HANDSHAKE_NO_WAIT|STANDARD`), and `mieru_transport: BOTH` binds TCP at the port and UDP at port+1 in one inbound (the `mierus://` link lists both).
- Snell: served by sing-box (bosun >= 0.41; its snell server speaks v5, which is v4's wire protocol without the QUIC mode nobody implements) with one server `psk`, optional `obfs` http, and — with `snell_multi_user` — a key per user (the user's password) so traffic is accounted per user like every other sing-box inbound. Only sing-box's own client (1.14+) can present a user key, so the sing-box subscription carries such lines with `user_key` while Surge, Stash and mihomo documents leave them out; shared-psk lines reach every client. Surge's closed-source `snell-server` stays as the `snell` core for `obfs` tls or when sing-box is disabled: one process per inbound, everyone shares the PSK, no per-user accounting. The share "link" is a Surge proxy line (`NAME = snell, host, port, psk=…, version=5`), which Surge, Loon and mihomo import.
- Per-user traffic via each core's own control plane, hand-encoded protobuf, no generated stubs (`internal/core/grpcraw`).
- Built-in relay (`internal/forward`): TCP and UDP port forwarding to the next hop with per-rule byte and connection counters and a TCP probe of the target (5 s retry while down, 30 s while up); a rule may list further targets for failover or weighted round-robin (see "Several targets"). Rules come from the config file with Xboard; a panel that manages forwarding (Captain) supplies them through the `panel.ForwardSource` interface. Two more backends per rule: nftables kernel DNAT and a supervised realm process (see "Forwarding chains"). Verified e2e: mihomo connecting to the relay port reaches an Xray REALITY landing behind it.
- Online devices: cores that know which IPs a user connects from report them (Xray via its online-IP stats API, Hysteria from auth callbacks); the panel uses them for device limits. Upstream sing-box and mita expose no per-user connection info, so inbounds on those cores do not count toward device limits.
- Prometheus endpoint (`metrics_listen`, `/metrics`): core running state, provisioned users, and per-forward up/rtt/connections/bytes. No client library.
- Supervised child process: log relay, restart with backoff, graceful stop.
- Core installer with a tested-version manifest (`internal/coreinstall`): leave `binary` empty and bosun downloads the newest release it has verified, checks its sha256, and installs it under `<data_dir>/cores/<core>/<version>/`. Releases known to break deployments are marked `broken` and only installed when named explicitly. sing-box is downloaded from bosun's own CI build of the upstream tag with the stats API tag (GitHub pre-release `singbox-<version>`); when that build is missing it is built from source, which needs a Go toolchain on the node.
- Every inbound passes `spec.Inbound.Validate()` (the shape check Captain, the local panel and the agent share: keys, TLS/REALITY fields, ciphers, transports) before rendering; an invalid one is skipped with the reason in the doctor instead of breaking the core's config. Config validated with `sing-box check` before every start or apply.
- Failed applies are retried on the next pull and unacknowledged traffic deltas are kept across failed reports, so a panel outage loses no accounting.

Core selection: `cores.order` in the config is the preference; an inbound goes to the first core that supports its protocol, transport and cipher. XHTTP only runs on Xray, HTTP/2 transport and Shadowsocks 2022 multi-user only on sing-box, mieru only on mita. Hysteria2 runs on sing-box (default) or the official server when `hysteria` is listed first.

## Layout

```
cmd/bosun/            entry point: run | render | core list|install | admin set|reset-password | doctor | backup create|restore | version
pkg/spec/             core-agnostic (public, imported by Captain) node / inbound / user model
pkg/agentproto/       wire types between Captain and bosun (pair, state, report, beat, jobs)
pkg/subscription/     subscription renderers per client (Clash/mihomo, Stash, sing-box, Surge, Surfboard, Loon, QX, Egern, URI list, WireGuard), used by Captain too
pkg/subdesign/        visual subscription designer: proxy groups + ACL4SSR rules -> every template
pkg/selfupdate/       GitHub Releases check, atomic binary swap, rollback, restart (shared with Captain)
pkg/wg/               WireGuard key helpers shared by node and panel
internal/core/        Core interface, registry, inbound -> core assignment, per-core config overrides
internal/core/subprocess/   child process supervisor
internal/core/grpcraw/      raw gRPC invoke for hand-encoded protobuf
internal/core/v2stats/      V2Ray-lineage StatsService client (sing-box and Xray)
internal/core/singbox/      sing-box renderer, stats client, process driver
internal/core/xray/         Xray renderer, HandlerService hot user updates, process driver
internal/core/mita/         mieru server (mita) renderer, RPC client, process driver
internal/core/hysteria/     Hysteria 2 renderer, auth endpoint, stats client, process driver
internal/core/snell/        Surge snell-server driver, one process per inbound
internal/coreinstall/ tested-version manifest, download + sha256 check, source builds
internal/panel/       Driver interface (and ForwardSource for panels that manage forwarding)
internal/panel/captain/     Captain driver: pairing, ETag/long-poll state, reports, beats, jobs
internal/panel/xboard/      Xboard UniProxy v1 driver
internal/local/       standalone mode: inbounds, users, forwards and settings in <data_dir>/local.json
internal/ui/          built-in web panel: JSON API over the local store + embedded SPA (read-only under a panel)
web/                  the panel frontend (web/ui, Vite) embedded via web/embed.go
internal/authutil/    password hashing and random identifiers for the panel login
internal/agent/       managed-mode loop: pull -> render -> apply, stats -> push
internal/forward/     TCP/UDP userspace relay with probes and counters; nftables and realm backends
internal/ingressguard/ nftables input guard for cores that cannot bind one address (mita behind a line)
internal/firewall/    opens bosun's own ports in ufw / firewalld and closes them again
internal/certs/       ACME certificates for inbounds and the panel (HTTP-01 / Cloudflare DNS-01), pushed PEM pairs
internal/dns/         Cloudflare records for the panel domain, decoy site and TLS inbound names
internal/decoy/       the node's own HTTPS site on loopback for REALITY to steal
internal/realityscan/ REALITY target scanner with CDN detection
internal/warp/        Cloudflare WARP registration and WireGuard outbound
internal/shaper/      per-user bandwidth limits with nft connmark + tc
internal/probe/       latency checks for the panel's status page (carrier probe points, icmp/tcp/http/download tasks), attached to every beat
internal/komari/      reports the node to a Komari server as an agent
internal/doctor/      read-only self-check (listeners, certs, ports, firewall, disk, panel, clock)
internal/backup/      standalone backup archive and restore
internal/telegram/    Bot API client for the standalone panel (doctor alerts, /status)
internal/logring/     recent log records in memory for the panel's log view
internal/metrics/     Prometheus text exposition
internal/config/      YAML config
internal/sysinfo/     host status snapshot
```

## Install on a node (Linux: systemd, or OpenRC on Alpine)

Standalone, with the built-in web panel on port 2053:

```sh
curl -fsSL https://raw.githubusercontent.com/zeptop-dev/bosun/master/scripts/install.sh | sh
```

The installer prints the generated login. Open `http://<server>:2053/`, add inbounds
and users, hand out subscription links. Put the panel behind Caddy or reach it over
an SSH tunnel; or set `web.cert`/`web.key` for TLS.

Managed by Captain from the start (no local panel edits):

```sh
curl -fsSL https://raw.githubusercontent.com/zeptop-dev/bosun/master/scripts/install.sh | sh -s -- \
  --captain https://captain.example.com --pair ABCD-EFGH
```

"Add node" in Captain prints this ready to paste as
`curl -fsSL https://<captain>/api/agent/install.sh?pair=CODE | sh`, and a Docker
one-liner: `docker run -d --network host -v bosun-data:/var/lib/bosun
-e BOSUN_CAPTAIN=https://<captain> -e BOSUN_PAIR=CODE zeptop/bosun:latest`
(the two variables select the Captain driver without editing the config; the
code is only used until the token is stored). The pair code is used once. Either way the
installer verifies the binary against the release checksums, writes
`/etc/bosun/config.yaml`, and starts the `bosun` service; cores are downloaded on
first start. Re-run without arguments to upgrade; `... | sh -s -- uninstall`
removes everything again (`--keep-data` keeps `/var/lib/bosun`). Piped through
`sh` the script itself never lands on disk.

### Docker Compose

Docker installed (`curl -fsSL https://get.docker.com | sh`), then:

```sh
mkdir -p /opt/bosun && cd /opt/bosun
curl -fsSLO https://raw.githubusercontent.com/zeptop-dev/bosun/master/deploy/docker-compose.yml
docker compose up -d
docker compose logs bosun 2>&1 | grep 'web panel login'   # first-start login, printed on stderr once
```

Open `http://<server>:2053/` (or reach it over an SSH tunnel:
`ssh -L 2053:127.0.0.1:2053 root@<server>`). `network_mode: host` is required:
the proxy cores bind the node's ports directly and forwards use the real
interfaces. Cores are downloaded into the `bosun-data` volume on first use.

To start already managed by Captain, or to change the panel port or add TLS
certificates for inbounds, put a `config.yaml` next to the compose file (start
from `config.example.yaml`) and uncomment the mount lines in the compose file.

Day-to-day:

```sh
docker compose logs -f bosun
docker compose pull && docker compose up -d   # upgrade; the panel shows this command when a release is out
```

## Online devices

Captain's device limit needs each node to report which client IPs a user is
connected from. Xray (stats API, sampled every 10 s and kept for 3 minutes
because Xray forgets an address 20 s after its last connection), Hysteria
(auth callback) and sing-box (joined from its per-connection log lines;
sing-box always runs at log level `info` for this, the configured
`log_level` only filters what reaches bosun's own log) report them. mieru
(mita) exposes sessions without user names, so mieru inbounds do not count
toward device limits.

Traffic is counted per user *and inbound*: each inbound's users get their
own identity in the core (Xray email / sing-box name `NAME|TAG`,
`spec.InboundUser`), and the report carries one entry per user and inbound
so a panel can charge the inbound's own group. Panels that only know users
(Xboard, the local panel) receive one summed entry per user.

## Probe beats

When Captain's probe page is on, the node sends a light host sample every
few seconds (`POST /api/agent/beat`): CPU, memory, swap, disk, load, network
rate and totals, TCP/UDP/process counts, uptime, IPv4/IPv6 reachability,
static host facts, plus latency results: TCP-connect checks against the
carrier probe points (CT/CU/CM by default; Captain can name its own; no
ICMP privileges needed) and panel-defined tasks (icmp, tcp, http,
download). Nothing runs while the panel keeps probing off.

Without Captain (local or Xboard driver) a `probe:` section in config.yaml
runs the same checks and exposes them on `/metrics` as
`bosun_probe_latency_seconds` / `bosun_probe_loss_ratio`:

```yaml
probe:
  enabled: true
  carriers:                      # omit for the default CT/CU/CM points
    - { name: CT, addr: ct.tz.cloudcpp.com:80 }
    - { name: HK, addr: www.hkix.net:443 }
  tasks:
    - { name: cf, type: tcp, target: 1.1.1.1:443, interval_seconds: 30 }
    # a dedicated line measured from its own NIC (tcp/icmp honour source_ip)
    - { name: IPLC, type: tcp, target: 198.51.100.20:17701, source_ip: 10.10.0.2 }
```

## Komari reporting

Probe → Komari reporting turns the node into a Komari agent: with the
server URL and the auto-discovery key (Komari → Settings → General) it
registers once (`POST /api/clients/register`, client named `Auto-<name>`),
keeps the token in `<data_dir>/komari.json`, then posts `agent.basicInfo`
and `agent.report` over JSON-RPC every few seconds and answers Komari's
ping tasks (icmp/tcp/http) through its own probe runner. Only the `ping`
capability is advertised: no terminal, file or exec access. Captain can push
the same setting to every managed node (`state.komari`). A deleted client on
the Komari side makes the node re-register automatically.

## Certificates

Inbounds that need TLS (Hysteria2, Trojan, AnyTLS, VLESS/VMess over TLS) can
tick "Automatic certificate": bosun obtains a Let's Encrypt certificate for the
inbound's server name and renews it a month before expiry, then restarts the
core so it picks the new files up. Two challenge types:

- **HTTP** (default): port 80 on this machine must be reachable from the
  internet for the few seconds of the challenge; bosun listens on it only then.
- **DNS**: for wildcards and for boxes that only expose a port range (IPLC
  entrances). Needs a Cloudflare API token with `Zone.DNS` edit permission,
  entered once in Settings (or pushed by Captain).

Set the Let's Encrypt account email in Settings. The same mechanism serves the
panel over HTTPS: enter a panel domain in Settings and restart. Certificates and
the ACME account live in `<data_dir>/certs/`. Certificates you manage yourself
still work through `certs:` in config.yaml; an inbound whose certificate cannot
be obtained is skipped (shown on the overview) and retried on the next pull,
so one broken domain never takes the other inbounds down.

### Pushed certificates

Captain can push PEM pairs (uploaded by the operator or delivered by a
certificate manager such as Certimate through Captain's webhook) in
`node.certificates`. bosun validates each pair, writes it under
`<data_dir>/certs/custom/<domain>/` and uses it for every standard-TLS
inbound whose server name it covers (exact or `*.wildcard`), ahead of ACME
and the local `certs:` config. They are reported with method `custom`.

## Updating

Settings → "Version and updates" checks GitHub Releases (cached 20 minutes; a
red dot on the version badge means a newer release exists). "Update and
restart" downloads `bosun-linux-<arch>` for the running platform, verifies it
against the release's `SHA256SUMS`, swaps the binary atomically (the previous
one stays as `bosun.backup` for "Roll back") and exits; systemd's
`Restart=always` starts the new version. Cores restart with it, so users drop
for a few seconds. Managed nodes can also be upgraded from Captain's node list,
one at a time or all at once: the request rides on the next report and the node
applies it the same way. Captain can also roll a node back (a `rollback` job):
bosun puts `bosun.backup` back, reports the version and restarts.

Inside Docker the binary is part of the image, so the panel only shows the
`docker compose pull && docker compose up -d` command instead. `bosun` also logs
a notice every six hours when a newer release exists.

## Standalone vs managed

`panel.driver: local` (the default) keeps inbounds, users and forwards in
`<data_dir>/local.json`, edited through the web panel. Every save applies at once:
cores are reconfigured or restarted as needed. Users get per-user quota and expiry,
traffic counters, share links and a `/sub/<token>` subscription whose format follows the client (Clash/mihomo YAML, sing-box JSON, Surge, Loon, Quantumult X, Stash, Surfboard, else a base64 URI list; `?client=` forces one). The renderers live in `pkg/subscription`, which Captain imports too.

The standalone panel carries the same node-side features as Captain's node
page: line ingresses (IPLC / dedicated NICs: inbounds bind to the line
address, share links advertise the provider's entry or its domain on the
mapped port, and every line gets an RTT task from its NIC), landing
outbounds and route rules (paste a share link, chain exits, pick a default
exit), operator certificates (PEM pairs used ahead of ACME for the names
they cover) and the probe (carrier latency targets, tasks with an optional
source address; results on the overview and `/metrics`). In local mode the
panel's probe settings win; the `probe:` section of config.yaml only applies
to the Xboard driver.

The installer asks for the panel username, password and port when run on a
terminal (blank keeps `admin`, a generated password and `:2053`; `r` picks a
random port); `--yes` skips the questions, `--user`, `--password` and
`--web-listen` answer them up front. `bosun admin set -user U -password P`
changes the login later; `bosun admin reset-password` generates a new one.

Settings → Mode → "Hand over to Captain" takes a pair code, snapshots the local
objects, and restarts the agent on the Captain driver; the panel turns read-only.
"Detach" comes back to local mode, restoring the snapshot or keeping the last
state the panel pushed. `bosun admin reset-password` recovers a lost login.

`panel.driver: captain` or `xboard` pins headless managed mode from the config
file; `web:` may still be set for read-only diagnostics. `panel.captain.url`
has to be https (`panel.captain.allow_insecure: true` allows plain http for a
lab, where the node token and every pushed config travel in clear).
`web.trusted_proxies` names the reverse proxies whose `X-Forwarded-For` the
panel's login limiter and allow-list believe.

### Doctor

Doctor is a read-only self-check: cores running, every inbound answering a
TCP connect on its bind address (UDP-only inbounds are skipped), bind
addresses present on an interface, forward listeners and targets, certificate
presence and expiry, port clashes across inbounds and forwards, a
best-effort firewall look (a default-drop input policy without an accept
rule for an inbound port), disk and swap, contact with the panel, Komari
reporting and NTP sync. The agent runs it 30 s after start and every 10
minutes and sends the result to Captain when it changed (at least every 30
minutes) as `report.doctor`; the panel page "Doctor" (`GET /api/doctor`)
runs it on demand with a 30 s cache. `bosun doctor -c config.yaml` runs the
same checks outside the service and exits 1 when one failed; because that
process does not run the cores, the core check is skipped there.

### Backup and restore (standalone)

Settings → Backup downloads `bosun-backup-<date>.tar.gz` with `local.json`,
its traffic history, the Komari registration and operator certificates
(`certs/custom`); ACME storage and panel TLS files are not included and are
obtained again. Restore (`POST /api/backup/restore`, local mode only)
validates the archive, refuses one taken while managed, writes the files
atomically and reloads the store in place, so cores reconfigure at once;
the archive's admin login wins and existing sessions end when it differs.
The archive carries every node secret (admin hash, TOTP, API-token hashes,
user credentials, WARP key, Cloudflare and Telegram tokens), so it can be
sealed with a passphrase (AES-256-GCM under an argon2id key) and the panel
asks for one by default; restore takes the same passphrase.
`bosun backup create [-o FILE] [-passphrase P]` and
`bosun backup restore FILE [-passphrase P]` do the same from the shell
(restore wants the service stopped, or `--force`).

## Run

```sh
make build
cp config.example.yaml /etc/bosun/config.yaml   # edit panel settings
bin/bosun core list                              # manifest + what is installed
bin/bosun core install xray                      # optional; run installs missing cores itself
bin/bosun render -c /etc/bosun/config.yaml       # print what would be applied
bin/bosun run    -c /etc/bosun/config.yaml
```

Current manifest:

| core | version | status | note |
|---|---|---|---|
| singbox | 1.14.1-r2 | tested | upstream 1.14.1 rebuilt with Go 1.26.8 (`-r1` was compiled with Go 1.26.0) |
| singbox | 1.14.1-r1 | tested | upstream 1.14.1 built with `with_v2ray_api` and `with_wireguard` (WARP); WireGuard endpoints survive network changes |
| singbox | 1.14.0-r2 | tested | upstream 1.14.0 built with `with_v2ray_api` and `with_wireguard` (WARP) |
| singbox | 1.14.0 | caution | first build without `with_wireguard`; WARP outbounds fail |
| xray | 26.3.27-r1 | tested | upstream 26.3.27 rebuilt by bosun CI with Go 1.26.8 (the official binary is Go 1.26.1); REALITY works with mihomo and sing-box clients |
| xray | 26.3.27 | tested | official binary; REALITY works with mihomo and sing-box clients |
| xray | 26.9.9 | broken | REALITY rejects mihomo/sing-box clients |
| mita | 3.37.0 | tested | official mieru server; line-bound inbounds bind natively (`listenIPAddress`) |
| mita | 3.36.1 | tested | official mieru server; line-bound inbounds need the nft ingress guard |
| hysteria | 2.12.3 | tested | official Hysteria 2 server |
| hysteria | 2.12.2 | tested | official Hysteria 2 server |
| snell | 5.0.0 | caution | Surge snell-server v5 (official zip, digest pinned); not verified end to end |
| snell | 4.1.1 | caution | Surge snell-server v4 for older clients |
| realm | 2.9.6 | caution | zhboner/realm for the `realm` forward backend; not verified end to end |

## sing-box and Xray binaries, and CI

Official sing-box release builds do **not** include the V2Ray stats API, which
per-user accounting needs. `scripts/build-singbox.sh` builds the unmodified
upstream tag with the extra tags (`with_v2ray_api` among them); module
checksums are verified by the Go toolchain. Not a fork.

Xray's official binaries are fine feature-wise but trail Go's security
releases (26.3.27 is Go 1.26.1, which misses the crypto/tls and net/http fixes
since), so `scripts/build-xray.sh` rebuilds the unmodified upstream tag with
upstream's own release flags and the Go toolchain pinned in bosun's `go.mod`.
Every Go binary bosun ships or builds — bosun itself, sing-box, Xray — uses
that one toolchain line, and a weekly `govulncheck` run says when it is due.

GitHub Actions (`.github/workflows/`) run tests on every push, and on a `v*`
tag cross-build bosun for linux amd64/arm64 and attach the binaries plus
`SHA256SUMS` to the GitHub Release, and push the container image. The
`singbox` and `xray` workflows (run by hand with a version and a rebuild
suffix) build those cores the same way and publish them as pre-releases:

```
releases/download/singbox-1.14.1-r2/sing-box-1.14.1-r2-linux-{amd64,arm64}  + SHA256SUMS
releases/download/xray-26.3.27-r1/xray-26.3.27-r1-linux-{amd64,arm64}      + SHA256SUMS
releases/download/<tag>/bosun-linux-{amd64,arm64}                     + SHA256SUMS
```

The installer downloads sing-box and Xray from there and verifies them against
the published SHA256SUMS. If a sing-box download is not available (workflow not
run for that version yet), the installer falls back to building from source,
which needs a Go toolchain on the node; for Xray, name an older release in
`cores.xray.version` instead. `cores.registry_token` in config.yaml is
a leftover from the GitLab package registry days: it is sent as a
`Deploy-Token` header, and only to bosun's own release downloads on GitHub,
which are public and need no token, so leave it unset (the comment next to
it in `config.example.yaml` still describes the GitLab setup). Note sing-box has no runtime user API: every
user or inbound change is a config rewrite plus restart, batched per pull interval.

## Xray binary and REALITY interop

Tested: Xray 26.3.27 serves REALITY to mihomo 1.19.30 and sing-box 1.14.0
clients. **Xray 26.9.9 does not**: xtls/reality commit 8cdf7bf (2026-09-08,
"Reject outdated/strange Client Hello that doesn't have X25519MLKEM768 before
optional X25519") makes the server treat those clients' handshakes as
unauthenticated and forward them to the real target; Xray's own client
offers the post-quantum group first and still connects. Until
the client ecosystem catches up, pin Xray at 26.3.x for REALITY nodes or let
sing-box serve them. This is the reason bosun keeps a tested version list per
core instead of tracking the newest upstream release blindly.

Outbounds come in two forms. `remote` is core-agnostic (host, port,
credentials and the same TLS/transport vocabulary as inbounds, e.g. parsed
from a share link) and bosun renders it in each core's dialect: sing-box takes
every protocol, Xray takes vless/vmess/trojan/shadowsocks/socks/http. Raw
`settings` are passed through untranslated in the serving core's own layout.
Route rules match `inbound:<tag>` besides domain/ip/protocol/port, and
`default_outbound` on the node sends unmatched traffic through a landing
server (sing-box `route.final`; Xray puts it first).

## mita binary

Any official `mita` release works (3.36.x tested). Bosun runs it with
`MITA_CONFIG_JSON_FILE`, `MITA_UDS_PATH` and `MITA_INSECURE_UDS` pointing into
its own data dir, so it does not touch a system-installed mita's config or
socket. Unix socket paths are limited to ~100 bytes; bosun falls back to the
temp dir automatically when the data dir path is too long.

## License

MIT, see `LICENSE`. bosun runs sing-box, Xray, mita, Hysteria, snell-server
and realm as separate processes from their upstream release binaries and talks to them over their
own APIs and config files; none of their code is linked or copied, so their
licenses (GPL-3 for sing-box and mieru) do not extend to bosun. The sing-box
stats client re-implements the wire format from the public proto definition.

## Forwarding chains

A chain such as `client -> entry -> relay -> landing` is one `forwards` rule on
each hop, pointing at the next hop. The landing node serves the real protocol
(REALITY, Hysteria2, mieru, ...) and does the per-user accounting; hops in
front of it relay raw bytes and report bytes, connections and probe results.
Clients get the landing node's protocol settings with the entry host and port,
which Xboard's separate `host`/`port` vs `server_port` fields already express.

### Several targets: failover and round-robin

A rule can name further next hops in `targets` (`[{target, weight}]`, at
most eight hops in all) — a backup line for when the first one is down, or
more lines to spread connections over. `balance` picks per new connection:

- `failover` (the default): the first hop whose TCP probe is up. A dial
  that fails moves on to the next hop at once, before the client has sent
  a byte, and marks the failed hop down without waiting for its next probe;
  a recovered hop takes new connections again. Built-in relay only.
- `roundrobin`: connections spread over the hops that are up, in
  proportion to `weight` (`weight` on the rule is the first target's),
  interleaved rather than in runs. Built-in relay and realm (realm's
  `extra_remotes` + `balance = "roundrobin: …"`; realm does not retry a
  failed hop, which is why it offers no failover).

One connection always uses one hop: this spreads and survives lines, it does
not make a single download faster. nftables DNAT forwards to one address and
refuses extra targets. The report carries per-hop health, RTT and
connection counts (`targets` in each forward status; bosun ≥ 0.49), and an
older agent ignores the extra fields and keeps using `target`.

### Firewall (ufw / firewalld)

With a firewall active, bosun opens what it listens on and closes it again
when the inbound or forward goes away (`firewall_auto_open`, default on;
state in `<data_dir>/firewall.json`, doctor check "Firewall auto-open").
That covers every inbound port, every forward, the standalone panel's own
port, and **80/tcp whenever something on the node gets its own certificate
over HTTP-01** — an inbound with `auto_cert` that is not set to `dns`, or
the decoy site. Without that last one the first issuance succeeds on a
fresh machine and a renewal fails two months later.

The sync happens when bosun applies state. **Turning the firewall on after
bosun is already running leaves the ports closed until the next apply**, so
restart bosun (`systemctl restart bosun`) after enabling ufw. SSH is never
bosun's business: open it yourself.

### PROXY protocol (real client addresses behind a relay)

A relay hides the client: the landing node sees the relay's address, so
device counting and access logs lump everyone behind it together. A rule
with `proxy_protocol: true` (built-in relay or realm, not nft) prefixes each
TCP connection with a PROXY protocol v2 header, and an inbound with
`accept_proxy_protocol: true` (xray only, `sockopt.acceptProxyProtocol`)
reads the client's address from it. Such an inbound must be reached only
through relays that send the header: direct connections fail. Captain sets
both ends when a forward targets one of its own inbounds that expects it.

### nftables backend

A forward rule with `backend: nft` is relayed by the kernel instead of
bosun's userspace relay: bosun writes one nftables table (`inet bosun_fwd`,
regenerated on every apply and deleted when the last nft rule goes) with a
prerouting `dnat` per tcp/udp port, a postrouting `masquerade` toward the
target, a `ct status dnat accept` forward rule, and sets
`net.ipv4.ip_forward=1`. `preserve_source: true` drops the masquerade so
the target sees the client's address, which only works when the target
routes its replies back through this node. Targets must be IPv4 (host names
are resolved once at apply); the `nft` binary must be installed, otherwise
the rule shows "nftables not installed" and stays down. Byte and connection
counters are not collected for nft rules; the target probe still is.

### Realm backend

`backend: realm` hands the rule to a [zhboner/realm](https://github.com/zhboner/realm)
process: bosun installs the pinned release (`coreinstall` manifest, musl
build on Alpine), writes `<data_dir>/realm/realm.toml` with every
realm-backed rule (`[[endpoints]]` with `listen`/`remote`; `both` turns UDP
on, `udp` turns TCP off) and supervises one `realm -c` process, restarting
it when the set changes. Host-name targets and UDP work; there are no byte
or connection counters. The doctor fails a realm rule when the process is
not running.

### Egress follows ingress (multi-IP hosts)

With `Node.EgressByIngress` (Captain: node → "Egress follows ingress") an
inbound bound to a specific address (its `listen`) sends its users' traffic
out from that same address: sing-box gets a `direct` outbound with
`inet4_bind_address` / `inet6_bind_address` and a rule per bound inbound,
xray a `freedom` outbound with `sendThrough`, hysteria `bindIPv4` /
`bindIPv6` on its direct outbound. Any-address inbounds keep the default
route, a node with a default landing outbound ignores the option (traffic
leaves through the landing), and speed-limited users keep their marking
exit on sing-box and xray. mita has no per-inbound egress control.

### Per-user speed limits, beside someone else's shaping

A limit becomes an HTB class per user on the egress interface (upload) and
another on an ifb device that mirrors ingress (download), both selected by
the firewall mark the cores stamp on that user's traffic.

The egress interface may already belong to something else — a VPS init
script that paces the line below the provider's policer, a hand-written tc
setup. bosun looks at the root qdisc before touching it:

- an HTB it did not install (its own is the one with `default 0`) is left
  alone, and the per-user classes hang **under** the class that qdisc sends
  unclassified traffic to, so the line shaping still applies above them;
  removing the limits then removes only bosun's classes and filters;
- anything else — no qdisc, `fq`, `fq_codel`, `mq`, `pfifo_fast`, or
  bosun's own HTB — is replaced with bosun's, as before.

The node status and the doctor say which of the two happened
(`nested_under`). Nesting is what makes "the line is capped at 500 Mbit and
each user gets 50" work; before it, a limit silently wiped the line
shaping and removing the last limit deleted the root qdisc with it.

### Audit rules

The panel may push audit rules (`Node.AuditRules`): each is a route-rule
match list (`domain:`, `full:`, `keyword:`, `regexp:`, `ip:`, `port:`,
`inbound:`, `geosite:`, `geoip:`, `protocol:`) with action `block` or
`log`. Block rules are prepended to the node's route rules on every core
with routing (sing-box and xray). hysteria and mita cannot route, so a
block rule does not stop their traffic; hysteria still *reports* hits
(its request log feeds the matcher) and the panel marks those hits
"log-only" rather than counting them as blocked. Every hit of either action is matched by bosun
itself on the same log feed the connection log uses (so xray's access log
and hysteria's debug log are switched on while rules exist) and reported
with the next report as user, inbound, client address, destination and
rule; one hit per user and rule per minute, 2000 buffered. A match value
the core would refuse (a bad CIDR, an unknown protocol, an empty pattern)
is dropped here and reported by the doctor check "Panel rules" instead of
being written into a config no core will load.

sing-box writes the client's requested destination into its log without
escaping it, so a crafted destination can forge whole log lines. bosun
therefore believes a line only when it names a user this node actually
serves on that inbound and the destination looks like a host; a forged
line naming somebody else is dropped. xray and hysteria escape their
fields and are not affected. Treat sing-box attribution as advisory
anyway: it comes from a log, not from an API. `geosite`,
`geoip` and `protocol` matches block in the core but cannot be evaluated
for the hit log.

### Connection log

When the panel asks for it (`Node.ConnLog`, Captain's Settings → Connection
log), the agent reports every accepted connection with the next report:
user, inbound, client address, destination host and port, TCP/UDP. The
facts come from the cores' own logs — sing-box and xray at their normal
level (xray's access log is switched on only then), hysteria at debug
(bosun filters those lines out of its own log) — so nothing extra runs on
the node; mita has no per-connection log and is not covered. A bounded
buffer (5000 events) drops the oldest when the panel is slow and reports
how many. Off by default; nothing is recorded until the panel enables it.

### Core isolation: unprivileged cores and the egress guard

With `cores.user: bosun-proxy` in config.yaml (the installer writes it for
new nodes; on an existing node add the line and restart, the account is
created on first start) every core process — sing-box, xray, mita,
hysteria, snell-server, realm — runs as that system account with only
`CAP_NET_BIND_SERVICE`, and supplementary groups are cleared. sing-box
and xray additionally hold `CAP_NET_ADMIN` while a speed limit is really
installed, because the limit marks sockets with `SO_MARK`; no other core
gets it, and the doctor says when it is granted. bosun itself stays root
for nftables, tc and the installers. If the account cannot be created or
used, bosun logs it, runs the cores as itself and fails the doctor's
isolation check rather than refusing to start. The work directories stay owned by bosun
(traversable, not writable, so a core cannot plant a symlink for a later
root-run write) and only the files a core must read change owner: its own
config and the two certificate PEMs of its inbounds. Every one of those
writes refuses to follow a symlink. certmagic's store next to the PEMs,
with the ACME account key and every site key, stays bosun's. All cores
share one account, so they can read each other's configs; nothing else on
the node is readable by a core.

The egress guard (on whenever `cores.user` is set; `cores.egress_guard:
false` turns it off) adds an nftables output rule for that account:
*new* connections from a core to loopback, link-local (`169.254.0.0/16`,
the cloud metadata service), RFC 1918, CGNAT (`100.64.0.0/10`) and the
IPv6 equivalents are dropped, so a subscriber cannot use the node to
reach the provider's internal network, the metadata endpoint, or the
node's own control services. On loopback only the ports a core genuinely
needs stay open: port 53 for a local DNS stub, hysteria's auth callback
and the decoy site a REALITY fallback dials. Nameservers in
`/etc/resolv.conf` that fall inside a blocked range (a VPC or
link-local resolver) are allowed automatically, so DNS keeps working on
cloud images. Replies on established flows are never touched, so clients
that arrive from private space (relays, line ingresses) keep working.
Ranges a node must reach go in `cores.egress_allow: [10.10.0.0/24]`.

The cores themselves also refuse those destinations for user traffic:
sing-box and xray get a reject rule for loopback, link-local, RFC 1918
and CGNAT ahead of every other rule (`Node.AllowPrivateDest` turns it
off, `Node.PrivateDestAllow` lists exceptions). The nft guard is the
backstop for destinations reached by name, which a route rule on
addresses cannot see.

The cores' own control APIs are the third layer. sing-box's `v2ray_api`
and xray's `api` are unauthenticated gRPC on loopback (127.0.0.1:9101 and
:9102 by default) and can add users, change inbounds and reset counters —
upstream offers no password for either. The guard therefore drops **every
non-root** connection to those ports, not just the core account's, so
neither a compromised core nor any other unprivileged process on the node
can reach them; bosun runs as root and is unaffected. This rule is
installed even when `cores.user` is unset.

The doctor check "Core isolation" shows the account, the guard's state and
the protected control ports, and warns when cores still run as root.

### ShadowTLS

A Shadowsocks inbound can be wrapped in ShadowTLS v3 (`Inbound.ShadowTLS`,
sing-box only — Xray has no ShadowTLS; REALITY is its answer to the same
problem). bosun then renders two inbounds: the public one is the
`shadowtls` listener, which performs a real TLS handshake with a site you
name (`handshake`, e.g. `www.apple.com:443`) and hands only authenticated
clients through to the Shadowsocks inbound, which moves to loopback. A
prober that connects sees that site's certificate and nothing else.

Every user gets their own ShadowTLS password, derived from their UUID
(`spec.ShadowTLSUserKey`), so a client needs two credentials — the
ShadowTLS password and the Shadowsocks key — and revoking a user revokes
both. `strict_mode` is on by default, which makes the listener refuse a
ClientHello the handshake server would not accept.

Subscriptions carry it where the client can express it: mihomo and Stash
as `plugin: shadow-tls` with `plugin-opts`, sing-box as a `shadowtls`
outbound the Shadowsocks outbound dials through (`detour`), Surge and Loon
as the flat `shadow-tls-*` keys, and share links as the
`?plugin=shadow-tls;…` form. The version is always written out because
mihomo, Stash and the link readers default to v2.

The sing-box document asks for a uTLS fingerprint, which is what makes the
handshake look like a browser's rather than Go's. Official sing-box
releases and the build bosun's own CI publishes both include `with_utls`;
a sing-box compiled without that tag refuses the whole document, so build
your own client with it if you build one.

### Strict ingress for mita and firewall auto-open

mita 3.37.0 and later bind a line-bound inbound's address natively
(`listenIPAddress`; bosun runs one mita process per inbound, and an address
change restarts that process because mita's reload keeps the old
listeners). Older mita builds listen on every address, so such an inbound
gets an nftables input rule instead (table `inet bosun_ingress`,
`ip daddr != <bind> tcp dport <port> drop`, one per port, UDP for BOTH's
second port): traffic for that port arriving on any other local address is
dropped, which is nobrand's "strict ingress" fallback. The doctor check
"Strict ingress" shows the state; with a native-binding mita it reports no
rules.

When ufw or firewalld is active, bosun allows the ports it listens on
(inbounds, forwards, the web panel) and removes the openings it made once
the inbound or forward is gone (`<data_dir>/firewall.json` remembers what
it opened; ports the operator opened by hand are never touched). Raw
nftables/iptables policies are only reported by the doctor. Set
`firewall_auto_open: false` in config.yaml to turn it off.

### mita native quotas

With the setting "mita native quotas" on (Settings page, or Captain's node
option), each user's allowance is also written into mita's own
`quotas: [{days, megabytes}]`, so the core keeps enforcing it while the
panel is unreachable. The window is the reset cycle: `days` mode as is, a
calendar-month reset becomes a rolling 31 days, no reset means the
subscription's lifetime. Right after a calendar reset mita may therefore
still block a heavy user for a few days.

### Subscription templates on the standalone panel

The "Sub templates" page is the same editor Captain has: a text template
per client format (`{{proxies}}`, `{{proxy_names}}` with `:tag=` and
`:match=` filters) and the visual designer (`pkg/subdesign`: proxy groups
whose members are all servers, name patterns per region or other groups,
plus an ordered ACL4SSR rule list with presets) that generates every
format at once. Under Captain the page is read-only and Captain's templates
apply.
