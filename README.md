# Bosun

Single-server node agent. Runs upstream proxy cores as child processes and is
driven by a management panel. Standalone mode with a local UI comes later; the
first cut is managed mode only.

## Status

Working vertical slice, verified end to end against sing-box 1.14.0:

- Panel driver for Xboard's UniProxy v1 API (config, users, traffic push, status), with ETag caching.
- sing-box adapter: renders VLESS, VMess, Trojan, Shadowsocks (incl. 2022), Hysteria2, TUIC, AnyTLS, SOCKS, HTTP, Naive; TLS, REALITY, ws/grpc/httpupgrade/http transports, multiplex, custom outbounds with chaining, route rules.
- Xray adapter: VLESS, VMess, Trojan, Shadowsocks (AEAD), SOCKS, HTTP over raw/ws/grpc/httpupgrade/xhttp, TLS and REALITY; **hot user add/remove** on VLESS/VMess/Trojan through HandlerService, restart otherwise; per-user stats via StatsService; config validated with `xray run -test`. Verified e2e: REALITY traffic, hot add and hot remove, per-user push.
- Hysteria adapter (official Hysteria 2 server): users live in bosun, not in the config. Hysteria calls bosun's HTTP auth endpoint per connection, so adds are instant and removals are enforced with a kick through the traffic stats API; only listener changes restart the process. Per-user stats from `/traffic?clear=1`. One hysteria2 inbound per node with this core; sing-box serves several. Verified e2e with the official client.
- mita adapter (official mieru server): config file + `mita run` as a child, gRPC over a unix socket for hot user reload, proxy restart on port change, and per-user counters (deltas computed by bosun). Verified with the official mieru client.
- Per-user traffic via each core's own control plane, hand-encoded protobuf, no generated stubs (`internal/core/grpcraw`).
- Supervised child process: log relay, restart with backoff, graceful stop.
- Core installer with a tested-version manifest (`internal/coreinstall`): leave `binary` empty and bosun downloads the newest release it has verified, checks its sha256, and installs it under `<data_dir>/cores/<core>/<version>/`. Releases known to break deployments are marked `broken` and only installed when named explicitly. sing-box is built from the upstream tag with the stats API tag (needs a Go toolchain until CI ships binaries).
- Config validated with `sing-box check` before every start or apply.

Not yet: forwarding chains; local UI; traffic spool on push failure; CI-built sing-box.

Core selection: `cores.order` in the config is the preference; an inbound goes to the first core that supports its protocol, transport and cipher. XHTTP only runs on Xray, HTTP/2 transport and Shadowsocks 2022 multi-user only on sing-box, mieru only on mita. Hysteria2 runs on sing-box (default) or the official server when `hysteria` is listed first.

## Layout

```
cmd/bosun/            entry point: run | render | version
internal/spec/        core-agnostic node / inbound / user model
internal/core/        Core interface, registry, inbound -> core assignment
internal/core/subprocess/   child process supervisor
internal/core/grpcraw/      raw gRPC invoke for hand-encoded protobuf
internal/core/v2stats/      V2Ray-lineage StatsService client (sing-box and Xray)
internal/core/singbox/      sing-box renderer, stats client, process driver
internal/core/xray/         Xray renderer, HandlerService hot user updates, process driver
internal/core/mita/         mieru server (mita) renderer, RPC client, process driver
internal/core/hysteria/     Hysteria 2 renderer, auth endpoint, stats client, process driver
internal/panel/       Driver interface
internal/panel/xboard/      Xboard UniProxy v1 driver
internal/agent/       managed-mode loop: pull -> render -> apply, stats -> push
internal/config/      YAML config
internal/sysinfo/     host status snapshot
```

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
| singbox | 1.14.0 | tested | built from source with `with_v2ray_api` |
| xray | 26.3.27 | tested | REALITY works with mihomo and sing-box clients |
| xray | 26.9.9 | broken | REALITY rejects mihomo/sing-box clients |
| mita | 3.36.1 | tested | official mieru server |
| hysteria | 2.12.2 | tested | official Hysteria 2 server |

## sing-box binary

Official sing-box release builds do **not** include the V2Ray stats API, which
per-user accounting needs. The installer therefore runs
`go install -tags with_quic,with_utls,with_clash_api,with_v2ray_api,with_gvisor,with_acme github.com/sagernet/sing-box/cmd/sing-box@v1.14.0`,
unmodified upstream source with extra build tags, not a fork. Module checksums
are verified by the Go toolchain. Bosun's CI will publish prebuilt binaries so
nodes do not need Go; until then a Go toolchain is required for sing-box. Note sing-box has no runtime user API: every
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

Custom outbounds are passed to the serving core in that core's own dialect
(sing-box flat fields, or Xray `settings` / `streamSettings`); bosun does not
translate between the two yet.

## mita binary

Any official `mita` release works (3.36.x tested). Bosun runs it with
`MITA_CONFIG_JSON_FILE`, `MITA_UDS_PATH` and `MITA_INSECURE_UDS` pointing into
its own data dir, so it does not touch a system-installed mita's config or
socket. Unix socket paths are limited to ~100 bytes; bosun falls back to the
temp dir automatically when the data dir path is too long.

## Licensing notes

`references/` in the workspace contains projects under GPL/AGPL. Nothing from
them is copied here. The sing-box stats client re-implements the wire format
from the public proto definition.
