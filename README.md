# Bosun

Single-server node agent. Runs upstream proxy cores as child processes and is
driven by a management panel. Standalone mode with a local UI comes later; the
first cut is managed mode only.

## Status

Working vertical slice, verified end to end against sing-box 1.14.0:

- Panel driver for Xboard's UniProxy v1 API (config, users, traffic push, status), with ETag caching.
- sing-box adapter: renders VLESS, VMess, Trojan, Shadowsocks (incl. 2022), Hysteria2, TUIC, AnyTLS, SOCKS, HTTP, Naive; TLS, REALITY, ws/grpc/httpupgrade/http transports, multiplex, custom outbounds with chaining, route rules.
- Xray adapter: VLESS, VMess, Trojan, Shadowsocks (AEAD), SOCKS, HTTP over raw/ws/grpc/httpupgrade/xhttp, TLS and REALITY; **hot user add/remove** on VLESS/VMess/Trojan through HandlerService, restart otherwise; per-user stats via StatsService; config validated with `xray run -test`. Verified e2e: REALITY traffic, hot add and hot remove, per-user push.
- mita adapter (official mieru server): config file + `mita run` as a child, gRPC over a unix socket for hot user reload, proxy restart on port change, and per-user counters (deltas computed by bosun). Verified with the official mieru client.
- Per-user traffic via each core's own control plane, hand-encoded protobuf, no generated stubs (`internal/core/grpcraw`).
- Supervised child process: log relay, restart with backoff, graceful stop.
- Config validated with `sing-box check` before every start or apply.

Not yet: official Hysteria core; forwarding chains; local UI; traffic spool on push failure.

Core selection: `cores.order` in the config is the preference; an inbound goes to the first core that supports its protocol, transport and cipher. XHTTP only runs on Xray, HTTP/2 transport and Shadowsocks 2022 multi-user only on sing-box, mieru only on mita.

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
internal/panel/       Driver interface
internal/panel/xboard/      Xboard UniProxy v1 driver
internal/agent/       managed-mode loop: pull -> render -> apply, stats -> push
internal/config/      YAML config
internal/sysinfo/     host status snapshot
```

## Run

```sh
make build
cp config.example.yaml /etc/bosun/config.yaml   # edit panel + core paths
bin/bosun render -c /etc/bosun/config.yaml       # print what would be applied
bin/bosun run    -c /etc/bosun/config.yaml
```

## sing-box binary

Official sing-box release builds do **not** include the V2Ray stats API, which
per-user accounting needs. Build from the upstream tag with the tag enabled:

```sh
go build -tags "with_quic,with_utls,with_clash_api,with_v2ray_api,with_gvisor,with_acme" ./cmd/sing-box
```

This is unmodified upstream source with an extra build tag, not a fork. Bosun
releases will ship such a binary. Note sing-box has no runtime user API: every
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
