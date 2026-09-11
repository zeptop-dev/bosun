# Bosun

Single-server node agent. Runs upstream proxy cores as child processes and is
driven by a management panel. Standalone mode with a local UI comes later; the
first cut is managed mode only.

## Status

Working vertical slice, verified end to end against sing-box 1.14.0:

- Panel driver for Xboard's UniProxy v1 API (config, users, traffic push, status), with ETag caching.
- sing-box adapter: renders VLESS, VMess, Trojan, Shadowsocks (incl. 2022), Hysteria2, TUIC, AnyTLS, SOCKS, HTTP, Naive; TLS, REALITY, ws/grpc/httpupgrade/http transports, multiplex, custom outbounds with chaining, route rules.
- mita adapter (official mieru server): config file + `mita run` as a child, gRPC over a unix socket for hot user reload, proxy restart on port change, and per-user counters (deltas computed by bosun). Verified with the official mieru client.
- Per-user traffic via each core's own control plane, hand-encoded protobuf, no generated stubs (`internal/core/grpcraw`).
- Supervised child process: log relay, restart with backoff, graceful stop.
- Config validated with `sing-box check` before every start or apply.

Not yet: Xray and official Hysteria cores; forwarding chains; local UI; traffic spool on push failure.

## Layout

```
cmd/bosun/            entry point: run | render | version
internal/spec/        core-agnostic node / inbound / user model
internal/core/        Core interface, registry, inbound -> core assignment
internal/core/subprocess/   child process supervisor
internal/core/grpcraw/      raw gRPC invoke for hand-encoded protobuf
internal/core/singbox/      sing-box renderer, stats client, process driver
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
