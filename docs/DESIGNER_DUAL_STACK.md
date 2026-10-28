# Node dual-stack connection selection

The subscription designer's optional `enhancements.node_dual_stack` setting
generates these top-level Mihomo settings:

```yaml
ipv6: true
tcp-concurrent: true
```

The setting is saved with the design, so generating or applying that design
again preserves it. Turning it off restores the previous generated output;
it does not force IPv6 off. Existing templates and saved designs remain
unchanged until an administrator applies a design. This enhancement is limited
to the `clash` (Mihomo) format. Inspection reports other formats as unsupported
while it is enabled, instead of silently dropping the option.

These are client-wide settings. They also affect other connections using the
client's common dialer, including applicable direct connections; Mihomo does
not expose this switch exclusively for one server protocol. They do not enable
TUN or change `dns.ipv6`, the separate client-facing DNS AAAA response setting.
The final node's explicit `ip-version` override is preserved; its default in
Mihomo is already `dual`.

## Prerequisites

- Publish a domain as the node's actual connection address (`server`). Changing
  a TLS/REALITY SNI alone does not change the address used to connect.
- The domain must resolve to the intended public A and AAAA addresses. Both
  listeners, ports, firewalls and network paths must work. DNS health alone
  does not establish connectivity.
- Do not force one family with `ip-version: ipv4` or `ipv6` if both are wanted.
  A fixed IP address has no alternate family to resolve.
- The client device needs usable IPv6 for its IPv6 attempt to succeed. The
  first successful connection is selected; bandwidth is not combined.
- For a chained proxy, dialing is delegated to the chosen upstream. Do not
  assume the downstream node independently performs local dual-stack racing.

## Protocol boundary

The following audit uses Mihomo **v1.19.33**, commit
`3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`, rather than assuming all protocols
behave the same because they share the `server` field.

| Captain/bosun protocol | Mihomo node address behavior |
| --- | --- |
| VLESS, VMess, Trojan | Their TCP transports use the common concurrent dialer. This includes TCP/TLS/REALITY where supported, WebSocket, HTTP upgrade, HTTP/H2, and gRPC. QUIC variants must be considered separately. |
| Shadowsocks, including ShadowTLS | TCP connection to the proxy uses the common dialer. Native Shadowsocks UDP resolution is separate and is not proof of UDP handshake racing. UDP-over-TCP reuses its TCP carrier. |
| AnyTLS | The AnyTLS client receives a dialer adapter that delegates TCP connections to Mihomo's common dialer. |
| SOCKS5, HTTP/HTTPS proxy | The connection to the proxy uses the common TCP dialer. SOCKS5 UDP relay destinations have separate handling. HTTP proxy support does not gain UDP support from this enhancement. |
| Snell | Uses the common TCP dialer. The existing supported Snell versions and multi-user export restrictions remain unchanged. |
| Hysteria2, TUIC | In this audited version, `common.DialQuic` wraps QUIC connection establishment in the same concurrent dialer. It can select between IPv4/IPv6 QUIC candidates; this is **QUIC**, not TCP racing. TUIC's `reduce-rtt` and VLESS XHTTP H3 use early QUIC dialing, whose completion is not the same as fully validated service reachability. Older client versions may differ. |
| Mieru | Its Mihomo resolver selects a single address before handing it to the Mieru client, even for TCP transport. Either family may be used, but this enhancement does not establish a dual-stack race. |
| WireGuard | Resolves and configures one endpoint per peer. Accepting A/AAAA is not parallel peer-handshake racing. No duplicate peers or credentials are generated. |
| SSH, Naive | Captain/bosun's current Mihomo renderer does not export these protocols. This enhancement does not add an adapter or silently reinterpret them as another protocol. |
| ShadowsocksR, Hysteria v1 | Not Captain/bosun inbound protocol types. They are outside the generated-node support claim, even if a separately authored Mihomo configuration can use them. |

Protocol-wide support does not override transport-specific restrictions or
administrator-supplied client fields. A successful TCP socket selection also
does not guarantee the selected server will complete TLS or proxy
authentication; the race is not an end-to-end health check.

## Server listeners

Xray and sing-box already render the omitted listener as `::`; the native
Hysteria adapter renders an all-address `:port`, and Mieru omits the address
when listening everywhere. The standalone Snell adapter retains its existing
omitted-listener default, `0.0.0.0:port`. It does not automatically rebind an
existing IPv4 service. An administrator who wants both address families must
explicitly choose `::` and verify that the actual host and Snell core accept
both IPv4 and IPv6 connections. Hosts with IPv6 disabled or IPv6-only wildcard
sockets cannot be assumed to provide this behavior. Explicit addresses and
Snell's separate `ipv6 = false` outbound DNS policy remain unchanged.

IPv4-mapped listening on an IPv6 wildcard still depends on the host network
stack and the core. Explicit single-family binds, NAT mappings, container port
publishing and host firewalls can prevent one family from being reachable.
This change does not rewrite those configurations or publish an AAAA record
as a substitute for testing the IPv6 listener.

## Verification

Automated tests cover saved-design JSON round trips, opt-in/opt-out behavior,
format gating, DNS-policy independence, and final subscription delivery for
all 12 currently exported protocols, including preservation of explicit
single-family overrides. Snell render tests cover the existing omitted IPv4
default and explicit IPv4, IPv6 and `::` wildcard addresses.

`TestSnellListenerFamiliesLive` is an opt-in listener check using
`BOSUN_SNELL_TEST_BINARY` in an isolated Linux network namespace. It checks the
unchanged default IPv4 listener, explicit `::` dual-family wildcard, and
explicit IPv4/IPv6 listeners. The dual-family case requires the host and core
to support IPv4-mapped IPv6 sockets. This Linux Snell check has not been run in
this change; generated configuration tests are not proof of live connectivity.

`TestMihomoNodeDualStackConnectivityLive` can run with
`BOSUN_MIHOMO_TEST_BINARY` set to an installed Mihomo binary. It starts an
isolated temporary client, synthetic DNS and local HTTP proxy listeners. The
three scenarios are IPv4-only, IPv6-only and both families, while DNS always
returns both A and AAAA. It also keeps `dns.ipv6: false` to verify that the
node's dual-stack lookup is independent of client-facing AAAA responses. It
does not read the user's running configuration or change system proxy/TUN
settings. This is a representative TCP connectivity check, not an end-to-end
test of every listed protocol or public network performance.

The existing `TestMihomoDesignerConfigurationsLive` parser suite also enables
this enhancement alongside the other designer enhancements.

## Upstream sources

- [Mihomo global settings](https://wiki.metacubex.one/config/general/) and
  [per-proxy IP version](https://wiki.metacubex.one/config/proxies/#ip-version).
- Pinned [common dialer](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/component/dialer/dialer.go)
  and [outbound dialer selection](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/base.go).
- Pinned [VLESS](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go),
  [VMess](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vmess.go),
  [Trojan](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/trojan.go),
  [Shadowsocks](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/shadowsocks.go),
  [AnyTLS](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/anytls.go),
  [Snell](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/snell.go),
  [SOCKS5](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/socks5.go),
  and [HTTP](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/http.go) adapters.
- Pinned [QUIC dialer](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/tuic/common/dial.go),
  [Hysteria2](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/hysteria2.go),
  [TUIC](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/tuic.go),
  [Mieru](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/mieru.go),
  and [WireGuard](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/wireguard.go) adapters.
- [Surge's server-listener discussion](https://www.nssurge.com/blog/snell-v6/)
  distinguishes explicit separate-family listeners from IPv6 socket
  compatibility behavior. This task does not upgrade the pinned Snell core.
