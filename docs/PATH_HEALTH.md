# Complete business-path handshakes

Captain may attach an optional `path_health` object to the entry Forward of a
complete path route. Existing deployments default to no health policy. Only
native TCP relay is supported; UDP, nft, realm and PROXY-prefixed paths are not
part of this feature. Ordinary next-hop TCP probes and counters remain intact.

Each candidate must exactly match an existing forwarding target. The agent
connects to that **business port**, allowing the existing relays to carry the
handshake to the real landing inbound. It never creates a shadow port,
unauthenticated responder, proxy user, arbitrary URL probe or direct fallback.
Shared validation rejects mismatched targets and unsupported automatic modes.

Supported handshakes are:

- Standard TLS with a DNS server name, host-system trusted certificates and
  TLS ≥1.2. There is no insecure certificate mode. SNI only affects the TLS
  handshake, not the target used for dialing. Landing ALPN settings are retained.
- A plain HTTP proxy: fixed `OPTIONS * HTTP/1.1` with `Host: example.com`,
  requiring status 407 and a `Proxy-Authenticate` header. The Host value is not
  resolved or connected to. No URL or CONNECT request is sent.
- A plain SOCKS5 proxy: offer username/password authentication (`05 01 02`),
  requiring `05 02`. Neither credentials nor a destination follow.

REALITY, ShadowTLS and other unsupported landing protocols remain unsupported.
A TLS success only proves the landing TLS handshake, including for WS/gRPC
transports. None of these samples proves customer authentication, UDP,
Internet egress or the client-to-entry path.

## Sampling and selection

Each manager process has a fresh random epoch and increasing probe sequence.
The sequence and observation time advance only after a real handshake attempt;
report construction, retry and snapshot reads never renew them. A node-wide
eight-slot budget bounds concurrent path handshakes. Queued work is cancellable
and does not renew old evidence; every active handshake has a deadline.

The defaults are a 15-second interval, 3-second timeout, three consecutive
failures to withdraw and two consecutive successes to restore. Samples expire
after `max(90, 2*interval_seconds + timeout_seconds)` seconds. Captain also binds
evidence to a recent accepted process/configuration receipt, current identity,
actually delivered Forward and candidate digest. A deeper port/address change
invalidates the old candidate evidence even when its first-hop port is unchanged.

With `auto_failover:false`, probes only observe; ordinary selection is unchanged.
With it explicitly enabled, only fresh up candidates are used in declared
failover order. Unknown at startup, stale, down or unsupported candidates are
not appended as a last resort, including a single candidate. If none qualifies,
the new connection is rejected. Hysteresis preserves an up candidate during
the configured failure threshold; the latest failure is reported separately.
Recovering candidates need the configured consecutive successes.

Health-state changes leave established streams alone. Applying a different
Forward or normal shutdown can still close them. Service-control pause and
lease expiry cancel probes and remove their listeners through the existing
agent lifecycle. Socket ownership/marks follow the ordinary controlled relay
path. Offline cached state cannot produce a new delivered-state confirmation.

There is no automatic user traffic entry: the handshake never authenticates a
customer or opens a proxy destination. Its actual bytes still contribute to
relay and host NIC counters, and therefore may count against supplier traffic
or existing server-wide traffic protection.

## Validation evidence

Native TCP tests exercise A → B1 → B2 → D and A → C → D. Stopping B2 leaves
B1's first-hop TCP probe successful but fails the complete-path handshake;
automatic selection then uses C. The tests cover all-down rejection, thresholded
recovery, unchanged monitoring-only behavior, stale/unknown single candidates,
established-stream preservation, eight-slot concurrency and cancellation of
queued/active handshakes. Agent tests exercise the actual relay manager,
immutable report sample identity, cached/expired authorization and pause cleanup
using an injected guard runner; they do not claim host firewall enforcement.

Direct protocol compatibility was separately verified on Linux with Xray
26.3.27-r1 and official sing-box 1.14.1-r2, and on Darwin with Xray 26.3.27 and
sing-box Extended 1.14.1-2.7.2. Each returned the expected HTTP/SOCKS challenge;
trusted TLS with the correct name passed, while wrong-name and untrusted TLS
failed. Those checks do not establish proxy-account authentication or Internet
access. No upstream core changes or forks are introduced by this feature.
