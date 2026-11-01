# Forward transport semantics

A complete path is compiled by Captain into dedicated forwarding listeners.
Bosun receives ordinary `Forward` rules; this does not add another wire protocol,
change structural revisions or make a configuration receipt a connectivity test.

## Native relay

TCP connections and UDP sessions independently select their next hop. A UDP
session is keyed by the client's source address and port at one listener and
stays on its selected target. Weighted round-robin advances for new sessions,
not individual datagrams. A `both` listener does not promise that a client's TCP
and UDP traffic selects the same branch.

UDP has no generic connection handshake. Sequential candidate attempts can
recover from address resolution or local routing errors; a successful socket
creation or write does not prove that the destination received the datagram.
TCP probe results never remove a candidate from UDP selection. Complete-path
UDP and mixed paths must not inherit TCP health or automatic health failover.

A native UDP session expires after 60 seconds without a successful write toward
the target or a successful reply to the client. Either direction keeps it alive,
including a continuous one-way stream. Failed reads or writes close the socket;
a later datagram may create a new session. Idle expiry, failed return delivery,
rule deletion and cancellation close the upstream socket and retire connection
counters exactly once. UDP delivery itself remains best effort.

An identical relay rule keeps its sessions. Changing or deleting a rule closes
its existing TCP connections and UDP sessions. There is no drain or zero-loss
handoff contract.

## Realm 2.9.6

The pinned realm backend accepts TCP, UDP and `both` for single-target endpoints.
Its TCP balancer supports weighted round-robin. Its UDP implementation uses only
the primary remote; it does not select `extra_remotes`. Existing forward inputs
are retained for compatibility, but a new complete-path compiler must not use a
realm UDP/mixed endpoint as a multiple-candidate selector. A native entry can
select dedicated single-target realm branches instead.

All realm endpoints on a node share one process. Any configuration change,
including adding an unrelated endpoint, restarts that process and interrupts
its existing traffic. Identical configurations leave a running process alone.
There is no per-endpoint drain. An installed process is not an end-to-end check.

## nftables

Each nft rule has one target. An explicit listen address and its target must use
the same address family. Hostnames resolve to one address, using the listen's
family or preferring IPv4 without an explicit family. This is not NAT64/NAT46 or
a dual-stack target fan-out. Service-control preparation pins the exact resolved
target and family for the matching subsequent apply.

Bosun resolves and validates every desired nft target before installing one
batch. A preflight failure preserves the previously installed table, fails the
apply and marks the requested backend state unsuccessful. A repaired complete
set can be retried. An nft command failure likewise does not update bosun's
record of the successfully installed script.

The table uses PREROUTING DNAT and POSTROUTING masquerade, with no OUTPUT NAT.
A client running on the forwarding host does not exercise that DNAT path.
Complete paths must avoid a co-located preceding hop that dials its own nft
listener. Source preservation needs explicit return routing and is not implied
by composing multiple hops.

Atomic table replacement does not flush connection tracking. Existing flows
may retain their old NAT mapping after a rule changes or disappears. A successful
apply is not proof that old flows drained or that old path resources can be
removed without interruption. Bosun does not flush conntrack or promise drain.

## Validation

The ordinary `internal/forward` race tests use actual loopback sockets to cover
UDP affinity, round-robin, mixed TCP/UDP, one-way activity in each direction,
idle retirement, failed client reply delivery and cancellation. nft unit tests
exercise failed preflight, retry and exact service-control resolution reuse.

Linux network-namespace integration is opt-in and requires root plus `unshare`,
`nsenter`, `ip`, `nft` and `python3`. Run only on an isolated disposable Linux
host; namespaces own the links, sysctls and nft table. The test does not contact
an operational panel or node:

```sh
BOSUN_NFT_TEST=1 GOWORK=off go test -race ./internal/forward -run TestNFTLinux -v -timeout=3m
```

The runtime transaction test drives the actual Manager in the forwarding
namespace. Separate client and target namespaces prove real DNAT traffic over
IPv4/IPv6 TCP/UDP. A failed DNS preflight retains the listed table and working
traffic; replacement sends new tuples to the new target while held tuples retain
the old target. It closes those tuples before removing its table. This is a
measured conntrack boundary, not an application-level drain guarantee.

A realm acceptance run additionally needs the manifest-pinned 2.9.6 executable.
Verify its release archive against `internal/coreinstall/manifest.go`, extract it
in a disposable directory, then pass the executable and its computed SHA-256:

```sh
BOSUN_REALM_TEST=1 BOSUN_REALM_BINARY=/absolute/path/to/realm \
  BOSUN_REALM_SHA256=<verified-executable-sha256> GOWORK=off \
  go test -race ./internal/forward -run TestRealmLinuxRuntime -v -timeout=3m
```

This test uses loopback only, checks the supplied digest and version, transfers
actual single-target TCP/UDP traffic, verifies unchanged configuration keeps a
TCP stream, and proves that adding an endpoint replaces the shared process and
interrupts the old TCP stream. New TCP and UDP traffic must recover. It neither
downloads a binary nor configures an operational node. Rendering TOML is not
evidence of a real realm transfer. Neither an unexecuted opt-in test nor a skipped
test counts as Linux/realm acceptance.

For a Linux host without Go, cross-compile this package's test binary using Go
1.26.10, for example `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOWORK=off go test -c
-o forward.test ./internal/forward`, and invoke it with the same environment plus
`-test.run='TestNFTLinux|TestRealmLinuxRuntime' -test.v -test.timeout=3m`. Build a
race-enabled binary on a Linux host with a C compiler when race instrumentation
is required; a static cross-compiled binary does not provide race coverage.
