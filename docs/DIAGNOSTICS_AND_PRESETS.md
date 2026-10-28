# Exit diagnostics, delivery journals and configuration presets

Available from bosun 0.57.0. Existing Captain state/report fields remain
compatible; `traffic_epoch` and exit diagnostic results are additive.

## Exit diagnostics

Standalone **Probe → Network diagnostics → Exit** and Captain 1.8.0's node
diagnostics run a bounded node-origin check. The report contains IPv4/IPv6
observations, location/ASN sources, available reputation observations and,
when selected, AI/streaming service checks. Results can be exported as JSON.
They describe the node's host egress, not traffic through every configured
inbound/outbound chain. Missing IPv6, failed providers and unknown service
results must not be interpreted as success or an unlock guarantee.

The optional checker is [GeoCheck](https://github.com/remnawave/geocheck),
version 0.3.0, under MIT. It remains a separate process. The source tag is
rebuilt with unchanged application source, this repository's pinned Go
toolchain and `CGO_ENABLED=0`. The build updates `golang.org/x/net` to
v0.62.0 for HTTP/2 and HTML parser/renderer security fixes; see
`scripts/build-geocheck.sh` and
`licenses/geocheck-MIT.txt`. No AGPL panel/node implementation is linked or
copied. The release includes amd64/arm64 checker binaries, its license and
checksums. This dependency update affects newly built release attachments;
it does not change the pinned download or replace an already installed tool.

On the first Linux exit check, bosun downloads its fixed release artifact,
verifies SHA-256 and installs it into
`<data_dir>/tools/geocheck/0.3.0-r1/`. The pinned distribution is bosun
`v0.57.0`, not the latest upstream download. Root-owned/private directory
checks and no-symlink opens protect installation. A missing/unreachable
artifact produces an explicit error; no arbitrary executable is run from PATH.

One diagnostic runs at a time. Installation is bounded to 20 seconds and
the exit diagnostic to 90 seconds including preparation; output is bounded
to 128 KiB and validated against the expected JSON schema. Commands use a
fixed argument list with no shell or operator-supplied flags. MTR, portals
and automatic source detection are disabled for this diagnostic. Optional
source addresses must be IP literals; environment proxy/API secrets are
not inherited. Selecting service checks contacts those external services;
the default only requests address/location/reputation providers.

## Durable Captain traffic reports

`<data_dir>/traffic/` contains private immutable in-flight batches, each
bound to the panel URL and paired node identity. Keep this directory across
upgrades and restarts. A report is persisted and fsynced before delivery;
an unacknowledged report is retried with the same epoch, sequence, counters
and window. While it waits, new counters remain in the cores. A corrupt or
unsafe journal fails closed and is reported in the node log; do not remove
it merely to suppress that error.

Captain 1.8.0 records the receipt and all associated accounting atomically.
The sequence-only compatibility path remains available for older panels and
nodes, but the full receipt transaction improvement needs the newer Captain.
Core counter collection itself cannot participate in a disk transaction:
host failure between counter reset and fsync, or loss of uncollected counters
inside a core, remains a possible loss window.

## Named standalone presets

The inbound and routing editors can save named typed presets, edit reusable
fragments and preview changes before loading them into the draft. They take
effect only after the normal Save action and core/port checks. A changed
draft requires a new preview. Libraries persist in the private local state;
managed/fixed mode refuses mutations.

Inbound capture strips source keys, user scope, listener placement and local
certificate paths. Applying preserves the destination placement and user
permissions but generates fresh server keys, which can invalidate existing
clients. Outbound fragments accept typed share-link remotes, balancers and
node-owned WARP; remote proxy credentials remain in the private preset.
Route/outbound fragments append, leaving DNS and the default exit alone.
Unknown references, duplicate tags and mixed chain/balancer cycles fail.

Presets cannot override core control endpoints, accounting identities or
the node's private-network guards. Their preview is the portable typed
configuration, with credentials redacted in the diff; generated per-core
files still belong to bosun. Core routing limitations remain unchanged.
