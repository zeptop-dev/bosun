# Core packages, adapters and runtime instances

In the standalone console, open **Overview → Core management**. For managed nodes, use **Captain → Nodes → node details → Core management** as a full administrator. Upgrade bosun before using the controls: older nodes do not advertise the new inventory or execute these jobs.

An inbound selects a protocol and an adapter using the existing `core` field. Core management selects the installed release for each adapter. Downloading a package does not start it or alter any inbound. Each distribution has one active version; several distributions can run together. The catalog contains reviewed versions, not arbitrary URLs or executable uploads.

1. Choose a distribution/version and download it.
2. Select **Activate / switch**, review the interruption notice, and confirm.
3. Select that core in an inbound's editor, or retain automatic selection for existing supported protocols.

A switch serializes with configuration application and reporting. It checks the inventory revision and configuration compatibility, validates sing-box/Xray configurations with the candidate binary, checkpoints outstanding traffic, stops the old instance and waits for the new instance's statistics API. Failed startup or selection persistence restores the old instance and reports the error. Other adapters validate their rendered model and then use startup/readiness checks. Switching interrupts connections served by that distribution. It cannot atomically stop network traffic and persist counters; the boundaries below still apply.

Successful selections and preference order persist in `<data_dir>/cores/active.json`; downloaded executables are under `<data_dir>/cores/<distribution>/<version>/`. New UI-enabled distributions are appended to the preference order. A switch that would move existing automatically assigned inbounds to another core is rejected; pin them first. A failed configuration apply must be resolved before switching. These files are installation state, separate from the standalone configuration backup; preserve the data volume or reselect cores when restoring on a new host. An explicit `config.yaml` binary path remains an administrator pin and cannot be replaced through the UI.

The agent's catalog is the source of available packages. Extending it requires reviewing the upstream format, adapter capabilities, platform assets, checksums and runtime tests. Updating the inventory never silently activates a release. Concurrent activation requests, stale revisions and expired tasks are rejected. Successful replayed jobs do not restart the core again.

## Traffic accounting during changes

With Captain or the standalone driver, bosun collects running core counters before applying configuration changes, disabling cores, switching packages and graceful shutdown. It fsyncs them to the private traffic journal before proceeding. An unavailable panel does not prevent these local checkpoints: a report already sent retains its original sequence and contents, while newer unsent checkpoints accumulate separately. After acknowledgement, they form the next report. The standalone store saves its receipt with user and aggregate totals so replay after a restart does not charge twice. Counter identities and sing-box aliases remain tied to the last successfully applied configuration, including when a new render or apply fails.

Reading user statistics resets only user counters. Official sing-box and Extended use a different protobuf filter field from Xray; bosun sends both supported forms so subsequent native inbound and outbound totals remain available. No estimated totals are substituted for the core's counters.

The supplied systemd unit uses `KillMode=mixed`: systemd initially signals bosun, allowing it to checkpoint and stop its children, then kills any remaining processes if the stop timeout expires. **Existing service units are not changed by binary self-update.** After installing a version containing this fix, add the following using `sudo systemctl edit bosun` if the effective unit still uses the default `control-group` mode:

```ini
[Service]
KillMode=mixed
```

Run `sudo systemctl daemon-reload` and check `systemctl show bosun -p KillMode`. Keep the normal service stop timeout long enough for the ten-second checkpoint and child shutdown. Process managers and containers likewise need to let bosun handle termination before killing its cores. The first upgrade from an old binary cannot retroactively collect counters that the old shutdown path discards.

A failed statistics read or journal save defers ordinary changes; private-access revocation still stops old sockets even when accounting cannot be saved. This is not a guarantee against arbitrary crashes, SIGKILL, disk failure or power loss: upstream read/reset and local fsync are separate operations, and bytes arriving after the final sample but before the core stops may be lost. Xboard's legacy push protocol does not gain durable receipts. Standalone daily graph history is a separate file from receipt-protected quota and aggregate totals. Before downgrading to an older bosun, stop client traffic and allow pending and buffered batches to be acknowledged; older binaries do not understand the new buffered checkpoints.

The real Extended regression runs with `BOSUN_EXTENDED_TEST_BINARY=/path/to/sing-box go test -race ./internal/agent -run '^TestRealExtendedTrafficCheckpointAndAggregates$' -v`. It uses local SSH/echo traffic to check immediate reload/shutdown, lost-response replay, identities and native user/inbound/outbound counters. CI downloads the reviewed package with `BOSUN_TEST_DOWNLOAD_CORES=1` for this test; it does not use WARP credentials or alter host firewall rules.

## Xray WireGuard device accounting and compatibility

Registered WireGuard device identities require bosun 0.77 and an Xray binary
reporting the `wireguard_devices` capability. The adapter reads the executable's
version; upstream 26.6.27 introduced WireGuard source-address attribution to
users. The older 26.3.27 core ignores peer email and cannot provide native
WireGuard user accounting or user-routing marks. Its existing legacy clients
remain supported, while new device fields require an explicit core upgrade.
Each registered device has an independent key and address but shares the
parent account's `NAME|INBOUND` statistics and shaping mark. A peer change
restarts Xray; retained clients may take a WireGuard handshake retry interval
to reconnect. The version threshold identifies a capability, not a blanket
recommendation to select every newer Xray release; use the reviewed catalog.

Since bosun 0.77.1, generated REALITY server settings explicitly retain the
previous no-client-version-floor policy with `minClientVer: "0.0.0"`.
[Xray 26.7.11 changed the omitted-field default to 26.3.27](https://github.com/XTLS/Xray-core/commit/af7eb68028732a8ee3c0e5d6ab2b8a657bb2e770),
rejecting clients such as Mihomo that send a REALITY version identity of 1.8.2.
The default is applied during initial inbound rendering, before overrides;
explicit raw version restrictions are never rewritten. Managed inbounds still
cannot be replaced through the node-level override. Keys, short IDs, user
authentication and unauthenticated fallback limits remain required as before.
Upstream's version floor addresses client TLS-fingerprint concerns; restoring
connectivity does not upgrade those fingerprints or establish resistance to
traffic classification.

The 26.7.28-r2 build is marked broken: it uses Go 1.27.3, whose standard TLS
buffer layout no longer matches the unsafe layout assumptions in that upstream
version's Vision implementation. See the [upstream compatibility fix](https://github.com/XTLS/Xray-core/pull/7176).
Passing WireGuard or REALITY-only tests does not verify ordinary TLS + Vision.
The separately published 26.7.28-r3 rebuild retains Go 1.26.10's compatible
TLS layout and the same security dependency updates. It remains an explicitly
selected caution version; use bosun 0.77.1 or newer for its REALITY compatibility
policy. The default 26.3.27-r1 core remains unchanged.

New Xray versions also apply a [final destination policy in freedom
outbounds](https://github.com/XTLS/Xray-core/blob/v26.7.28/proxy/freedom/freedom.go).
bosun states its existing permissions explicitly: private destinations stay
blocked unless the node's global policy or that inbound's private grant
allows them. Per-inbound grants retain their address, protocol, port and
socket-mark scopes; other direct/shaping outbounds do not inherit them.
Managed VLESS Reverse permits public destinations while keeping its existing
private-destination restrictions. An explicit operator `finalRules` policy
is preserved. The removed `ipsBlocked` setting is rejected on capable modern
cores so an upgrade cannot silently drop an explicit restriction.

Core-owned DNS queries under a scoped private policy use a separate reserved
`private-dns` outbound. This preserves the existing resolver/upstream access
without granting subscribers that access. The existing non-root nft policy,
resolver exceptions and configured upstream exceptions still govern those
DNS sockets; the renderer creates no new firewall permissions. Real listeners
cannot impersonate the internal DNS tag. System-resolver queries and core
API listeners do not use freedom outbounds.

Xray 26.7.11 and later also removed unencrypted VMess/SS modes and disallow
unencrypted public VLESS/Trojan outbounds. bosun rejects incompatible rendered
configurations, including reverse connections and custom legacy-shaped
outbounds, before the running core is stopped. Configure TLS/REALITY or keep
the previous core for those paths. It never changes a requested VMess
`none`/`zero` mode into `auto` silently. The candidate binary's own config
check remains mandatory after bosun's preflight checks.

The opt-in tests use only local sockets and temporary configurations:

```sh
BOSUN_XRAY_WG_TEST_BINARY=/path/to/xray go test ./internal/core/xray -run 'TestWireGuardDevicesLiveXray|TestFreedomFinalRules.*LiveXray' -count=1
BOSUN_XRAY_TEST_BINARY=/path/to/xray go test ./internal/core/xray -run '^TestReverseLiveXray$' -count=1
BOSUN_XRAY_TEST_BINARY=/path/to/xray-26.7.28 BOSUN_MIHOMO_TEST_BINARY=/path/to/mihomo go test ./internal/core/xray -run '^TestRealityMihomoClientVersionLive$' -count=1
```

The Mihomo regression uses a local TLS disguise service and HTTP destination.
It checks that the omitted upstream version floor rejects Mihomo, bosun's
rendered compatibility default permits a real REALITY + Vision request, and
an explicitly restored 26.3.27 floor rejects that same client again. This does
not test public network quality or ordinary certificate-based TLS + Vision.

They cover concurrent device clients, shared account/separate inbound
counters, revocation, private destination permission changes, internal DNS
isolation and reverse connectivity. Linux tc enforcement additionally needs
the dedicated privileged, isolated-network shaping test.

## sing-box Extended

`singbox-extended` is a separate distribution and adapter instance. The official `singbox` instance remains available, with a separate statistics port (9101 versus 9105). Optional YAML boot configuration:

```yaml
cores:
  singbox: {}
  singbox_extended:
    version: 1.14.1-extended-2.7.2-r3
    stats_listen: 127.0.0.1:9105
```

The build pins [shtorm-7/sing-box-extended](https://github.com/shtorm-7/sing-box-extended) at `v1.14.1-extended-2.7.2`, commit `55faa763f986f4ca8a492d9b2719bc6330d2bef5`, with `with_v2ray_api` and the tags listed in `scripts/build-singbox-extended.sh`. The upstream release binary lacks the statistics API needed for billing. Vetted dependency security updates are applied to go.mod/go.sum; upstream Go implementation files are unchanged. Published packages include corresponding source, the updated module manifests, GPL license, build instructions and checksums. No GPL implementation is copied into bosun's MIT source.

Linux amd64/arm64 packages are produced by the reusable release workflow. Before those assets are published, or on other platforms, the installer can build from the pinned source when Go and git are available. The source build applies the same dependency pins. The release workflow checks the exact source/build tags for reachable vulnerabilities and exercises the real binary; a bare Go module advisory is not evidence that its affected package is compiled into the executable.

The `-r3` package keeps the same upstream commit and reviewed October dependency pins, and uses Go 1.26.10 for the certificate security update. Previous `-r1`/`-r2` assets remain immutable; existing explicitly activated installations retain their selection until the administrator switches versions.

### WARP outbound

Both sing-box distributions reuse bosun's registered or manually supplied WARP credentials. Extended's WireGuard endpoint does not accept the official `reserved` option, so bosun omits it only from that instance's generated configuration. The stored account and the official sing-box/Xray configuration keep those bytes. No account re-registration or core-package replacement is needed for this adapter fix.

CI checks default, rule-selected and unused WARP configurations with the real pinned binaries, including Extended SSH and Mieru. A separate live check is available with `BOSUN_EXTENDED_TEST_BINARY=/path/to/sing-box BOSUN_WARP_TEST_ACCOUNT=/private/account.json go test ./internal/core/singbox -run '^TestExtendedLiveWARP$' -v`. It reads a `spec.WARPAccount` JSON file without modifying it, verifies direct/WARP egress using Cloudflare's trace response and checks SSH per-user/per-inbound traffic counters. Keep that account file private and outside the repository; the test never registers an account or changes host routing.

### Mieru

Select `singbox-extended` explicitly; automatic selection continues to use the existing Mieru adapter. TCP, UDP and BOTH are supported. BOTH uses adjacent ports, preserving the existing subscription convention. The embedded upstream implementation cannot bind a specific listener IP: direct binds and NAT/IPLC ingress binds are rejected; use `mita` for those installations.

Extended Mieru accounts use `UUID|inbound-tag` as the wire username to maintain per-inbound accounting. Statistics map back to the unchanged billing identity. Switching from `mita` retains the user's UUID/password and subscription URL, but clients **must refresh their subscription**. Native mita rolling quotas are unsupported and incompatible combinations are rejected; Captain/bosun still enforce their normal allowance rules. Do not enable mita native quotas for an Extended Mieru deployment. Empty-user listeners wait for a grant instead of preventing the rest of the core from starting.

### SSH proxy

The SSH inbound provides password-authenticated TCP `direct-tcpip` forwarding. Its users are panel subscribers, not operating-system accounts. It does not provide a shell, SFTP, root login or native UDP and does not replace the machine's SSH service. Use a separate free port.

Saving creates a persistent Ed25519 host key. Editing the inbound preserves it; reusable presets omit the key. sing-box subscriptions contain the host **public** key and a per-inbound username. The host private key never belongs in a subscription. Formats without supported SSH output omit this entry.

Typed remote SSH outbounds accept a username, password or inline private key, and a required pinned host public key in `remote.ssh.host_key`; private-key file paths and shell commands are not accepted. They are available through sing-box's outbound adapter. This is protocol support, not a claim of validation against a particular commercial SSH provider.
