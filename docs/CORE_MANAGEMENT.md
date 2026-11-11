# Core packages, adapters and runtime instances

In the standalone console, open **Overview → Core management**. For managed nodes, use **Captain → Nodes → node details → Core management** as a full administrator. Upgrade bosun before using the controls: older nodes do not advertise the new inventory or execute these jobs.

An inbound selects a protocol and an adapter using the existing `core` field. Core management selects the installed release for each adapter. Downloading a package does not start it or alter any inbound. Each distribution has one active version; several distributions can run together. The catalog contains reviewed versions, not arbitrary URLs or executable uploads.

1. Choose a distribution/version and download it.
2. Select **Activate / switch**, review the interruption notice, and confirm.
3. Select that core in an inbound's editor, or retain automatic selection for existing supported protocols.

A switch serializes with configuration application and reporting. It checks the inventory revision and configuration compatibility, validates sing-box/Xray configurations with the candidate binary, checkpoints outstanding traffic, stops the old instance and waits for the new instance's statistics API. Since v0.84.0, Linux activation also checks expected business TCP/UDP sockets against the supervised process's ownership; unused or deliberately userless inbounds do not create fictitious listener requirements. Failed startup or selection persistence restores the old instance and reports the error. Other adapters validate their rendered model and then use startup/readiness checks. Switching interrupts connections served by that distribution. It cannot atomically stop network traffic and persist counters; the boundaries below still apply.

Successful selections and preference order persist in `<data_dir>/cores/active.json`; downloaded executables are under `<data_dir>/cores/<distribution>/<version>/`. New UI-enabled distributions are appended to the preference order. A switch that would move existing automatically assigned inbounds to another core is rejected; pin them first. A failed configuration apply must be resolved before switching. These files are installation state, separate from the standalone configuration backup; preserve the data volume or reselect cores when restoring on a new host. An explicit `config.yaml` binary path remains an administrator pin and cannot be replaced through the UI.

The agent's catalog is the source of available packages. Extending it requires reviewing the upstream format, adapter capabilities, platform assets, checksums and runtime tests. Updating the inventory never silently activates a release. Concurrent activation requests, stale revisions and expired tasks are rejected. Successful replayed jobs do not restart the core again.

## Received and successfully applied revisions

Captain-managed reports retain `revision` as the latest state received by the
watcher. Since bosun v0.81.0, the additive `applied_revision` field confirms that
this process has successfully applied both proxy configuration and forwarding
from that exact revision. It uses the revisions actually consumed by the agent, not a newer
watcher snapshot. Partial failure, early checkpoint failure, activation/rollback,
mode transitions and process restart clear the relevant confirmation; core-only
reconciliation cannot acknowledge or suppress retries of failed forwards.

An application acknowledgement is still not a connectivity test. Captain must
also check the reported running inbound, forwarding observations and reverse
connection evidence. Agents predating this field omit it and cannot provide this
stronger status confirmation. A userless inbound can be successfully configured
while waiting for authorization; this does not claim that its listener is running.
No credentials, routes or customer accounting semantics change with the new field.

| Combination | Application confirmation |
|---|---|
| bosun v0.81.0 or newer with Captain v1.41.0 or newer | Captain can compare `applied_revision` with the current desired revision, then evaluate fresh per-component runtime evidence. |
| Older bosun with Captain v1.41.0 or newer | Existing proxy operation remains supported; missing confirmation is unknown, not proof of health or failure. |
| bosun v0.81.0 or newer with Captain older than v1.41.0 | The older panel can ignore the additive field; `revision` retains its original received-state meaning. |
| Standalone or Xboard driver | No Captain application confirmation is manufactured; existing operation and reporting remain unchanged. |

**中文说明：** bosun v0.81.0 新增 `applied_revision`，仅在本进程成功应用同一版本的代理配置和转发规则后确认；原 `revision` 仍只表示已收到的版本。失败、内核切换、模式切换或重启后须重新确认。Captain v1.41.0 对缺少该字段的旧节点保持状态未知，旧节点仍可继续提供已有代理服务；旧面板可以忽略新字段。确认成功不代表端到端访问成功，也不代表暂无授权用户的入站正在监听。升级不改变配置键、默认内核或用户计费。

Kernel nft forwarding reports installation, replacement and cleanup failures to
the caller. Failed scripts are retried even when the desired rules are unchanged;
successful identical scripts retain the existing no-reinstall behavior. A failed
removal of the last rule cannot be acknowledged as a successful empty config.

## Session-bound configuration receipts

bosun v0.84.0 and Captain v1.49.0 add a structural `config_revision` and a
`config_receipt`, alongside the existing received/applied revisions. The
structural digest covers runtime configuration while excluding dynamic users,
jobs and monitoring-only state. Each full-state delivery still binds both
revisions to a random session generated for the current bosun client process.
The receipt's observation sequence increases within that session; HTTP retries
reuse the frozen observation, rather than refreshing its time or sequence.

A positive receipt requires coherent node, users and forwarding revisions
actually consumed by the apply loop. Watcher prefetches cannot supply missing
proof. Failed dynamic user changes, skipped required configuration, unavailable
helpers/decoy, or a stopped required core/realm process withhold confirmation.
Monitor-only mode can confirm its genuinely empty runtime only after successful
cleanup. Deliberately idle no-user Mieru/Snell instances remain valid. Cached
offline state never acknowledges a new delivery, and retirement of a session
removes its delivery metadata on consumption.

Captain evaluates the delivery identity and freshness before presenting recent
application confirmation. A receipt does not prove subscriber authorization,
remote reachability or a working end-to-end line. A changed desired structure
requires a new confirmation; an older successful receipt cannot make it green.
Older panels ignore these additive fields. Older agents continue serving their
existing configuration but cannot provide this new evidence. Standalone and
Xboard modes do not manufacture Captain receipts. The exact digest contract is
in [pkg/configrevision](../pkg/configrevision/README.md).

**中文说明：** bosun v0.84.0 / Captain v1.49.0 新增结构版本与进程会话绑定的配置回执。
确认来自实际消费并成功应用的节点、用户和转发状态，不能借用 watcher 预取或离线缓存。
应用失败、应运行的进程退出或依赖组件失败时不确认；回执只证明近期应用，不能代替端到端连通测试。
旧面板和旧节点继续兼容，但缺少新回执时不提供这项确认。

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
BOSUN_XRAY_TEST_BINARY=/path/to/xray BOSUN_MIHOMO_TEST_BINARY=/path/to/mihomo go test ./internal/core/xray -run '^TestVisionTLSMihomoHTTPSLive$' -count=1
```

The Mihomo regression uses a local TLS disguise service and HTTP destination.
It checks that the omitted upstream version floor rejects Mihomo, bosun's
rendered compatibility default permits a real REALITY + Vision request, and
an explicitly restored 26.3.27 floor rejects that same client again. This does
not test public network quality or ordinary certificate-based TLS + Vision.
The separate TLS + Vision fixture uses locally generated certificates and a
local HTTPS destination. Two connections each upload and download a fixed
payload and compare every byte. Core debug events must confirm TLS 1.3 detection and the
Vision direct-copy command, exercising the reflected TLS buffers instead of
only checking that a TLS handshake succeeded. Both fixture certificate checks
are disabled only for these generated local test certificates.

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
    version: 1.14.1-extended-2.7.2-r4
    stats_listen: 127.0.0.1:9105
```

The build pins [shtorm-7/sing-box-extended](https://github.com/shtorm-7/sing-box-extended) at `v1.14.1-extended-2.7.2`, commit `55faa763f986f4ca8a492d9b2719bc6330d2bef5`, with `with_v2ray_api` and the tags listed in `scripts/build-singbox-extended.sh`. The upstream release binary lacks the statistics API needed for billing. Vetted dependency security updates are applied to go.mod/go.sum; upstream Go implementation files are unchanged. Published packages include corresponding source, the updated module manifests, GPL license, build instructions and checksums. No GPL implementation is copied into bosun's MIT source.

Linux amd64/arm64 packages are produced by the reusable release workflow. Before those assets are published, or on other platforms, the installer can build from the pinned source when Go and git are available. The source build applies the same dependency pins. The release workflow checks the exact source/build tags for reachable vulnerabilities and exercises the real binary; a bare Go module advisory is not evidence that its affected package is compiled into the executable.

The `-r4` package keeps the same upstream commit and Go 1.26.10, and adds `github.com/andybalholm/brotli@v1.2.7` and `github.com/klauspost/compress@v1.20.2` to address [GO-2026-6888](https://vuln.go.dev/ID/GO-2026-6888) and [GO-2026-6865](https://vuln.go.dev/ID/GO-2026-6865). Previous `-r1`/`-r2`/`-r3` assets remain immutable and are marked `broken` because their pinned dependencies are affected. This status does not block an explicitly selected old version; administrators must switch existing installations to `-r4`. The new package remains `caution` and does not replace the default sing-box distribution.

### WARP outbound

Both sing-box distributions reuse bosun's registered or manually supplied WARP credentials. Extended's WireGuard endpoint does not accept the official `reserved` option, so bosun omits it only from that instance's generated configuration. The stored account and the official sing-box/Xray configuration keep those bytes. No account re-registration or core-package replacement is needed for this adapter fix.

CI checks default, rule-selected and unused WARP configurations with the real pinned binaries, including Extended SSH and Mieru. A separate live check is available with `BOSUN_EXTENDED_TEST_BINARY=/path/to/sing-box BOSUN_WARP_TEST_ACCOUNT=/private/account.json go test ./internal/core/singbox -run '^TestExtendedLiveWARP$' -v`. It reads a `spec.WARPAccount` JSON file without modifying it, verifies direct/WARP egress using Cloudflare's trace response and checks SSH per-user/per-inbound traffic counters. Keep that account file private and outside the repository; the test never registers an account or changes host routing.

### Mieru

Select `singbox-extended` explicitly; automatic selection continues to use the existing Mieru adapter. TCP, UDP and BOTH are supported. BOTH uses adjacent ports, preserving the existing subscription convention. The embedded upstream implementation cannot bind a specific listener IP: direct binds and NAT/IPLC ingress binds are rejected; use `mita` for those installations.

Extended Mieru accounts use `UUID|inbound-tag` as the wire username to maintain per-inbound accounting. Statistics map back to the unchanged billing identity. Switching from `mita` retains the user's UUID/password and subscription URL, but clients **must refresh their subscription**. Native mita rolling quotas are unsupported and incompatible combinations are rejected; Captain/bosun still enforce their normal allowance rules. Do not enable mita native quotas for an Extended Mieru deployment. Empty-user listeners wait for a grant instead of preventing the rest of the core from starting.

### SSH proxy

The SSH inbound provides password-authenticated TCP `direct-tcpip` forwarding. Its users are panel subscribers, not operating-system accounts. It does not provide a shell, SFTP, root login or native UDP and does not replace the machine's SSH service. Use a separate free port.

Saving creates a persistent Ed25519 host key. Editing the inbound preserves it; reusable presets omit the key. Mihomo (`client=clash`) and sing-box (`client=singbox`) subscriptions contain the host **public** key, subscriber password and per-inbound username. Mihomo supports SSH since v1.18.2; Clash Verge must use a supporting Mihomo core. SSH remains TCP-only (`udp: false` in Mihomo), and a missing host pin omits the entry. The host private key never belongs in a subscription. Generic URI and Stash exports retain their existing SSH omission; Stash's SSH schema and version-dependent host-key support differ from Mihomo's.

NekoBox Android 1.3.8+ can import sing-box outbound subscriptions; `client=nb4a` and `client=nekobox-android` are explicit aliases for that format. Its default User-Agent still selects Clash to preserve existing format behavior, but the Android 1.4.2 YAML importer has no SSH branch. For SSH, add the explicit sing-box subscription; keep any existing subscription needed for other formats. Switching format does not add protocols that the chosen renderer or client core cannot support. Archived NekoBox PC/NekoRay 4.0.1 has different import paths, so an Android alias is not a universal desktop import fix. See the [Android format documentation](https://matsuridayo.github.io/nb4a-configuration/) and [versioned importer](https://github.com/MatsuriDayo/NekoBoxForAndroid/blob/5768494d8ae3c74a057bb6d46c0f8dc071b0d821/app/src/main/java/io/nekohasekai/sagernet/group/RawUpdater.kt).

**中文说明：** SSH 可通过 Mihomo/Clash Meta 或支持 SSH 的 sing-box 订阅下发，包含用户密码、逐入站用户名和主机公钥，不含主机私钥。NekoBox Android 1.3.8+ 可选 `client=singbox`（别名 `nb4a`、`nekobox-android`）；默认 Clash 导入在已核对的 Android 1.4.2 中不识别 SSH。不同客户端的导入器与内核能力分别生效，不能把一个格式称为所有 NekoBox 版本、所有协议通用。

Typed remote SSH outbounds accept a username, password or inline private key, and a required pinned host public key in `remote.ssh.host_key`; private-key file paths and shell commands are not accepted. They are available through sing-box's outbound adapter. This is protocol support, not a claim of validation against a particular commercial SSH provider.


### Go 1.26.11 security rebuilds (2026-11-11)

GO-2026-6859 affects the Go net/http implementation used by previous builds.
The maintained build toolchain and Docker builder now use Go 1.26.11.
New immutable candidates are sing-box 1.14.1-r4 (compatible default),
1.14.4-r2 (explicit opt-in), and Extended 1.14.1-extended-2.7.2-r5
(explicit opt-in). Previous r3/r1/r4 assets remain available, marked broken.
Pinned installed binaries are not silently replaced; a source update alone
does not patch already running services. Historical Xray/GeoCheck assets
are not regenerated by changing this toolchain; their separate immutable
rebuild and activation must be verified independently.
