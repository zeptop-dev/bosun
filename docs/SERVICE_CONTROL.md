# Managed server service control

Available with bosun v0.83.0 and Captain v1.48.0. Captain requires fresh
capability reports before enabling controls; older agents continue existing
services but cannot enforce this feature. The current built-in updater refuses
updates or rollback below bosun v0.85.0 to preserve path-health policies as well
as the authorization lease and optional local traffic policy described below.

**中文说明：** 服务器暂停与总限速需要 bosun v0.83.0 / Captain v1.48.0
及节点新鲜的能力报告。总限速是托管流量上传与下载共用的丢包限速，不是平滑整形，
也不等于供应商账单封顶；系统和管理连接不计入该限制。旧节点仍可提供原服务，
但不能启用此保护。当前内置更新与回滚不允许低于 v0.85.0，以免旧程序忽略
路径健康、离线授权期限或本地流量策略。

Captain decides when a server policy applies from its recorded NIC traffic
period and the administrator's manual selection. bosun receives an optional
`Node.ServiceControl` with a stable revision, mode (`normal`, `limit`, or
`pause`), and `limit_mbps` for limit mode. Existing states without this field
retain their previous behavior. This control does not alter user quotas,
traffic receipts, or per-user speed limits.

## Optional offline automatic policy

bosun v0.84.0 and Captain v1.49.0 add a `Node.ServiceControl.offline`
snapshot for local automatic threshold evaluation. It is absent by default and requires the independent
`Report.ServiceControl.offline_supported` capability. Captain sends the action,
quota, threshold, counting direction, manual restriction, exemption, current
cycle, twelve absolute cycle boundaries and an authenticated NIC counter anchor.
This uses host counters and never modifies customer traffic receipts or quotas.

The serial local timer checks counters every fifteen seconds, independently of
panel HTTP success. The sampler's boot/interface identity and cumulative bytes
must remain continuous. A private `offline-service-control/offline-traffic.json`
journal is written and synced before applying a transition. Process restart can
continue from the journal when the same boot/interface counters remain valid.
Same-policy anchor refreshes cannot clear an existing local automatic hold in
the same cycle. Period recovery requires a fresh observed boundary crossing;
manual holds persist, and cycle exemptions expire. A disabled auto-resume policy
keeps its automatic hold in later cycles.

Missing interfaces, reset counters, a missed boundary, expired cycle schedule,
stale anchor after journal loss/reinstall, corrupt journal, or persistence failure
produce a conservative pause, never a fabricated zero-usage period. A fresh panel
anchor can repair lost observations. A corrupt journal requires an explicit
administrative disable/re-enable; disabling retires only this owned journal.
A recovered cached state must match both the saved policy identity and the exact
last accepted command revision; it cannot delete or replace newer protection.
Missing or conflicting journals pause recovery until a fresh online state arrives.
Applied revision is withheld while evidence or service reconciliation fails.
Guard checks and local metering share the same stop/restart path, so releasing a
pause also restores the configured managed processes and forwards.

Versions without this capability ignore the additive object. The built-in
v0.84.0 rollback floor prevents that silent loss of protection. Manual binary
replacement bypasses the floor and is not a supported way to clear an active
hold. If an older installation must be recovered, first restore authenticated
panel access, explicitly disable offline protection and active server controls,
and confirm normal reconciliation. Stop client traffic and let pending and
buffered accounting finish before restoring a compatible installation backup.
Do not delete owned journals to bypass an uncertain or active policy. The
feature extends when automatic decisions occur; the existing nft enforcement
and management isolation described below are unchanged.

## Enforcement boundary

One owned nftables table, `inet bosun_service_control`, covers:

- Non-root managed proxy/core output, including realm and reverse VLESS.
- In-process relay TCP and UDP sockets, marked when control is enabled.
- Managed nft DNAT using its original destination, port, transport, and family.
- Managed reverse WireGuard forwarding through the exact owned interfaces.

A forwarded packet enters the common control chain once. For a userspace
proxy, output to the destination represents upload and output to the client
represents download; input is not counted again. Loopback output is excluded
so local core API calls and local chaining do not consume this allowance.
WireGuard's inner forwarding is controlled rather than counting its outer
encapsulation again. Unmarked bosun management sockets, SSH, and unrelated
host traffic are outside this scope. Foreign DNAT rules on other tuples are
left alone. The guard does not modify existing qdiscs or foreign firewall
rules.

Enabling or disabling control recreates in-process relay sockets because an
existing listener cannot retroactively mark all accepted sockets. Switching
between unchanged active policies does not recreate the relay. Original NAT
selectors and WG interface ownership are retained until `normal`, so old
established mappings cannot escape a simultaneous topology change.

## Rate semantics and prerequisites

`limit_mbps` is a **combined upload plus download** maximum for managed
traffic, using a shared named byte token bucket. One Mbps is 125,000 bytes
per second, with a 65,536-byte burst allowance. Packets beyond the bucket
are dropped. This is policing, not queued pacing or a fair per-connection
scheduler; TCP retransmissions and UDP loss can occur. Existing per-user
tc shaping remains separate.

The scope differs from the host NIC counters that trigger a quota policy.
It excludes system traffic and cannot prevent a provider from charging
inbound packets that already reached the machine. It is not an exact
supplier billing ceiling or a substitute for upstream bandwidth controls.

Support requires Linux, a root bosun process with network-administration
capabilities, nftables named byte limits, and a dedicated non-root proxy
account. Active nft flowtables are rejected because offloaded traffic can
bypass the forwarding hook. A collision with a legacy user speed mark is
also rejected. Root relay socket mark `0xb0500001` is reserved for this
feature; unrelated host policy routing must not interpret that mark as a
routing selector.

Capability is refreshed during application and every minute. Unsupported
systems without prior owned control continue normal service and report the
reason. Existing control ownership cannot be silently cleared or reported
as restored when the kernel runtime is unavailable. Captain must require a
fresh capability report before enabling active policies on a server.

## Pause, recovery, and confirmation

Pause installs the drop guard before checkpointing counters, then stops
managed proxy cores, ordinary forwards, and managed WG links. Checkpoint
failure is reported but cannot keep services running. The guard also covers
established DNAT mappings that survive removal of a NAT rule.

The agent stores a journal of owned scopes under
`service-control/service-control-owned.json` in its data directory. The
journal stores only listeners and interface names, without targets or
credentials. An ordinary shutdown leaves protection installed. Explicit
normal operation removes the owned guard and ownership journal, then
restores the configured services. Full uninstall removes this table and
journal without flushing shared tables. Leaving full-server mode requires
releasing the control first.

The minute check compares the actual complete nft table structure, ignoring
only runtime handles and counter values. It repairs missing or modified
rules. An unchanged policy does not reinstall the table or refill the bucket.
If an active guard cannot be verified or repaired, managed services are
stopped immediately even when Captain is unreachable; the agent reports an
error and retries. If kernel permissions are lost while the old guard has
also been removed externally, existing kernel DNAT mappings may outlive the
failed cleanup; that outcome is never reported as successfully controlled.
Restoring the guard alone does not confirm that stopped services have recovered.

`Report.ServiceControl` reports capability, actual mode, desired revision,
last checked time, and error. Its applied revision is set only after the
requested guard and both core and forwarding application paths have
succeeded. The doctor's service-control check follows that confirmation.
Intentionally paused listeners are not presented as unexpected failures.

## Verification

Unit and fake-runner tests cover unsupported defaults, persistent ownership,
failed application and retry, checkpoint failure, application confirmation,
mark collisions, family-scoped DNAT, and repair after table mutation.

The opt-in Linux fixture creates an isolated network namespace, private
veth peers, and an actual WireGuard tunnel. It uses real nftables and relay
SO_MARK sockets, a non-root socket server, IPv4/IPv6 TCP and UDP, established
flows, unrelated DNAT, and an unmarked management connection. It verifies
pause, recovery, aggregate policing, and repair after rule removal. It does
not run a separate real proxy binary for every supported core.

```sh
go test -c ./internal/servicecontrol -o /tmp/bosun-service-control.test
sudo env BOSUN_SERVICE_CONTROL_TEST=1 /tmp/bosun-service-control.test \
  -test.run '^TestServiceControlLinux$' -test.v -test.timeout 2m
```

The fixture requires `nft`, `ip`, `wg`, `unshare`, `nsenter`, Python 3, root,
and a kernel with WireGuard. All fixture network rules and processes stay
inside its private namespaces. No existing host firewall or proxy service
is modified.
