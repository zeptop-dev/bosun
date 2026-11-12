# Core preparation and agent startup

`bosun run` registers configured core identities before attempting executable
preparation. Agent state/reporting and the local UI can start even if a package
is unavailable. `bosun render` retains synchronous preparation and explicit errors.
A failed core is not treated as a running proxy or successful configuration apply.

Preparation workers never receive node/user snapshots or start listeners. The
agent loop publishes a completed adapter, refreshes state, and uses the existing
apply path, including service pause, offline lease, user authorization, private
access and accounting gates. A replaced adapter cannot be overwritten by a late
preparation result. Cancellation rejects late successes.

There is one attempt per pending configured proxy distribution, at most six concurrently,
with a ten-minute attempt deadline. Failed attempts retry after 30, 60, 120, 240,
and then 480 seconds, continuing at that capped interval. The installer serializes
only an identical core/version; a slow unrelated package cannot block all others.
Download errors never silently change the configured source or core distribution.
Existing digest/TLS and same-origin credential checks remain in force.
The on-demand realm forwarding backend uses a separate agent-lifetime worker
and the same timeout/backoff policy; completion is consumed by the existing
current-state forwarding retry loop, never by a stale forwarding snapshot.

Reports add optional `preparation_error` fields to core status/inventory. The
management cards display preparation errors without labelling the core active.
Older panels ignore these additive fields; they can still receive reports.

After a configured default successfully starts, its version is remembered in a
separate `defaults` map in `cores/active.json`. Explicit administrator selections
and explicit configuration versions remain authoritative. Remembered defaults
keep the original runtime directory and are not automatically used if marked
broken or absent from the new catalog. This does not discover or promote arbitrary
old cached executables, and does not repair unrecorded selections retroactively.

## Native upgrade preflight

For native updates using Captain delivery, the running fixed agent checks the
checksum-verified candidate before moving the current executable or backup:

```
bosun preflight-upgrade /etc/bosun/config.yaml
```

The target executable reads configuration and selection metadata, then checks its
own exact catalog against Captain for configured uncached proxy-core packages.
Runtime-only forwarding backend choices are not part of this configuration preflight. The check does
not write local selections or install local cores. Captain may populate its normal
artifact cache while serving manifests. Missing catalog entries, authentication
errors, invalid manifests or timeout fail the upgrade; the old executable remains.
Monitor-only configuration skips proxy-core checks. Docker/host-updater and external
manual replacement workflows are outside this native candidate hook.

The hook cannot retrofit an already running old bosun. When first adopting this
fix from an older agent, update Captain's package catalog first. Captain must pin
the matching shared bosun module to retain/display the new report fields. This
feature does not promise zero-downtime proxy upgrades or make invalid configuration,
corrupt identity/selection files, or unwritable essential state non-fatal.
