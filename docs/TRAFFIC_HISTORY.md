# Traffic batch provenance

Captain reports can include optional `traffic_sample` and `traffic_delivery`
objects. They explain counter collection and delivery; they do not change
traffic amounts, journal epoch/sequence, rate windows, or customer accounting.
Other panel drivers keep their existing traffic behavior.

`traffic_sample` is saved inside the existing version 1 traffic journal before
sending. Its timestamps and source information remain unchanged when a pending
batch is retried or restored. `traffic_delivery` is a separately sampled view of
the current journal, so a new host report is never used as the old batch's
collection time. Pending and buffered bytes include only customer counters
already read into the journal, excluding counters still held by cores.

Collection start/end bracket the counter API operations. Each source identifies
the core and one of `users`, `inbounds`, or `outbounds`. When two successful reads
belong to the same supervised process generation, its interval records the
previous read completion and this read completion, with a monotonic elapsed
duration. These are observation boundaries, not an atomic timestamp supplied by
the upstream core. Different sources can cover different intervals.

An initial read, an uncertain failed reset, a process change, or an adapter
without verifiable process ownership has an unknown interval. Lifecycle
checkpoints invalidate the next baseline because the caller may replace or
reconfigure the counters. Process generations distinguish PID reuse. Agent
restarts never restore live read baselines from disk. A wall-clock discontinuity
withdraws interval precision.

`observed` means the reported read boundaries were observed continuously for
those sources. It does not promise that upstream counters are complete. Upstream
reset APIs and the journal fsync cannot form one transaction, so abrupt process
or machine failure can still lose an unknowable amount. `partial` and `unknown`
retain the reason without inventing a byte count for a gap. Merged checkpoints
retain bounded source envelopes and explicitly say `coalesced`; they cannot be
expanded into an accurate per-minute traffic chart.

The fixed reasons are `first_read`, `counter_error`, `process_changed`,
`process_unverified`, `clock_discontinuity`, `coalesced`, `legacy_metadata`,
`no_running_sources`, and `source_limit`. No usernames, destinations, filesystem
paths, process IDs, or raw upstream errors appear in this metadata. Sources are
limited to 18 and the complete metadata object to 4 KiB; truncation is explicit.

Old journals remain readable. Missing metadata is unknown; malformed optional
metadata does not invalidate otherwise valid journal accounting. Old panels
ignore the new fields. Old agents may discard the added observation data when
rewriting the journal, while retaining its existing bytes and receipt identity.
No new rollback floor is required by this observational feature.

This is not a host telemetry replay queue. CPU, memory and NIC-rate history that
was not delivered remains missing. Existing bounded network-probe attempt
buffers and resource sampling keep their separate clocks and semantics.
