# Temporary host diagnostics

Captain can grant an authenticated process a short observation lease. This is
separate from desired proxy configuration, normal host beats, active probes and
traffic reporting. Paused proxy service and disabled public monitoring do not
disable these passive, administrator-requested measurements.

State requests advertise diagnostics version 1 and a fresh request nonce. The
agent echoes the server challenge and the last accepted `epoch:generation`
cursor. A challenge-only command has zero remaining time and does not sample.
Only the candidate process handshake carries a challenge. Active and stopped
commands have an empty challenge, clearing the header on the next request.
Every start, stop or renewal must advance generation; changing worker/process
identity also changes epoch. Repeated generations cannot extend a lease.

The driver checks the session, request nonce, authorization generation and
request order. An accepted command lasts at most 15 seconds from the request's
local monotonic start. Responses older than 10 seconds cannot activate it. One
immediate fresh request is attempted; consistently slow diagnostic metadata
cannot indefinitely block delivery of ordinary configuration. Diagnostics-only
state responses do not notify the configuration consumer or rewrite recovery
snapshots. Diagnostic metadata is stripped from cached and offline state.

A single driver-owned worker remains idle when there is no lease. Renewals keep
its sequence and baselines; stopping or expiring clears baselines, and resuming
the same epoch continues its sequence. A new epoch starts sequence 1. Rejection,
offline recovery and shutdown cancel in-flight requests. Samples are sent
serially with a two-second deadline, with no backlog or retries. A failed send
requires a fresh lease generation before further sampling.
Successful sends leave at least 500 milliseconds before the next sample, so a
slow response cannot cause a catch-up burst against the server's arrival budget.

The one-second sampler reads only aggregate CPU times, virtual memory and NIC
counters. It does not enumerate connections/processes, scan filesystems, execute
programs, collect proxy counters, or run network probes. First samples, counter
resets, missing observations and gaps over three seconds have null rates, not
zero. Rates use actual elapsed time and are bytes per second. At most 16 NICs are
included, in name order, within an 8192-byte payload. The truncation flag exposes
omissions. Aggregate network rates include all observed non-loopback NICs,
including omitted detail rows; virtual devices can count the same packet again.
These observations are neither billing traffic nor a physical uplink estimate.

Older Captains ignore the new headers and never activate diagnostics. Older
agents ignore the additive control field. Neither direction changes the normal
Beat, Report or proxy configuration protocols.
