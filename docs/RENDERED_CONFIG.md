# Activated core configuration evidence

Captain reports can include optional rendered_config evidence alongside the
existing config_receipt. This describes configuration files successfully
activated by bosun's core adapters. It is independent of the desired structural
cfg1 digest, and cannot be compared with that digest or used to reconstruct a
configuration.

The supported adapters are sing-box, sing-box Extended, Xray, Hysteria, mita and
Snell. Their successful startup/restart boundaries record the bytes supplied to
the core, after rendering and overrides. Mita also records a successful complete
proxy stop/start cycle within one process. A config check, a file written to
disk, or a rendered candidate alone never creates evidence.

The scope is deliberately activation_files. Xray's user RPCs, mita's user
Reload and Hysteria's in-memory authentication changes do not prove that the core
reloaded the complete file. Their successful later updates preserve the original
activation digest and set runtime_updates=true. A file may therefore describe
an earlier user list than the current authorization state. External certificate
file contents, host/nft rules, managed forwarding and network reachability are
outside this evidence. It is not a dump of current core memory or an end-to-end
health result.

## Protocol

Report.RenderedConfig is additive; old reports omit it and mean unknown.
ConfigReceipt remains unchanged. The receiver must bind this field to the
same report's newly accepted receipt: session, delivery ID, complete State
revision, receipt sequence and observation time. A retry or stale delivery must
not refresh current evidence. A structural digest alone is insufficient.

The version 1 object has version, status and at most six artifacts.
Status observed requires a successful current configuration receipt and valid
evidence for every active expected core. Observed with an empty array means a
successfully applied configuration with no active proxy cores. Missing evidence,
offline recovery, failed/partial configuration, an unavailable core or an
unbound delivery produces unavailable. An unavailable object can contain the
safe artifacts observed from other cores, but cannot confirm the entire node.

Each artifact contains only:

- core: one of the six fixed adapter names.
- scope: activation_files.
- format: json, yaml or ini, fixed by the adapter.
- files and processes: bounded counts, with no file names or PIDs.
- activated_at: the earliest activation represented in the aggregate.
- runtime_updates: whether later accepted dynamic updates are excluded.
- digest: a keyed rcf1- HMAC-SHA256 value.
- digest_scope: process.

The random HMAC secret exists only in the adapter's memory. No plain content hash,
raw JSON/YAML, credential, inbound tag, file path, hostname or address is sent.
Failure to obtain cryptographic randomness yields no evidence. Equal digests are
meaningful only within the same bosun process and adapter lifetime; a restart or
adapter replacement can change the digest without changing the files.

ValidateRenderedConfigReport enforces the fixed enums, unique cores, timestamps,
counts and a 4 KiB maximum. Malformed optional JSON becomes an invalid sentinel
without rejecting otherwise valid traffic accounting. Receivers must discard or
mark invalid evidence, not retain an earlier green result under a newer receipt.
Typed decoding and re-encoding discard unknown fields.

## Process lifecycle and failure

Evidence binds to every locally supervised child generation, not just a PID or
the adapter's Running flag. This matters for Snell and mita, where one healthy
child does not prove that the other instances are alive. Snapshots verify the
complete generation set. Stop, death, automatic restart or replacement withdraws
the old confirmation, including when a PID is reused.

Failed operations invalidate the aggregate. A partially completed RPC or proxy
cycle also forgets the affected activation: a later hot-only retry cannot
resurrect the old file digest. Ordinary retries that actually activate all
required files can recover evidence. An unchanged retry preserves its original
activation time instead of inventing a new activation.

After an automatic restart, the file on disk may differ from the last accepted
file because validation or a failed update wrote new bytes. Consequently, even a
running replacement process remains unknown until the adapter observes a fresh
complete activation. Bosun does not restart a healthy core merely to restore
this observability. A later normal full activation or an explicit restart can
establish new evidence.

Core installation/rollback keeps the existing full-state confirmation rules:
switching the adapter cannot borrow an earlier receipt. Reports freeze the safe
artifact values before asynchronous HTTP, and accounting retries collect a new
observation without changing the immutable accounting batch.

## Verification

Tests include real isolated executable fixtures that read the actual file paths
passed through exec or the mita environment. They cover staged-file changes
without reload, rejected config checks, repeated Start, no-op retries, Xray user
RPCs, Hysteria in-memory auth, Snell partial multi-process failure, and mita Unix
RPC activation followed by failed readiness and a hot retry. Automatic process
replacement must clear current evidence. Shared tracker tests cover entropy
failure, keyed privacy, process reuse, bounds and concurrent observations.

These fixtures validate the adapter lifecycle and protocol. They do not claim
that every released upstream binary or a remote production node was exercised.
