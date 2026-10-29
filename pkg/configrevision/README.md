# Structural configuration identity

`Digest(node spec.Node, forwards []spec.Forward) (string, error)` returns
`cfg1-` followed by a SHA-256 digest of a private, explicitly typed projection.
It observes declared configuration structure; it is not a configuration
snapshot, a rendered-file hash, an authorization boundary or an apply result.
There is no deserialize/replay API. No spec structs or arbitrary maps are
embedded in the projection.

Call it on the original desired state, before local certificate path resolution,
WARP account injection, or runtime private-access enforcement selection. The
second argument is authoritative, just as the Captain driver's `Node()` replaces
`Node.Forwards` with `State.Forwards`; local callers can pass `node.Forwards`.

The complete state revision must continue to change for authorization,
credential rotation, jobs and other dynamic state. Structural confirmation must
also bind that complete state revision, the current process session and the
particular delivery. Matching structural digests alone do not prove credentials
or peer trust match, do not authorize a subscriber, and do not prove connectivity.

## Field classification

| Source | Included structure | Excluded material or other state |
| --- | --- | --- |
| Node | Effective mode; listeners, outbounds, ordered route/audit rules; DNS order; default outbound, connection logging, private destination policy, source egress; decoy; reverse/WG links and upstream exceptions | Node ID, mode command revision, service-control subtree, default user speed limit, certificate/ACME material; redundant Node.Forwards |
| Inbound | Identity, protocol/core/listener; transport, TLS policy, mux, protocol options; private access and reverse association; fallback order; shared vs multi-user Snell mode | All Users and ScopedUsers; SSH server keys; SS server key, obfs password, Snell PSK; WG server keys |
| TLS / Reality | Mode, server name, ordered ALPN, certificate automation/challenge choice; handshake target/port and fallback policy | Local certificate/key paths; Reality private/public keys and ShortIDs |
| Certificate / ACME | None; intended name and challenge are already in TLS/Decoy | Entire certificate list including domain and PEM pair; ACME account contact and token |
| PrivateAccess | Every policy field and rule, as declared | No runtime resolved enforcement or host observations are accepted as replacements for the declaration |
| Reverse | Association ID/receiver role; client target, private access and TLS structure | Tunnel UUID |
| WireGuardLink | Slot, side, endpoint/listener, MTU, private policy, domain preference and forwarding policy | Private/peer keys; this is separate from subscriber WG device authorization |
| Remote outbound | Host/port, verification policy, fingerprint, typed protocol settings | Username, password, UUID and SSH private/pinned host keys |
| WARP | FromNode intent, endpoint and interface addresses | Private/peer keys, account reserved bytes and license; hash before resolving FromNode |
| Balancer | Member order and strategy | None |
| Forward | Tag/listener/protocol/backend; source preservation, PROXY protocol; primary and candidate target order/weights and strategy | Ingress editor metadata |
| User / WG device | None | Entire subscriber authorization tree, credentials, quotas, limits and device identities/addresses |
| State outside Node/Forwards | None | Users, Jobs, Probe, intervals, old retired exporters, full revision and configuration-delivery metadata |

`Node.Overrides` and nonempty `Outbound.Settings` are native JSON escape hatches.
They may contain both structure and credentials, so this version returns
`ErrUnsupported` with a fixed, safe reason. Multiple typed outbound selectors
(Remote/WARP/Balancer) also return it because different cores select them in
different orders. Callers should omit the structural identity and continue
ordinary delivery; this does not validate or reject an otherwise existing
configuration. Nil/empty Settings and empty, whitespace-only, `{}` or `null`
override values are no-ops. A nonempty unknown-core override is conservative:
it is still unsupported. No error echoes input keys, values or tags.

DNS and decoy-upstream URLs can also embed authentication. URL userinfo,
query/fragment components, non-root decoy paths, and DNS paths other than the
ordinary `/dns-query` are conservatively unsupported (including encoded path
variants). Such configurations retain ordinary delivery. Other declared match,
host and transport-path strings are structural input, not automatically
classified secret stores. This package is not a general-purpose redactor and
its private projection should not be exposed as a public settings response.

## Canonicalization and maintenance

- Identity-keyed inbounds/outbounds/forwards/reverse clients/WG links are sorted
  by their unique nonempty tag, ID or slot. If identities are missing/ambiguous,
  input order is retained; this package is not a substitute for spec validation.
- Upstream exceptions and private destination allowances are unordered sets for
  this purpose and are sorted. Duplicates remain represented.
- Route/audit/fallback evaluation, failover candidates and primary hop, DNS,
  ALPN, padding rules, balancer membership and interface-address order remain
  unchanged. No speculative sorting of these lists is allowed.
- Only established defaults are collapsed: empty node mode = full; missing or
  empty transport type = tcp; empty forward backend = relay; empty balance =
  failover; nonpositive hop weights = one; nil and empty collections coincide.
  Other optional objects/defaults retain their declared shape. This may cause
  conservative extra revisions; it must not erase meaningful differences.
- `fields_test.go` inventories every field of every projected spec type,
  requires newly reachable projected types to be classified, and mutates each
  field to test whether the digest should change or return unsupported.
  Excluded subtrees remain entirely excluded when their internals evolve.
- Projection types are separately checked against embedding `spec` types,
  interfaces or maps. Credential rotation, dynamic authorization, ordering,
  defaults, input isolation and safe errors have behavioral tests.

Changing these classifications or canonicalization rules changes the identity
contract. Review the cross-version behavior and bump `Prefix` when a released
contract changes. Different prefixes cannot confirm one another. Existing full
state delivery and its revision are independent of this package.
