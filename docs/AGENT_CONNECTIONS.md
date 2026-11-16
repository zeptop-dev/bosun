# Captain connection migration

Requires Captain v1.67.0 and bosun v0.98.1. Older agents continue to work but do not execute migration commands; the panel shows them as unconfirmed/upgrade required. The update/rollback floor is v0.98.1.

The administrator first enables both old and new origins, then explicitly migrates selected nodes. A target is not an installed-agent observation. The node makes an anonymous HTTPS challenge request before sending any existing token. Its HMAC proof is bound to that TLS session, so a different server cannot relay a challenge to Captain and then collect the token. Confirmation pins the public key seen during the proof. Redirects and incorrect/expired attempts are rejected.

**Default direct-mode targets must terminate TLS in Captain itself.** A CDN or TLS-terminating reverse proxy in front of the target does not share the same TLS exporter and cannot pass this proof. The current/source connection may still pass through a CDN. Custom HTTPS installation addresses remain supported; a custom migration target must satisfy the same direct-TLS check. Do not turn off certificate verification to migrate.

A successful migration persists `captain-connection.json` in `data_dir` (0600), bound by HMAC to the existing node token and the installation's original URL. It does not rewrite config.yaml, replace a read-only Docker bind mount, change the download source or re-pair the node. Config loading and installer-download-config expose the effective address; Captain downloads use the verified running address. The traffic journal, offline snapshot and mode identity retain the original approved authority so pending deltas keep their existing epoch/sequence and cannot be double charged by a URL change. A manual different installation URL or replacement token does not inherit the old override.

Only the control channel changes: proxy cores are not restarted. Failed verification/persistence keeps the source; after the new selection is durable, an unsuccessful final confirmation retains that selection and retries the receipt on subsequent authenticated state fetches. It never silently rolls back an outcome the controller may already have committed. Ambiguous filesystem errors are not reported as success. Old in-flight state responses are fenced by connection generation, including A→B→A changes. A failed attempt requires an explicit retry with a new identity; it is not reused after cancellation or re-pairing.

The five-at-a-time queue leaves offline/older agents waiting. Restarting the node after successful persistence keeps the selected origin without an installer run. A normal service restart still has the usual proxy interruption; it is not required for hot migration.

For recovery, retain the source entry until every node has confirmed. Do not delete the token or run a new pairing just to change an address. A root administrator can back up and remove the private connection-selection file to return to the installation URL, then restart the same service; preserve the data directory and journals. This is a recovery operation, not a routine migration method. Observe the new connection and accounting delivery before retiring an entry.

Capability version 2 (v0.98.1) is required by the final Captain implementation. Same-origin reconciliation also performs a durable checkpoint before completion. Unresolved failures keep both entries referenced until a later durable confirmation; a running URL observation alone is insufficient.


## Trusted CDN / reverse proxy (next release)

Captain1.68 / bosun0.99 add a separately advertised trusted-proxy migration
capability without changing direct capability version2. An administrator must
select this mode and acknowledge trust in the exact target intermediary, which
can read Agent credentials and contents. Direct verification never downgrades.
The anonymous proof binds the random challenge, frozen target, migration ID,
proxy-mode separator and expiry to an attempt-specific key delivered over the
old authenticated connection. No node token is sent before verification, and
standard HTTPS verification and redirect rejection remain mandatory. Rewritten
backend Host is allowed only for the stored proxy-mode attempt; forwarded
headers cannot opt a direct task into this mode. Signature relay through the
explicitly trusted intermediary is allowed, not proof that it is independently
trustworthy. Cloudflare/WAF challenges may need an operator-controlled bypass
for Agent paths; this feature does not change those external policies.

A failed uncommitted target does not revoke the old connection. After the
selection is saved, lost final responses keep it selected and retry confirmation.
No core restart, token replacement or traffic/offline identity change is required.
The planned minimum versions above must follow the actual containing release.


### bosun v0.99.1 correction

Trusted-proxy migration accepts the implicit default HTTP transport used by a
normal installed client. Earlier v0.99.0 could verify the anonymous proof but
reject its nil transport before sending confirmation. This patch keeps strict
certificate validation, direct-mode proofs and persistent identity unchanged.
After upgrading bosun, retry the failed trusted-proxy migration; Captain1.68.0
already supports it and does not require a panel upgrade.


## Detect before migration (Captain1.69 / bosun0.100)

The normal console flow is select target, detect from nodes, then confirm. A
separate capability/cursor delivers temporary anonymous probes; old agents never
receive these commands. No target credentials, URL selection, config revision or
traffic/offline identity change during detection. The node first checks a real
TLS-bound proof; only a valid separate same-panel application proof can recommend
trusted-proxy mode. Certificate/redirect/network/signature failures are failures,
not automatic permission to trust a proxy. A trusted result still requires an
explicit administrator confirmation before a separate migration is issued.

Five simultaneous probes, five-minute expiry and bounded private diagnostic
history limit work. Results bind node identity, frozen target and source; stale
previews cannot authorize migration. Lost result receipts retry only at the
authenticated current source. Manual direct/proxy modes remain in advanced
settings for older agents and special cases. Existing migration wire capability2
and proxy capability1 stay unchanged. This read-only extension does not require
a higher node rollback floor; older versions simply lack automatic detection.
