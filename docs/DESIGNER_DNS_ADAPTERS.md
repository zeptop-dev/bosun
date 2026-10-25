# Designer DNS adapters

Capability research checked on 2026-10-24. The DNS enhancement means encrypted
DNS through the chosen proxy policy, with independent node-name resolution.
Having a DoH setting alone is not sufficient. These settings apply to queries
handled by the client; they do not guarantee protection for traffic bypassing
the client, external browsers' DNS settings, or arbitrary operating-system DNS.

## Mihomo and Stash

Mihomo retains its existing explicit resolver policy fragments. Stash uses
`follow-rule` and routes the resolver IPs before user rules, rather than emitting
Mihomo's `#policy` syntax. The bootstrap and proxy-name resolvers use IP-addressed
encrypted endpoints and remain direct. The latter has an independent path in
Stash iOS/tvOS 3.6+ and macOS 4.3+; older versions are outside this adapter's
supported range.

The ordinary encrypted resolvers and the Claude resolver have distinct IPs.
That distinction is required when DNSPolicy and ClaudePolicy select different
groups. Both DNS queries and traffic rules use the same pinned Claude snapshot;
an exact domain remains exact, while a suffix includes the apex and descendants.
The domestic resolver routes precede BackCN or other custom final rules.

Sources: [Stash DNS](https://stash.wiki/en/features/dns-server),
[Cloudflare resolver addresses](https://developers.cloudflare.com/1.1.1.1/ip-addresses/).

## Surfboard

Surfboard's encrypted DNS connections always use DIRECT. Its current documented
configuration has no equivalent to Surge's `encrypted-dns-follow-outbound-mode`.
Therefore DNSProtection cannot be published for this format. This restriction
does not disable supported routing enhancements, including Claude rules.

Sources: [encrypted DNS](https://getsurfboard.com/docs/profile-format/general/encrypted_dns_server/),
[configuration reference](https://getsurfboard.com/docs/ai-profile-guide/reference/).

## Surge

Surge exposes `encrypted-dns-follow-outbound-mode`, but documents a DIRECT
fallback when the DNS proxy has a hostname and cannot resolve it independently.
A configured DoH rule does not by itself prove the selected DNS policy is used.
The encrypted-DNS page suggests a proxy IP or Host IP mapping; the Host page
also says proxy hostnames bypass its mappings, while an earlier official
changelog allows explicit IP or traditional-DNS Host mappings. These descriptions
do not establish a universal safe hostname bootstrap for generated subscriptions.
The generated template carries `# captain-dns-protection: surge-ip-only`; actual
subscription delivery must reject hostname proxy endpoints, including nested
policy and client-chain candidates. Never resolve and freeze an operator's
hostname at template-publication time. Resolver IP rules select the requested
policies, and Host entries preserve the Claude snapshot's exact/suffix semantics.
Only `.cn` domains use the domestic resolver; other domestic domains use the
general proxied resolver, with this difference disclosed in format warnings.

Sources: [encrypted DNS](https://manual.nssurge.com/dns/encrypted-dns.html),
[Host mapping](https://manual.nssurge.com/dns/local-dns-mapping.html),
[official changelog](https://t.me/s/SurgeChangelog/834).

## Loon and Quantumult X

Loon supports encrypted DNS and per-domain Host assignments, but its documented
encrypted-to-plain fallback is controlled on the app's DNS page. The documented
profile keys alone do not establish selected-policy routing and prohibition of
plaintext fallback. Its newer `server-dns` node option independently resolves
node names, but does not establish global encrypted DNS policy selection.

Quantumult X distinguishes local DNS for routing/direct connections from remote
destination resolution for proxied connections. Its official sample documents
per-domain encrypted resolvers, but does not provide a DNS outbound-policy binding
or a separate proxy-hostname bootstrap equivalent. Adding unrelated filter rules
cannot be treated as evidence that internal DNS requests obey those rules.
DNSProtection therefore blocks publication to these two formats with precise
reasons; their supported routing enhancements remain usable with DNSProtection
disabled.

Sources: [Loon DNS](https://nsloon.app/en/docs/DNS/),
[Loon DNS mapping](https://nsloon.app/en/docs/DNS/hostmap/),
[Loon node DNS](https://nsloon.app/en/docs/Node/),
[Quantumult X official sample](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf).

## Egern

Egern documents two paths: ordinary DNS follows Forward and proxy routing;
proxy DNS is always direct. A nonempty `proxy_nameservers` bypasses Forward for
the latter, including domain-specific assignments. Its startup bootstrap accepts
only plain direct DNS. These paths must not be collapsed into a claim that every
DNS lookup follows the chosen proxy policy. IP-addressed encrypted upstreams
avoid hostname bootstrap for those upstreams; a final wildcard Forward prevents
ordinary unclassified queries falling through to plain bootstrap. The adapter
implements these distinct paths and reports the direct proxy-DNS boundary in
format warnings. Default DNS uses separate generic and Claude upstream IPs so
their selected policies can differ. Only `.cn` uses the domestic resolver, also
reported as a format warning. Claude forwarding entries precede domestic and
wildcard entries, preserving the pinned snapshot's exact/suffix semantics.

Source: [Egern DNS](https://egernapp.com/docs/configuration/dns/).

## Verification

Regression tests inspect both DNS-query selection and outbound selection, test
separate DNS and Claude policies, preserve full/suffix snapshot semantics, and
retain existing behavior when the enhancement is disabled. Closed-source
client configuration structures are checked against their documentation; these
tests are not actual iOS/macOS client or packet-capture acceptance tests.
