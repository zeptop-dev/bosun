# Public IPv4 source redundancy

IPv4 observations query these fixed, independent service endpoints:

- https://api.ipify.org — plain address
- https://ipv4.icanhazip.com — plain address
- https://myip.ipip.net — explicit Chinese address field
- https://ip.3322.net — plain address

At least two successful, valid public IPv4 responses must agree. Missing/failed
responses do not veto consensus. Any conflicting successful response does veto
it, even when three other responses agree. Duplicate endpoint URLs do not count
as independent votes. The Captain trace fallback remains advisory and retains
all currently observed conflicts. Existing IPv6 sources/rules are unchanged.

Requests force IPv4, bypass environment proxies, omit node credentials, verify
TLS normally and do not follow redirects. Existing 4-second dial / 5-second
request limits remain; requests run concurrently within the sampler deadline.
Plain bodies are limited to 128 bytes. IPIP bodies are limited to 512 bytes and
only its explicit address field is parsed; HTML/error pages are not scanned for
arbitrary IP-looking substrings.

3322 requests have a conservative process-local 65-second minimum interval,
including failed attempts. Rate-limited slots are unavailable observations,
never reused cached successes. If only the two new sources are reachable, this
can delay startup confirmation until the normal sampling cadence; existing
confirmation-window rules are not weakened. This is not an availability SLA.

The remote acceptance used a read-only compiled DNS package test on the
user-selected mainland host. It did not replace or restart the installed agent.
Deploying this change requires a new bosun release/upgrade; Captain's protocol
and stored address-policy settings do not need to change.
