# Standalone listener credentials (development)

An optional `spec.Inbound.standalone` object enables independent SOCKS5 or
single-user SS2022. SOCKS requires username/password; SS2022 uses only the
cipher-sized `server_key`. The mode never supplies EffectiveUsers and cannot
combine with managed reverse, WG slots, ShadowTLS or per-user private grants.
Normal destination protection and node-level service controls remain effective.

Sing-box/Extended and Xray advertise `standalone_auth`; SS2022 uses sing-box.
Standalone SOCKS usernames are excluded from customer online-log attribution,
including collisions with another listener's customer identity. Rotation restarts
the relevant core; it is not treated as a dynamic customer-list update.

Captain state requests send `X-Bosun-Standalone-Auth: 1` even on the first pull.
Older agents must not receive such a listener based only on a stale process report.
No existing wire/config key changes. Only the mode boolean enters structural cfg1;
username, password and key remain excluded, with the full state revision binding
credential changes. The planned containing release is v0.99.0; confirm that version
when integrating. The rollback floor prevents older binaries from ignoring the mode.

The opt-in `TestStandaloneRealSOCKSAndSS2022` runs a real compatible sing-box binary
through `BOSUN_STANDALONE_TEST_BINARY`, using loopback only. It verifies authorized
SOCKS and one-key SS2022 TCP echo, wrong/anonymous/subscriber SOCKS rejection and
absence of subscriber traffic counters. It does not claim a public NAT path, UDP
throughput or real Xray process validation.
