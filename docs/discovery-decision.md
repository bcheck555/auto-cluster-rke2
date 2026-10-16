# Discovery decision (initial design)

Status: selected as an initial lab candidate, not implemented or tested on a VM.

## Options considered

| Mechanism | Advantages | Failure/security concerns | Decision |
|---|---|---|---|
| mDNS/DNS-SD | Simple on shared isolated L2; no preconfigured DNS; service/endpoint hints can be scoped | Multicast may be filtered; spoofable; collisions and partitions; does not establish trust | Use only to find candidate endpoints in the lab, not to authorize a cluster or convey secrets. |
| Custom UDP broadcast | Small implementation; fast peer announcements | Broadcast filtering, packet loss/spoofing, protocol maintenance, easy accidental secret disclosure | Do not implement initially; no security advantage over mDNS. |
| DNS/SRV records | Mature, stable service discovery | Requires trusted DNS and records before cluster exists; creates dependency/authority problem | Possible future production provider when DNS is independently available and authenticated. |

## Protocol boundary

The discovery provider returns endpoint hints (address, port, transport, observation time, and advertised public cluster identifier only). It never accepts or returns registration secrets, bearer tokens, bootstrap grants, private keys, or authority decisions. Every endpoint must prove its identity through authenticated transport and a signature chained to the trusted authority/cluster identity. Unauthenticated or unverifiable adverts are ignored and audited.

Initial topology assumes a dedicated isolated Layer-2 VM network. mDNS/DNS-SD availability must be tested in that exact libvirt network; if multicast is unavailable, do not silently fall back to unauthenticated UDP or cluster creation-on-timeout. Use the bootstrap authority's provisioned endpoint or an explicitly configured authenticated DNS record instead.

## First-cluster safety

Before the first cluster exists, no peer has an authoritative shared state. A distributed election among fresh peers cannot distinguish two isolated partitions and therefore cannot guarantee a single cluster UUID. A host-side lab authority issues exactly one persisted single-use bootstrap grant and records the cluster UUID before server initialization. If the authority is unavailable, bootstrap waits. Production must replace this single-host authority with a redundant external authority or operator approval; mDNS is never the trust root.

## Acceptance checks

- Concurrent first-boot requests produce one authority-issued cluster UUID/grant; others are denied or receive join authorization.
- Malformed, replayed, spoofed, wrong-cluster, and unsigned advertisements never authorize bootstrap/join.
- Network partition or empty discovery result never creates a cluster.
- Logs include endpoints and decisions but never credentials.
