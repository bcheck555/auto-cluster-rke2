# Trust assumptions and threat model

## Trust roots

- Per-host private identity key is generated once and held with least privilege on the node; public identity is registered with bootstrap authority.
- Pre-cluster bootstrap authority is the only entity allowed to authorize initial cluster identity. Lab authority on the development host is a trusted single point of failure and is not a production HA design.
- Cluster CA and RKE2 credentials are protected secrets. Discovery data is untrusted until cryptographically authenticated.
- Fencing service credentials and libvirt authority remain host-side; cluster nodes cannot access the libvirt socket or broad host command execution.

## Threats and required response

| Threat | Required control |
|---|---|
| Simultaneous first boot creates competing clusters | Single-use authority grant bound to persistent cluster UUID; deny bootstrap absent grant. |
| Spoofed mDNS or UDP discovery response | Treat discovery only as endpoint hint; verify signed identity and authenticated TLS before use. |
| Leaked/observed registration traffic | Never advertise join token; use protected, expiring role-scoped credentials and TLS. |
| Compromised worker requests promotion | Independent policy authorization, eligible identity, quorum check, audit record, fencing of replaced server. |
| Network partition mistaken for dead server | No destructive replacement without positive external fencing confirmation. |
| Stale host returns after replacement | Compare persistent host and cluster identities against etcd membership; quarantine until approved reconciliation. |
| Controller/API unavailable or etcd quorum lost | Fail closed; do not mutate membership, reset quorum, or delete local data. |
| Malicious input triggers arbitrary host command | Typed allowlisted operations and argument arrays; no shell command endpoint. |
| Secrets leak through logs/config repository | Restrictive file mode, redaction tests, no secret-bearing discovery, ignore generated state. |

## Limits

A host agent without a pre-existing trust root cannot distinguish an authorized new cluster from another independently bootstrapped group. Network reachability and leader election among first-boot peers do not solve that authority problem. Lab authority is not highly available; if unavailable, bootstrap pauses. Production needs an independently operated redundant authority/fencing system and explicit credential rotation/revocation procedures before deployment.
