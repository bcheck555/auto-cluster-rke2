# Implementation status

Implemented universal-image path:

- Node-resident authenticated multicast discovery and HTTPS enrollment.
- First-node bootstrap, pending-cluster advertisement, and durable restart.
- Three-server limit followed by workers, with quorum-backed CAS reservations.
- Native RKE2 registration failover, local API health proxy, and persisted server endpoints.
- Distinct server/worker credentials and host-key-bound health certificates.
- Independent Kubernetes/etcd checks and certificate renewal.
- Universal image package closure, enabled boot service, sealed-state checks,
  signed raw export, and four-clone candidate validation/publication gate.
- Local controller, auth, concurrency, endpoint failover, and image-contract tests.

The fresh universal image passed offline builds and four-clone libvirt
acceptance: first-alone bootstrap, automatic server/server/worker joins,
simultaneous reboot with stable IDs, three voting servers, offline DNS, and
cross-node workload connectivity. See [validation results](universal-image-results.md).

Remaining hardware acceptance: validate the raw disk on representative physical
hosts, including boot firmware, network drivers, unique machine identity, and
persistent storage. Existing lab generations remain unchanged.

Future work: deployment-key and cluster-CA rotation, address migration, tested
manual reservation reconciliation, lifecycle upgrades, and separately gated
fencing/recovery procedures. General partition-proof zero-touch bootstrap
requires a stronger assumption or external coordination; it is not promised.

Prior external-authority prototypes remain historical code and tests. The
earlier separate-role lab evidence remains separate from universal-image results.
