# Universal node architecture

## Deployment model

The deployment unit is one disk image. Every clone contains both pinned RKE2
role packages, offline container archives and chart overrides, the node agent,
and its enabled systemd unit. Roles are selected at runtime. A generic sealed
image contains no enrollment secret, host private key, formation journal,
registration tokens, cluster certificates, or datastore state.

## Components and locations

Each node runs these components:

| Component | Location | Responsibility |
| --- | --- | --- |
| Node agent | `autonomous-rke2-host-agent.service` | Discovery, durable formation, health, fixed-role restart |
| Host identity and journal | `/var/lib/autonomous-rke2` on that node | Unique Ed25519 identity and immutable cluster/role intent |
| Authenticated discovery | IPv4 multicast `239.192.42.42:9444` | Find deployment peers and pending/healthy clusters |
| Enrollment HTTPS | Node IP, TCP 9443 | Healthy servers reserve and complete initial membership |
| API health proxy | Loopback TCP 7443 on every node | Fail over among discovered or persisted server endpoints |
| RKE2 server + embedded etcd | Nodes admitted up to control target (default 3; configurable 5 or 7) | Kubernetes control plane and membership serialization |
| RKE2 agent | Subsequent admitted nodes | Worker runtime |
| Membership ledger | Kubernetes ConfigMap, replicated by etcd | CAS reservations shared by all healthy servers |

No component runs on a separate authority or management host. The hypervisor
and connected artifact build/signing tools are outside the runtime cluster.
Physical hosts run the same userspace and formation code.

## Initial formation and enrollment

The first node waits through its startup grace and a complete authenticated
discovery cycle. If no cluster is advertised, it persists a new cluster UUID,
advertises pending formation, generates separate server/worker passwords, and
starts RKE2 server. After Kubernetes, its Node, and etcd are independently
healthy, it writes the immutable cluster marker and initializes the membership
ledger and health-reader RBAC. Only then does it advertise enrollment readiness.

Later nodes pin the certificate/key carried by an authenticated discovery
reply. A healthy server verifies the caller's persistent identity and source
address, then reserves membership using Kubernetes resourceVersion CAS. Initial
membership proceeds one node at a time: controls fill the catalog's target,
then workers. The mutable target is separate from immutable image policy.
An uncertain reservation never expires into a reusable server
slot. Repeated requests for the same identity and operation resume the same
reservation; name/address/identity changes stop convergence.

The admission server observes actual Kubernetes readiness and etcd membership
before completing a reservation. Server members share the same replicated
ledger. Workers receive only a CA-pinned worker token and a read-only health
certificate bound to their own host key. All private keys stay local. RKE2
registration uses the responding server's native supervisor port. RKE2's own
client load balancer retains discovered server addresses across reboots.
Read-only API health traffic uses a node-local TCP proxy with end-to-end cluster
TLS. No external VIP, DNS seed, or load balancer is required.

## Restart and failure boundaries

On reboot, identity and journal load before discovery starts. Self-healing-capable
controls start with a local-only recovery API and existing datastore, then check
live role authorization before exposing full control services. Valid existing
voters can restore quorum together; retired generations cannot reclaim a vote.
Missing completed data, changed configuration, or conflicting cluster identity
halts convergence. Lost-quorum reset and new-machine provisioning are absent.
Explicit [libvirt reconciliation](scaling.md) uses a root-only node management
CLI, catalog CAS operation ownership, serialized admission, and journaled
retirement. It replaces roles with fresh nodes and retains retirement tombstones.
Operator management remains a root-only CLI. The authenticated node protocol
also carries healthy heartbeats, current role authorization, and stop
acknowledgements. An opt-in healing controller uses the same catalog operation
ownership as manual scaling, removing a failed voter before admitting its worker
replacement. Physical signer identities remain stable; fresh role generations
receive new Node and etcd identities. See [self-healing](self-healing.md).

This design assumes the first node is booted alone, then additional nodes join
the reachable cluster. ID ordering reduces races among mutually visible fresh
peers; it cannot guarantee one cluster across network partitions or hidden
groups of fresh nodes. See [discovery assumptions](discovery-decision.md).

## Network behavior

NIC names may differ between nodes. Automatic selection ignores RKE2's CNI
interfaces after startup. Because Flannel chart arguments are cluster-wide,
every server emits the same subnet-based IP regex for uplink selection; no
server's local NIC name becomes global configuration, and a default route is
unnecessary. Nodes share one IPv4 subnet, outside the pod/service ranges. See
[Flannel interface flags](https://github.com/flannel-io/flannel/blob/master/main.go)
and the [RKE2 Flannel DaemonSet template](https://github.com/rancher/rke2-charts/blob/main/charts/rke2-flannel/rke2-flannel/v0.28.907/templates/daemonset.yaml).

The node also maintains a link route for its fixed Kubernetes service CIDR,
with a distinct metric. This lets kube-proxy perform initial OUTPUT routing
on isolated hosts without a default gateway. Default routes remain under the
site network configuration; the acceptance seed does not inject this route.

## Related information

- [Deploy the universal image](universal-node.md)
- [Operate the libvirt lab](lab-lifecycle.md)
- [Trust boundaries](trust-and-threat-model.md)
- [Outstanding work](open-questions.md)
