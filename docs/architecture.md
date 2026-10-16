# Proposed architecture

## Component boundaries

1. **Host bootstrap agent** (`cmd/host-agent`, systemd on every Rocky 9 node): persistent unique identity, signed bootstrap grants, authenticated discovery, durable operation journal, idempotent RKE2 server/agent install and join, local health, and reboot-safe resume. It does not decide to create a cluster from a timeout and exposes no arbitrary shell interface.
2. **Membership controller** (`cmd/membership-controller`, Kubernetes): reconciles desired versus actual server membership only while API and embedded etcd health are proven; selects eligible workers and records recovery operations. It does not perform destructive recovery while the control plane is unavailable.
3. **Host-side fencing authority/service** (`cmd/fence-service` on the development host for lab): narrow authenticated API to inspect and power off only project-owned libvirt domains. Nodes never receive unrestricted libvirt socket/API access. Production fencing is an interchangeable Redfish/BMC implementation, not part of the lab's security claim.
4. **Bootstrap authority**: independent pre-cluster trust root that issues a single-use signed first-cluster grant and persistent cluster UUID. Development-host implementation is lab-only and not HA. Production must provide a redundant authority or documented operator-mediated authorization.

## Trust and data flow

Discovery is an address hint over the isolated lab L2 segment (evaluate mDNS/DNS-SD first); every response is authenticated and bound to the persistent cluster UUID. Discovery never carries a plaintext registration token. A host presents its unique key/identity to the authority; the authority issues narrowly scoped, expiring credentials for initialization or joining. RKE2 registration uses its documented stable endpoint and credentials are stored with restrictive permissions, not logged. Kubernetes API and etcd health are observed separately.

## Role and recovery flow

Policy defaults to three voting RKE2 servers, with workloads enabled on servers and eligible workers. Initial server creation requires a signed grant. Additional servers/agents join only under authenticated policy. Recovery requires: surviving quorum; evidence distinguishing transient partition from host failure; authority approval; positive fencing confirmation; exact etcd member identity; documented member removal; a controlled agent stop/reconfigure/server start; etcd synchronization; and audit completion. Any quorum loss, ambiguous identity, or inconclusive fence stops automation. Returning nodes are reconciled against cluster UUID and member identity before any local state change.

## Rocky/RHEL node platform

All test nodes use the same pinned x86_64 Rocky Linux 9 GenericCloud image plus cloud-init. Provisioning must create unique machine-id, hostname, SSH host keys, and cluster identity. Guest configuration uses DNF/RPM, NetworkManager, firewalld, systemd, SELinux Enforcing, and RKE2/containerd. Install RKE2 from verified EL9 RPM repositories; install `rke2-selinux`, configure `selinux: true` on both server and agent, and verify enforcing status before/after service start. No Ubuntu guest configuration is permitted. RHEL 9 portability is a separate evidence-based comparison in `docs/rocky-to-rhel9.md`.

## Initial topology and constraints

Start with three Rocky VMs, then expand to five. The development host remains outside Kubernetes. Current assessment shows 251 GiB RAM and 618 GiB free in `/var`, but backing SSD and privileged firewall state are unverified. Existing `hyperv1`, `default` network, and `ad-hyperv-lab` pool are protected. No VM or network creation is authorized by this design document; present exact plan and obtain approval first.

## Failure guarantees and non-goals

Peer discovery cannot establish first-cluster authority. Leader election has no meaningful safe winner when there is no preexisting shared authority; a partitioned set of brand-new hosts may each believe it is first. Only an external authority/grant prevents this. Three-member etcd tolerates one failure; five-member etcd requires three votes. Automatic quorum reset is disabled. KubeVirt, Windows guests, AD, distributed storage, and production Redfish operations are deferred until Rocky guest cluster formation and failure acceptance tests pass.
