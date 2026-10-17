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

All profiles derive from the same pinned x86_64 Rocky 9.8 GenericCloud source. Signed standalone OS, server, and agent images are built offline; deployment cloud-init supplies identity, networking, operator access, and validation. Provisioning creates unique machine IDs, host IDs, SSH host keys, domain UUIDs, and NVRAM. Cluster identity is created only during separately authorized bootstrap. The OS profile keeps firewalld enabled and active; RKE2 profiles keep it installed, inactive, and disabled. Both RKE2 services remain masked in unjoined guests. Install RKE2 and `rke2-selinux` from verified local EL9 RPM closures, configure `selinux: true`, and preserve SELinux Enforcing. Use Flannel VXLAN; pod NetworkPolicy enforcement is deferred. No Ubuntu guest configuration is permitted. See `docs/offline-images.md`; RHEL validation remains separate in `docs/rocky-to-rhel9.md`.

## Initial topology and constraints

The approved Phase 1 lab contains three Rocky VMs on an isolated network with no bridge IP, DHCP, or forwarding and with IPv6 filtered at guest NICs. The development host remains outside Kubernetes. Image and replacement preflight preserve 300 GiB disk and 32 GiB RAM reserves, including existing lab commitments and temporary resources. Physical media remains unverified. `hyperv1`, `default`, and every pre-existing pool remain protected. Expansion to five nodes and production cluster bootstrap remain later tasks; the approved replacement scope is limited to the three unjoined Phase 1 guests.

## Failure guarantees and non-goals

Peer discovery cannot establish first-cluster authority. Leader election has no meaningful safe winner when there is no preexisting shared authority; a partitioned set of brand-new hosts may each believe it is first. Only an external authority/grant prevents this. Three-member etcd tolerates one failure; five-member etcd requires three votes. Automatic quorum reset is disabled. KubeVirt, Windows guests, AD, distributed storage, and production Redfish operations are deferred until Rocky guest cluster formation and failure acceptance tests pass.
