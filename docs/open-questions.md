# Initial decisions, assumptions, and unresolved risks

## Decisions taken

1. Development host is Ubuntu 24.04.5 and remains outside Kubernetes; guests are Rocky Linux 9 x86_64 with SELinux Enforcing and firewalld.
2. Pin an identical Rocky 9.8 GenericCloud x86_64 base image candidate for all test guests; unique identity comes from cloud-init at instance creation. Image is not downloaded or checksum-verified yet.
3. Use the current official RKE2 v1.37 line and `rke2-server`/`rke2-agent` RPM method as a candidate. Exact RPM availability/signature and latest patch must be rechecked before lab build.
4. RKE2 embedded etcd starts at three voting servers; servers remain workload eligible. Two later agents are eligible for controlled promotion.
5. Use authenticated mDNS/DNS-SD only as an endpoint hint on isolated L2; external bootstrap authority establishes cluster authority and UUID.
6. Require positive external fencing before server replacement. Quorum loss and uncertain membership halt; no automatic quorum reset/data deletion.
7. Do not touch current `hyperv1`, default libvirt network, or `ad-hyperv-lab` pool. Lab network/pool and VM creation require a reviewed exact change proposal and approval.
8. No KubeVirt, guest VM workload, or Windows/AD integration in initial cluster milestone.

## Assumptions

- Three VMs are the first validation gate; expand to five only after resource and safety gate.
- Current available RAM and `/var` free space are observations at a single time, not guaranteed reservations.
- A compatible Rocky GenericCloud image is available at an official mirror, but the candidate URL/checksum must be verified before use.
- Host libvirt is reachable via system `virsh` with current user privileges; this does not imply permission to modify resources.
- The Go module path `autonomous-rke2` is provisional until a remote repository namespace is established.

## Open questions / blockers

- Privileged firewall inspection failed: what are the actual nftables/UFW rules and host-level route/filter policies? Must be inspected by an authorized administrator before network proposal.
- `ROTA=1` on the PERC H330-backed disks does not prove whether the actual media is SSD or HDD. What are the physical drive type, RAID virtual-disk/cache policy, and expected IOPS? Do not claim SSD-backed VM disks until known.
- Existing pool `ad-hyperv-lab` reports 701.52 GiB free while `df` on `/var` reports 618 GiB free. Reconcile pool vs filesystem accounting and retain a host reserve before estimating safe disk allocation.
- What external trust anchor will authorize joining hosts in the lab, and how is its private key protected/rotated? Initial proposed lab authority is host-local and single point of failure.
- What exact stable registration endpoint will remain reachable through a server replacement? Initial test network may use authority-maintained DNS/IP; production endpoint design depends on independent infrastructure.
- What project license and repository remote/module namespace should be used? No LICENSE has been added pending owner choice.
- RKE2 release, Rocky image, and artifact checksums remain candidates; revalidate official support matrix, RPM publication, signed image metadata, and security notices immediately before provisioning.
- What are the exact preferred libvirt network/pool names and nonconflicting isolated CIDR? Assessment identifies existing ranges but firewall state and approval remain outstanding.

## Approval gates

No installation of host packages, host service changes, host network modifications, or changes to existing VMs/networks/pools. Before creating any VM or isolated libvirt network/pool, present resource allocations, exact names/paths/CIDR, commands, network isolation properties, and rollback steps for approval.
