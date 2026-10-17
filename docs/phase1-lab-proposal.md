# Phase 1 lab proposal — approved and applied

Status: owner approved apply and functional testing on 2026-10-16; Phase 1 is complete. This document preserves the reviewed proposal and pre-apply capacity assessment. See [Phase 1 results](phase1-lab-results.md) for the actual deployed state, UEFI and permission repairs, offline firewalld installation, IPv6 packet filtering, and validation evidence. Do not rerun the historical apply command against the existing lab. All 48 lab tests pass; earlier temporary pool definitions remain untouched.

## Selected topology

Use one strictly isolated libvirt L2 segment with no forwarding, no host bridge IP, no DHCP, and no default route/DNS in guests. Static guest addresses allow same-L2 peer communication and mDNS while preventing the guests from reaching the host or external networks at Layer 3. Pre-stage any later RPM/image artifacts; do not add a NAT NIC or host service route without a separately reviewed firewall design.

| Resource | Proposed value |
|---|---|
| Libvirt network | `autonomous-rke2-isolated` |
| Linux bridge | `virbr-rke2` (currently absent from `ip -j link`) |
| IPv4 subnet | `192.168.250.0/24` (no overlap in current host routes or existing libvirt networks) |
| Forwarding / host address / DHCP | none / none / disabled |
| New directory pool | `autonomous-rke2-lab` |
| Pool path | `/var/lib/libvirt/images/autonomous-rke2-lab` on `/var` (`/dev/sdb2`) |
| Base image | Rocky Linux GenericCloud Base 9.8 x86_64, dated `20260525.0`; signed checksum and local image verified |
| VMs | `rke2-r9-cp01` `.11`, `rke2-r9-cp02` `.12`, `rke2-r9-cp03` `.13` |
| Per VM | 4 vCPU, 8192 MiB RAM, one qcow2 overlay with 60 GiB virtual capacity |
| Total maximum guest allocation | 12 vCPU, 24 GiB RAM, 180 GiB virtual disk |

Each node receives a unique UUIDv4 host ID in cloud-init metadata and a root-owned `/var/lib/autonomous-rke2/host-id`; cloud-init deletes/regenerates SSH host keys; NetworkManager gets a static guest-only address with no gateway. The image's machine-id cleanliness is not yet verified; after first boot, require three distinct machine IDs, hostnames, SSH host-key fingerprints, and host IDs before any cluster agent may run. The cloud-init lab operator account has password login locked and an SSH public key only; its passwordless sudo is broad inside these disposable, L3-isolated guests and must not be reused in production.

## Exact host-side effects if approved

1. Re-verify the staged Rocky image, signed checksum, detached signature, and pinned keyring under ignored `lab/artifacts/`. The apply tool does not download artifacts. Apply verifies the signature, exact signer fingerprint, checksum, size, qcow2 format, virtual-size ceiling, and absence of a backing file before any libvirt mutation. Current SHA-256 is `92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8`; signer is `21CB256AE16FC54C6E652949702D426D350D275D`. Evidence is in `lab/results/rocky9-image-verification.json`.
2. Define/start `lab/libvirt/network.xml`, creating the new `virbr-rke2` bridge with no IP, DHCP, or forwarding. No physical NIC, host route, NAT, host firewall rule, existing `default` network, or guest access to host services is intended. Libvirt may add its own bridge filtering state; compare nftables and interface snapshots before/after and stop if unrelated changes appear.
3. Create the new directory `/var/lib/libvirt/images/autonomous-rke2-lab`, define/start the new directory pool, upload the verified staged image into a libvirt-managed base volume, and create three per-node qcow2 overlays. Do not use or alter `ad-hyperv-lab` or any other existing pool.
4. Define and boot exactly the three named VMs with the resource limits and static addresses above. No guest package installation from the internet is possible on this network; RKE2/RPM artifacts must be staged in a later, separately validated step.

The host currently reports 617 GiB free on `/var`; the plan reserves at most 180 GiB of VM virtual capacity plus up to 20 GiB for the image and enforces a minimum 300 GiB free-space reserve. The conservative remainder is 417 GiB if the full image cap and all disk capacity are consumed. Available RAM was 245 GiB; the guest total is 24 GiB and the planner retains 32 GiB for the host. These are point-in-time figures; preflight re-reads them immediately before any apply.

Storage is on a PERC H330-backed virtual disk reporting `ROTA=1`; actual physical media and SSD backing are unknown. The proposal does not claim SSD performance. The existing pool's reported free space (701.52 GiB) disagrees with filesystem free space (617 GiB); planner uses filesystem free space and does not allocate from the existing pool. If SSD-backed storage is mandatory, do not approve until media/path is confirmed.

## Read-only plan command and current blockers

```text
python3 -B lab/libvirt/provision.py --config lab/libvirt/lab-config.example.json
```

This command reads libvirt inventories, host routes, memory, and filesystem capacity and verifies staged image artifacts. It prints JSON and makes no infrastructure changes. At the approved preflight, the plan was 3 servers / 12 vCPU / 24576 MiB / 180 GiB, with subnet `192.168.250.0/24` and no blockers. After staging, available filesystem capacity was 661605134336 bytes; the conservative remainder after the full 200 GiB project allocation was 446856769536 bytes, above the 300 GiB reserve. Available RAM was 250446 MiB. The lab now exists; collision checks deliberately prevent reapplying it.

Run these exact commands from the repository root only after apply approval. Choose fresh snapshot filenames if these already exist; snapshots refuse overwrites.

```sh
python3 -B lab/libvirt/snapshot.py --output lab/results/phase1-apply-before.json
sudo -n python3 -B lab/libvirt/provision.py --config lab/libvirt/lab-config.example.json --apply --confirm-lab autonomous-rke2-isolated
python3 -B lab/libvirt/snapshot.py --output lab/results/phase1-apply-after.json
```

The snapshot command reads named resource XML/status, interface addresses, IPv4/IPv6 routes, and the privileged nftables ruleset; it changes only its local evidence file. An initial baseline is already saved at `lab/results/phase1-before.json`. If apply fails, capture the after snapshot but do not retry automatically; inspect the reported partial work first.

Preparation verification: `phase1-before.json` versus `phase1-prepared.json` has identical domain/network/pool XML and status. Interface/route differences are only address lifetimes and route expiry countdowns; nftables differences are only packet/byte counters. No host configuration change was observed during preparation.

## Validation after approval

- Snapshot `virsh list --all`, `virsh net-list --all`, `virsh pool-list --all`, `ip -j link`, `ip route`, and `nft list ruleset` before and after.
- Verify only the three new domain names, one new isolated network, one new pool, and the new bridge appeared; all pre-existing resources and physical interfaces must match snapshots.
- Use `virsh console`/guest-agent access, not guest L3 access to the host, to verify Rocky 9.8, cloud-init completion, unique machine-id, hostname, host SSH key fingerprints, host UUIDs, static peer addresses, no default route, and no reachable host/external address.
- Do not declare Phase 1 complete until these checks pass on the actual VMs.

## Rollback boundary

Apply is not transactional and does not automatically roll back. If a command fails, it stops and reports the last completed actions; it does not clean up resources or resume automatically. Do not rerun after a partial failure. First inspect exact named resources and the configured path, then obtain approval for any manual recovery. If rollback is approved, it may touch only resources created by this change: stop/undefine the three named VMs and remove their VM-owned overlays; destroy/undefine `autonomous-rke2-isolated`; destroy/undefine `autonomous-rke2-lab`; remove only the exact project directory after verifying its canonical path and contents. Preserve the base image by default. Never use broad globs, never undefine `default`, never modify/delete `hyperv1`, and never alter/delete any pre-existing pool.

## Approval record

Owner selected “Approve apply and functional testing,” including functional testing despite unverified physical media. The network, pool, and three VMs were created, then repaired and validated within that lab scope. Libvirt's IPv6 packet filter was added to close the observed host tap link-local path. Existing `boot-scratch` and all four inactive persistent/autostart pools under Hermes scratch remain protected. Two of those pools (`tmp34lvksot`, `tmpm5w4rn5q`) appeared after an earlier CLI dry-run mistakenly used `qemu:///system`; none were removed. Further expansion or cleanup is outside this completed Phase 1 approval.
