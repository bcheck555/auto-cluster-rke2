# Development host and lab assessment

Assessment timestamp: 2026-10-16 16:30 EDT (system clock)
Workspace: `/var/github/auto-cluster`

## Host identity and virtualization

| Item | Observed | Notes |
|---|---|---|
| OS | Ubuntu 24.04.5 LTS (Noble) | Host only; not a Kubernetes node. |
| Kernel | Linux 6.8.0-146-generic, x86_64 | Observed via `uname -a`. |
| CPU | 2 × Intel Xeon E5-2697 v3; 28 physical cores / 56 logical CPUs | VT-x and EPT flags visible. |
| Hypervisor context | `systemd-detect-virt` => `none` | Current process appears on bare metal, not inside a guest. |
| Nested virtualization | `/sys/module/kvm_intel/parameters/nested` => `Y` | Intel KVM nested virtualization is enabled on host. Do not change it. |
| QEMU/libvirt | QEMU 8.2.2; libvirt API/library 10.0.0 | `virsh uri` is `qemu:///system`; tools are present. |
| Cloud-init | 26.1-0ubuntu1~24.04.1; `/usr/bin/cloud-init` | Tool present on host. |
| Go | `go: command not found` | No Go test/build possible until an approved/repository-local toolchain is chosen. |

## Capacity and storage

- RAM: 251 GiB total; 245 GiB reported available at assessment time; swap 8 GiB.
- CPU: 56 logical processors.
- `/var` (`/dev/sdb2`, ext4): 1.7 TiB total, 618 GiB free from `df`; existing `ad-hyperv-lab` libvirt pool reports 701.52 GiB available. Difference between filesystem and pool reporting should be reconciled before allocation.
- `/` (`/dev/sda2`, ext4): 227 GiB total, 32 GiB free, 86% used.
- `/home` (`/dev/sdb1`, ext4): 98 GiB total, 9.9 GiB free, 90% used.
- Both physical volumes report `ROTA=1`, model PERC H330 Mini. SSD-backed storage is not established; the suggested SSD-backed VM disk target is therefore unverified and should not be promised. Determine actual controller/cache/media configuration before performance claims.
- Existing pool `ad-hyperv-lab` is persistent/autostart and contains approximately 958.42 GiB allocated. Do not use, modify, or clean it for this project without explicit approval.

## Existing libvirt and network inventory (read-only)

- Existing domain: `hyperv1`, persistent, shut off, 20 vCPUs, configured maximum/used memory 131072 MiB, two existing disks (`hyperv1.qcow2`, `hyperv1-data.raw`), interface attached to `default`. Do not modify or start it.
- Existing libvirt network: `default`, active/persistent/autostart, NAT bridge `virbr0`, subnet `192.168.122.0/24`, DHCP includes static reservation `192.168.122.116` for `hyperv1`.
- `virsh net-list --all` listed only the existing `default` network. `ad-hyperv-lab` is the existing storage pool (not a libvirt network). Preserve this distinction; do not infer a network exists from the pool name.
- Existing pool: `ad-hyperv-lab`, directory pool at `/var/lib/libvirt/images/ad-hyperv-lab`; active, persistent/autostart.
- Host interfaces include `bond0` at `192.168.1.50/24`, `wg0` at `10.77.0.1/24`, `virbr0` at `192.168.122.1/24`, and Docker bridges in `172.17.0.0/16` through `172.20.0.0/16`. Network manager reports systemd-networkd active. Do not change any host network settings.
- No ISO/qcow2/img files were found in the searched `/var/lib/libvirt`, `/var/lib/cloud`, and `/var/cache` paths (some paths may be inaccessible). No Rocky GenericCloud image was located in those paths.
- Firewall inspection is incomplete: `ufw status` and `nft list ruleset` returned permission errors. Do not infer that host firewall is absent or permissive. Privileged read-only follow-up must be performed by an authorized operator before lab network approval.

## Preliminary lab recommendation (not authorization)

Memory and `/var` capacity are sufficient on paper for three initial VMs (three × 4 vCPU, 8 GiB RAM, 60 GB virtual disks), with nominal totals of 12 vCPU, 24 GiB RAM, and 180 GB disk. A later five-VM lab with two 2-vCPU/4-GiB/40-GB workers would nominally total 16 vCPU, 32 GiB RAM, and 260 GB disks. Those totals do not account for guest overhead, image snapshots, thin-provisioning behavior, filesystem reserve, existing workload, or IO performance. `/var` free space is 618 GiB, but the existing pool is protected and actual SSD backing is unverified. Do not provision until a new isolated pool/network proposal is reviewed and approved, remaining host reserves are computed, firewall/network state is inspected with adequate privileges, and collision-free CIDR is selected.

Suggested safe next assessment actions (read-only): authorized `sudo nft list ruleset`/`sudo ufw status verbose`, inspect physical backing for `/var` (controller and media details), and map the existing pool's filesystem path/usage. No host-impacting actions have been taken.
