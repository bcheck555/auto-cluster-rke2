# Development host and lab assessment

Signed-image replacement update (2026-10-17): three server-profile VMs passed boot/reboot checks and remain unjoined with RKE2 masked, firewalld disabled, and SELinux Enforcing. Existing network/pool/filter and protected resource definitions were preserved. Non-tap routes match; lab tap identities changed. All seven baseline pools remain and `hyperv1` stays off. Approximately 565 GiB disk free, 385 GiB after remaining lab commitments, and 240 GiB RAM available were observed. See [release hashes, host differences, and rollback evidence](offline-image-results.md). Historical assessments below retain their original timestamps and inventory.

Phase 1 update (2026-10-16): owner approved apply and functional testing. The three Rocky guests, isolated network/pool, and per-NIC IPv6 filter are deployed and validated. Existing resource definitions were preserved; `/var` retained approximately 606 GiB available. See [Phase 1 results](phase1-lab-results.md). The assessment below is the pre-apply baseline, including its then-current inventory and approval gates.

Assessment timestamp: 2026-10-16 16:30 EDT (system clock)
Workspace: `/var/github/auto-cluster-rke2` (renamed from `/var/github/auto-cluster`).

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
| Go | Host Go 1.27.2 at `/usr/local/go`; `go` and `gofmt` exposed through `/usr/local/bin` | On 2026-10-17, owner authorized host installation. Moved the previously checksum-verified official distribution out of the repository and made it root-owned; repository-local toolchain removed. |

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
- `virsh net-list --all` currently lists only the existing `default` network. `ad-hyperv-lab` is a storage pool (not a libvirt network). Preserve this distinction; do not infer a network exists from the pool name.
- The earlier baseline recorded `ad-hyperv-lab`, a directory pool at `/var/lib/libvirt/images/ad-hyperv-lab`, active and persistent/autostart. A later read-only inventory on 2026-10-16 also observed `boot-scratch` (running/autostart, target `/var/lib/libvirt/boot`) plus inactive persistent/autostart pools `tmpe_g7opn3` and `tmpqg55m0lc`, targeting `/home/checkb/.hermes/cache/scratch/tmpe_g7opn3` and `/home/checkb/.hermes/cache/scratch/tmpqg55m0lc`. A subsequent snapshot observed two more inactive persistent/autostart pools, `tmp34lvksot` and `tmpm5w4rn5q`, targeting corresponding paths under the same Hermes scratch directory. Their appearance followed a project `virt-install --dry-run` invocation that mistakenly used `qemu:///system`; this is the only project operation in that interval that could have modified libvirt, so it is the likely cause, though attribution cannot be proven from the snapshots alone. Their target directories are now absent and current pool refresh reports zero capacity/allocation; no cleanup was attempted. The CLI test has since been changed to use `test:///default`, and a subsequent test-driver run left the QEMU system pool list unchanged. Preserve all observed pools; do not infer they are disposable from their names or paths, and do not remove them without approval.
- Host interfaces include `bond0` at `192.168.1.50/24`, `wg0` at `10.77.0.1/24`, `virbr0` at `192.168.122.1/24`, and Docker bridges in `172.17.0.0/16` through `172.20.0.0/16`. Network manager reports systemd-networkd active. Do not change any host network settings.
- No ISO/qcow2/img files were found in the searched `/var/lib/libvirt`, `/var/lib/cloud`, and `/var/cache` paths (some paths may be inaccessible). No Rocky GenericCloud image was located in those paths.
- Firewall inspection was initially blocked unprivileged, then completed with non-interactive read-only sudo on 2026-10-16. `ufw status verbose` reported `Status: inactive`; host `firewalld` service is inactive. `nft list ruleset` shows IPv4 INPUT and FORWARD base-chain policies `accept`, with existing libvirt/Docker-managed chains and NAT rules (warnings say those tables are managed by iptables-nft; do not edit them directly). This is not a restrictive default-deny host firewall. Proposed lab therefore uses a libvirt L2 network with no forwarding, no bridge IP, and no DHCP; guests have static peer-only addresses and no host/internet L3 access. Starting a libvirt network still creates a bridge and may create libvirt-managed filtering state; require before/after verification and approval. No firewall or host network changes have been made.

## Preliminary lab recommendation (not authorization)

Memory and `/var` capacity are sufficient on paper for three initial VMs (three × 4 vCPU, 8 GiB RAM, 60 GB virtual disks), with nominal totals of 12 vCPU, 24 GiB RAM, and 180 GB disk. A later five-VM lab with two 2-vCPU/4-GiB/40-GB workers would nominally total 16 vCPU, 32 GiB RAM, and 260 GB disks. Those totals do not account for guest overhead, image snapshots, thin-provisioning behavior, filesystem reserve, existing workload, or IO performance. `/var` free space is 618 GiB, but the existing pool is protected and actual SSD backing is unverified. Do not provision until a new isolated pool/network proposal is reviewed and approved, remaining host reserves are computed, firewall/network state is inspected with adequate privileges, and collision-free CIDR is selected.

Remaining safe assessment actions (read-only): reconcile pool/filesystem accounting and identify physical backing for `/var` (controller, media, and cache details). Firewall inspection is complete. No host-impacting actions have been taken by this project work.
