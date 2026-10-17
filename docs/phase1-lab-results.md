# Phase 1 lab results

Historical record of the original generation completed on 2026-10-16. Owner approved apply and functional testing despite unverified physical storage media. On 2026-10-17, signed server-profile images replaced these guests while preserving names, addresses, and resources. RKE2 is now installed but masked and unjoined; firewalld is installed and disabled. See [current image/replacement results](offline-image-results.md) for current identities, hashes, validation, and rollback. Findings below describe the retained original generation, where RKE2 was not installed and firewalld was active.

| Guest | IPv4 | vCPU | RAM | Virtual disk |
|---|---|---:|---:|---:|
| `rke2-r9-cp01` | `192.168.250.11` | 4 | 8192 MiB | 60 GiB |
| `rke2-r9-cp02` | `192.168.250.12` | 4 | 8192 MiB | 60 GiB |
| `rke2-r9-cp03` | `192.168.250.13` | 4 | 8192 MiB | 60 GiB |

Network: `autonomous-rke2-isolated`, bridge `virbr-rke2`, no bridge addresses, forwarding, or DHCP. Pool: `autonomous-rke2-lab` at `/var/lib/libvirt/images/autonomous-rke2-lab`. Each NIC references the new `autonomous-rke2-ipv4-only` libvirt filter, which drops IPv6 Ethernet traffic in both directions. This closes the host tap link-local path; a bridge without an IP alone was insufficient to justify IPv6 isolation. IPv4 peer traffic, including IPv4 mDNS, remains available.

## Verified behavior

- All three guests report Rocky Linux 9.8, cloud-init `done` with no errors, SELinux `Enforcing`, and active firewalld.
- Machine IDs, host UUIDs, hostnames, and ED25519 SSH host-key fingerprints are distinct. Host UUIDs match the checked-in configuration; identity files are root-owned with mode `0600`.
- The configured operator SSH public key is installed on each guest. Operator passwords are locked after validation. No password or private key is recorded in evidence.
- Every guest can ping both peers. Every guest lacks IPv4 and IPv6 default routes. Host/external IPv4 probes and host tap IPv6 link-local probes fail.
- All three VMs use UEFI and the guest-agent channel; no diagnostic graphics device or VNC listener remains attached.
- Existing `hyperv1` remains shut off. Existing domain, network, and pool definitions match the before snapshot after excluding changing pool capacity/allocation/available counters.
- Existing nftables rules remain present. Added rules are libvirt rules scoped to the new bridge and three lab taps, including IPv6 drops. No physical NIC configuration or existing route was changed; new tap link-local routes and ordinary lifetime/counter changes are recorded in snapshots.
- `/var` retained approximately 606 GiB available after provisioning and artifact staging, above the 300 GiB reserve. Physical media and SSD performance remain unverified.

## Apply findings and repairs

The first apply stopped before creating a VM because the new pool directory was `root:root 0750`, preventing QEMU traversal. The exact partial state was inspected and snapshotted before recovery; the complete apply command was not rerun. The directory now uses `0711`; libvirt manages disk ownership and file permissions. The provisioner and its regression check use the corrected mode and preserve command stderr on failure.

BIOS boot stalled during early boot. The same verified disk boots with the host's existing OVMF firmware. All guests now use `/usr/share/OVMF/OVMF_CODE_4M.fd` with per-guest NVRAM in the new pool. No host firmware package was installed.

Rocky disables guest-agent command execution by default. Validation used serial consoles and cloud-init attestations; guest-agent execution restrictions remain in place. Empty stale password lock files were cleared during the inspected cloud-init recovery, and host UUIDs were rotated to the final configured values to trigger reinitialization. Final cloud-init completion and installed SSH keys were rechecked.

The GenericCloud Base image omits firewalld. A disposable official Rocky container downloaded its dependency closure. All 112 RPMs passed signature checks against an isolated RPM database containing only the pinned Rocky 9 key. Guests installed firewalld and required dependencies from a read-only local repository ISO with GPG checks enabled and remote repositories disabled. The repository was then unmounted and each guest's NoCloud seed restored. Temporary containers were removed automatically; the downloaded container image remains in Docker's cache. Host packages were not installed.

The provisioner now generates NoCloud ISOs inside the new pool, includes the staged RPM repository, selects UEFI, starts firewalld, and attaches the IPv6 packet filter. It checks required tools, firmware, and offline repository metadata before infrastructure mutation. Apply still refuses collisions and does not resume partial work automatically.

The running lab was completed through the recorded recovery steps. A fresh end-to-end run of the revised apply path was not repeated against these existing resources; its arguments and guards were checked with the isolated test driver and lab tests.

## Evidence and repeatable checks

Local evidence is intentionally ignored by Git:

- `lab/results/rocky9-image-verification.json`: official signer, image SHA-256, and size. The tracked image lock records the same pin. A logical `qemu-img compare` of the uploaded base and staged image also passed.
- `lab/results/firewalld-rpms.json`: exact RPM SHA-256 manifest and resolved official container digest; staging logs include all signature results.
- `lab/results/phase1-apply-before.json`: host baseline immediately before apply.
- `lab/results/phase1-apply-after.json`: inspected partial state after the first failure.
- `lab/results/phase1-complete-host.json`: final host definitions, interfaces, routes, nftables, and filter XML.
- `lab/results/phase1-validated.json`: final guest reports, connectivity probes, account/key checks, and validation errors.
- `lab/results/phase1-*.py` and XML files: exact inspected recovery operations; retained for audit, not automatic rerun.

Run from the repository root, choosing fresh output filenames:

```sh
python3 -B lab/libvirt/snapshot.py --output lab/results/phase1-recheck-host.json
python3 -B lab/libvirt/validate_guests.py --console --baseline lab/results/phase1-recheck-host.json --output lab/results/phase1-recheck-guests.json
python3 -B -m unittest discover -s tests/integration/lab -v
```

Serial validation temporarily sets an in-memory password for the lab operator, locks it before probing, logs out, and locks it again in a `finally` block. The explicit `--console` option requires the existing `pexpect` Python module. Default guest-agent execution mode requires guest-agent commands that stock Rocky disables.

All 48 lab tests pass, including real signed-image verification, cloud-init schema validation, seed/UEFI/filter CLI validation through `test:///default`, the pool traversal regression, and refusal to overwrite an existing filter before any mutation. Do not rerun provisioning against this existing lab. Further topology changes, cleanup of pre-existing resources, and cluster bootstrap require their own scope review.
