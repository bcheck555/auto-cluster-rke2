# Offline image execution record

Signed release published on 2026-10-16 EDT (2026-10-17 UTC). Implementation
branch: `feat/autonomous-rke2`; no commit or push requested.

## Immutable artifacts

Release: `lab/artifacts/packer/release-20261016/release.json`.
Release SHA-256:
`78574de1f662cf06ff7832d5913104af07adf2e639a7fa3d4a71a87858286cd5`.
Project signing fingerprint:
`F8BE2082B8EF04D441172C055F59BDC3D0E1B573`.
Compare this fingerprint through an independently trusted channel.

| Profile | File bytes | SHA-256 |
|---|---:|---|
| OS | 1,565,589,504 | `e9da48c9a4ea6e8d8045e45ca626955d88d46de62f97698fb5758e6c4f90d1f6` |
| Server | 2,384,920,576 | `2a44fa915e549f63f112bbe1cd4990d480efaa93db7bc791276fcb2d0adc0a0f` |
| Agent | 2,384,855,040 | `6c7ebb1bd8394adf62c28108a58ba585886a39852cf460fb5d12700a325f9506` |

All images are standalone qcow2, 32 GiB virtual capacity, below the 16 GiB
file-size limit, without backing files or shared NVRAM. Pins: Rocky 9.8,
Packer 1.15.3, QEMU plugin 1.1.4, RKE2 v1.37.1+rke2r1, Flannel VXLAN.

Transfer bundle: `lab/artifacts/packer/offline-input-9.tar`.
Signed input: `lab/artifacts/packer/input-9/input.json`, SHA-256
`a62a7de3313463cd4f6ba11b5f9492c7b5387e32830a079d85f72c044eccca7e`.
The closure contains 232 vendor-signed RPMs. Rocky source verification,
HashiCorp signatures, repository provenance, and all input hashes passed.
Both role closures are retained in RKE2 variants. Matching core/Flannel
archives and the validation workload are local; no guest download is needed.
Workload:
`docker.io/library/busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e`.

## Validation

Published `validation.json` SHA-256:
`6c494dca7fe37ba7a7d2fec317689c2bc942926976ca374950b5a91f530e31e2`.
Its project signature and candidate binding passed publication checks.

- All profiles booted and rebooted with fresh metadata and NVRAM. Host,
  machine, domain, and SSH identities were unique; guest identities persisted
  across reboot. Full RPM inventories matched signed build inventories.
- Operator passwords were locked, operator SSH keys installed, cloud-init
  completed, and SELinux remained Enforcing.
- OS firewalld remained enabled/active after reload and reboot. Both RKE2
  profiles retained firewalld installed, disabled/inactive, with both RKE2
  services masked/stopped during normal deployment.
- A disposable server/agent cluster reached two Ready nodes with healthy
  system workloads, internal DNS, cross-node Pod-IP HTTP, and cross-node
  Service-IP HTTP. Checks passed again after reboot; the cluster UID remained
  `6f4516c4-64c4-4693-988f-544d8a5a135c`. CoreDNS had no external forwarding.
- No default route or host/external reachability appeared. Existing isolated
  network and IPv6 NIC filters remained effective. Test overlays, authority,
  grants, and credentials were removed; no test domains remain.

Normal profile checks used each image's sealed helper. Disposable cluster
checks used an independently delivered test runner, SHA-256
`9b78b92d9209cda3f5051da7e5cd44a9a888962d780d52b7343c035b5faeb61c`;
the signed report also records the host validator hash. Candidate image bytes
were unchanged. Signed profile checkpoints were reused for the same candidate.
The exact validated runner is retained at
`lab/artifacts/packer/validated-test-runner.py`; its bytes match the hash in the
signed validation report.

Builds ran with namespace loopback communication only. A directly inspected
earlier build QEMU PID 2079066 occupied `net:[4026533536]`, distinct from host
`net:[4026531840]`, with only `lo` and loopback routes. The same mandatory
namespace/uplink guards protected all three final builds.

Execution exposed an incomplete OpenSSH RPM pair, package-owned empty state
directories, and validation service ordering; each was corrected before final
builds. Smoke metadata needs an on-link Service-CIDR route before OUTPUT DNAT,
without adding a default route. DNS is checked separately from bounded literal
IP HTTP probes. Simultaneous reboot requires time for etcd, kubelet streaming,
and Flannel recovery; live probes retry within a deadline. Earlier failed
generations remain unpublished. No manually repaired guest supplied passing
release evidence.

Python integration suite: 67 passing tests, including the original 48,
signature corruption/wrong-signer rejection, profile/cloud-init policy,
resource reserves, archive rejection, journal recovery, rollback ownership,
and direct domain creation without storage-pool side effects.
`git diff --check` passes.

## Phase 1 replacement

The first real replacement validated all three new guests, then its protected
host comparison detected a new directory-pool definition automatically created
by `virt-install`. Automatic rollback restored all three original UUIDs and
running states, exercising real journal recovery while retaining both disk
generations. The retained rollback journal is
`/var/lib/libvirt/images/autonomous-rke2-lab/replacement-0011a2ae62ab448e/journal.json`.

The launcher now defines explicit domain XML and starts by UUID, avoiding
implicit pool creation. Ten temporary test-pool definitions and the failed
replacement's generated pool definition were removed only after checking their
absence from the saved baseline and exact generation targets/UUIDs. Files were
preserved. Cleanup audit: `lab/results/packer/owned-pool-cleanup.json`. All seven
baseline pools, including every pre-existing scratch pool, remain protected.

Replacement completed on 2026-10-17. Signed plan:
`lab/state/packer/replacement-20261017.json`. Active generation:
`/var/lib/libvirt/images/autonomous-rke2-lab/replacement-c657ffa16aa54b56`.
Its `journal.json` is `complete`, with all three nodes `validated`.

| Guest | IPv4 | Domain UUID | Host UUID |
|---|---|---|---|
| `rke2-r9-cp01` | `192.168.250.11` | `8a3c119c-4de5-4f36-8064-b84817407190` | `61785c20-9099-400b-9373-9ef64cbfc6d9` |
| `rke2-r9-cp02` | `192.168.250.12` | `127424f3-dd1c-45c3-b1e1-b9a7851ae209` | `ead4b230-8bc3-4f71-9e9a-986dd47751d9` |
| `rke2-r9-cp03` | `192.168.250.13` | `4091d49f-494c-4768-9cb5-be2588b555a2` | `4ba26a69-8077-4774-be6a-5e831fb7b84b` |

All three run the server profile, pinned to the release and server image hashes
above. Names, MACs, addresses, 4 vCPU, 8 GiB RAM, and 60 GiB virtual disks were
preserved. Each node passed boot and reboot validation: SELinux Enforcing,
locked operator password, installed operator key, distinct persistent machine
and SSH identities, firewalld installed/inactive/disabled, both RKE2 units
masked/inactive, successful cloud-init, and no cluster credentials or state.
Each has separate generation-specific NVRAM. They remain unjoined.

`effective-nodes.json` in the active generation records exact configuration and
image/release pins. Per-node `*.validation.json` records boot/reboot evidence.
`host-before.json`, `host-after.json`, and `host-differences.json` preserve host
evidence. Protected domain/network/pool/filter definitions match. Non-tap IPv4
and IPv6 routes match. Only owned lab taps changed (`vnet40`–`vnet42` to
`vnet43`–`vnet45`), with libvirt-managed filtering for those interfaces. The
existing lab network/pool/filter were reused; all seven baseline pools remain.
`hyperv1` stays shut off, `default` stays unchanged, and no test domain remains.

Final observed capacity: approximately 565 GiB free disk, 180 GiB remaining lab
disk commitment, and 385 GiB after that commitment; approximately 240 GiB
available RAM and 21 GiB remaining lab RAM commitment. The 300 GiB disk and
32 GiB RAM reserves hold. Physical storage media remain unverified.

Old domain definitions, disks, seeds, NVRAM snapshots, and both replacement
generations are retained. Explicit rollback for the active generation:

```sh
sudo -n python3 -B lab/libvirt/replace.py rollback --journal /var/lib/libvirt/images/autonomous-rke2-lab/replacement-c657ffa16aa54b56/journal.json
```

Rollback checks current UUIDs and storage ownership before changing anything;
ownership mismatch stops recovery. Production bootstrap, pod NetworkPolicy
enforcement, and RHEL validation remain deferred.
