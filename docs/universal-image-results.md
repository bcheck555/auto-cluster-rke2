# Universal image validation

This records the original image, whose release and disk exports have been
removed locally. For the current release with resizing and self-healing, see
[control-recovery image validation](healing-image-results.md). Paths below are
historical; compact evidence remains under `lab/artifacts/packer/retained-evidence/`.
Existing clusters created from this original image require one rebuild to
enable resizing and self-healing.

The universal node image passed clean libvirt acceptance and was published
locally as `release-universal-20261017`. All four guests cloned the same sealed
disk. No guest binaries, runtime configuration, or membership records were
patched during this acceptance run.

## Artifacts

Paths relative to the repository root:

- VM disk: `lab/artifacts/packer/release-universal-20261017/node.qcow2`
- Signed release: `lab/artifacts/packer/release-universal-20261017/release.json`
- Signed acceptance: `lab/artifacts/packer/candidate-universal-20261017-v7/validation.json`
- Physical-host disk: `lab/artifacts/packer/raw-universal-20261017/node.raw`
- Signed raw provenance: `lab/artifacts/packer/raw-universal-20261017/export.json`

Both disk formats have a 32-GiB logical size. QCOW2 is standalone with no backing
file. Raw export passed geometry checks and `qemu-img compare` against the
validated QCOW2. Export provenance includes the source release and its signature.

| Disk | SHA-256 |
| --- | --- |
| `node.qcow2` | `744ab90231472952d656c796f64cce91d7ae0994bf82cf3d59c187e91c86174f` |
| `node.raw` | `525cb6d8077dac74428b0c78316748681804f7e1a8c9458917a94927f7b4ddd7` |

## Acceptance evidence

The OS base and unjoined node profile each passed boot/reboot checks, including
sealed cluster state, unique machine/SSH identities, pinned RPM inventories,
SELinux Enforcing, and expected firewall policy.

Formation supplied only a common ephemeral enrollment secret plus the test
observer. It supplied no roles, cluster UUID, native tokens, grants, or server
addresses. The first clone bootstrapped alone; later clones discovered it and
were admitted automatically.

| Clone | Uplink | Automatic role | Voters after reboot | Identity checks |
| --- | --- | --- | --- | --- |
| 1 | `rke2test0` | Server | 3 | Stable |
| 2 | `rke2test1` | Server | 3 | Stable |
| 3 | `rke2test2` | Server | 3 | Stable |
| 4 | `rke2test3` | Worker | Not an etcd member | Stable |

All four rebooted together. Cluster UUID, host identity, Kubernetes Node UID,
and each server's etcd cluster/member identities remained unchanged. All
servers observed the same etcd cluster with three voters. Native service
readiness was required before accepting Kubernetes health.

After reboot, all four nodes and system pods became Ready. Real workload
probes passed Kubernetes/service DNS, worker-to-server service traffic, and
direct cross-node pod traffic. CoreDNS had no external forwarding. The test
seed did not inject the service-CIDR route; the node service established it.

Validation used isolated disposable guests and bounded temporary storage.
All disposable VMs and temporary mounts were removed. Existing
`rke2-r9-cp01`, `rke2-r9-cp02`, and `rke2-r9-cp03` remained running and unchanged.

Additional checks passed: full Go race suite, `go vet`, 74 Python lab tests,
build/format checks, and systemd unit verification.

## Provenance

Pins: Rocky Linux 9.8, RKE2 `v1.37.1+rke2r1`, Flannel VXLAN, Packer 1.15.3,
QEMU plugin 1.1.4. Acceptance used QEMU 8.2.2 and libvirt/virsh 10.0.0.

| Manifest | SHA-256 |
| --- | --- |
| `input-universal-20261017-v7/input.json` | `7c71d3fb0d7652b2829232310170f5dfdf34a94bd61a9982e1b3431fa9552eb1` |
| `candidate-universal-20261017-v7/candidate.json` | `981caac64f16749a9e498a9d625ec9afbc1047fe1d62c82477f6ea02a6be78b8` |
| Candidate `validation.json` | `1a3acacaa1bf3167f83ea01dded3c962b381856176dda5b5871d711d3abcd582` |
| Published `release.json` | `52b758837e7cae6e693bf431638c9befa85676d5adcf7e0ca667e97a5050ae53` |
| Raw `export.json` | `d035a46036b7acc521dd184aa3b438dfbd4e331ca8f09bab7c157706fb3a24db` |

Use the pinned artifact-signing trust configuration to verify signatures;
these hashes alone do not establish trust. The signed input contains the
compiled agent and its public Go source snapshot.

Physical hardware boot, drivers, and storage remain untested. Raw conversion
does not establish bare-metal acceptance. See [deployment assumptions and
instructions](universal-node.md) before booting a deployment. Automatic member
replacement, promotion, quorum reset, and destructive recovery remain excluded.
