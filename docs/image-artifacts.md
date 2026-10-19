# Image artifacts

Use `lab/artifacts/packer/release-healing-20261018/release.json` for current VM
deployments. Configure the signed manifest, rather than an individual disk, in
cluster YAML. Its universal `node.qcow2` supports scaling and opt-in self-healing.
The same disk is used for controls and workers.

Generated artifacts are ignored by Git. A fresh checkout must build or receive
the signed artifacts and independently trusted verification files. Follow the
[Packer build workflow](offline-images.md#build-a-new-generation) to create a
new generation; see [acceptance evidence](healing-image-results.md) for the
tested local release.

## Current local generations

All paths below are relative to `lab/artifacts/packer/`.

| Directory | Contents and purpose | Needed for deployment? |
| --- | --- | --- |
| `release-healing-20261018/` | Signed `release.json` and `.sig`, `node.qcow2`, `os.qcow2`, both RPM inventory JSON files, and `validation.json` | Keep the entire directory for VM provisioning and release verification |
| `raw-healing-20261018/` | Signed `export.json` and `.sig`, copied `source-release.json` and its signature, plus `node.raw` for physical-disk imaging | Optional for VM-only use; physical boot/driver acceptance remains pending |
| `candidate-healing-20261018-v6/` | Signed `candidate.json`, duplicate OS/node disks, inventories, build logs, signed final validation and checkpoints, stage progress, preserved acceptance inputs | Build/acceptance provenance; not required by deployed VMs or release-based create |
| `input-healing-20261018-v6/` | Signed `input.json`, verified Rocky source, RPMs, RKE2/container payloads, Packer/plugin binaries, source snapshots, recipe, agent binary/unit, public vendor keys, and staging metadata | Required for an offline rebuild, not runtime |
| `retained-evidence/` | Small historical manifests/reports and preserved test YAML/`.env` files from removed generations | Historical evidence and source inputs; not a usable image bundle |

The raw image is 32 GiB logically; its allocated filesystem size can be smaller.
`os.qcow2` is the intermediate OS base, not a cluster node image. It remains in
the release because signed inventory verification checks every listed file.
Candidate disks duplicate release disks deliberately to preserve the original
signed build bundle. Do not remove individual files from a bundle you still
intend to verify, test, publish, or rebuild from.

## Supporting files outside those generations

| Repository-relative location | Purpose |
| --- | --- |
| `lab/artifacts/Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2` | Downloaded upstream source cache, not a deployment image; its checksum, detached signature, Rocky public key, and keyring accompany it |
| `lab/artifacts/rocky9-firewalld/` | Earlier local RPM repository/cache, not a bootable image |
| `lab/artifacts/packer/CLEANUP.md`, `retained-evidence/cleanup-summary.json`, `retained-evidence/release-retirement.json` | Local cleanup records and recovered-space counts; evidence archive access is restricted |
| `lab/credentials/artifact-signing/` | Private signing key and public trust files; keep protected and back up independently; never commit or include in guest images |
| `clusters/*.yaml`, `clusters/*.env` | User deployment settings and private inputs; never removed by cluster destruction or artifact cleanup |
| `/var/lib/libvirt/images/autonomous-rke2-<cluster>/` | Initialized VM disks, seeds, ownership state, operator access, kubeconfig, and operation journals; managed by cluster lifecycle scripts, not artifact cleanup |

`AUTONOMOUS_IMAGE_TRUST_DIR` can select a separate directory containing
`trust.json` and `public.gpg` for verification. Cluster private inputs and
initialized guest disks are distinct from disposable image build outputs.

## Retired releases

The older `release-scaling-20261018` and `release-universal-20261017` bundles
have been removed at the user's request, along with the superseded scaling
input generation. Historical documents retain their names and original hashes.
Compact evidence and YAML/private source inputs remain in `retained-evidence/`.

The CLI default and local dev YAML now select the healing release. Existing
initialized VM disks and saved ownership state were not rewritten or upgraded.
A cluster created from an older image needs a destroy/rebuild to adopt the new
release; rerunning create against a different release is rejected. Back up
application data first, then follow [destroy and rebuild](lab-lifecycle.md#destroy-and-rebuild-a-cluster).
Do not edit saved release hashes or relabel an existing disk as the new image.
