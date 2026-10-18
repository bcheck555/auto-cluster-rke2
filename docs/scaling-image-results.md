# Scaling image validation

The `release-scaling-20261018` universal image passed disposable libvirt
formation and scaling acceptance. Every guest used the same signed candidate
disk. Validation created isolated networks and owned VM resources; existing
user clusters were not resized.

## Local artifacts

Paths relative to the repository root; generated disks, manifests, and test
inputs are ignored by Git:

| Artifact | Path |
| --- | --- |
| Signed build input | `lab/artifacts/packer/input-scaling-20261018/input.json` |
| Signed candidate | `lab/artifacts/packer/candidate-scaling-20261018/candidate.json` |
| Signed acceptance evidence | `lab/artifacts/packer/candidate-scaling-20261018/validation.json` |
| Signed release | `lab/artifacts/packer/release-scaling-20261018/release.json` |
| VM disk | `lab/artifacts/packer/release-scaling-20261018/node.qcow2` |
| Signed physical-disk export | `lab/artifacts/packer/raw-scaling-20261018/export.json` |
| Physical disk | `lab/artifacts/packer/raw-scaling-20261018/node.raw` |

The release and raw export advertise `membership-reconciliation-v1` in signed
metadata. The VM disk SHA-256 is
`d7daaa0a643c5fa406cba08b2e328ffd3d90584a3f6b20b5440433384ed8e148`.
The raw disk has a 32 GiB virtual size. Physical-hardware boot and driver
acceptance remain pending.

## Accepted behavior

Baseline acceptance covered four clones, first-node bootstrap, simultaneous
reboot, stable identities, offline DNS, and cross-node pod/service traffic.
Scaling acceptance then exercised this sequence:

| Total nodes | Control target | Verified controls | Purpose |
| --- | --- | --- | --- |
| 3 | 3 | 3 | Establish baseline |
| 5 | 5 | 5 | Grow controls |
| 7 | 7 | 7 | Grow controls |
| 8 | 7 | 7 | Add worker |
| 7 | 7 | 7 | Remove worker first |
| 5 | 5 | 5 | Shrink controls |
| 5 | 3 | 3 | Replace controls with workers |
| 5 | 5 | 5 | Replace workers with controls |
| 3 | 3 | 3 | Shrink controls |
| 2 | 3 | 2 | Allow even, below-target count with warning |
| 1 | 3 | 1 | Allow zero failure tolerance with warning |
| 3 | 3 | 3 | Regrow controls |

Each stage verified exact etcd voters, retired-member absence, stable cluster
and surviving member identities, and workload connectivity. A disruption
budget blocked retirement while preserving the VM; explicit force removal
completed the same operation. Source YAML and environment files remained
unchanged and survived destruction of the disposable cluster.

Local automated coverage includes operation ownership, lost quorum, sparse
indices, capacity preflight, interrupted retirement phases, repeated removal,
node-local storage protection, and recorded-target recovery. The publication
gate requires successful signed acceptance evidence bound to the candidate
disk; local unit tests alone cannot publish a scaling image.

A supplemental public-CLI run against the published release created four
controls with target five, verified a read-only shrink plan, and confirmed that
an unmounted retained local PV and then a disruption budget each blocked
retirement without deleting the VM. After stopping SSH and deleting only the
selected retiring node's generated seed, explicit force removal proved the
remaining majority and completed retirement without reconstructing that seed.
All three surviving identities and source inputs were preserved. Destroy then
removed the test lab while retaining its YAML and environment files. Supplemental
results are in
`lab/artifacts/packer/candidate-scaling-20261018/cli-smoke-results.json`;
these host-CLI results are separate from the signed image acceptance record.

Validation also passed 161 Python lab tests, all Go tests, Go vet and formatting,
and race tests for formation and host-agent packages. Both published manifests'
signatures and file inventories were verified after export.

## Use the release

Copy the committed [cluster template](../clusters/cluster.yaml.example), set
`release` to the release manifest above, and follow the
[lifecycle guide](lab-lifecycle.md). Existing images require one rebuild;
rolling upgrades are excluded. See [scaling](scaling.md) for reconciliation,
quorum warnings, force removal, and interrupted-operation recovery.
