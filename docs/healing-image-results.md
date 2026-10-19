# Control-recovery image validation

The `release-healing-20261018` universal image passed all publication gates and
was published locally with a signed raw disk export. Existing user clusters were
not rebuilt, resized, or used for failure injection. Physical-hardware boot and
driver acceptance remain pending.

## Candidate and local checks

Generated artifacts remain ignored by Git:

| Artifact | Repository-relative path |
| --- | --- |
| Signed input | `lab/artifacts/packer/input-healing-20261018-v6/input.json` |
| Signed candidate | `lab/artifacts/packer/candidate-healing-20261018-v6/candidate.json` |
| Acceptance output | `lab/artifacts/packer/candidate-healing-20261018-v6/validation.json` |
| Signed release | `lab/artifacts/packer/release-healing-20261018/release.json` |
| VM disk | `lab/artifacts/packer/release-healing-20261018/node.qcow2` |
| Signed raw export | `lab/artifacts/packer/raw-healing-20261018/export.json` |
| Physical disk image | `lab/artifacts/packer/raw-healing-20261018/node.raw` |

The signed candidate advertises `membership-reconciliation-v1` and
`control-self-healing-v1`. Node disk SHA-256:
`7218672a9e66111ad5038dc3129260268022f93375868145ea6e359d75729d53`.
Input manifest SHA-256:
`3ceea4df8e75194b8d212e4d80b07a81faacf8f6cabedd3afb108734ced0a855`.
Previous exploratory candidates cannot authorize this release.

The raw image has a 32 GiB virtual size. Export verified geometry and byte
equivalence with the published VM image before signing. Raw disk SHA-256:
`0d72f9e79e4ed872fe2c6117ae1d7dea796de198b8748525a12fa0ac594a17e6`.
Release, export, and final validation signatures were verified against the
configured trusted signing key.

Local checks passed: `go test ./...`, `go vet ./...`, race tests for formation
and hostagent packages, and 169 Python integration tests. Documentation relative
file links and `git diff --check` passed.

## Acceptance gates

Publication requires signed evidence for boot/reboot, formation, manual scaling,
and automatic recovery using the exact candidate disk. Healing acceptance uses
five disposable VMs: three controls and two workers. Required scenarios include
short shutdown, protected drain blockers, promotion, worker return, repeated
failure, controller failover, partition/reconnect, lost quorum, and simultaneous
reboot. Checks include exact voters, retired-member absence, stable physical
identity/name/address/subnet, local-data preservation, workload connectivity,
and unchanged source YAML/private inputs.

Earlier exploratory runs verified protected drain blockers and completed a
promotion/worker return, but did not pass all gates. An acceptance fixture wrote
its sentinel without syncing it before abrupt VM power loss. Read-back succeeded
from cache; the powered-off node later had an empty sentinel before healing.
The corrected fixture syncs file and directory metadata before failure injection.
Its next run passed one complete promotion/worker-return cycle, preserving all
five physical identities, pod subnets, and local-data sentinels. Controller
failover then exposed a probe-peer bug: a restricted control remained Node Ready
but no longer sent agent heartbeats, and its diagnostic pod cleanup stalled.
The new candidate requires advancing authenticated heartbeats for probe peers
and uses label/UID-checked cleanup of its disposable resources. Regression tests
cover stopped-but-Ready controls, expired heartbeats, stale Node UIDs, foreign
resources, finalizers, and cleanup retries. Exploratory evidence cannot authorize
publication.

The exploratory v5 candidate passed controller failover and repeated promotion with
preserved identities and data. A live partition/reconnect then exposed an
orphaned native API container after service shutdown: its listener blocked the
returning worker's local load balancer. The current candidate adds scoped OCI
container cleanup with exact native identity checks. Unit coverage verifies
that recovery retains etcd voters, retirement stops obsolete control containers,
application containers/data survive, and interrupted stops resume safely.

## Verified healing behavior

The corrected v6 candidate passed all healing gates on the disposable
`accept-heal-13b880f1c1` cluster. All five VMs used the same signed node image.

| Failed node | Promoted worker | Completed transition |
| --- | --- | --- |
| 03 | 04 | Protected drains blocked until budgets were removed; control returned as worker |
| 02 | 03 | Another controller resumed the recorded operation after the active agent stopped |
| 04 | 02 | Partitioned control returned as worker with its native control port closed |

Each operation recorded verified cross-node connectivity. Exact voter counts,
retired-member absence, stable physical identities/names/addresses/pod subnets,
and preserved local-data sentinels passed after every cycle. Lost quorum blocked
writable management; restoring original voters produced no replacement. A
simultaneous reboot preserved role generations, Node UIDs, and etcd IDs. Final
DNS/pod/service checks and unchanged source YAML/private-input checks passed.

Signed final evidence is recorded in
`lab/artifacts/packer/candidate-healing-20261018-v6/validation.json`.
The disposable cluster's owned VM resources were removed; its source inputs
remain preserved outside the generated pool.

## Baseline and manual scaling

OS and universal-node boot/reboot checks passed. Four-clone formation verified
three voters plus a worker, stable identities through reboot, offline DNS, and
cross-node pod/service traffic.

Manual scaling passed growth through 3/5/7 controls, addition of a worker at
seven controls, worker-first shrinkage, and five-node role replacements in both
directions between control targets three and five. Reduction through three,
two, and one control produced the expected warnings and preserved surviving
identities. Regrowth to three controls passed. A disruption budget preserved its
blocked worker VM; explicit force removal passed; missing initialized disk
protection passed. Source inputs remained unchanged.
