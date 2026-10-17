# Implementation roadmap

Build a reproducible RKE2 host agent and membership controller that form one
authorized cluster, maintain server membership, and recover only with proven
quorum and confirmed fencing. Rocky Linux 9 is the lab platform; RHEL 9
portability remains unvalidated. The development host stays outside the cluster.

## Current baseline

- Go interfaces cover identity, discovery, bootstrap authority, operation journals,
  and fencing evidence. They are contracts, not working agent/controller daemons.
- The isolated three-VM lab and signed offline image workflow are implemented.
  See [current image and replacement results](offline-image-results.md),
  [image lifecycle](offline-images.md), and [original lab results](phase1-lab-results.md).
- Current RKE2 guests have SELinux Enforcing and RKE2 installed but masked and
  unjoined. Firewalld remains installed and disabled in RKE2 profiles; the OS
  baseline profile keeps it active.

## Remaining implementation

1. Implement durable host identity and revision-guarded operation journals.
   Verify restrictive permissions, restart stability, concurrent creation,
   corruption handling, and recovery from interrupted writes.
2. Implement authenticated discovery and bootstrap authority. Treat mDNS/DNS-SD
   as endpoint hints only; verify signed responses and persistent cluster identity.
   Single-use signed grants must persist atomically. At least three concurrent
   bootstrap requests must produce exactly one cluster identity. An unreachable
   cluster never authorizes a new one.
3. Implement the host agent and systemd service, pinned offline RKE2 configuration,
   stable registration endpoint, and deterministic role assignment. Use typed,
   allowlisted operations, redact credentials, and resume safely after interruption.
   Start with one server, then reach three voting servers and two workers only
   after capacity assessment and approval for lab expansion. Verify etcd health
   separately from Kubernetes Node Ready and permit workloads on servers.
4. Implement the membership controller, least-privilege Kubernetes manifests,
   documented etcd membership operations, and a narrowly scoped host fencing
   service. Guests receive no general libvirt or arbitrary command access.
   Recovery must prove quorum, establish failure evidence, obtain authority,
   confirm fresh fencing for the exact host, remove only the identified stale
   member, and journal the authorized worker-to-server transition through etcd
   synchronization. Ambiguity stops recovery. Reconcile returning nodes without
   duplicate identities or members; retain append-only, redacted audit evidence.
5. Implement and run the acceptance suite below on Rocky guests. Require bounded
   timeouts, explicit preconditions, before/after inventory checks, and results in
   ignored `lab/results/`. Complete two clean-room runs using tracked sources and
   approved local inputs. Expected results never count as observed passes.

## Acceptance scenarios

| ID | Scenario | Required outcome |
| --- | --- | --- |
| A | First server | Authorized cluster; healthy single-member etcd |
| B | Two additional servers | Three healthy voting members |
| C | Two workers | Ready workers; correct roles and scheduling |
| D | Concurrent bootstrap | Exactly one cluster identity |
| E | Server failure | Replacement only after confirmed fencing |
| F | Failed node returns | Reconciled identity; no duplicate etcd member |
| G | Partition without fencing | No replacement and no new cluster |
| H | Two-of-three quorum loss | Automation halts and reports quorum loss |
| I | Interrupted install, join, or promotion | Safe journaled resumption |
| J | Repeated restart | Stable identity and idempotent behavior |

Run Go unit/race tests, vet, formatting, and lab tooling tests at relevant gates.
Pin lint tooling before making it a required check. Validate profile-specific
firewalld policy and SELinux Enforcing in guest acceptance checks.

## Scope boundaries

[Architecture](architecture.md), [component contracts](component-contracts.md),
[state machine](state-machine.md), [trust model](trust-and-threat-model.md), and
[recovery runbooks](recovery-runbooks.md) retain the detailed design. Track unresolved
decisions in [open questions](open-questions.md).

Keep current signed release/input artifacts, credentials, validation evidence,
and rollback journals/disks. Failed build payloads and redundant extraction caches
may be removed after proving they are unused; do not infer VM or pool ownership
from names. Create source/deployment directories when implementations need them.

Production requires a redundant external authority and validated fencing; Redfish
remains an interface until actual BMC access is authorized. Validate RHEL 9 before
claiming support. Licensing and the final module namespace remain owner decisions.
KubeVirt, Multus, CSI, and Windows/AD workload research follows successful cluster
acceptance; installing or deploying those systems is outside the current scope.
