# Node formation states

Every node uses one local `formation` operation. Its cluster, host identity,
deployment fingerprint and runtime policy remain fixed across revisions.

| State | Durable meaning | Allowed next action |
| --- | --- | --- |
| Discovering | No cluster selected; no runtime data allowed | Probe authenticated peers; wait for pending cluster or startup grace |
| Selected | Cluster UUID and bootstrap/join intent persisted | Resume same intent; generate or request credentials |
| Credentialed | Fixed role and private credentials established | Validate image and prepare exact pinned configuration |
| Configured | Configuration and credential digest persisted | Persist Starting before native service start |
| Starting | Native start may already have happened | Resume service; observe real Kubernetes and etcd readiness |
| Healthy | Recorded Node/etcd identities and completed membership | Validate live role generation; restore authorized role or resume a recorded transition |

Discovery runs alongside convergence. Selecting a cluster immediately makes
it visible as pending; pending is never enrollment readiness. An existing
selection always prevents fresh bootstrap even when discovery is empty.

The first healthy server creates an immutable cluster marker and initializes
the replicated membership ledger. Joiners reserve one role and later complete
that reservation only after independently observed Node readiness and, for
servers, voting etcd membership. Server reservations include the bootstrap
member in the revision-controlled control target. Only one initial member may
be pending. Scaling and healing serialize membership changes through the same
catalog operation record.

Crash boundaries are resumable: credential files may precede their journal
revision; a start may succeed before its caller returns; an enrollment response
may be lost after CAS. Retrying uses the original identity and reservation.
No time-based reservation expiry or alternate bootstrap is allowed. A role
change requires a quorum-authorized next generation and fresh membership
identity; cached local state cannot authorize it. The responding server's native registration origin is journaled
with credentials and remains fixed across restarts. RKE2 maintains its native
client load balancer; saved public server endpoints also feed the API health proxy.

Missing data after Healthy, changed credential digests, changed host/interface/
address/deployment/runtime policy, or changed Node/etcd IDs require
reconciliation. Same-data native restarts are allowed. Failed health or missing
quorum withdraws enrollment readiness. The agent never resets quorum or bootstraps
from initialized data. Opt-in [control recovery](self-healing.md) can retire a
failed voter and promote an eligible worker while an existing majority remains.

## Healing and return transitions

The cluster operation advances through `select`, `drain`, `retire`, `promote`, and
`verify`. Blocked candidates retain diagnostic evidence; recovery tries another
candidate or waits in `blocked`. Before retirement commitment, verified recovery
or disabling healing cancels the operation and uncordons its candidate. After
commitment, another controller resumes the exact recorded identities and phases.

Promotion records the failed incarnation's tombstone, grants its physical host
a worker generation, and waits for the candidate's native stop acknowledgement.
The old worker incarnation is retired before a fresh control generation joins.
Completion requires exact voting membership, readiness, and cross-node workload
connectivity. Generation history remains available for CLI ownership adoption.

Locally, role-transition intent precedes quarantine. The new generation starts
at `Selected` in join mode and proceeds through the same enrollment states.
The physical identity, VM, address, disk, Kubernetes name, and pod subnet survive;
Node UID and role-specific credentials are fresh. Retired incarnations remain
rejected.

On boot, existing controls start in restricted recovery with their current
datastore and a local-only API. Full endpoints and controllers require live
authorization. Runtime authorization expiry withdraws them after sixty seconds.
An unreachable authority leaves recovery restricted; it never permits guessing
a role or forming another cluster.
