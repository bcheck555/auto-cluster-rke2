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
| Healthy | Recorded Node/etcd identities and completed membership | Restart same role/data on reboot; verify identity and health |

Discovery runs alongside convergence. Selecting a cluster immediately makes
it visible as pending; pending is never enrollment readiness. An existing
selection always prevents fresh bootstrap even when discovery is empty.

The first healthy server creates an immutable cluster marker and initializes
the replicated membership ledger. Joiners reserve one role and later complete
that reservation only after independently observed Node readiness and, for
servers, voting etcd membership. Server reservations include the bootstrap
member in the three-server limit. Only one initial member may be pending.

Crash boundaries are resumable: credential files may precede their journal
revision; a start may succeed before its caller returns; an enrollment response
may be lost after CAS. Retrying uses the original identity and reservation.
No time-based reservation expiry, role reassignment, or alternate bootstrap
is allowed. The responding server's native registration origin is journaled
with credentials and remains fixed across restarts. RKE2 maintains its native
client load balancer; saved public server endpoints also feed the API health proxy.

Missing data after Healthy, changed credential digests, changed host/interface/
address/deployment/runtime policy, or changed Node/etcd IDs require
reconciliation. Same-data native restarts are allowed. Failed health or missing
quorum withdraws enrollment readiness. The agent never deletes data, resets
quorum, removes members, promotes workers, or invokes fencing.
