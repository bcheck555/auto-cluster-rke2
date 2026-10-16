# Recovery runbooks (design only; not yet executable)

## Replace one failed RKE2 server

1. Confirm the intended cluster UUID and read exact etcd membership from a healthy API/etcd view.
2. Confirm surviving voting members retain quorum (3-member cluster requires 2; 5-member cluster requires 3). If unavailable or ambiguous, STOP; do not attempt automatic quorum reset.
3. Gather failure duration and independent reachability evidence. A partition is not proof of power failure.
4. Request fencing through the authenticated, narrowly scoped fencing authority. Continue only after the backend confirms the exact VM/host identity is powered off and records evidence.
5. Re-read etcd membership and map the fenced host to one exact member ID. If mapping is ambiguous or membership changed, STOP.
6. Remove only that stale member using the currently documented RKE2-supported procedure and a tested command path. Do not remove data files.
7. Select one eligible healthy worker under policy. Drain when API is available and safe; stop agent, preserve identity, stage server configuration, and start server using authorized credentials.
8. Wait for new etcd member to synchronize and become healthy; verify total voting count equals desired count and ensure no duplicate node/member identity.
9. Append evidence and outcome to the audit log. Leave the fenced old host off pending return-node reconciliation.

## Lost quorum

Halt all automatic membership changes. Do not elect a new cluster, delete etcd state, or invoke a quorum-reset tool. Preserve data and evidence; require the documented, version-specific human recovery procedure.

## Network partition without fencing

Do not remove membership or promote a replacement. Keep existing cluster state; report suspected failure and await recovery or confirmed fencing.

## Returning node

Quarantine automatic server startup until identity, cluster UUID, and current etcd membership are checked. If old member was removed, use a validated rejoin/reinstall path only after authoritative approval. Preserve old state until procedure proves it safe to change.

> Commands are intentionally omitted until official version-specific RKE2/etcd procedures are validated on Rocky Linux 9.
