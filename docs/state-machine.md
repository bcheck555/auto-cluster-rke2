# Host and membership state-machine contract

This file defines required behavior before daemon implementation. All transitions must be persisted atomically with a monotonically increasing operation revision and stable operation ID; restart resumes by inspecting real system state, never by replaying destructive commands blindly.

## Host-agent states

`Uninitialized -> IdentityReady -> AwaitingAuthority -> BootstrapAuthorized | JoinAuthorized -> Installing -> Configured -> Starting -> Healthy`

- `Uninitialized -> IdentityReady`: generate one persistent host key/identity and unique machine identity; concurrent invocations converge on the same atomic record.
- `IdentityReady -> AwaitingAuthority`: discover endpoint hints, then authenticate authority. No hint, timeout, or unreachable cluster is not authorization to bootstrap.
- `AwaitingAuthority -> BootstrapAuthorized`: accept a valid, unexpired, single-use grant bound to host identity, requested cluster UUID, policy revision, and operation ID.
- `AwaitingAuthority -> JoinAuthorized`: verify signed cluster identity and receive role-scoped join authorization.
- `* -> Interrupted`: record failure/reboot without erasing progress; on restart, inspect package, config, systemd, local RKE2 data, API identity, and membership before resuming.
- `Healthy -> ReconcileRequired`: observed cluster UUID or membership differs; freeze role-changing/destructive work pending authority decision.

## Membership operation states

`Observed -> SuspectedFailure -> QuorumVerified -> ReplacementAuthorized -> FenceRequested -> FenceConfirmed -> MemberRemovalAuthorized -> OldMemberRemoved -> CandidatePrepared -> ServerJoining -> EtcdSynced -> Healthy -> Audited`

At every transition persist evidence (timestamps, observations, cluster UUID, member IDs, actor/grant ID, and result). `FenceConfirmed` requires authenticated evidence of power-off from the fencing backend; timeout or network isolation is not equivalent. Any quorum ambiguity, unavailable control plane, cluster identity mismatch, or failed fence transitions to `HaltedNeedsOperator`. No data directory cleanup is a transition in the initial design.

## Returning old node

A recovered host authenticates with its persistent identity and reports its old cluster UUID/member identity. If the member was removed/replaced, it must not start as an independent server from stale state. Controller/authority select a documented reconciliation path; ambiguous local etcd state halts for operator intervention. Never create a second etcd member based only on hostname.

## Invariants

1. At most one bootstrap grant for a given cluster-authority epoch is consumed.
2. No automatic cluster creation because discovery/API fails.
3. No destructive membership action without verified quorum and positive fence confirmation.
4. Never alter/delete etcd data as a generic retry.
5. Every transition is idempotent, auditable, and resumes from inspected state.
6. Desired count is policy, not permission to bypass quorum/fencing.
