# Automatic control recovery

Enable self-healing when a cluster should restore control redundancy using its
existing workers. It runs on the nodes and requires no management server or
hypervisor credentials. It does not provision machines or recover lost quorum.

## Configure recovery

Use an image advertising the signed `control-self-healing-v1` capability. Older
images require one rebuild; enabling this setting does not upgrade a running
image. Set `self_healing.enabled: true` in your cluster YAML and rerun create
using the [lifecycle guide](lab-lifecycle.md). Create publishes the mutable
policy into the cluster; editing YAML alone does not change running behavior.

`self_healing.failure_timeout` defaults to `5m`. Supported values are positive
integer durations ending in `s`, `m`, or `h`, between `1m` and `24h`.
Self-healing defaults to disabled. See the commented
[cluster template](../clusters/cluster.yaml.example).

Reserve spare workers. Four nodes with control target three provide one spare;
four nodes with target five provide none. Controls and workers remain eligible
to run workloads according to normal Kubernetes scheduling rules.

For deployments outside libvirt, publish the policy once from a healthy control.
This example uses four total nodes and retains the existing control target:

```bash
printf '%s\n' '{"action":"policy","nodes":4,"self_healing":{"enabled":true,"failure_timeout":"5m"}}' \
  | sudo /usr/local/libexec/autonomous-rke2/host-agent -manage
```

Use the intended total for `nodes`. The root-only command reads bounded JSON on
stdin, verifies writable cluster authority, and returns public membership status.
Node agents continue recovery independently after this operator command exits.

## What triggers replacement

Controls check recovery every ten seconds. Replacement requires all three
signals continuously for the configured timeout:

- Missing authenticated healthy-agent heartbeats.
- Kubernetes reports the control as NotReady/Unknown, or its recorded Node is absent.
- The corresponding etcd endpoint fails verification.

A healthy datastore member is not replaced merely because its API or node agent
is unavailable. Verified recovery resets the timer. A new controller starts a
fresh uncommitted observation window; committed operations resume their journal.

An existing writable majority must remain. Losing two of three controls cannot
be repaired through ordinary membership changes. Restore existing voters first;
never delete journals or reset the cluster to bypass this condition.

## Worker selection and promotion

Recovery selects the lowest-index healthy worker with compatible image policy,
available resources, and no conflicting operation. Resource eligibility requires
at least two CPUs, a nominal 4 GiB installed memory (3 GiB visible to Linux), and 8 GiB free runtime
disk space. A protected drain must succeed before failed-voter removal starts.

Disruption budgets, unmanaged pods, emptyDir data, application hostPath, and
node-local or hostname-bound PVs can block a candidate. Recovery tries another
worker, then reports a blocker and retries later. It never forces workload
eviction or deletes application data. Resolve the workload or storage blocker
instead of expecting an automatic override.

After draining, recovery rechecks the failed control, removes its exact etcd
membership, and verifies removal before admitting a replacement. The worker
acknowledges that its native services are stopped before its old Node identity
is retired. It then enrolls as a control with a fresh membership generation,
Node UID, and etcd ID. Its VM, disk, address, Kubernetes name, pod subnet, and
physical signer remain stable. The prior subnet is reserved before new join
credentials are issued, preserving CNI state and hostname affinity.

Recovery completes only after the replacement is healthy, voter membership is
exact, and a disposable cross-node DNS/service probe succeeds. Its peer must
also have advancing authenticated agent heartbeats; Node Ready alone cannot
establish that an agent is active. Probe resources use an operation-owned
namespace, carry ownership labels, and mount no service-account token. Cleanup
checks exact resource UIDs and stops on unexpected finalizers. A failed probe
leaves recovery pending.

## Returning controls and reboot

A replaced control does not reclaim its former role. Its agent checks the
cluster's current role authorization and re-enrolls it as a worker under the next
generation. The promoted replacement remains a control; no other node is demoted.
Earlier membership generations remain retired.

Stopping an RKE2 service can leave its container shims running. Before role
transition, the agent verifies and stops only native control containers using
their OCI identity, static-pod metadata, and physical node name. Recovery keeps
existing datastore voters running. Application containers and data are excluded
from this cleanup; uncertain identity blocks the transition.

Obsolete native control state and credentials are quarantined in root-only
`.autonomous-role-history/generation-N` directories beside their original
locations. Containerd state, image caches, and application storage remain in
place. Quarantine is retained for inspection; do not copy it back into active
paths to restore an old role. Unsafe or incomplete cleanup blocks re-enrollment.

Known controls initially start with a local-only recovery API, disabled
scheduler/controllers, and kubelet registration disabled. Existing datastore voters can restore quorum during a
simultaneous reboot. Full control endpoints start only after live authorization
matches the saved physical identity and membership generation. No authority
means restricted recovery, never a new cluster.

During operation, controls renew authorization against the writable cluster.
After sixty seconds without verification, the agent withdraws full control
services into restricted recovery while retaining datastore recovery capability.
Systemd also invokes this restriction when the agent stops unexpectedly.

## Observe and resume

Run create with `--plan` to inspect a healing operation and its blockers. Node
agents own healing journals and finish recorded membership work before manual
scaling may proceed. A repeated create adopts verified role-generation changes
instead of reverting promotions. An offline retired host is reported as pending
return; restore its existing artifacts and access before completing reconciliation.

Disabling self-healing stops new operations. Once membership changes have been
committed, recovery finishes safely. Returning-node role checks remain active
regardless of whether further automatic recovery is enabled.

Source YAML and `.env` files are never rewritten or deleted by recovery. Missing
initialized boot disks are not reconstructed. See [scaling](scaling.md) and
[troubleshooting](troubleshooting.md) for related lifecycle safeguards.
