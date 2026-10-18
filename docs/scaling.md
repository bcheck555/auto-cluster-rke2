# Resize a cluster and change its control-node target

Rerunning create reconciles total nodes and the control/worker mix for a signed
image advertising `membership-reconciliation-v1`. This is an operator action on
the local libvirt host; no persistent external management server is introduced.

## Before you begin

- Older images hardcode three controls and lack retirement support. Rebuild once
  with a scaling-capable release using [lab lifecycle](lab-lifecycle.md).
  This feature does not upgrade running agents or change releases in place.
- Back up applications and node-local data. Removal/replacement deletes the
  selected node's writable disk and generated credentials.
- Keep the release, network, enrollment secret, hostname prefix, and VM resources
  unchanged. Those changes still require recreation.
- Reserve capacity for one temporary extra VM during role replacement. Address
  space, catalog capacity, RAM, and full disk reservations must fit the peak.
- Ensure an existing etcd majority is available. A warning about a small topology
  does not permit writes to a cluster that has already lost quorum.

## Change size or roles

1. Edit `nodes` in your cluster YAML to the desired positive total. Set
   `control_nodes` to `3`, `5`, or `7` (default `3`). For example, total seven
   with target five means five controls and two workers. Total two with target
   three means two controls and no workers.
2. From the checkout root, inspect the proposed changes:

   ```bash
   sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --plan
   ```

   Plan reads the protected state and live catalog, Kubernetes identities, and
   etcd membership. It reports additions, retirements, replacements, warnings,
   and peak capacity without changing the cluster. Run as root to access the
   generated operator key. VM names use the configured prefix; Kubernetes names
   use durable `rke2-<identity>` names and can differ from VM names.
3. Reconcile:

   ```bash
   sudo python3 lab/libvirt/create.py --config clusters/dev.yaml
   ```

4. Verify `Ready` nodes, their roles, and application health:

   ```bash
   sudo kubectl --kubeconfig /var/lib/libvirt/images/autonomous-rke2-dev/admin.yaml get nodes -o wide
   ```

   Substitute the generated directory for your cluster. Create verifies the
   final membership and refreshes kubeconfig to a surviving server. Source YAML
   and `.env` are never overwritten or deleted.

## Selection and quorum rules

- Actual controls are `min(nodes, control_nodes)`; other nodes are workers.
- Growth fills missing controls first, then workers. Shrinkage removes excess
  workers first, then excess controls. Highest index is selected within a role.
- A changed control target reconciles roles even at an unchanged total. A fresh
  node joins and becomes healthy before its counterpart is retired. Initialized
  nodes never change roles in place.
- Surviving names, IPs, disks, and identities remain unchanged. Removed indices
  can be reused for fresh identities after owned storage and SSH records are cleaned.
- All membership changes are serialized. A three/five/seven target does not
  guarantee failure tolerance when fewer total nodes exist.

| Actual controls | Majority required | Server failures tolerated |
| --- | --- | --- |
| 1 | 1 | 0 |
| 2 | 2 | 0 |
| 3 | 2 | 1 |
| 4 | 3 | 1 |
| 5 | 3 | 2 |
| 6 | 4 | 2 |
| 7 | 4 | 3 |

Create warns for a below-target, even, or zero-failure-tolerance control count
and still permits the desired topology. Existing lost quorum stops changes.
Etcd changes require a live majority and run sequentially; see
[etcd runtime reconfiguration](https://etcd.io/docs/v3.6/op-guide/runtime-configuration/).

## Interrupted or blocked changes

Rerun the same create command after resolving its reported blocker. The journal
retains operation ID, target, selected identities, and completed phases. If YAML
changed again, create first finishes the interrupted target, then reconciles the
latest values. Do not delete state files or membership records to skip a phase.
Missing disks, NVRAM, or seeds are never reconstructed for initialized nodes.
A known node selected for retirement can proceed through retirement instead;
unavailable guests still require the explicit force path and a safe majority.

Drains respect disruption budgets and protect unmanaged pods and local ephemeral
data by default. Application hostPath, local PVs, and hostname-bound PVs also stop
retirement until data is migrated or removal explicitly overridden. After
reviewing the plan and accepting workload disruption/data
loss, an explicit override is available:

```bash
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --force-remove
```

This overrides drain protections, including disruption budgets and emptyDir data,
and deletes pods with zero grace time. It never bypasses ownership, identity, or
quorum checks. If a control guest cannot be reached for restart fencing, force
may power it off only after independent health checks prove that a current
majority remains without it. Otherwise restore guest access or quorum first.
Drain behavior follows
[Kubernetes node drain guidance](https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/).

Retirement records intent, drains, fences restart, removes membership, and
deletes owned VM resources. Controls retain their current vote until etcd
commits removal, then power off. Powering off a voter first would make two-to-one
shrinkage impossible. Workers power off before membership finalization. Retirement
tombstones reject subsequent enrollment by a retired identity; local retirement
markers prevent the node agent restarting its old role.

## Related information

- [Configuration reference](cluster-config.md)
- [Lab lifecycle](lab-lifecycle.md)
- [Troubleshooting](troubleshooting.md)
