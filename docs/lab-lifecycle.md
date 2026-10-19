# Create and manage a libvirt cluster

Use these procedures to deploy a signed universal image on the local KVM host,
resume it, or delete generated resources. Commands target `qemu:///system`.
No guest Internet connection is required during deployment.

## Before you begin

- Use a Linux amd64 KVM host with working system libvirt and permission to run
  the scripts as root. These scripts do not install the hypervisor.
- Provide Python 3 and [lab/requirements.txt](../lab/requirements.txt) in the
  interpreter used by `sudo`. YAML mode requires PyYAML 6.x.
- Provide `virsh`, `ip`, `qemu-img`, `qemu-system-x86_64`, `genisoimage`, `ssh`,
  `ssh-keygen`, and `gpgv`.
- Provide `/usr/share/OVMF/OVMF_CODE_4M.fd` and
  `/usr/share/OVMF/OVMF_VARS_4M.fd`.
- Have a published signed universal release, its referenced artifacts, and the
  repository's artifact trust files. The template points to the locally built
  `lab/artifacts/packer/release-scaling-20261018/release.json`; a fresh checkout
  does not include ignored artifacts. See the [image workflow](offline-images.md)
  if they are missing. Do not create an unsigned replacement manifest.
- Reserve an unused private IPv4 subnet outside pod CIDR `10.42.0.0/16` and
  service CIDR `10.43.0.0/16`. The owned network is isolated, without external
  forwarding. Multicast must work between its nodes.
- Allow host capacity. Defaults per VM: 4 vCPUs, 8192 MiB RAM, standalone
  60 GiB virtual disk. Checks reserve new disks at full size, RAM for stopped/new
  VMs, and another 8 GiB each of host disk and RAM.

Use a normal SSH shell. If an old pasted runbook enabled `set -e` or `set -u`,
reconnect first. The scripts do not change shell options.

## Create a cluster

1. Enter the checkout and copy the public template without replacing an existing
   config. Adjust the checkout path if needed:

   ```bash
   cd /home/checkb/repos/github/auto-cluster-rke2
   cp -n clusters/cluster.yaml.example clusters/dev.yaml
   ```

2. Edit `clusters/dev.yaml`. The template selects `dev`, `dev-node`,
   `dev-private`, and `192.168.100.0/24`. Choose values appropriate to your host.
   For another cluster, use a different filename, cluster name, hostname prefix,
   network name, and nonoverlapping subnet. Keep configs together. See the
   [configuration reference](cluster-config.md) for field limits.

3. Preview the deployment:

   ```bash
   sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --plan
   ```

   Resolve reported configuration, naming, or network conflicts. Plan creates no
   secrets or VMs and needs no `.env`. Actual create performs additional release
   and capacity checks; a successful plan is not image acceptance.

4. Initialize the missing private file once:

   ```bash
   sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --init-secrets
   ```

   This creates `clusters/dev.env`, root-owned mode `0600`, without creating VMs.
   Existing files are refused. When adopting a saved deployment, it reuses that
   deployment's key. Existing private files need no initialization. See the
   [private-input template](../clusters/cluster.env.example) for manual setup.

5. Create the cluster:

   ```bash
   sudo python3 lab/libvirt/create.py --config clusters/dev.yaml
   ```

   Create verifies the signed release, prepares unique disks and local seeds,
   boots the first new node alone, checks health, then starts additional nodes
   sequentially. Controls fill `control_nodes` (default three); others become workers.
   Names remain independent of roles.

### Verify the result

Successful create prints node/pod status and saves a kubeconfig. With a host
`kubectl` installed, inspect the example cluster:

```bash
sudo kubectl --kubeconfig /var/lib/libvirt/images/autonomous-rke2-dev/admin.yaml get nodes -o wide
```

Expect the configured number of `Ready` Kubernetes nodes. VM names are
`dev-node01`, `dev-node02`, and so on; Kubernetes names use durable host identities.
At the default control target, one node means one server; three nodes means three servers; four nodes
adds one worker. Servers can run workloads.

Inspect the example's first node with its generated operator key:

```bash
sudo ssh -i /var/lib/libvirt/images/autonomous-rke2-dev/operator \
  -o UserKnownHostsFile=/var/lib/libvirt/images/autonomous-rke2-dev/known_hosts \
  rke2lab@192.168.100.11 \
  'sudo journalctl -u autonomous-rke2-host-agent.service -n 100 --no-pager'
```

For another cluster, substitute its generated directory and node IP. Protect
the operator key, kubeconfig, and saved state as credentials.

## Resume after interruption or host reboot

Fix the reported problem, then rerun the same create command:

```bash
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml
```

Create preserves disks, identities, and secrets. Previously booted nodes start
before health waits so an existing etcd quorum can recover. VM autostart is
disabled. First-node-alone applies to new formation; restarting an existing
three-server cluster requires its existing voters.

Changing release, VM resources, or network requires destroy/create. For a
scaling-capable release, editing `nodes` or `control_nodes` and rerunning create
performs [resumable reconciliation](scaling.md). Older images need one rebuild.
Missing initialized disk,
NVRAM, or seed files stop resume rather than generating replacement identities.
See [troubleshooting](troubleshooting.md).

## Enable automatic control recovery

Use a release advertising `control-self-healing-v1`. Add this to your cluster
YAML, then publish the policy through create:

```yaml
self_healing:
  enabled: true
  failure_timeout: 5m
```

```bash
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --plan
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml
```

Keep spare workers: four nodes with `control_nodes: 3` provide one candidate.
Without a spare, recovery reports degraded capacity. Existing writable quorum
and a protected drain are required. Recovery never creates a VM or forces an
eviction. Older images require one rebuild before enabling this policy.

The plan shows pending healing phases, blockers, and retired hosts awaiting
return. Restore a returning host's existing disk; its agent joins as a worker.
Create adopts verified role generations and leaves promoted controls in place.
An active operation finishes before manual scaling proceeds. Disabling healing
prevents new operations; committed membership work still finishes.
See [automatic control recovery](self-healing.md) for detection and startup rules.

## Destroy and rebuild a cluster

**Destructive operation:** destroy removes workloads and all owned generated
disks, NVRAM, seeds, operator keys, kubeconfig, runtime state, and runtime copies
of secrets. It removes owned VM, pool, network, filter, and leftover bridge
resources, including partial deployments and old generated disk copies.
Back up application data before proceeding.

1. Review resources selected for deletion:

   ```bash
   sudo python3 lab/libvirt/destroy.py --config clusters/dev.yaml --plan
   ```

2. Delete them with explicit cluster-name confirmation:

   ```bash
   sudo python3 lab/libvirt/destroy.py --config clusters/dev.yaml --confirm-cluster dev
   ```

   Destroy never overwrites or deletes source YAML or `.env`. It needs no valid
   or readable `.env`. Saved ownership is used when YAML already describes
   replacement settings. Repeated destroy can finish interrupted cleanup.
   Unknown consumers or source files inside generated directories stop cleanup;
   resolve the reported conflict instead of deleting broadly.

3. Review the preserved config. Change replacement settings if needed, then run:

   ```bash
   sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --plan
   sudo python3 lab/libvirt/create.py --config clusters/dev.yaml
   ```

   The preserved `.env` supplies the same enrollment secret. Do not initialize
   it again. New nodes form a new cluster with new runtime identities; restore
   applications and persistent data separately.

After destroy, verify its plan reports no remaining owned resources. A config
left in the shared directory reserves its names/subnet until you manually retire
it. There is no source-config purge option.

## Related information

- [Configuration and CLI reference](cluster-config.md)
- [Troubleshooting](troubleshooting.md)
- [Universal image deployment outside this lab](universal-node.md)
