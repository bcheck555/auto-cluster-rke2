# Autonomous RKE2 Cluster

One bootable Rocky Linux image for every node, on VMs or physical hosts. The
first node creates a single-server RKE2 cluster; later nodes discover and join
it. The next two become servers, subsequent nodes become workers. Formation,
enrollment, and endpoint failover run on the nodes. No external authority,
database, management server, or load balancer is required at runtime.

Boot the first node alone and wait until healthy before starting additional
nodes. This first-node-first design assumes working IPv4 multicast on one L2
segment. Empty discovery cannot distinguish an empty network from a partition.
A previously selected node never bootstraps a replacement cluster.

See [deployment and operation](docs/universal-node.md), [architecture](docs/architecture.md),
and [trust boundaries](docs/trust-and-threat-model.md). Every clone needs unique
machine identity and address. Supply one common private enrollment secret per
deployment; no node roles, cluster UUIDs, grants, or seed addresses are entered.

The image pipeline builds an OS base and one universal `node.qcow2` containing
both RKE2 roles, offline payloads, and the enabled node service. It can export
the same disk as signed `node.raw` for physical-host imaging. See
[offline image workflow](docs/offline-images.md). Pins remain Rocky 9.8,
RKE2 v1.37.1+rke2r1, Flannel VXLAN, and SELinux Enforcing. Firewalld remains
installed and disabled on node images; the OS base keeps it active.

The universal image passed four-VM formation, simultaneous reboot, and network
acceptance. See [artifacts and validation results](docs/universal-image-results.md).
Physical hardware validation remains pending. [Previous lab evidence](docs/offline-image-results.md)
describes the earlier separate-role images, not acceptance of the universal image.

## TL;DR: destroy or create the local VM lab

Run these scripts from your normal SSH shell. Each `sudo python3` invocation
exits back to that shell on success or failure; no interactive root shell,
exported variables, or pasted shell settings are needed. Commands target only
local `qemu:///system` on the hypervisor.

If you used the earlier pasted runbook, reconnect SSH first to clear any
`set -e`/`set -u` settings left in that shell. Those settings can close a shell
when a command fails; these scripts never enable them.

```bash
cd /home/checkb/repos/github/auto-cluster

# Inspect cleanup targets without changing anything.
sudo python3 lab/libvirt/destroy.py --plan

# PERMANENTLY DELETE lab workloads, disks, NVRAM, seeds, credentials and settings.
sudo python3 lab/libvirt/destroy.py --confirm-lab autonomous-rke2-lab
```

Back up needed data before destroying. Teardown handles partial deployments,
missing definitions, orphaned files, inactive pools/networks, and repeated runs.
It deletes `/var/lib/libvirt/images/autonomous-rke2-lab` including retained old
generations and rollback copies, plus the lab's VM/network/pool/filter
definitions and empty leftover bridge. It refuses cleanup if unrelated VMs use
these resources, ownership differs, or mounts remain inside the disk directory.
Published images, repository signing/SSH keys, and unrelated VMs remain intact.
Remove or replace any old kubeconfig you copied outside the lab directory.

After destroy succeeds, create a fresh three-server cluster:

```bash
sudo python3 lab/libvirt/create.py
```

For three servers **and a fourth worker**, use this command instead:

```bash
sudo python3 lab/libvirt/create.py --nodes 4
```

Default signed release:
`lab/artifacts/packer/release-universal-20261017/release.json`. To choose another
universal release, add `--release /absolute/path/to/release.json`. Each node
requires 8 GiB RAM, 4 vCPUs, and an independent 60 GiB virtual disk. Creation
requires 8 GiB additional available host RAM and disk reserve; allow 60 GiB free
disk per new VM. Host prerequisites: running system libvirt/KVM, Python 3,
`virsh`, `ip`, `qemu-img`, `qemu-system-x86_64`, `genisoimage`, `ssh`,
`ssh-keygen`, `gpgv`, repository artifact trust files, and
`/usr/share/OVMF/{OVMF_CODE_4M.fd,OVMF_VARS_4M.fd}`. No guest Internet access is
required.

Create verifies the signed release, generates fresh identities and one shared
enrollment secret, prepares disks/seeds, and boots the first node alone. Each
additional node starts after the previous node passes its health check. The
nodes are named `rke2-node01` through `rke2-node04`, independent of their roles.
Hostnames remain stable if roles change; automatic worker promotion is future
work. Existing scripted deployments retain their saved legacy names when
resumed, and destroy recognizes both naming schemes. Recreate the lab to adopt
the neutral names; running nodes are never renamed automatically. The
isolated network uses `192.168.250.0/24` without external forwarding; the
hypervisor gets `192.168.250.1` for management. Servers use `.11`–`.13`, the
optional worker `.14`. These subnets and the pod/service networks
`10.42.0.0/16`, `10.43.0.0/16` must not overlap other host networks.

**If create fails or is interrupted, resolve the reported error and rerun the
same command.** It resumes using saved identities, disks, and secret; it does
not silently reset a cluster. Health waits default to 1,200 seconds per node;
override with `--timeout SECONDS`. Use destroy followed by create when you want
a genuinely fresh cluster. Old manually created leftovers require destroy
before the first scripted create. Errors retain files and report retry steps.

VM autostart stays disabled. To start this existing cluster after a host reboot,
rerun the same create command: previously booted nodes start before health
checks so existing etcd voters can regain quorum. This differs from the
first-node-alone sequence used for a fresh cluster. Keep the same release and
`--nodes` value when resuming. Saved deployment state and secret reside in the
root-only `universal-lab.json` inside the lab disk directory. Both scripts share
the existing image/lab operation lock.

Create prints node/pod status and saves a root-only admin kubeconfig. If a host
`kubectl` is installed:

```bash
sudo kubectl --kubeconfig /var/lib/libvirt/images/autonomous-rke2-lab/admin.yaml get nodes -o wide
```

For diagnostics (substitute `.12`, `.13`, or `.14` for another node):

```bash
sudo ssh -i /var/lib/libvirt/images/autonomous-rke2-lab/operator \
  -o UserKnownHostsFile=/var/lib/libvirt/images/autonomous-rke2-lab/known_hosts \
  rke2lab@192.168.250.11 \
  'sudo journalctl -u autonomous-rke2-host-agent.service -n 100 --no-pager'
```

The old `replace.py` and default lab config target historical separate-role
images. Use [create.py](lab/libvirt/create.py) and [destroy.py](lab/libvirt/destroy.py)
for the universal-image lab. Applications and persistent data must be restored
separately after a fresh deployment.

Development uses the Go version pinned in `go.mod`:

```sh
make build test vet fmt-check
go test -race -timeout 60s ./...
python3 -B -m unittest discover -s tests/integration/lab -v
```

`make build` produces the Linux amd64 node agent. The earlier authority-backed
libraries and command remain available for historical tests; they are not
included in the universal node boot workflow. Automatic member removal,
promotion, quorum reset, fencing, and destructive recovery are outside this
implementation.
