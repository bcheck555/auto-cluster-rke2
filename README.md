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

For multiple clusters, select a stable `--cluster` identity. Each gets separate
VMs, storage pool/directory, bridge, network, IPv6 filter, enrollment secret,
SSH credentials, and kubeconfig. Customize the hostname prefix, libvirt network
name, and node subnet on first creation:

```bash
sudo python3 lab/libvirt/create.py --cluster dev \
  --hostname-prefix dev-node --network dev-private --subnet 192.168.100.0/24 --plan
sudo python3 lab/libvirt/create.py --cluster dev \
  --hostname-prefix dev-node --network dev-private --subnet 192.168.100.0/24

# Another independent cluster; allocate an unused private /24 automatically.
sudo python3 lab/libvirt/create.py --cluster qa --hostname-prefix qa-node --nodes 4

# Saved names, network and subnet are inherited when resuming.
sudo python3 lab/libvirt/create.py --cluster dev

# Destroy only dev, including its disks and settings. Leave qa intact.
sudo python3 lab/libvirt/destroy.py --cluster dev --plan
sudo python3 lab/libvirt/destroy.py --cluster dev --confirm-cluster dev
```

`--hostname-prefix dev-node` produces `dev-node01` through `dev-node04`.
Without a prefix, a named cluster uses `rke2-CLUSTER-node01` through `04`.
`--network` names a **new isolated libvirt network managed by this cluster**;
the script never attaches to or repurposes someone else's network. Cluster
names scope storage under `/var/lib/libvirt/images/autonomous-rke2-CLUSTER`.
The default `--cluster lab` retains the original lab paths and naming.

Before creating resources, the script checks active and inactive libvirt
network subnets/routes, host IPv4 addresses and routes in all routing tables,
and this image's Kubernetes pod/service CIDRs (`10.42.0.0/16`, `10.43.0.0/16`).
Node subnets must be private IPv4 ranges, `/28` or larger, with no overlap in
either direction. Existing VM/network/bridge/pool/filter name collisions also
stop creation. If `--subnet` is omitted, an unused private `/24` is selected
and saved. Resuming checks again and refuses newly introduced conflicts rather
than changing the cluster's addresses.

Remote Kubernetes/VPN ranges absent from the hypervisor's configuration cannot
be discovered from local routes. Supply those explicitly, including the full
pod and service CIDRs, using repeatable `--reserved-cidr` options on first
creation:

```bash
sudo python3 lab/libvirt/create.py --cluster staging \
  --reserved-cidr 10.244.0.0/16 --reserved-cidr 172.20.0.0/16
```

Each isolated cluster reuses the image's internal pod/service CIDRs; the
networks have no external forwarding. Routing pods/services between clusters
requires additional support for configurable Kubernetes CIDRs. Only node
subnets are configurable here.

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
additional node starts after the previous node passes its health check. Default
lab nodes are named `rke2-node01` through `rke2-node04`. All hostnames are
independent of roles; automatic worker promotion is future work.
Existing scripted deployments retain their saved legacy names when
resumed, and destroy recognizes both naming schemes. Recreate the lab to adopt
the neutral names; running nodes are never renamed automatically. The
isolated network defaults to `192.168.250.0/24` when that range is available.
The hypervisor gets subnet address +1 for management. The first three nodes use
addresses +11 through +13; the optional fourth uses +14. The selected subnet
and gateway are printed before resource creation. Non-`/24` masks are also
written into the cloud-init seed.

**If create fails or is interrupted, resolve the reported error and rerun the
same command.** It resumes using saved identities, disks, and secret; it does
not silently reset a cluster. Health waits default to 1,200 seconds per node;
override with `--timeout SECONDS`. Use destroy followed by create when you want
a genuinely fresh cluster. Old manually created leftovers require destroy
before the first scripted create. Errors retain files and report retry steps.

VM autostart stays disabled. To start this existing cluster after a host reboot,
rerun the same create command: previously booted nodes start before health
checks so existing etcd voters can regain quorum. This differs from the
first-node-alone sequence used for a fresh cluster. Keep the same `--cluster`,
release and `--nodes` value when resuming. Saved hostname/network/subnet options
are reused; explicit conflicting options are rejected. Saved deployment state
and secret reside in the root-only `universal-lab.json` inside the lab disk
directory. Both scripts share the existing image/lab operation lock.

Create prints node/pod status and saves a root-only admin kubeconfig. For the
default lab, if a host `kubectl` is installed:

```bash
sudo kubectl --kubeconfig /var/lib/libvirt/images/autonomous-rke2-lab/admin.yaml get nodes -o wide
```

For named clusters use their storage directory, for example
`/var/lib/libvirt/images/autonomous-rke2-dev/admin.yaml`. For diagnostics on the
default lab (substitute the selected cluster's directory and node IP as needed):

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
