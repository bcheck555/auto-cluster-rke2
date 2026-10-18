# auto-cluster-rke2

Boot the same Rocky Linux image on every VM or physical host. The first node
creates an RKE2 cluster; additional nodes discover and join it. Discovery,
enrollment, membership, and endpoint failover run on the nodes. No separate
management server, database, or load balancer is required at runtime.

**Boot the first new node alone and wait until healthy before adding nodes.**
Nodes must share one IPv4 subnet with working multicast. Empty discovery cannot
distinguish an empty network from a network partition.

## Project status

The scaling image passed formation, simultaneous reboot, offline DNS, cross-node
networking, and resizing through seven controls plus a worker. Physical disk
export is verified; physical hardware boot validation remains pending.
See [scaling validation evidence](docs/scaling-image-results.md).

The default control-node target is three; `control_nodes` can select three,
five, or seven. Actual controls are limited by total `nodes`; the remainder are workers.
One- and two-server clusters are possible, but provide no tolerance for a
server failure. Scaling-capable images support operator-requested resizing and
role replacement through create. Unattended failure recovery, in-place role
promotion, upgrades, and lost-quorum recovery are not implemented.

Current image pins: Rocky Linux 9.8 amd64, RKE2 v1.37.1+rke2r1, Flannel VXLAN,
and SELinux Enforcing. Node images have firewalld installed and disabled.

## Get started

For the local KVM/libvirt workflow, check the
[prerequisites](docs/lab-lifecycle.md#before-you-begin). A signed release and its
trust files must already exist; create does not download images. For another
hypervisor or physical hardware, use the [universal deployment guide](docs/universal-node.md).

Run these commands from a normal SSH shell. Adjust the checkout path if needed.
The example config describes cluster `dev`; review it before creating resources.

```bash
cd /home/checkb/repos/github/auto-cluster-rke2
cp -n clusters/cluster.yaml.example clusters/dev.yaml
```

Edit `clusters/dev.yaml`: choose the release, node count, VM resources, hostname
prefix, network name, and an unused private subnet. Keep cluster configs together
so their names and networks can be checked for conflicts.

```bash
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --plan
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --init-secrets
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml
```

Run `--init-secrets` only when `clusters/dev.env` is absent. It creates a
root-owned `0600` file without creating VMs and refuses to overwrite an existing
file. If create is interrupted, fix the reported problem and rerun the final
command. [Full procedure and expected results](docs/lab-lifecycle.md#create-a-cluster).

## Destroy and rebuild

**Destroy permanently deletes workloads, disks, NVRAM, seeds, generated SSH
keys, kubeconfig, and runtime state. Back up needed data first.** It also removes
the cluster's owned libvirt definitions and network resources.

```bash
cd /home/checkb/repos/github/auto-cluster-rke2
sudo python3 lab/libvirt/destroy.py --config clusters/dev.yaml --plan
sudo python3 lab/libvirt/destroy.py --config clusters/dev.yaml --confirm-cluster dev
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml
```

**Create and destroy never overwrite or delete source YAML or `.env` files.**
Rebuild reuses their values, including the enrollment secret. Restore application
data separately. See [destroy and rebuild](docs/lab-lifecycle.md#destroy-and-rebuild-a-cluster)
for partial deployments and changed configurations.

## Resize a cluster

For a cluster created from a scaling-capable image, edit `nodes` and optionally
`control_nodes` (`3`, `5`, or `7`) in its YAML, then rerun:

```bash
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --plan
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml
```

Create adds missing nodes, drains/removes excess workers before controls, and
reconciles role changes with fresh replacements. **Removed/replaced nodes lose
their local disks.** Blocked drains stop by default. Low/even control counts warn
but are allowed; actual lost quorum blocks changes. Older images require one
rebuild. See [scaling behavior and recovery](docs/scaling.md).

## Documentation

- [Documentation index](docs/README.md): current guides, design references, and historical records.
- [Create, inspect, restart, and destroy a lab](docs/lab-lifecycle.md).
- [Cluster configuration reference](docs/cluster-config.md) and committed
  [YAML](clusters/cluster.yaml.example) / [private-input](clusters/cluster.env.example) templates.
- [Troubleshooting](docs/troubleshooting.md).
- [Architecture and component locations](docs/architecture.md).
- [Build, validate, sign, and export images](docs/offline-images.md).

The project folder and Go module use `auto-cluster-rke2`. Runtime services,
paths, and protocol identifiers retain `autonomous-rke2` for compatibility with
existing images and clusters.

## Development

Use the Go version pinned in [go.mod](go.mod). From the checkout root:

```bash
make build test vet fmt-check
go test -race -timeout 60s ./...
python3 -B -m unittest discover -s tests/integration/lab -v
```

`make build` produces the Linux amd64 node agent. Keep secrets, initialized
disks, and generated credentials out of commits. Documentation changes should
follow the [documentation guide](docs/documentation-guide.md).
