# auto-cluster-rke2

One bootable Rocky Linux image for every node, on VMs or physical hosts. The
first node creates a single-server RKE2 cluster; later nodes discover and join
it. The next two become servers, subsequent nodes become workers. Formation,
enrollment, and endpoint failover run on the nodes. No external authority,
database, management server, or load balancer is required at runtime.

The repository folder and Go module are named `auto-cluster-rke2`. Runtime
service names, configuration paths and protocol identifiers retain their
`autonomous-rke2` names for compatibility with existing images and clusters.

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

## TL;DR: cluster configs and private inputs

Keep one public YAML and one private `.env` per cluster under `clusters/`.
Committed, commented templates:

- [cluster.yaml.example](clusters/cluster.yaml.example): identity, release,
  hostnames, node count, VM resources, subnet and additional reservations.
- [cluster.env.example](clusters/cluster.env.example): private-input format,
  permissions, initialization and enrollment-secret lifecycle.

Real YAML configs can be committed. Real `*.env` files are Git-ignored.
**Create and destroy never overwrite or delete either input file.** Only you
decide when to edit, move, rotate, or delete them. `--init-secrets` is an explicit
initialization action that creates an absent `.env` and refuses to overwrite one.

Run commands from your normal SSH shell. If you used the old pasted runbook,
reconnect SSH first to clear its `set -e`/`set -u` settings. The scripts change
no shell settings and always target local `qemu:///system`.

```bash
cd /home/checkb/repos/github/auto-cluster-rke2
cp -n clusters/cluster.yaml.example clusters/dev.yaml
# Edit dev.yaml: select a unique cluster, hostname prefix, network and subnet.
# The template describes dev; change these fields for additional clusters.
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --plan
```

Initialize the private file **once**, after reviewing the YAML. This creates
`clusters/dev.env` as root with mode `0600`, without creating any VMs. If the
selected cluster already has saved runtime state, it adopts that deployment's
enrollment key instead of generating a replacement. Existing files are refused;
edit them manually when needed. The `.env` template documents manual setup too.

```bash
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml --init-secrets
```

Create the cluster, or resume it after a failed run or host reboot:

```bash
sudo python3 lab/libvirt/create.py --config clusters/dev.yaml
```

Inspect and permanently remove its generated resources:

```bash
sudo python3 lab/libvirt/destroy.py --config clusters/dev.yaml --plan
sudo python3 lab/libvirt/destroy.py --config clusters/dev.yaml --confirm-cluster dev
```

**Destroy deletes workloads, VM disks, NVRAM, cloud-init seeds, generated SSH
keys, kubeconfig and runtime state. Back up needed data first.** The public YAML
and private `.env` remain unchanged. Recreating the cluster reuses their values,
including the enrollment secret. Runtime copies of the key disappear with the
generated resources. There is no option to purge the source files.

Destroy does not require a readable or valid `.env`. It uses saved runtime
ownership when YAML already describes a replacement. Partial deployments,
missing definitions, inactive pools/networks, orphaned files, and repeated
teardown are supported. Unrelated VMs/resources are protected. YAML/`.env`
inputs found inside generated disk directories stop cleanup before VM changes;
move those inputs out manually. Keep input files in `clusters/` or another
dedicated configuration directory.

## Config and network validation

YAML mode requires PyYAML in the Python interpreter used by `sudo`; see
[lab/requirements.txt](lab/requirements.txt). This host already has it. Relative
release paths resolve from the YAML file's directory. Unknown fields, duplicate
keys, aliases, unsafe YAML tags and invalid types are rejected. With `--config`,
edit deployment settings in YAML; deployment flags cannot override them.
`--timeout SECONDS` can override the operational health wait.

The paired filename is automatic: `qa.yaml` or `qa.yml` uses `qa.env`.
Actual create requires a regular, root-owned, mode `0600` `.env`, without
symlinks. Only literal `ENROLLMENT_SECRET=<64 hex characters>` and full-line
comments are accepted; optional paired quotes around the key are allowed.
No shell evaluation, expansion, exports, inline comments, or unknown variables
are accepted. Values are not printed. A changed key is rejected for a saved
deployment; restore the key or destroy and recreate intentionally.

Each cluster gets separate VM names, pool/directory, bridge, network, filter,
credentials and kubeconfig. `--hostname-prefix dev-node` (or its YAML field)
produces `dev-node01`, `dev-node02`, and so on. Names stay independent of roles.
Automatic worker promotion remains future work.

Every real `.yaml`/`.yml` in the selected config's folder reserves its cluster
identity, hostname prefix, network and node subnet, including stopped or
destroyed clusters. Reservations also include peer configs' explicit reserved
CIDRs. Templates ending in `.example` are excluded. Retire obsolete configs
manually when you want to release those reservations. Keep cluster YAML files
together for these checks; arbitrary other folders are not scanned.

Create also checks active/inactive libvirt network subnets and routes, host
IPv4 addresses and routes in all routing tables, and image Kubernetes ranges
`10.42.0.0/16` (pods) and `10.43.0.0/16` (services). Overlap in either direction
or resource-name collisions stops creation before provisioning. Add remote
Kubernetes/VPN ranges invisible to the host to `network.reserved_cidrs`.

YAML requires an explicit private IPv4 node subnet, `/28` or larger. Hypervisor
management uses subnet address +1; nodes use +11 onward, ending before broadcast.
Positive node counts are accepted within host, subnet and image capacity. The
current image's membership catalog supports up to 1,024 nodes. A `/28`
fits 4 nodes and a `/24` fits 244 with this address allocation; use a larger
subnet for more. Prefixes plus growing node indices must fit DNS hostname limits.
The selected mask is written to every seed. Networks are isolated without
external forwarding. Their internal Kubernetes CIDRs can be reused in separate
isolated clusters; routing pods/services between clusters needs additional
support for configurable Kubernetes CIDRs.

## Operation and prerequisites

Default resources per VM are 4 vCPUs, 8192 MiB RAM and a standalone 60 GiB
virtual disk; YAML can change them within the documented template limits.
Host capacity checks reserve each new disk's full size, RAM for stopped/new
VMs, and an additional 8 GiB of disk and RAM for the host. Requires system
libvirt/KVM, Python 3, `virsh`, `ip`, `qemu-img`, `qemu-system-x86_64`,
`genisoimage`, `ssh`, `ssh-keygen`, `gpgv`, repository artifact trust files, and
`/usr/share/OVMF/{OVMF_CODE_4M.fd,OVMF_VARS_4M.fd}`.

Create verifies the signed release, prepares ordinary deployment seeds, boots
the first node alone and checks health before each subsequent boot. One node
forms a single-server cluster; nodes two and three become servers. Every node
after the third becomes a worker. No guest Internet access is needed.
The default release is
`lab/artifacts/packer/release-universal-20261017/release.json`.

If create fails or is interrupted, resolve its reported error and rerun the
same config. Disks, identities and secret are preserved. Changing release,
node count, VM resources or network settings on an existing deployment requires
recreation. VM autostart stays disabled; rerun create after a host reboot. All
previously booted voters start before health waits so quorum can recover.
Both scripts share the existing image/lab operation lock.

For cluster `dev`, generated files live under
`/var/lib/libvirt/images/autonomous-rke2-dev`. The root-only
`universal-lab.json` contains saved runtime identity and key copies. Create
prints node/pod status and saves `admin.yaml` there. For a host Kubernetes client:

```bash
sudo kubectl --kubeconfig /var/lib/libvirt/images/autonomous-rke2-dev/admin.yaml get nodes -o wide
```

For diagnostics, substitute the configured first node's IP below:

```bash
sudo ssh -i /var/lib/libvirt/images/autonomous-rke2-dev/operator \
  -o UserKnownHostsFile=/var/lib/libvirt/images/autonomous-rke2-dev/known_hosts \
  rke2lab@192.168.100.11 \
  'sudo journalctl -u autonomous-rke2-host-agent.service -n 100 --no-pager'
```

CLI-only deployments remain supported through `--cluster`, `--hostname-prefix`,
`--network`, `--subnet`, `--reserved-cidr`, `--release`, and `--nodes` (see
`--help`). Without YAML, an omitted subnet selects an unused private `/24`, or
a larger private subnet when the requested node count needs one.
The default `lab` identity retains `/var/lib/libvirt/images/autonomous-rke2-lab`
and recognizes historical names during resume/cleanup. Existing deployments can
adopt a matching YAML and initialize its `.env` from saved runtime state.

The old `replace.py` and default lab config target historical separate-role
images. Use [create.py](lab/libvirt/create.py) and [destroy.py](lab/libvirt/destroy.py)
for universal-image deployments. Restore applications and persistent data
separately after recreation.

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
