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
Physical hardware validation remains pending.
Existing lab VMs and historical releases have not been replaced or bootstrapped
by this change. [Previous lab evidence](docs/offline-image-results.md) describes
the earlier separate-role images, not acceptance of the universal image.

## TL;DR: delete and recreate the local VM cluster

These commands target this repository's **local libvirt lab** on the current
Linux/KVM host. They permanently delete its workloads, volumes, VM disks,
NVRAM, cloud-init seeds, enrollment secret, and libvirt settings. Back up needed
data first. Published images and repository signing/SSH keys remain available.
No teardown or deployment happens merely by updating this README.

Run all blocks, in order, in **one root Bash shell** from the repository root:

```bash
sudo bash
cd /home/checkb/repos/github/auto-cluster
set -euo pipefail
umask 077
export LIBVIRT_DEFAULT_URI=qemu:///system
pool=/var/lib/libvirt/images/autonomous-rke2-lab
release="$PWD/lab/artifacts/packer/release-universal-20261017"

# Verify the signed release and every listed file BEFORE deleting anything.
python3 - "$release/release.json" <<'PY'
import sys
from lab.packer.artifacts import verify_manifest
release = verify_manifest(sys.argv[1])
assert release['kind'] == 'release' and 'node' in release['profiles']
print('Universal release verified')
PY
for tool in virsh qemu-img qemu-system-x86_64 genisoimage ssh ssh-keygen; do
  command -v "$tool" >/dev/null
done
test -f /usr/share/OVMF/OVMF_CODE_4M.fd
test -f /usr/share/OVMF/OVMF_VARS_4M.fd
```

**Delete the old cluster.** Stop all members before removing any disks. Names
include an optional fourth node created by this recipe. The pool directory must
contain only this lab's files; inspect it and ensure no other VM uses its disks.
This also removes retained replacement generations and rollback copies.

```bash
virsh list --all
virsh pool-dumpxml autonomous-rke2-lab
ls -la "$pool"

nodes=(rke2-r9-cp01 rke2-r9-cp02 rke2-r9-cp03 rke2-r9-worker01)
for node in "${nodes[@]}"; do
  if virsh dominfo "$node" >/dev/null 2>&1; then
    if virsh list --name | grep -Fxq "$node"; then
      virsh destroy "$node"
    fi
  fi
done
for node in "${nodes[@]}"; do
  if virsh dominfo "$node" >/dev/null 2>&1; then
    virsh undefine "$node" --nvram --managed-save \
      --snapshots-metadata --checkpoints-metadata
  fi
done
if virsh net-info autonomous-rke2-isolated >/dev/null 2>&1; then
  if virsh net-list --name | grep -Fxq autonomous-rke2-isolated; then
    virsh net-destroy autonomous-rke2-isolated
  fi
  virsh net-undefine autonomous-rke2-isolated
fi
if virsh pool-info autonomous-rke2-lab >/dev/null 2>&1; then
  if virsh pool-list --name | grep -Fxq autonomous-rke2-lab; then
    virsh pool-destroy autonomous-rke2-lab
  fi
  virsh pool-undefine autonomous-rke2-lab
fi
if virsh nwfilter-dumpxml autonomous-rke2-ipv4-only >/dev/null 2>&1; then
  virsh nwfilter-undefine autonomous-rke2-ipv4-only
fi
test "$pool" = /var/lib/libvirt/images/autonomous-rke2-lab
rm -rf --one-file-system -- "$pool"
```

**Create the new cluster.** Requires at least 24 GiB guest RAM, 12 guest vCPUs,
and space for three independent 60 GiB virtual disks. Set `count = 4` below for
an additional worker (8 GiB RAM, 4 vCPUs). All nodes use the same signed image.
The isolated network has no external forwarding; `192.168.250.1` gives this
hypervisor local SSH/API access. Ensure `192.168.250.0/24` does not overlap
another host network. The old `replace.py` and default lab config still target
historical images; use this recipe for the universal release.

```bash
install -d -m 0711 "$pool"
cat > "$pool/network.xml" <<'XML'
<network>
  <name>autonomous-rke2-isolated</name>
  <bridge name='virbr-rke2' stp='on' delay='0'/>
  <dns enable='no'/>
  <ip address='192.168.250.1' netmask='255.255.255.0'/>
</network>
XML
virsh net-define "$pool/network.xml"
virsh net-start autonomous-rke2-isolated
virsh net-autostart autonomous-rke2-isolated
virsh pool-define-as autonomous-rke2-lab dir --target "$pool"
virsh pool-start autonomous-rke2-lab
virsh pool-autostart autonomous-rke2-lab
virsh nwfilter-define lab/libvirt/ipv4-only.xml
ssh-keygen -q -t ed25519 -N '' -f "$pool/operator"

# Reuse tested VM-definition helpers; create ordinary deployment seeds.
python3 - "$release/node.qcow2" "$pool" <<'PY'
import json, os, secrets, shutil, subprocess, sys
from pathlib import Path
from lab.packer.runtime import domain_xml, make_spec

image, directory = map(Path, sys.argv[1:])
count = 3  # Change to 4 to include a worker.
secret = secrets.token_hex(32)
key = (directory / 'operator.pub').read_text().strip()
for i in range(1, count + 1):
    name = f'rke2-r9-cp{i:02}' if i <= 3 else 'rke2-r9-worker01'
    spec = make_spec(name, f'192.168.250.{10 + i}', 'node', directory)
    seed = directory / (name + '-seed')
    seed.mkdir(mode=0o700)
    userdata = {
        'hostname': name, 'preserve_hostname': False, 'ssh_deletekeys': True,
        'disable_root': True, 'ssh_pwauth': False,
        'package_update': False, 'package_upgrade': False,
        'users': [{'name': 'rke2lab', 'shell': '/bin/bash', 'lock_passwd': True,
                   'sudo': ['ALL=(ALL) NOPASSWD: ALL'],
                   'ssh_authorized_keys': [key]}],
        'write_files': [{'path': '/etc/autonomous-rke2/enrollment-secret',
                         'owner': 'root:root', 'permissions': '0600',
                         'content': secret}],
        'runcmd': [['systemctl', 'enable', '--now', 'qemu-guest-agent'],
                   ['systemctl', 'restart', '--no-block',
                    'autonomous-rke2-host-agent.service']]}
    network = {'version': 2, 'ethernets': {'rke2lab0': {
        'match': {'macaddress': spec['mac']}, 'set-name': 'rke2lab0',
        'dhcp4': False, 'dhcp6': False, 'accept-ra': False,
        'addresses': [spec['address'] + '/24'],
        'routes': [{'to': '10.43.0.0/16', 'via': '0.0.0.0'}]}}}
    (seed / 'user-data').write_text('#cloud-config\n' + json.dumps(userdata))
    (seed / 'meta-data').write_text(json.dumps({
        'instance-id': spec['instance_id'], 'local-hostname': name}))
    (seed / 'network-config').write_text(json.dumps(network))
    subprocess.run(['genisoimage', '-quiet', '-output', spec['seed'], '-volid',
                    'cidata', '-joliet', '-rock',
                    *map(str, (seed / p for p in
                              ('user-data', 'meta-data', 'network-config')))], check=True)
    subprocess.run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'qcow2',
                    str(image), spec['disk']], check=True)
    subprocess.run(['qemu-img', 'resize', spec['disk'], '60G'], check=True)
    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', spec['nvram'])
    xml = directory / (name + '.xml')
    xml.write_text(domain_xml(spec))
    for path in (spec['seed'], spec['disk'], spec['nvram']):
        os.chmod(path, 0o600)
    subprocess.run(['virsh', 'define', str(xml)], check=True)
PY

# Accept fresh SSH host keys into a private, deployment-specific file.
labssh() {
  ssh -i "$pool/operator" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$pool/known_hosts" "rke2lab@$1" "${@:2}"
}
wait_healthy() {
  local address=$1
  for ((attempt=0; attempt<120; attempt++)); do
    if labssh "$address" \
      'sudo /usr/local/libexec/autonomous-rke2/host-agent -health'; then
      return 0
    fi
    sleep 10
  done
  echo "Node unhealthy: $address; inspect host-agent journal before continuing" >&2
  return 1
}

# First node creates the cluster. Gate every subsequent boot on health.
virsh start rke2-r9-cp01
wait_healthy 192.168.250.11
virsh start rke2-r9-cp02
wait_healthy 192.168.250.12
virsh start rke2-r9-cp03
wait_healthy 192.168.250.13
if virsh dominfo rke2-r9-worker01 >/dev/null 2>&1; then
  virsh start rke2-r9-worker01
  wait_healthy 192.168.250.14
fi

# Use bundled kubectl; no host Kubernetes client required.
labssh 192.168.250.11 \
  'sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml wait --for=condition=Ready node --all --timeout=300s'
labssh 192.168.250.11 \
  'sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes -o wide'
labssh 192.168.250.11 \
  'sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get pods -A'
labssh 192.168.250.11 'sudo cat /etc/rancher/rke2/rke2.yaml' \
  | sed 's/127.0.0.1/192.168.250.11/g' > "$pool/admin.yaml"
chmod 600 "$pool/admin.yaml"
# If kubectl is installed on this host:
# kubectl --kubeconfig "$pool/admin.yaml" get nodes
```

Expect three Ready server nodes, plus one Ready worker if requested. Restore
applications/data separately. For a failed boot, run
`labssh 192.168.250.11 'sudo journalctl -u autonomous-rke2-host-agent.service -n 100 --no-pager'`
(substitute the failing IP). Existing nodes retain identity on reboot; a fresh
cluster requires the teardown and fresh disks above. This recipe leaves VM
autostart disabled: after a host reboot, start all existing servers before
waiting for quorum and health, then start workers. The first-node-alone gate
applies to initial cluster creation. Runtime formation itself needs no external
server or Internet. Any old kubeconfig copied elsewhere must be removed or
replaced separately; the commands never alter your global kubeconfig.

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
