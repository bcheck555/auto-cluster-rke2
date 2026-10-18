# Deploying the universal node image

Every machine boots the same disk image. A single deployment shares one private
enrollment secret. The first machine forms a single-server cluster, the next
two join as servers, and later machines join as workers. No per-node role,
cluster ID, authority address, registration endpoint, or health-reader private
key is provisioned.

## Requirements

- Linux amd64 guests/hosts with persistent disks and the pinned Rocky 9.8 image.
- One reachable IPv4 subnet on an L2 segment with multicast and unicast between
  nodes. It must not overlap pod/service networks `10.42.0.0/16` and `10.43.0.0/16`.
- A unique, stable IPv4 address on each clone. DHCP reservations or static
  networking are suitable; address/interface changes after formation halt.
- Exactly one suitable interface/address, or `Interface` explicitly selected
  in common image settings. Multiple NICs are not guessed from their order.
- Correct clocks from the hypervisor/RTC or site time infrastructure; signed
  messages have a bounded freshness window.
- Boot the first node alone and wait for independent health before additional
  boots. ID ordering is not a guarantee across partitions or hidden peers.

Allow deployment traffic within its network: UDP 9444 multicast plus unicast
replies to probe sockets, TCP 9443 enrollment, RKE2 TCP 9345/6443, etcd TCP
2379/2380 between servers, kubelet TCP 10250, and Flannel VXLAN UDP 4789
(the bundled RKE2 chart's backend port).
Loopback TCP 7443 is the local API health proxy. Initial registration uses a
discovered server on native TCP 9345; RKE2 then manages its own client load
balancer and cached server addresses. Registration ports are never translated.
The pinned RKE2 etcd HTTPS health/API gateway uses loopback TCP 2382.
The node installs its own service-CIDR link route, so isolated nodes need no
default gateway for kube-proxy's initial route lookup.
No external DNS, load balancer, lease server, or bootstrap server is required.
The node image keeps firewalld installed and disabled; enforce site boundaries
at the surrounding network. External package/image downloads are not used.

## Build and acceptance

See [offline image workflow](offline-images.md) for artifact signing and cached
inputs. In a new output generation, run:

```sh
python3 -B lab/packer/images.py lock --output /path/to/new-input
python3 -B lab/packer/images.py build --input /path/to/new-input/input.json --output /path/to/new-build
sudo -E python3 -B lab/packer/images.py test --input /path/to/new-build/candidate.json --output /path/to/new-build/validation.json
python3 -B lab/packer/images.py publish --input /path/to/new-build/candidate.json --output /path/to/new-release
```

To reuse verified cached downloads, use `lock --from-lock /path/to/old/input.json
--output /path/to/new-input` instead of a fresh connected lock. This creates a
new signed generation, combines the two cached role RPM selections, and adds
the current node binary, unit, and public Go sources. Existing locks/releases
are never rewritten. Compiling the agent occurs during input preparation;
offline Packer needs no Go toolchain or network access.

Output includes an OS base and **one runtime image**, `node.qcow2`. Both native
RKE2 units remain masked/stopped in the sealed image. The node service is enabled
but conditional on the common configuration and enrollment secret. The
generated `/etc/autonomous-rke2/node.json` contains actual offline payload hashes;
do not replace those with documentation placeholders.

Candidate acceptance boots four clones from the same node disk. It supplies
only an ephemeral common enrollment secret, waits for the first healthy node
before launching each additional clone, verifies server/server/server/worker
assignment, then reboots all four and compares cluster, host, Node and etcd
identities. It also checks three voters, offline DNS, and cross-node service/pod
connectivity. Publication requires signed formation evidence for that disk.
The validator reserves capacity for four disposable 8-GiB guests plus retained
lab allocations and QEMU overhead. If disk reserves prevent temporary test
storage, it can use a size-limited tmpfs after reserving its entire maximum
against available RAM as well. Both host reserves still apply. The owned mount
is removed after disposable guests stop. Existing lab guests are not modified.

## Supply one deployment secret

Generate 32 random bytes once as 64-character hex text, and securely inject the same secret
on every clone at `/etc/autonomous-rke2/enrollment-secret`, root-owned mode 0600.
Trailing newlines and hex letter case are normalized. Documentation placeholders
are rejected. Do not generate an independent secret
on each node. A protected site customization or NoCloud `write_files` seed can
supply this common file; the secret is not part of the generic signed image.

The [cloud-init fragment](../configs/site-cloud-init.example.yaml) shows the file
and service restart. Replace its placeholder before use and combine with your
normal hostname/network configuration. No external cloud-init server is
necessary: a local NoCloud disk/ISO or protected customization works. Never
commit the real secret or initialized node disk.

Start the first node alone. Its default startup grace is 30 seconds, followed
by normal RKE2 readiness checks; image imports and control-plane startup can
take longer. Check it locally or through the guest console:

```sh
systemctl status autonomous-rke2-host-agent.service
journalctl -u autonomous-rke2-host-agent.service
/usr/local/libexec/autonomous-rke2/host-agent -health
```

`-health` observes the API, immutable marker, Node readiness and local etcd for
servers; a cached journal is insufficient. Once this succeeds, boot additional
clones. Membership reservations serialize concurrent joins. No manual role or
token copying is needed. Servers enroll through any discovered healthy server;
workers receive only worker credentials and a limited read-only certificate.

## VM and physical disk formats

Use `node.qcow2` as a read-only template with distinct persistent per-VM disks,
unique machine identity, MAC, address, and NVRAM. Clone only a sealed image,
never an initialized node. The lab provisioner accepts the universal derived
profile with `role: auto`; shared-secret injection is supplied separately through
the site customization/seed. Existing lab configs/releases remain historical.

For physical hosts, export the published node disk:

```sh
python3 -B lab/packer/images.py export --input /path/to/new-release/release.json --output /path/to/raw-export
```

This produces `node.raw` and signed `export.json`, verifies geometry and compares
raw contents with the source disk. It writes a new directory, never a block
device. Verify signatures and target-disk ownership before imaging a physical
disk, then provide the same common enrollment file and local networking seed.
UEFI/boot drivers, NIC drivers, storage and cloud-init behavior on representative
hardware still need acceptance testing. Raw export alone does not establish
bare-metal compatibility.

## Restart and reconciliation

Identity and formation state live under `/var/lib/autonomous-rke2`; credentials
are private files beneath it. RKE2 data remains under `/var/lib/rancher/rke2`.
Preserve both across reboot. The service restores the recorded role and cluster
before advertising, uses persisted server endpoints while discovery recovers,
and starts only that role with the same existing data. It does not enable the
native RKE2 unit as an independent boot path.

Missing completed data, changed address/interface, deployment fingerprint or
runtime policy, multiple cluster UUIDs, and changed Node/etcd identities stop
convergence. Pending reservations remain assigned to their original identity;
they are not freed by a timeout. A failed join during the two-server stage may
temporarily prevent quorum until that same node resumes. Do not delete journals
or reset etcd to make discovery succeed.

Reader and enrollment TLS certificates renew under the same host keys. Site-key
and cluster-CA rotation, abandoned reservation reconciliation, node replacement,
and upgrades need explicit future procedures. There is no automated promotion,
member removal, quorum reset, disk cleanup or fencing. See
[remaining work](open-questions.md).
