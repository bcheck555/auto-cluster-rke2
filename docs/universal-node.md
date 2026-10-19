# Deploy the universal node image

Use the same sealed image for every VM or physical host. Supply common enrollment
trust and unique machine/network identities, then boot the first new node alone.
Controls fill the default target of three; later nodes become workers. Managed
libvirt deployments can select a target of five or seven. No per-node role,
cluster UUID, seed server address, or grant is entered.

For the supported local KVM automation, use [lab lifecycle](lab-lifecycle.md).
This guide describes provisioning requirements for other hypervisors and physical
hosts. Physical hardware acceptance is still pending.

## Before you begin

- Obtain a signed universal release and verify it against independently trusted
  signing material. See [build and verification](offline-images.md) and
  [recorded acceptance](universal-image-results.md).
- Use Linux amd64 hosts/guests with persistent disks and the pinned Rocky 9.8 image.
- Provide one IPv4 subnet on a shared L2 segment with multicast and unicast. It
  must not overlap pods `10.42.0.0/16` or services `10.43.0.0/16`.
- Assign each clone a unique stable IPv4 address, using static configuration or
  DHCP reservations. Address/interface changes after formation halt convergence.
- Provide exactly one suitable interface/address, or explicitly select `Interface`
  in common image settings. Multiple NICs are not guessed from their order.
- Keep clocks correct using hypervisor/RTC or site time infrastructure; discovery
  messages have a bounded freshness window.
- Permit the node traffic below. Node images have firewalld installed and disabled;
  enforce site boundaries in the surrounding network.

| Traffic | Purpose |
| --- | --- |
| UDP 9444, multicast `239.192.42.42` and unicast replies to probe sockets | Authenticated discovery |
| TCP 9443 between nodes | Enrollment on healthy servers |
| TCP 9345 / 6443 | Native RKE2 registration / Kubernetes API |
| TCP 2379 / 2380 between servers | Embedded etcd |
| TCP 10250 | Kubelet |
| UDP 4789 between nodes | Bundled Flannel VXLAN backend |

Loopback TCP 7443 is the local API health proxy; loopback TCP 2382 is the pinned
RKE2 etcd health/API gateway. RKE2 registration uses discovered native port 9345,
then its own client load balancer and cached server addresses. Ports are not
translated. A node-maintained service-CIDR route permits isolated operation
without a default gateway. External DNS, bootstrap servers, load balancers,
and package/image downloads are not required at runtime.

## Prepare and boot nodes

1. Clone only the sealed `node.qcow2`, never an initialized node disk. Give each
   VM its own persistent writable disk, unique MAC, machine identity, IPv4 address,
   and NVRAM. Physical deployments use the signed raw export described below.

2. Generate one random 32-byte enrollment key as 64 hex characters. Securely
   supply the same key on every node at `/etc/autonomous-rke2/enrollment-secret`,
   root-owned mode `0600`. Trailing newlines and hex case are normalized;
   placeholders are rejected. Do not generate a different key on each node.

   The [cloud-init fragment](../configs/site-cloud-init.example.yaml) shows the
   file and service restart. Replace its placeholder and combine it with site
   hostname/network settings. A protected local NoCloud ISO/disk or customization
   step requires no external cloud-init server. Never commit real secrets or
   initialized disks.

3. Preserve the image-generated `/etc/autonomous-rke2/node.json`: it contains
   actual offline payload hashes. Do not replace them with documentation values.
   The node service is enabled but conditional on config and secret. Native
   RKE2 units remain masked/stopped until the node agent selects a role.

4. Boot the first new node alone. Its default startup grace is 30 seconds;
   image imports and control-plane readiness take additional time. On its console:

   ```bash
   sudo systemctl status autonomous-rke2-host-agent.service
   sudo journalctl -u autonomous-rke2-host-agent.service -n 100 --no-pager
   sudo /usr/local/libexec/autonomous-rke2/host-agent -health
   ```

   Wait for a successful health check. It observes the API, immutable marker,
   Node readiness, and local etcd for servers; saved journal status alone does
   not establish health.

5. Boot additional prepared nodes. Reservations serialize joins; no manual token
   or role copying is needed. Servers enroll through discovered healthy servers;
   workers receive only worker credentials and limited read-only health access.
   Check each node's health and expected cluster membership. For managed target
   changes and retirement, follow [scaling](scaling.md).

### Verify membership

On a healthy server, use the bundled client and native kubeconfig:

```bash
sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes -o wide
```

Expect the intended nodes to be `Ready`, with the first three admitted nodes as
servers and subsequent nodes as workers. Node names need not encode roles.
Authenticated discovery cannot distinguish an empty network from a partition;
first-node-alone is a formation prerequisite, not a global election guarantee.

## Export for physical hosts

From the checkout root, with signing credentials and the verified published
release available, choose a new output directory:

```bash
python3 -B lab/packer/images.py export --input /path/to/release/release.json --output /path/to/new-raw-export
```

This produces `node.raw` and signed `export.json`, checks geometry, and compares
raw contents against the source disk. It writes a new directory, not a block
device. Before site-specific imaging, verify signatures and identify the intended
target disk; imaging overwrites that disk. Supply the same enrollment file and
local networking customization afterward.

Raw export does not establish bare-metal compatibility. UEFI, NIC/storage
drivers, and cloud-init behavior still need representative hardware tests.

## Restart existing nodes

Preserve `/var/lib/autonomous-rke2` identity, journal, and credentials, and
`/var/lib/rancher/rke2` data. On reboot, the node restores its recorded cluster
and starts existing control data in restricted recovery. Live quorum-backed
authorization must validate its role generation before full control services
start. A replaced control returns as a worker. Native RKE2 units are not an
independent boot path. See [automatic control recovery](self-healing.md).

Restart enough existing voters for etcd quorum. The first-node-alone rule applies
to new formation, not recovery of an existing three-server cluster.

Missing completed data, changed address/interface, fingerprint, or runtime policy,
multiple cluster UUIDs, and changed Node/etcd IDs stop convergence. Pending joins
remain reserved for their original identity; they never expire into reusable
slots. Resume the same node. A failure during the two-server stage may prevent
quorum until that node returns. Do not erase journals or reset etcd to force a join.

Reader and enrollment TLS certificates renew under the same host keys. Site-key
and CA rotation, abandoned reservation reconciliation, and upgrades need future
procedures. Opt-in recovery can promote existing workers while quorum remains;
it cannot reset quorum, provision machines, or repair missing initialized disks.
Lab teardown remains a separate host-side operation.

## Related information

- [Architecture](architecture.md) and [trust boundaries](trust-and-threat-model.md)
- [Troubleshooting](troubleshooting.md)
- [Remaining work](open-questions.md)
