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
