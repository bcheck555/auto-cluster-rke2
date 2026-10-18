# Remaining validation and design work

- Repeat formation and scaling acceptance gates for each new candidate. The
  scaling release has passed them; see [validation evidence](scaling-image-results.md).
  Local unit tests alone do not validate guest SELinux labeling, multicast
  switches, coinstalled RPM behavior, or RKE2 boot ordering end to end.
- Validate raw-image boot and drivers on physical hosts. Disk export exists;
  automatic disk selection/flashing is intentionally not part of node startup.
- Define manual reconciliation for abandoned membership reservations. Pending
  joins currently remain reserved, including server joins interrupted during
  the temporary two-voter stage. No automatic expiry or removal is safe here.
- Specify deployment-secret and Kubernetes CA rotation, stable-address changes,
  and runtime upgrades. These changes currently require explicit reconciliation.
- Define production network isolation and NetworkPolicy behavior. Current
  Flannel policy preserves the existing offline image baseline.
- Validate larger deployments and discovery bounds. Current probes accept at
  most 64 peers; the 1,024-member catalog limit is a data-structure ceiling,
  not evidence of deployment testing at that size. Recorded runtime acceptance
  covers eight nodes, including seven etcd voters.
- Define fencing-backed member replacement and disaster recovery separately.
  Managed libvirt resizing now retires members and replaces roles explicitly;
  no failure-driven replacement, quorum reset, or in-place promotion is automatic.

Settled: one universal image, node-resident coordination, first node booted
alone, common site enrollment secret, configurable control target (default three),
subsequent workers, no external runtime authority or load balancer.
