# Initial decisions, assumptions, and unresolved risks

## Decisions taken

1. Development host is Ubuntu 24.04.5 and remains outside Kubernetes; guests are Rocky Linux 9 x86_64 with SELinux Enforcing and firewalld.
2. Pin an identical Rocky 9.8 GenericCloud x86_64 base image for all test guests; unique identity comes from cloud-init at instance creation. The image is staged locally, with official key fingerprint, detached checksum signature, SHA-256, and qcow2 metadata verified on 2026-10-16.
3. Pin RKE2 v1.37.1+rke2r1 with vendor-signed server/agent RPM closures and matching core/Flannel archives. OS firewalld stays active/enabled; RKE2 variants keep it installed and inactive/disabled. Preserve SELinux Enforcing; defer pod NetworkPolicy enforcement.
4. RKE2 embedded etcd starts at three voting servers; servers remain workload eligible. Two later agents are eligible for controlled promotion.
5. Use authenticated mDNS/DNS-SD only as an endpoint hint on isolated L2; external bootstrap authority establishes cluster authority and UUID.
6. Require positive external fencing before server replacement. Quorum loss and uncertain membership halt; no automatic quorum reset/data deletion.
7. Preserve `hyperv1`, the default libvirt network, and all pre-existing pools. Owner approved the reviewed Phase 1 lab and functional testing; its three VMs, new network/pool, and IPv6 isolation filter are deployed and validated. Further expansion remains gated.
8. No KubeVirt, guest VM workload, or Windows/AD integration in initial cluster milestone.

## Assumptions

- Three VMs are the first validation gate; expand to five only after resource and safety gate.
- Current available RAM and `/var` free space are observations at a single time, not guaranteed reservations.
- The Rocky GenericCloud source is verified and staged under its upstream pin. Deployment independently verifies the signed derived release, signer, profile policy, digest, and qcow2 metadata.
- Host libvirt is reachable via system `virsh` with current user privileges; this does not imply permission to modify resources.
- The Go module path `autonomous-rke2` is provisional until a remote repository namespace is established.

## Open questions / blockers

- Phase 1 replacement is complete on no-forwarding L2 with no bridge IP or DHCP, static addresses `192.168.250.11`–`.13`, and per-NIC IPv6 drops. Signed RKE2 server images are installed, masked, and unjoined; firewalld is inactive/disabled and SELinux Enforcing. Current evidence and rollback are in `docs/offline-image-results.md`.
- `ROTA=1` on the PERC H330-backed disks does not prove whether the actual media is SSD or HDD. What are the physical drive type, RAID virtual-disk/cache policy, and expected IOPS? Do not claim SSD-backed VM disks until known.
- Existing pool `ad-hyperv-lab` reports 701.52 GiB free while `df` on `/var` reports 617 GiB free. Reconcile pool vs filesystem accounting and retain a host reserve before estimating safe disk allocation.
- What external trust anchor will authorize joining hosts in the lab, and how is its private key protected/rotated? A host-local authority would require a separate, explicitly filtered communication path; the chosen VM network has no host L3 address.
- What exact stable registration endpoint will remain reachable through a server replacement? Initial test network currently has no host route/service access; decide a filtered authority path before cluster bootstrap.
- What project license and repository remote/module namespace should be used? No LICENSE has been added pending owner choice.
- Rocky and RKE2 artifact signatures/digests are verified during staging. Publication and replacement require the image and disposable-cluster gates recorded in `docs/offline-image-results.md`; future version updates need a new verified input generation.
- Offline artifacts, three-profile validation, disposable cluster/reboot testing, and sequential replacement passed. Production cluster bootstrap still needs an authority design and stable registration endpoint. Pod NetworkPolicy enforcement and RHEL validation remain deferred.

## Approval gates

Phase 1 approval covered the isolated lab and functional testing despite unverified physical media. The owner also authorized offline image builds, disposable cluster validation, and journaled replacement of the three named Phase 1 VMs. Production bootstrap, expansion, host package/service changes, and unrelated resource changes require separate authorization. No approval for pre-existing pool cleanup is implied.
