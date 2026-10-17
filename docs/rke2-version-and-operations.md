# RKE2 release and node operations

Pins: Rocky 9.8 and RKE2 v1.37.1+rke2r1, using vendor-signed RPM dependency closures and matching core/Flannel archives. Image and disposable-cluster results are tracked in `docs/offline-image-results.md`. Production lab bootstrap and RHEL validation remain deferred. Never use `latest` for reproducible installs.

## Official references reviewed 2026-10-16

- RKE2 support matrix for v1.37: https://www.suse.com/suse-rke2/support-matrix/all-supported-versions/rke2-v1-37/
- RKE2 release notes v1.37: https://docs.rke2.io/release-notes/v1.37.X
- RKE2 install/RPM methods: https://docs.rke2.io/install/methods
- RKE2 SELinux: https://docs.rke2.io/security/selinux

Compatibility finding checked 2026-10-16: the official v1.37 support matrix lists Rocky Linux x86_64 in the RHEL/Rocky/Oracle/Amazon grouping for minor releases 9.6 and 9.8; footnote 11 says those combinations are considered validated as part of RHEL testing. The matrix includes RKE2 v1.37.1+rke2r1. Rocky Linux 9.8 is the latest GA 9.x image found in the official Rocky repository, with candidate GenericCloud Base image `Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2`. Therefore use Rocky 9.8 / RKE2 1.37.1+rke2r1 as the initial candidate pair, subject to checking RPM availability, signing metadata, exact support-matrix revision, and security advisories immediately before installation. The v1.37 matrix does not list 9.7, so do not infer it is supported for that release.

RKE2 RPM installation supports RHEL 9 and signed packages in `rpm.rancher.io`; the documented repository is under `/etc/yum.repos.d`, configured with GPG checks. It provides the `rke2-server` or `rke2-agent` systemd unit. RKE2 SELinux documentation says Enforcing mode is supported on RHEL derivatives including Rocky; RPM installs `rke2-selinux` and sets SELinux enabled via role-specific sysconfig, but this project also explicitly writes `selinux: true` in `/etc/rancher/rke2/config.yaml` and verifies package, loaded policy, config, Enforcing state, and process context. The policy RPM conflicts with `k3s-selinux`. RPM method is preferred for EL9 here; tarball install requires explicit policy setup before RKE2 and is not the selected initial path.

Official install guidance requires NetworkManager to ignore CNI-managed interfaces; configure and validate a persistent EL9-compatible setting. Record the configuration and verify it survives reboot.

## Required validation before choosing an RKE2 release

- Record exact RKE2 release and support-matrix evidence for Rocky Linux 9 and RHEL 9.
- Record repository URL/channel, signing key fingerprint, GPG behavior, version pin syntax, and package artifacts.
- Confirm embedded-etcd server bootstrap/join, agent registration, server workload scheduling, configuration fields, and role transition procedure.
- Preserve the OS profile's active/enabled firewalld policy and RKE2 profiles' inactive/disabled policy. Verify host-side isolation. Future production networking must separately account for TCP 9345/6443 and applicable CNI/etcd traffic.
- Confirm kernel modules/sysctl requirements for Rocky 9 and any additional EL9 package requirements.
- Confirm etcd health/member add/remove and disaster-recovery instructions for exact release. Automatic quorum reset remains disabled.

## Rocky node checks (future lab gate)

Capture OS release, SELinux Enforcing state, installed role/policy RPMs, loaded policy, firewalld active/enabled states, masked RKE2 unit states, and image/release pins. Query firewalld rules only on the active OS profile. Package queries for the opposite role may report not installed. Unjoined replacements keep RKE2 stopped; validate API Ready, system workloads, DNS, and cross-node traffic only in the explicitly authorized disposable smoke cluster. Its static service-subnet route is supplied by test metadata and adds no default route.
