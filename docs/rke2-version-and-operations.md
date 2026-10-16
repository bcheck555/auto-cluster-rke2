# RKE2 release and node operations

Status: candidate selected for the initial Rocky lab; no VM install has occurred. Recheck official support matrix, security advisories, repository availability, signatures, and exact artifact versions immediately before provisioning. Never use `latest` for reproducible installs.

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
- Confirm required firewalld protocol/ports from current official docs, including registration TCP 9345 and Kubernetes API TCP 6443, plus CNI/etcd requirements applicable to selected config.
- Confirm kernel modules/sysctl requirements for Rocky 9 and any additional EL9 package requirements.
- Confirm etcd health/member add/remove and disaster-recovery instructions for exact release. Automatic quorum reset remains disabled.

## Rocky node checks (future lab gate)

Capture actual outputs for: `cat /etc/os-release`; `getenforce`; `sestatus`; `rpm -q rke2-server rke2-agent rke2-selinux container-selinux`; `semodule -l | grep rke2`; `systemctl is-active firewalld`; `firewall-cmd --list-all`; `grep -Fx 'selinux: true' /etc/rancher/rke2/config.yaml`; and `ps -eZ | grep 'rke2 \(server\|agent\)'`. Package queries for the opposite role may report not installed; test the selected role explicitly. Validate node API Ready and etcd health separately.
