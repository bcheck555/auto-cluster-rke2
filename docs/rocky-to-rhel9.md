# Rocky Linux 9 to RHEL 9 portability ledger

Status: not yet validated. Rocky Linux 9 is the required initial test guest; RHEL 9 is the eventual production target. Do not claim RHEL support based on Rocky-only testing.

| Area | Rocky Linux 9 lab baseline | RHEL 9 production verification required |
|---|---|---|
| Base image | Official Rocky GenericCloud x86_64 image, exact version/checksum pinned | Approved RHEL cloud image source, subscription/entitlement and redistribution terms |
| Package management | DNF/RPM | DNF/RPM; confirm enabled Red Hat repositories and entitlement |
| RKE2 packages | Rancher EL9 RPM repositories with signature verification | Verify exact RHEL 9 support matrix and repository/channel/package compatibility |
| SELinux | Enforcing; `rke2-selinux` and `selinux: true` on all roles | Confirm policy RPM availability/dependencies and process/file labels on RHEL |
| Firewall | firewalld active; explicit verified RKE2 rules | Confirm default zones/services and persist/validate same required traffic |
| Networking | NetworkManager; cloud-init network datasource behavior | Confirm image datasource and NetworkManager keyfile behavior on chosen RHEL image |
| Machine identity | cloud-init resets machine-id/SSH keys and assigns unique names | Verify RHEL image cloning/cloud-init semantics and host key rotation |
| Support lifecycle | Rocky minor release and image support documented when pinned | Red Hat lifecycle, subscription, kernel, and certified support constraints |
| systemd/filesystem | RHEL-compatible service/path usage | Validate exact unit overrides, SELinux labels, and package paths |

Fill each cell with source, tested release, command output, and differences during Phase 6 readiness; label untested entries.
