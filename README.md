# Autonomous RKE2 Cluster

A Go-based host bootstrap agent and membership controller for reproducible RKE2 cluster formation and fail-closed, fencing-backed recovery.

## Guest OS target

Kubernetes lab guests use signed Rocky Linux 9.8 images derived from a verified GenericCloud source. SELinux stays Enforcing. Firewalld stays installed: enabled and active in the OS baseline, stopped and disabled in RKE2 profiles. Production portability targets RHEL 9; validation remains pending. The Ubuntu 24.04.5 LTS development host remains outside the cluster.

## Safety status

Phase 1 and its signed-image replacement are complete. Three lab VMs are running; protected VM/network/pool definitions remain unchanged. Earlier CLI dry-run side effects (`tmp34lvksot`, `tmpm5w4rn5q`) remain untouched and documented in the environment assessment. CLI tests use `test:///default`. See [offline image and replacement results](docs/offline-image-results.md) for validation, hashes, and rollback evidence.

## Current assessment

See [docs/environment-assessment.md](docs/environment-assessment.md). Read-only assessment includes libvirt, routes, storage, and firewall state. Host disk space and existing libvirt resources constrain lab planning; observed inventory drift is documented there.

## Design

See the [implementation roadmap](docs/roadmap.md) for current scope and remaining acceptance gates.

See [docs/architecture.md](docs/architecture.md), [docs/trust-and-threat-model.md](docs/trust-and-threat-model.md), and [docs/state-machine.md](docs/state-machine.md). The system must never form a cluster merely because peers are unreachable; first-cluster creation requires explicit trusted bootstrap authority. Quorum loss or unconfirmed fencing halts destructive recovery.

## Lab status

The three Rocky 9.8 guests now use the signed RKE2 server image, retain their addresses and resources, and have fresh identities and per-VM UEFI NVRAM. SELinux is Enforcing; firewalld is installed, inactive, and disabled. RKE2 is installed, stopped, masked, and unjoined. The isolated network has no bridge address, DHCP, or forwarding; host/external probes fail and per-NIC filters block IPv6. All profiles and a disposable offline server/agent cluster passed boot/reboot checks. See [current results and rollback](docs/offline-image-results.md); [original Phase 1 evidence](docs/phase1-lab-results.md) remains historical. Do not rerun fresh apply against existing resources.

The SSH key is in ignored `lab/credentials/`; verification evidence is in ignored `lab/results/` and generation directories. Re-verify the pinned upstream source with `python3 -B lab/libvirt/stage_image.py`. Fresh provisioning requires a signed derived release; follow the [offline image workflow](docs/offline-images.md). Deployment performs no package downloads or RPM installation. Run lab checks with `python3 -B -m unittest discover -s tests/integration/lab -v` (67 tests pass).

## Development

The [offline image lifecycle and replacement workflow](docs/offline-images.md)
builds three signed profiles and gates publication and replacement on offline
boot, reboot, and disposable cluster validation. OS images keep firewalld active;
RKE2 profiles keep it installed and disabled. Existing lab replacement status
is recorded separately from candidate build status.

The project Go module is pinned to Go 1.27.2. Install the matching official Go distribution on the host; no repository-local toolchain is required. This development host uses `/usr/local/go`, with `go` and `gofmt` available through `/usr/local/bin`. Run `make test vet fmt-check` and `go test -race ./...` from the repository root. The module path `autonomous-rke2` is provisional until a remote repository namespace is established.
