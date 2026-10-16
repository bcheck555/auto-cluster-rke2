# Autonomous RKE2 Cluster

A Go-based host bootstrap agent and membership controller for reproducible RKE2 cluster formation and fail-closed, fencing-backed recovery.

## Guest OS target

Kubernetes lab guests are Rocky Linux 9 x86_64, provisioned from a pinned Rocky Linux GenericCloud image with cloud-init. Preserve SELinux Enforcing and firewalld. Production portability targets RHEL 9; no portability claim is made until differences are tested and documented. The development host is Ubuntu 24.04.5 LTS and must remain outside the cluster.

## Safety status

This repository is at initial assessment/design stage. No lab VM, network, pool, host service, or host configuration has been created or changed. Existing libvirt resources are protected. Lab provisioning requires a reviewed proposal and explicit approval.

## Current assessment

See [docs/environment-assessment.md](docs/environment-assessment.md). Assessment is partial because this session cannot read privileged firewall state. Host disk space and existing libvirt resources constrain/affect lab planning.

## Design

See [docs/architecture.md](docs/architecture.md), [docs/trust-and-threat-model.md](docs/trust-and-threat-model.md), and [docs/state-machine.md](docs/state-machine.md). The system must never form a cluster merely because peers are unreachable; first-cluster creation requires explicit trusted bootstrap authority. Quorum loss or unconfirmed fencing halts destructive recovery.

## Development

Go toolchain is not currently installed on the development host. Select and pin the build toolchain and module path before the first Go implementation slice. Do not install host packages or alter the host without approval; a verified, repository-local toolchain or approved alternative can be evaluated.
