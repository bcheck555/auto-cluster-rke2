# Cluster configuration reference

This reference describes the current libvirt create/destroy scripts. Start with
the [lab lifecycle](lab-lifecycle.md) for a complete deployment.

## Files and ownership

| File | Purpose | Lifecycle |
| --- | --- | --- |
| `clusters/NAME.yaml` or `NAME.yml` | Public settings | May be committed; never overwritten/deleted by lifecycle scripts |
| Same directory/basename, `NAME.env` | Private enrollment input | Git-ignored; never overwritten/deleted by lifecycle scripts |
| `clusters/cluster.yaml.example` | Public template | Committed; excluded from reservations |
| `clusters/cluster.env.example` | Private-input template | Committed; no real key |
| Generated cluster directory | Disks, credentials, kubeconfig, state | Removed by destroy |

Keep inputs outside generated directories. The YAML `cluster` value selects
runtime identity, not the filename. `--init-secrets` creates an absent paired
`.env` only; it refuses existing files.

## YAML schema

Copy [the commented template](../clusters/cluster.yaml.example). Relative
`release` paths resolve from the YAML directory, not the shell directory.

| Field | Required | Default or constraint |
| --- | --- | --- |
| `schema` | Yes | Integer `1` |
| `cluster` | Yes | Stable identity and generated resource scope |
| `hostname_prefix` | No | `rke2-CLUSTER-node`; special default `lab` uses `rke2-node` |
| `release` | Yes | Signed universal `release.json` path |
| `nodes` | Yes | Positive integer; current image catalog limit 1,024; host/subnet limits also apply |
| `health_timeout` | No | `1200` seconds; `1..86400` |
| `vm.vcpus` | No | `4`; `2..256` |
| `vm.memory_mib` | No | `8192`; `4096..1048576` |
| `vm.disk_gib` | No | `60`; `32..4096`; at least the image size |
| `network` | Yes | Mapping with explicit subnet |
| `network.name` | No | `autonomous-rke2-CLUSTER`; special `lab` uses `autonomous-rke2-isolated` |
| `network.subnet` | Yes | Canonical RFC1918 IPv4 subnet, `/28` or larger |
| `network.reserved_cidrs` | No | Empty list; extra IPv4 ranges node subnets must avoid |

Names must pass script validation. Hostnames append an index (`dev-node01`,
`dev-node02`, …); growing indices must fit the 63-character DNS limit. Use short
lowercase names with digits/hyphens and run plan to validate actual values.

The loader rejects unknown fields, duplicate keys, aliases, unsafe tags, invalid
types, and configs over 64 KiB. Config mode cannot mix deployment override flags;
`--timeout` remains allowed as an operational override.

## Private input format

Only `ENROLLMENT_SECRET` is accepted: 32 random bytes represented as 64 hex
characters. All nodes in one deployment receive the same key. Use independently
initialized keys for different deployments.

The [.env template](../clusters/cluster.env.example) documents manual setup.
The file must be regular, root-owned, mode `0600`, at most 16 KiB, and not a
symlink. Blank lines, full-line comments, and paired quotes around the value are
accepted. Shell expansion, `export`, inline comments, duplicate/unknown variables,
and shell evaluation are rejected. Values are never printed.

Create normalizes hex case and refuses a key differing from saved state. Restore
the original key or deliberately destroy/recreate. Deleting the `.env` is not
rotation. Destroy neither reads nor requires it. Running-cluster site-key
rotation is not implemented.

## Addresses and reservations

The hypervisor uses subnet +1; nodes use +11 onward, ending before broadcast.
Address capacity is `subnet address count - 12`:

| Subnet | Node address capacity |
| --- | --- |
| `/28` | 4 |
| `/24` | 244 |
| `/23` | 500 |

Image and host limits can be smaller. The first three nodes are servers; larger
counts add workers. The catalog ceiling is not a tested scale guarantee;
[recorded acceptance](universal-image-results.md) covers four nodes and
[larger-scale discovery validation](open-questions.md) remains outstanding.

Every real `.yaml`/`.yml` in the selected config directory reserves cluster
identity, hostname prefix, network name, subnet, and explicit reserved CIDRs.
Reservations remain after stop/destroy. Other folders are not scanned. Invalid
or conflicting siblings block create, plan, and secret initialization. Destroy
skips sibling validation. Retire obsolete configs manually.

Create checks both directions of overlap against active/inactive libvirt network
addresses/routes, host IPv4 interfaces/routes in all tables (except default
routes), and fixed image Kubernetes CIDRs:

- Pods: `10.42.0.0/16`.
- Services: `10.43.0.0/16`.

Add invisible remote Kubernetes/VPN ranges to `network.reserved_cidrs`. Scripts
do not query remote Kubernetes APIs. Isolated clusters can reuse Kubernetes
CIDRs; routing pods/services between clusters needs configurable CIDRs, which
are not implemented.

## Generated resources

| Resource | Cluster `dev` |
| --- | --- |
| Example VM names | `dev-node01`, `dev-node02`, … |
| Pool name | `autonomous-rke2-dev` |
| Storage directory | `/var/lib/libvirt/images/autonomous-rke2-dev` |
| Example network | `dev-private` |
| Bridge | Stable hash-based `br-rke2-…` name |
| Filter | `autonomous-rke2-dev-ipv4-only` |
| Operator key / SSH host records | `operator` / `known_hosts` inside storage directory |
| Admin kubeconfig | `admin.yaml` inside storage directory |
| Root-only saved state | `universal-lab.json` inside storage directory; includes key copies |

Default cluster `lab` retains pool/directory `autonomous-rke2-lab`, bridge
`virbr-rke2`, network `autonomous-rke2-isolated`, and filter
`autonomous-rke2-ipv4-only`. Cleanup recognizes historical role-based names.
Runtime names retain `autonomous-rke2` despite the project rename.

## CLI options

Run from the checkout root; absolute script paths work from other directories.

```bash
python3 lab/libvirt/create.py --help
python3 lab/libvirt/destroy.py --help
```

| Option | Command | Meaning |
| --- | --- | --- |
| `--config PATH` | Both | Public YAML and paired private input |
| `--plan` | Both | Inspect without provisioning/deleting |
| `--init-secrets` | Create | Create absent `.env`; config mode only |
| `--timeout SECONDS` | Create | Health wait override |
| `--confirm-cluster NAME` | Destroy | Confirmation matching cluster name |
| `--confirm-lab POOL` | Destroy | Legacy confirmation matching the selected storage pool name |
| `--cluster NAME` | Both, CLI mode | Resource scope; default `lab` |
| `--hostname-prefix PREFIX` | Both, CLI mode | Role-neutral name prefix |
| `--network NAME` | Both, CLI mode | Owned isolated network; does not attach to existing network |
| `--subnet CIDR` | Both, CLI mode | Node network |
| `--reserved-cidr CIDR` | Both, CLI mode | Repeatable extra reservation |
| `--release PATH` | Create, CLI mode | Signed release |
| `--nodes COUNT` | Create, CLI mode | Positive count |

CLI-only create can choose an unused private `/24` or larger if subnet is omitted.
YAML requires an explicit subnet. CLI-only deployments keep existing runtime
secret behavior; use config mode for durable source inputs.

Scripts share the image/lab operation lock. Release, count, resource, or network
changes require recreation. Historical `replace.py` and `lab-config.example.json`
target separate-role images, not the universal-image lifecycle.
