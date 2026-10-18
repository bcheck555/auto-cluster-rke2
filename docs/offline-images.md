# Offline images

Current builds produce `os.qcow2` plus one universal `node.qcow2`. The node
image coinstalls both RKE2 roles, contains the agent binary and enabled boot
service, and selects its role only at runtime. The signed input includes that
binary, unit and public source snapshot. Fresh candidate validation now boots
four clones from the same disk, verifies automatic formation and reboot, and
gates publication on signed evidence for that image. A published node disk can
be exported as signed raw format without writing a physical device.

Follow [universal node build/deployment](universal-node.md) for current commands,
the common enrollment secret, first-node-first assumptions, and acceptance
requirements. Existing lab machines and prior signed releases remain untouched.

## Historical separate-role image and replacement record

The remainder describes the earlier three-profile release and its completed
Phase 1 replacement. Its separate authority/role requirements are superseded
by the universal-node design. Retain it for historical trust, ownership and
rollback context; it is not the current node startup procedure.

Three profiles share Rocky 9.8, SELinux Enforcing, and a retained signed local
RPM repository. `os` enables and starts firewalld. `server` and `agent` retain
firewalld installed, inactive, and disabled; neither masks firewalld. Both RKE2
units remain masked and stopped until separate bootstrap authorization.

Pins: Packer 1.15.3, QEMU plugin 1.1.4, RKE2 v1.37.1+rke2r1, Flannel VXLAN.
Pod NetworkPolicy enforcement, production bootstrap authority, and RHEL
validation remain deferred. Published images contain no lab addresses,
operator keys, bootstrap grants, cluster certificates, or datastore state.

## Trust and inputs

The dedicated project signing fingerprint is
`F8BE2082B8EF04D441172C055F59BDC3D0E1B573`.
Distribute and compare this fingerprint through an independent trusted channel;
a public key bundled alongside artifacts does not establish trust by itself.
Private signing material stays under `lab/credentials/artifact-signing/gnupg`,
outside bundles, releases, and guests. Keep an independently protected backup.
Verifier configuration uses `AUTONOMOUS_IMAGE_TRUST_DIR`, containing
`trust.json` and `public.gpg`; build/test publication also needs the signing key.

Connected preparation verifies the Rocky source checksum signature, vendor
tool checksum signatures, RKE2 release hashes, and RPM signatures. It records
exact NEVRAs, source locations, repository metadata, vendor fingerprints,
tool pins, workload digest, and every input file hash. Both role dependency
closures remain in each image's `/opt/autonomous-rke2/offline/rpms` repository.
Matching core and Flannel container archives are embedded in RKE2 profiles.
Offline CoreDNS configuration resides in the offline directory and is used by
the disposable smoke cluster; it has no external forwarding plugin.
The upstream staging pin is `lab/libvirt/rocky-source.json`; the deployment
example `lab-config.example.json` binds a derived release instead. For running
replacement nodes, use their generation's `effective-nodes.json` and journal;
fresh apply deliberately refuses existing resource names. New deployments
must generate fresh host identities and verify the independently trusted key.

```sh
python3 -B lab/packer/images.py lock --output lab/artifacts/packer/input-GENERATION
python3 -B lab/packer/images.py bundle --lock lab/artifacts/packer/input-GENERATION/input.json --output /path/to/offline-input.tar
python3 -B lab/packer/images.py build --input /path/to/offline-input.tar --output lab/artifacts/packer/candidate-GENERATION
sudo -n python3 -B lab/packer/images.py test --input lab/artifacts/packer/candidate-GENERATION/candidate.json --output lab/artifacts/packer/candidate-GENERATION/validation.json
python3 -B lab/packer/images.py publish --input lab/artifacts/packer/candidate-GENERATION/candidate.json --output lab/artifacts/packer/release-GENERATION
```

Every generation is immutable. Failed build directories remain unpublished
for diagnosis. `lock --from-lock OLD/input.json --output NEW` creates a new
signed recipe generation using verified cached inputs. Changed package
requirements need a new connected preparation. Bundle extraction rejects
links, traversal, duplicates, oversized archives, and unlisted input files.

Builds use KVM/q35/OVMF and 4 vCPU/8 GiB guests. A fresh network namespace has
only loopback; QEMU's restricted user network exposes temporary SSH solely to
that namespace's loopback. No namespace uplink exists. Packer installs its
plugin from the verified local binary, uses local artifact media and signed
RPMs, seals identities and credentials, and exports standalone 32 GiB qcow2
files bounded to 16 GiB file size. Source image and output profiles never share
writable NVRAM. Disk and RAM preflight reserves remain 300 GiB and 32 GiB,
including current lab disk commitments and temporary guest capacity.

## Validation and release policy

Publication requires a signed successful validation report bound to the exact
candidate manifest digest. Tests boot and reboot all profiles with fresh
NoCloud metadata, UUIDs, SSH host keys, and NVRAM; check package inventories,
operator password locks and keys, SELinux, firewalld, masked RKE2, identities,
and host/external isolation. An ephemeral signing authority authorizes only
the disposable two-node offline smoke cluster. The smoke workload uses a
digest reference and `imagePullPolicy: Never`; checks cover Ready nodes,
system pods, internal DNS, cross-node pod and service traffic, then repeat
after reboot. Test overlays, grants, token, and authority are discarded.

Temporary addresses `.241`–`.243` use the existing isolated network and IPv6
filter after domain/guest/neighbor collision checks. Failed validation never
publishes a release. Serial validation reports contain no bootstrap secrets.
Smoke network metadata includes an on-link `10.43.0.0/16` service-subnet route:
the kernel needs an initial route before kube-proxy can translate Service IPs.
It adds no default route and applies only to the authorized disposable cluster.
Unjoined replacement guests receive no cluster routing or bootstrap settings.
Signed `validation-progress.json` checkpoints preserve completed profile checks
for retries against the same candidate. Private redacted startup diagnostics
remain outside release artifacts.

Normal profile checks execute the helper sealed into each image. Disposable
cluster checks receive a separate test runner through their temporary metadata;
the signed validation report records its SHA-256 alongside the host validator
hash. This permits bounded probe fixes without changing candidate image bytes.
The runner checks service DNS separately from literal Service-IP and Pod-IP
HTTP requests. No test runner override enters replacement guest metadata.

Derived provisioning requires `image.kind=derived`, `release_manifest`,
`release_sha256`, `profile`, `sha256`, `keyring_path`, and
`signing_fingerprint`. Image and node profile, release digest, and firewalld
policy must agree. The project key verifies derived releases; Rocky's key
continues to verify upstream source images. Deployment cloud-init contains
identity, network, operator access, and validation only; it installs no RPMs
and never changes firewalld policy.
Raw upstream images remain verifiable staging inputs; provisioning apply
requires a signed derived profile and rejects an unbaked source before mutation.

## Replacement and rollback

```sh
sudo -n python3 -B lab/libvirt/replace.py plan --release lab/artifacts/packer/release-GENERATION/release.json --output lab/state/packer/replacement-GENERATION.json
sudo -n python3 -B lab/libvirt/replace.py apply --plan lab/state/packer/replacement-GENERATION.json
sudo -n python3 -B lab/libvirt/replace.py rollback --journal /var/lib/libvirt/images/autonomous-rke2-lab/replacement-GENERATION/journal.json
```

Plan output names the actual generation directory; use its journal path.
The signed plan binds current domain UUIDs, MACs, addresses, disks, firmware,
release digest, and generated replacement identities. Apply rechecks ownership,
saves host resource definitions, powers off each old node before reusing its
MAC/address, and validates each new node across reboot before advancing.
Failures restore touched nodes from the journal. UUID/ownership mismatch
halts recovery for inspection. Old definitions, disks, seeds, and firmware
snapshots remain available after success; rollback retains both generations.

All three production lab replacements use `server`, retain names and `.11`–
`.13`, 4 vCPU/8 GiB RAM/60 GiB disks, and remain unjoined with RKE2 masked.
`effective-nodes.json`, per-node validation reports, and `journal.json` record
actual release hashes and identities. Existing lab network/pool/filter are
reused. `hyperv1`, `default`, and pre-existing pools remain outside ownership.

See [execution results](offline-image-results.md) for the published release,
exact digests, completed replacement, observed host differences, and rollback
journal. A candidate alone does not authorize publication or deployment.
