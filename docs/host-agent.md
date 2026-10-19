# Initial host-agent lifecycle and deployment

Historical authority-backed lifecycle. The current `cmd/host-agent` uses
[universal node formation](universal-node.md); its flags, configuration and
systemd boot path have changed. The following describes the earlier prototype
and must not be used to configure universal images. Current role-generation,
startup-gate, and promotion behavior is documented in
[automatic control recovery](self-healing.md) and [formation states](state-machine.md).

`cmd/host-agent` implements initial convergence on the pinned offline Rocky 9.8
server/agent images. `cmd/bootstrap-authority` serves the existing signed
discovery and mutual-TLS grant APIs. Systemd templates, public configuration
examples, and read-only Kubernetes observer RBAC are tracked under `deploy/` and
`configs/`. No service, route, firewall, certificate authority, guest, or cluster
was deployed by this implementation task. VM acceptance results remain pending.

## Trust and operating boundaries

Bootstrap/join is an explicit configured mode. Role comes from an enrolled-host
signed grant and must match the local plan; no reachability-based election,
promotion, or package-role conversion exists. Supply the authority's reserved
cluster UUID, policy digest, signing public key, TLS CA, and a client certificate
for the host's persistent key. Discovery uses explicit provisioned hints and
persists the signed cluster pin. There is no implicit mDNS/UDP fallback.

The registration origin on TCP 9345 and Kubernetes origin on TCP 6443 must share
one operator-managed stable hostname/IP. Server TLS SAN configuration includes
that name. The agent never selects a registration endpoint from whichever peer
happens to answer, creates a VIP/load balancer, changes routes, or enables a host
bridge address. The authority's separate HTTPS path also needs approved filtering.

The existing VM network has no host L3 address, DHCP, or forwarding. Resolve that
deployment decision and provision trust before running either service in the
lab. At this prototype stage, production bootstrap, expansion, and host
package/service changes required a separately reviewed rollout. Building these
binaries did not authorize expansion to five VMs, replacement, cleanup, fencing,
or quorum reset. These are historical rollout boundaries; use the current
[lab lifecycle](lab-lifecycle.md) for universal-image deployment instructions.

## State transitions and interruption

One private execution lock serializes all agent instances on a host. The
revision-guarded journal stores one `initial-<full host ID>` operation with these
phases:

`AwaitingAuthority -> Authorized -> Consuming -> Consumed -> Configured -> Starting -> Healthy`

The checkpoint includes the public grant, plan/credential fingerprints, Node
UID, and observed etcd cluster/member IDs. It never contains registration tokens,
private keys, or command output. `state.Operation.Details` holds this strictly
decoded checkpoint JSON. Config or credential drift, unknown phases, mismatched
identities, corrupt state, or pre-existing unmanaged RKE2 data halts convergence.

The agent queries fresh, authority-signed grant status for the exact host,
operation, and random challenge. Lost issuance responses recover the existing
grant. Consumption intent is journaled before consumption; lost consumption
responses recover the exact consumed grant without issuing or consuming another.
A consumed grant can support resumption after its original expiration only with
fresh signed consumption evidence. An expired unconsumed grant requires an
operator. The authority never recreates missing state in response to these calls.

Config/manifests are written atomically before journaling `Configured`. `Starting`
is journaled before unmask/start. Interrupted preparation repeats only verified
file writes; interrupted startup inspects the same known config/data before
starting the fixed unit again. Agent process restarts leave an already running,
healthy RKE2 service intact and re-check its Node and etcd identities.

A stopped/returning RKE2 service whose checkpoint is already `Healthy` deliberately
halts for membership reconciliation. Native RKE2 units remain disabled at boot;
hidden enablement links beneath masks are rejected. This implementation does not
automatically restart a previously healthy member after a guest reboot or decide
whether an old member may return after replacement. That decision needs the
membership controller/fencing work. Do not count full guest reboot or returning
node acceptance scenarios as passed by these host-local tests.

## Offline runtime and credentials

The adapter validates Rocky 9.8, the configured interface/address, SELinux
Enforcing, installed firewalld with inactive/disabled state, persistent
NetworkManager CNI exclusions, RKE2 `v1.37.1+rke2r1`, role RPM
`1.37.1~rke2r1-0.el9.x86_64`, and `rke2-selinux` `0.23-1.el9.noarch`.
It requires the opposite role masked/inactive and rejects config drop-ins or
unmanaged role environment settings. It runs no package manager or installer.

Preparation streams SHA-256 verification of the pinned core/Flannel archives
already under `/var/lib/rancher/rke2/agent/images/`. Supply expected digests from
the reviewed signed release inputs, not an untrusted node's self-report. The
retained offline CoreDNS HelmChartConfig is independently checked and copied;
Flannel uses the configured interface and VXLAN with NetworkPolicy deferred.

RKE2 config is generated as JSON, accepted as YAML, with `selinux: true`, fixed
cluster/service CIDRs, identity labels, protected token-file paths, and no server
scheduling taint. A wildcard loopback registry sink plus
`disable-default-registry-endpoint` blocks remote image-pull fallback; required
images must already be imported from the offline archives. Existing unmanaged
registry/config/Helm override files are never silently replaced. See the official
[server configuration](https://docs.rke2.io/reference/server_config),
[registry mirror/fallback rules](https://docs.rke2.io/install/private_registry),
and [air-gap installation](https://docs.rke2.io/install/airgap) references.

Provision separate strong server and agent credentials as private regular files
with no group/other permissions beneath trusted, non-writable ancestors. First
bootstrap accepts a strong initial token. Join requires the CA-pinned `K10`
secure format and the appropriate `server:` or `agent:` credential, with at least
32 password characters. Server plans additionally supply the same separately
provisioned agent secret on every server. The runtime does not distribute or log
these credentials. See [RKE2 token formats](https://docs.rke2.io/security/token).

The executor builds fixed argument arrays for RPM queries, RKE2 version,
getenforce, and fixed-unit systemctl queries/unmask/start. Child environments
exclude inherited credentials; stdout is bounded and never logged, stderr is
discarded. No shell, arbitrary command, stop, enable, data deletion, member
removal, or reset operation is exposed. Errors/logs contain fixed status text.

## Independent health evidence

Health uses authenticated TLS 1.3, explicit CA/client credentials, bounded HTTP,
and no redirects/proxy inheritance. Servers use their local RKE2 admin identity;
workers use a separately provisioned `autonomous-rke2-health` client certificate
and [read-only RBAC](../deploy/kubernetes/host-health-reader.yaml). No worker
receives admin/etcd credentials through this implementation.

Checks require API readiness, the exact Node UID, host/cluster labels, address,
signed role, Node Ready, and schedulability. Host labels use the first 32 hex
characters of the host ID to fit Kubernetes label limits; the full public-key
identity remains bound by the authority and private journal. Server checks
separately require local etcd readiness, a leader, consistent etcd cluster/member
IDs, exactly one matching local voting peer, and the configured minimum voters
(at most three). Kubernetes Node Ready alone never establishes etcd health.
The etcd [monitoring endpoints](https://etcd.io/docs/v3.6/op-guide/monitoring/)
are the upstream basis for readiness checking.

Only the consumed-grant bootstrap operation, after Node and etcd checks pass, may
create `kube-system/autonomous-rke2-identity`. This immutable ConfigMap binds the
cluster UUID, policy digest, and full bootstrap host ID. Join/healthy/read-only
checks require the existing exact marker and never create or overwrite it.
Changes to the observed Node UID or local etcd cluster/member ID halt the agent.

## Preparing a reviewed rollout

1. Build with `make build`; outputs are ignored `bin/host-agent` and
   `bin/bootstrap-authority`. Builds target Linux amd64 with CGO disabled.
   Review the [host](../configs/host.example.json) and
   [authority](../configs/authority.example.json) examples. Placeholders are
   intentionally invalid; no real credentials are tracked.
2. Before any RKE2 startup, enroll each host using
   `host-agent -enroll -identity-directory /var/lib/autonomous-rke2/identity`.
   Save its public JSON outside source control. It includes an Ed25519 CSR;
   issue a client-auth certificate for that CSR using the approved host-client
   CA, keeping the host private key in its original store. Enroll all intended
   hosts/roles in the authority allowlist before initializing its immutable policy.
3. Provision the authority's independent server certificate/key, host-client CA,
   private config, filtered listen address, and state parent. Run
   `bootstrap-authority -config <private-config> -initialize` explicitly once.
   Save the returned public cluster UUID, policy digest, and signing key; distribute
   them with reviewed host plans and server CA roots. Normal service startup
   reads existing authority state and never initializes it.
4. Review the [authority unit](../deploy/systemd/autonomous-rke2-authority.service)
   and [agent unit](../deploy/systemd/autonomous-rke2-host-agent.service), install
   reviewed binaries under `/usr/local/libexec/autonomous-rke2/`, and provision
   root-owned private files under `/etc/autonomous-rke2/`. Service installation,
   enabling, and network changes require the existing deployment authorization.
   Run `host-agent -config <private-config> -check` for non-mutating RKE2 preflight.
5. First gate: one server with `Mode: bootstrap`, its enrolled server role,
   `MinVotingServers: 1`, pinned assets, separate strong credentials, and the stable
   registration/API origins. After authorized convergence, capture
   `host-agent -config <private-config> -health` output in ignored `lab/results/`.
   This read-only command reports observed Node UID, etcd cluster/member IDs,
   voting count, and UTC timestamp; failed checks emit no passing report.
6. Independently review that identity/health evidence before the trusted local
   administrative command `bootstrap-authority -config <private-config>
   -confirm-cluster-active <exact-UUID>`. Activation is absent from HTTP. Only
   then may explicitly enrolled join hosts receive initial membership grants.
7. Join two approved server guests sequentially using secure server tokens and
   the same agent secret; require observed voting counts two then three. Stop on
   ambiguity. Provision health-reader RBAC/certificates before later workers.
   The current three guests are server-profile images; worker images and expansion
   to five nodes require the separate capacity/approval gate.

## Validation and remaining execution gates

Host-local suites cover lost issuance/consumption responses, consumed-grant
expiry resumption, concurrent agents, unchanged repeated runs, unsafe data/config
drift, offline digest failures, fixed-unit execution, public CSR binding, mTLS
status access, Node/etcd health separation, and immutable identity handling.
Run `go test -race -timeout 60s ./...`, `go vet ./...`, `make fmt-check`, and
`make build`. Unit templates were syntax-checked with systemd 255 against temporary
built executables; deployment on Rocky's systemd 252 remains untested.

Required live gates remain: approved authority path/stable registration endpoint,
CA/key provisioning, SELinux service execution and exact RKE2/etcd endpoint
behavior on guests, one-server startup, then three voters and approved workers,
reboot/returning-node handling with membership authority, and clean-room runs.
Local mocks and expected outcomes do not satisfy those acceptance gates.
