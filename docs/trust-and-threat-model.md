# Trust boundaries

Every deployment receives one high-entropy 32-byte enrollment secret encoded
as 64 hex characters, shared across its node clones. Generic published images never contain
it. Provide it through a protected image customization or cloud-init seed,
root-owned mode 0600. Possession authorizes initial membership; protect it as
cluster-sensitive material. There is no external signing authority at runtime.

Discovery messages carry an Ed25519 host signature and HMAC with domain
separation, a deployment fingerprint, timestamp, and random challenge. Replies
must echo the probe challenge and match their actual source address. The host
ID hashes the public key. TLS certificates must match that key and advertised
address. UDP contains public metadata only; sizes and peer counts are bounded.

Enrollment uses TLS 1.3 with the discovered certificate as an explicit trust
anchor. Requests are signed, deployment-authenticated, fresh, and bound to the
connecting IPv4 address. Redirects, proxy environment inheritance, unbounded
responses, and unauthenticated enrollment are rejected. Retries/replays of a
valid initial request remain bound to the same durable reservation.

A deployment member holding the shared secret can claim a fresh identity.
The secret is therefore admission trust, not protection against compromised
members. A malicious trusted initial member could receive a server role.
Enrollment is not a separate administrator approval workflow. Secrets alone do
not isolate VXLAN traffic; use the intended deployment network boundary.

Role assignment and completion use one Kubernetes ConfigMap protected by etcd
quorum and resourceVersion CAS. Missing versions, conflicting cluster/policy
markers, and API failures do not permit a new reservation. Only one initial
member may be pending. A response lost after reservation cannot assign a
different role or let another host take that slot.

Server tokens are returned only for server reservations. Worker tokens use the
dedicated `node:` identity and are checked against the cluster CA hash. Server
agent-token files contain the underlying worker password. Worker health
certificates grant readiness/node/cluster-marker reads, with no administrative
group. CA signing keys and host private keys never cross enrollment APIs.
Reader certificates renew through the same authenticated membership service
without changing registration secrets or cluster roots. Node enrollment TLS
certificates rotate before expiry under the same persistent host key.

Identity, journal and credentials use private directories, atomic writes,
checksums and local execution locks. Public journal details contain no tokens
or private keys. Deployment fingerprint, runtime policy, node name, interface,
address, role and cluster identity are checked on resume. Offline payload pins,
SELinux, native service masks, and configuration are checked before starting.
Neither role is enabled to bypass journaled boot decisions.

Absent multicast does not prove absence of a cluster. First-node-first is an
operational trust assumption, not distributed consensus. Partitioned fresh
nodes may create competing clusters. Existing nodes never bootstrap on quorum
loss; conflicting deployments stop. There is no automatic destructive recovery
or implicit fencing. Compromised root/admin access, deployment-key rotation,
cluster-CA rotation, and recovery from lost durable state require separately
designed procedures.

Artifact signatures are an independent build/distribution trust boundary.
They do not require an online signing server when nodes boot. Historical
authority-backed code is not used by the universal node service.
