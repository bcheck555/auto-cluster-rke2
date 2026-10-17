# Authenticated discovery and bootstrap authority

The Go packages now implement a local file-backed authority, signed HTTPS
discovery, mutual-TLS grant APIs, and clients. No authority daemon, CA, trust
anchor, network route, host service, or guest configuration has been deployed.
The existing isolated VM network remains unchanged. Production still requires
an independently operated redundant authority and key-rotation design.

## Provisioned trust and enrollment

Provision the authority's persistent Ed25519 identity, its public signing key,
server/client certificate authorities, host client certificates, and an explicit
`bootstrap.Policy` allowlist. Each host's ID is the SHA-256 digest of its public
key. `HostPolicy` binds that key to `server` or `agent` and separately permits
initial bootstrap. Only server enrollments may bootstrap. Policy is copied at
construction and its canonical JSON SHA-256 digest is pinned in authority state,
requests, grants, discovery statements, and host cluster pins. There is no
discovery-based enrollment, role election, promotion, or automatic policy update.

`identity.FileStore.Sign` uses an existing key without exporting or regenerating
it. `identity.NewCryptoSigner` adapts the key to TLS; provision a client
certificate for its public key and use the adapter as `tls.Certificate.PrivateKey`.
The client CA certificate and authority signing key serve distinct purposes.

Construct `bootstrap.NewFileAuthority(ctx, Config{...})` with a persistent signer,
an absolute state directory, enrollment policy, and HTTPS origin. Identity-key
and authority-state directories must be distinct and have trusted ancestors;
custom signers must not re-enter the authority's directory lock. The endpoint
cannot contain credentials, a non-root path, query, or fragment. A trailing slash
is normalized away. [Durable storage requirements](durable-state.md) apply.

Call `Initialize` explicitly during operator provisioning. It reserves one
random cluster UUID and records the signing-key fingerprint, policy digest, and
endpoint. Repeated initialization reads existing state. Requests never initialize
missing state, and corrupt or mismatched state is rejected. Never delete state,
roll back its snapshot, change the allowlist in place, or initialize automatically
at daemon startup to recover from an error: doing so could erase replay evidence.

## Discovery and cluster identity

`discovery.StaticProvider` accepts provisioned endpoints. `DNSProvider` adapts
explicit DNS-SD SRV lookups (`_auto-cluster._tcp`) into untrusted endpoint hints.
An mDNS browser can implement `Provider`; native multicast browsing and exact-L2
VM validation remain host-agent integration work. Go's DNS resolver does not
browse mDNS automatically. Empty discovery never selects a bootstrap action.

`discovery.Handler` serves only `GET /v1/cluster-identity?challenge=<64 hex chars>`
over TLS. Its signed response binds the fresh random challenge, authority key,
cluster UUID, policy digest, endpoint, activation status, and one-minute validity.
It contains no grants, RKE2 tokens, or private keys. `HTTPProbe` requires explicit
TLS roots and TLS 1.3, presents no host certificate, disables redirects/proxy
inheritance, limits response size, and bounds network timeouts.

`Resolver.Resolve` authenticates hints with TLS, the independently pinned signing
key/policy verifier, and a fresh challenge. It atomically persists the first
signed cluster identity, then rejects subsequent mismatches and corrupt pins.
It tries at most 32 hints with two-second probes and a ten-second overall budget.
Its optional audit callback exposes only public endpoints and fixed decision
codes. Malformed, unsigned, replayed, expired, and wrong-cluster responses yield
no verified endpoint or new trust record. A verified inactive identity describes
the authority's reserved cluster; it does not authorize initialization.

## Grant issuance, execution, and replay

Use `bootstrap.SignRequest` to sign a fresh operation ID, host identity, and
policy digest. Requests expire after two minutes with at most five seconds of
future clock skew. Authority verifies enrollment and proof of key possession.
Clocks must be synchronized; expiration never triggers a replacement grant.

Bootstrap issuance atomically persists one signed grant together with the
cluster UUID. Concurrent candidates obtain exactly one grant; every later
bootstrap attempt is denied, including after expiration or restart. Grants bind
authority, cluster, host public key, operation, policy, issuance, and expiration;
join grants additionally bind the allowlisted role. Default lifetime is two
minutes, configurable up to five. JSON signatures use distinct versioned message
domains for requests, bootstrap grants, join grants, and advertisements.

`Verify*Grant` checks signatures and validity only. `Consume*Grant` is the atomic
single-use execution gate; persist the host operation and grant before consuming,
and consume before executing side effects. The authority records consumption
before acknowledging success. Local consumers are trusted executors acting for
the bound host. Remote consumption additionally requires its verified client key.
A consumed, expired, lost, or ambiguously acknowledged grant requires inspection
and operator reconciliation; these APIs never blindly reissue it. No RKE2
installation/join action is performed by the authority itself.

Only a trusted local caller may invoke `ConfirmClusterActive`, after independently
proving the bootstrap cluster's identity and health. Consumption alone cannot
activate it. Joins are denied until activation and require the exact cluster ID.
Each enrollment receives at most one initial membership grant, even with a new
operation ID; rejoin/replacement/promotion policy belongs to later membership
work. Failure to reach a previously initialized cluster never permits another.

## Transport and deployment boundary

`bootstrap.HTTPHandler` exposes four POST routes: `/v1/bootstrap`, `/v1/join`,
`/v1/bootstrap/consume`, and `/v1/join/consume`. Every route requires TLS 1.3 and
a verified Ed25519 client certificate whose public key matches the request or
grant host. Requests are size bounded and strictly decoded; errors contain only
fixed codes. Initialization, activation, key access, and command execution are
absent from this handler.

`bootstrap.NewHTTPClient(endpoint, pinnedClusterID, tlsConfig, verifier)` requires
explicit server roots, one host client certificate, and the cluster ID obtained
from verified persistent discovery. Responses must match the host, operation,
cluster, policy, signature, and validity. Network errors return unavailable;
clients never create a local authority or follow redirects.

A future daemon may combine public discovery and grant handlers on one listener
using `tls.VerifyClientCertIfGiven` and provisioned `ClientCAs`. Grant handlers
still require verified certificates; discovery remains public. Set TLS minimum
version and explicit HTTP header/read/write/idle timeouts. Do not expose an
administrative HTTP route. Lab CA/trust provisioning, the filtered authority
communication path, stable RKE2 registration endpoint, and systemd deployment
remain explicit host-agent integration tasks and existing approval gates.

## Validation

Tests exercise three independent concurrent authority processes, restart-stable
UUIDs and consumption, concurrent single-use joins, request/grant tampering,
expiry, missing/corrupt authority state, TLS discovery, challenge replay, signed
cluster resets against persistent pins, malformed/oversized responses, missing
and wrong-host certificates, and unreachable endpoints without bootstrap.
Run `go test -race -timeout 60s ./...`, `go vet ./...`, and `make fmt-check`.
These are host-local tests, not observed VM acceptance scenarios or HA evidence.
