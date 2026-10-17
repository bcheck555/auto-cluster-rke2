# Component contracts (implementation blueprint)

These Go signatures define component boundaries. Identity and journal filesystem
implementations now exist; see [durable storage](durable-state.md). Authenticated
discovery and bootstrap authority are [implemented](bootstrap-authority.md);
the initial host-agent/authority daemons now exist. Membership and concrete
fencing providers remain pending. Keep interfaces narrow so unit tests can inject
deterministic fakes without invoking system services. Every method accepts
context, returns typed errors, and must avoid logging secrets.

```go
package identity

type HostIdentity struct {
    ID string
    PublicKey []byte
    CreatedAt time.Time
}

type Store interface {
    LoadOrCreate(ctx context.Context) (HostIdentity, error)
}

type Signer interface {
    Store
    Sign(ctx context.Context, message []byte) ([]byte, error)
}
```

Identity storage must use an atomic create/rename or equivalent concurrency-safe operation, restrictive permissions, and private key material not exposed by `HostIdentity` serialization. Host identity and OS `machine-id` are distinct values.

```go
package discovery

type EndpointHint struct {
    Address string
    Port uint16
    Transport string
    ClusterID string // public identifier only; not proof of authority
    ObservedAt time.Time
}

type Provider interface {
    Discover(ctx context.Context) ([]EndpointHint, error)
}
```

An `EndpointHint` has no credential field by design. The caller must authenticate the advertised endpoint and validate its cluster identity against a trusted authority before using it.

```go
package bootstrap

type BootstrapRequest struct {
    HostID string
    PublicKey []byte
    PolicyDigest string
    RequestID string
    IssuedAt time.Time
    Signature []byte
}

type BootstrapGrant struct {
    AuthorityID string
    ClusterID string
    HostID string
    OperationID string
    PublicKey []byte
    PolicyDigest string
    IssuedAt time.Time
    ExpiresAt time.Time
    Signature []byte
}

type JoinGrant struct {
    AuthorityID string
    ClusterID string
    HostID string
    Role string
    OperationID string
    PublicKey []byte
    PolicyDigest string
    IssuedAt time.Time
    ExpiresAt time.Time
    Signature []byte
}

type Authority interface {
    AuthorizeBootstrap(ctx context.Context, req BootstrapRequest) (BootstrapGrant, error)
    AuthorizeJoin(ctx context.Context, clusterID string, req BootstrapRequest) (JoinGrant, error)
    VerifyBootstrapGrant(ctx context.Context, grant BootstrapGrant) error
    VerifyJoinGrant(ctx context.Context, grant JoinGrant) error
}

type Consumer interface {
    ConsumeBootstrapGrant(ctx context.Context, grant BootstrapGrant) error
    ConsumeJoinGrant(ctx context.Context, grant JoinGrant) error
}
```

Authority persists issuance and consumption with cluster identity atomically;
callers handle replay as denial. Verification alone does not authorize execution;
consume the exact grant through an authenticated executor first. Never place an
RKE2 token in discovery data or grant audit output.

```go
package fencing

type PowerState uint8
const (
    PowerUnknown PowerState = iota
    PowerOn
    PowerOffConfirmed
)

type Target struct { HostID string; DomainUUID string }
type Evidence struct {
    Target Target
    State PowerState
    ObservedAt time.Time
    Backend string
    OperationID string
    EvidenceID string
}

type Fencer interface {
    Inspect(ctx context.Context, target Target) (Evidence, error)
    Fence(ctx context.Context, target Target, operationID string) (Evidence, error)
}
```

Only exact identity-checked `PowerOffConfirmed` evidence from the configured trusted backend permits replacement. `PowerUnknown`, timeout, unreachable libvirt, stale timestamp, or API error never qualifies. No-fencing backend always returns an error for `Fence`.

```go
package state

type Operation struct {
    ID string
    ClusterID string
    HostID string
    Kind string
    Phase string
    Revision uint64
    UpdatedAt time.Time
    Details string // strictly decoded, redacted caller checkpoint JSON
}

type Journal interface {
    Get(ctx context.Context, operationID string) (Operation, error)
    CompareAndSwap(ctx context.Context, expectedRevision uint64, next Operation) error
}
```

Journal updates must be durable and compare-and-swap by revision so concurrent agents/controllers cannot silently overwrite an operation. Treat conflicts as re-read/reconcile, not blind retry of side effects.

## Implementation notes

- Replace package-specific `time.Time`/`context.Context` imports as usual; snippets omit imports only for brevity.
- These signatures deliberately do not expose `exec.Command`, shell strings, libvirt handles, or tokens.
- The first code slice should test journal/identity atomicity. Subsequent TDD slices cover authority replay, discovery authentication, and fencing evidence validity.
- Before source implementation, run tests with pinned Go toolchain and a test that fails before introducing each API/behavior.
