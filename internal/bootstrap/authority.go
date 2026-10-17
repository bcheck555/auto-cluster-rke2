package bootstrap

import (
	"context"
	"time"
)

// BootstrapRequest identifies the host and its requested operation; it carries
// no shared join secret.
type BootstrapRequest struct {
	HostID       string
	PublicKey    []byte
	PolicyDigest string
	RequestID    string
	IssuedAt     time.Time
	Signature    []byte
}

type BootstrapGrant struct {
	AuthorityID  string
	ClusterID    string
	HostID       string
	OperationID  string
	PublicKey    []byte
	PolicyDigest string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Signature    []byte
}

type JoinGrant struct {
	AuthorityID  string
	ClusterID    string
	HostID       string
	Role         string
	OperationID  string
	PublicKey    []byte
	PolicyDigest string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Signature    []byte
}

// Consumer is the atomic, single-use execution gate. Signature verification
// alone never authorizes executing a bootstrap or join. Callers must be trusted
// executors authenticated as the grant's host; these methods are local APIs.
type Consumer interface {
	ConsumeBootstrapGrant(context.Context, BootstrapGrant) error
	ConsumeJoinGrant(context.Context, JoinGrant) error
}

// Authority is the pre-cluster trust root. Implementations must persist
// consumed bootstrap grants and the cluster identity atomically.
type Authority interface {
	AuthorizeBootstrap(ctx context.Context, req BootstrapRequest) (BootstrapGrant, error)
	AuthorizeJoin(ctx context.Context, clusterID string, req BootstrapRequest) (JoinGrant, error)
	VerifyBootstrapGrant(ctx context.Context, grant BootstrapGrant) error
	VerifyJoinGrant(ctx context.Context, grant JoinGrant) error
}
