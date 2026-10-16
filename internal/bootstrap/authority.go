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
}

type BootstrapGrant struct {
	ClusterID   string
	HostID      string
	OperationID string
	ExpiresAt   time.Time
	Signature   []byte
}

type JoinGrant struct {
	ClusterID string
	HostID    string
	Role      string
	ExpiresAt time.Time
	Signature []byte
}

// Authority is the pre-cluster trust root. Implementations must persist
// consumed bootstrap grants and the cluster identity atomically.
type Authority interface {
	AuthorizeBootstrap(ctx context.Context, req BootstrapRequest) (BootstrapGrant, error)
	AuthorizeJoin(ctx context.Context, clusterID string, req BootstrapRequest) (JoinGrant, error)
	VerifyBootstrapGrant(ctx context.Context, grant BootstrapGrant) error
	VerifyJoinGrant(ctx context.Context, grant JoinGrant) error
}
