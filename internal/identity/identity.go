package identity

import (
	"context"
	"time"
)

// HostIdentity is the public, serializable identity material exposed to other
// components. Private key bytes must remain inside the secure identity store.
type HostIdentity struct {
	ID        string
	PublicKey []byte
	CreatedAt time.Time
}

// Store loads an existing persistent identity or safely creates it once.
type Store interface {
	LoadOrCreate(ctx context.Context) (HostIdentity, error)
}
