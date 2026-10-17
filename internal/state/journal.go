package state

import (
	"context"
	"time"
)

// Operation is a durable, resumable state transition record.
type Operation struct {
	ID        string
	ClusterID string
	HostID    string
	Kind      string
	Phase     string
	Revision  uint64
	UpdatedAt time.Time
	// Details carries caller-validated, redacted checkpoint JSON. Never store
	// registration tokens, private keys, or raw command/error output here.
	Details string
}

// Journal provides durable reads and revision-guarded updates. A revision
// conflict requires re-read/reconciliation, never blind side-effect replay.
// Revision zero means absent; creation writes revision one, and an update writes
// expectedRevision+1 while retaining the operation's cluster, host, and kind.
type Journal interface {
	Get(ctx context.Context, operationID string) (Operation, error)
	CompareAndSwap(ctx context.Context, expectedRevision uint64, next Operation) error
}
