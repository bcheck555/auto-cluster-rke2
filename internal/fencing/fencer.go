package fencing

import (
	"context"
	"time"
)

// PowerState describes the power state reported by an authenticated fencing
// backend. Only PowerOffConfirmed is sufficient to authorize replacement.
type PowerState uint8

const (
	PowerUnknown PowerState = iota
	PowerOn
	PowerOffConfirmed
)

// Target is the stable identity of one managed host/VM. Both identifiers must
// match the requested target before evidence can authorize recovery.
type Target struct {
	HostID     string
	DomainUUID string
}

// Evidence is an auditable observation from a fencing backend.
type Evidence struct {
	Target      Target
	State       PowerState
	ObservedAt  time.Time
	Backend     string
	OperationID string
	EvidenceID  string
}

// ConfirmsOffFor reports whether this evidence is a fresh, complete, positive
// power-off observation for exactly the requested target. It does not itself
// authenticate the backend; callers must validate the evidence source too.
func (e Evidence) ConfirmsOffFor(target Target, now time.Time, maxAge time.Duration) bool {
	if target.HostID == "" || target.DomainUUID == "" || e.Target != target {
		return false
	}
	if e.State != PowerOffConfirmed || e.Backend == "" || e.OperationID == "" || e.EvidenceID == "" {
		return false
	}
	if now.IsZero() || e.ObservedAt.IsZero() || maxAge <= 0 || e.ObservedAt.After(now) {
		return false
	}
	return now.Sub(e.ObservedAt) <= maxAge
}

// Fencer is implemented by an authenticated backend such as the lab's narrow
// libvirt service. An absent/unsafe backend must return an error, never success.
type Fencer interface {
	Inspect(ctx context.Context, target Target) (Evidence, error)
	Fence(ctx context.Context, target Target, operationID string) (Evidence, error)
}
