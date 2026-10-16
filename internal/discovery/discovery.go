package discovery

import (
	"context"
	"time"
)

// EndpointHint is an unauthenticated discovery result; it is never authority.
// Deliberately contains no credential or token fields.
type EndpointHint struct {
	Address    string
	Port       uint16
	Transport  string
	ClusterID  string
	ObservedAt time.Time
}

// Provider returns candidate endpoints. Callers must authenticate them and
// verify cluster identity against a trusted authority before use.
type Provider interface {
	Discover(ctx context.Context) ([]EndpointHint, error)
}
