package discovery

import (
	"context"
	"testing"
	"time"
)

type fakeProvider struct{}

func (fakeProvider) Discover(context.Context) ([]EndpointHint, error) {
	return []EndpointHint{{Address: "192.0.2.10", Port: 9345, Transport: "https", ClusterID: "cluster-public-id", ObservedAt: time.Unix(1, 0)}}, nil
}

var _ Provider = fakeProvider{}

func TestProviderContractReturnsOnlyEndpointHint(t *testing.T) {
	got, err := (fakeProvider{}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Address != "192.0.2.10" || got[0].ClusterID != "cluster-public-id" {
		t.Fatalf("unexpected endpoint hints: %#v", got)
	}
}
