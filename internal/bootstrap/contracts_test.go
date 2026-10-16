package bootstrap

import (
	"context"
	"testing"
	"time"
)

type fakeAuthority struct{}

func (fakeAuthority) AuthorizeBootstrap(context.Context, BootstrapRequest) (BootstrapGrant, error) {
	return BootstrapGrant{ClusterID: "cluster-1", HostID: "host-1", OperationID: "op-1", ExpiresAt: time.Unix(10, 0), Signature: []byte("signature")}, nil
}
func (fakeAuthority) AuthorizeJoin(context.Context, string, BootstrapRequest) (JoinGrant, error) {
	return JoinGrant{ClusterID: "cluster-1", HostID: "host-1", Role: "agent", ExpiresAt: time.Unix(10, 0), Signature: []byte("signature")}, nil
}
func (fakeAuthority) VerifyBootstrapGrant(context.Context, BootstrapGrant) error { return nil }
func (fakeAuthority) VerifyJoinGrant(context.Context, JoinGrant) error           { return nil }

var _ Authority = fakeAuthority{}

func TestAuthorityContractBindsBootstrapGrant(t *testing.T) {
	got, err := (fakeAuthority{}).AuthorizeBootstrap(context.Background(), BootstrapRequest{HostID: "host-1", RequestID: "req-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ClusterID != "cluster-1" || got.HostID != "host-1" || got.OperationID == "" || len(got.Signature) == 0 {
		t.Fatalf("unexpected bootstrap grant: %#v", got)
	}
}
