package identity

import (
	"context"
	"testing"
	"time"
)

type fakeStore struct{}

func (fakeStore) LoadOrCreate(context.Context) (HostIdentity, error) {
	return HostIdentity{ID: "node-1", PublicKey: []byte("public-key"), CreatedAt: time.Unix(1, 0)}, nil
}

var _ Store = fakeStore{}

func TestStoreContractReturnsStableIdentityFields(t *testing.T) {
	got, err := (fakeStore{}).LoadOrCreate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "node-1" || string(got.PublicKey) != "public-key" || got.CreatedAt.IsZero() {
		t.Fatalf("unexpected HostIdentity: %#v", got)
	}
}
