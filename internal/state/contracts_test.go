package state

import (
	"context"
	"testing"
	"time"
)

type fakeJournal struct{ op Operation }

func (j fakeJournal) Get(context.Context, string) (Operation, error)          { return j.op, nil }
func (j fakeJournal) CompareAndSwap(context.Context, uint64, Operation) error { return nil }

var _ Journal = fakeJournal{}

func TestJournalContractCarriesRevisionAndOperationID(t *testing.T) {
	want := Operation{ID: "op-1", ClusterID: "cluster-1", HostID: "host-1", Kind: "bootstrap", Phase: "authorized", Revision: 3, UpdatedAt: time.Unix(1, 0)}
	got, err := (fakeJournal{op: want}).Get(context.Background(), want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Revision != want.Revision || got.Phase != want.Phase {
		t.Fatalf("unexpected journal operation: %#v", got)
	}
}
