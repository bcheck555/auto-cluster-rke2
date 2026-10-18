package formation

import (
	"errors"
	"testing"
)

func TestKnownClusterNeverBootstrapsOnEmptyDiscovery(t *testing.T) {
	if _, err := Select("host-a", "known-cluster", nil); !errors.Is(err, ErrWaiting) {
		t.Fatal(err)
	}
}

func TestFreshNodeBootstrapsOnlyWhenAloneOrLowestObservedIdentity(t *testing.T) {
	choice, err := Select("a", "", nil)
	if err != nil || !choice.Bootstrap {
		t.Fatal(err)
	}
	if _, err := Select("b", "", []Peer{{ID: "a"}}); !errors.Is(err, ErrWaiting) {
		t.Fatal(err)
	}
	if _, err := Select("a", "", []Peer{{ID: "b", ClusterID: "pending", Phase: "Starting"}}); !errors.Is(err, ErrWaiting) {
		t.Fatal(err)
	}
}

func TestConflictingClustersHaltInsteadOfMerging(t *testing.T) {
	if _, err := Select("c", "", []Peer{{ID: "a", ClusterID: "one", Serving: true, Role: "server"}, {ID: "b", ClusterID: "two", Serving: true, Role: "server"}}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}
