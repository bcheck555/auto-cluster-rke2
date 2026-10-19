package formation

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeRoleRuntime struct {
	restricted, authorized, quarantined, stopped int
	fail, missingData                            bool
}

func TestExpiredAuthorizationWithdrawsControlWithoutRenewal(t *testing.T) {
	n := newNode(t, newCluster(t), 0)
	if err := n.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := &fakeRoleRuntime{}
	g := roleGate{node: n, runtime: r, lastAuthorization: time.Now().Add(-61 * time.Second)}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	g.Watch(ctx)
	if !g.restricted || r.restricted != 1 || n.Current().Serving {
		t.Fatal("expired role remained advertised", g.restricted, r.restricted, n.Current().Serving)
	}
}

func (r *fakeRoleRuntime) RestrictControl(context.Context) error  { r.restricted++; return nil }
func (r *fakeRoleRuntime) AuthorizeControl(context.Context) error { r.authorized++; return nil }
func (r *fakeRoleRuntime) QuarantineRole(context.Context, uint64) error {
	r.quarantined++
	if r.fail {
		return ErrWaiting
	}
	return nil
}
func (r *fakeRoleRuntime) StopRole(context.Context) error { r.stopped++; return nil }
func (r *fakeRoleRuntime) ControlDataIntact() bool        { return !r.missingData }

func TestBootAuthorizationAndFreshWorkerReturn(t *testing.T) {
	n := newNode(t, newCluster(t), 0)
	ctx := context.Background()
	if err := n.Step(ctx); err != nil {
		t.Fatal(err)
	}
	s := n.current
	old := n.member(s)
	a := RoleAuthorization{ClusterID: s.ClusterID, Policy: s.Policy, Member: old, Assignment: HostAssignment{Generation: s.Generation, Role: s.Role, Address: s.Address, Previous: old}}
	r := &fakeRoleRuntime{}
	g := roleGate{node: n, runtime: r, restricted: true, request: func(context.Context, State, []Peer, bool) (RoleAuthorization, error) { return a, nil }}
	n.serving = false
	r.missingData = true
	if err := g.Check(ctx, s, nil); err != ErrWaiting || r.authorized != 0 || n.Current().Serving {
		t.Fatal("missing datastore authorized control startup", err, r)
	}
	r.missingData = false
	if err := g.Check(ctx, s, nil); err != ErrWaiting || r.authorized != 1 {
		t.Fatal("valid voter not restored", err, r)
	}
	a.Assignment.Generation = 1
	a.Assignment.Role = "agent"
	a.Assignment.Operation = "operation"
	a.Member = Member{}
	r.fail = true
	if err := g.Check(ctx, s, nil); err != ErrWaiting {
		t.Fatal(err)
	}
	if n.current.Generation != 0 {
		t.Fatal("advanced before quarantine succeeded")
	}
	if _, err := os.Stat(filepath.Join(n.Settings.StateDirectory, "role-transition.json")); err != nil {
		t.Fatal("no durable transition intent", err)
	}
	r.fail = false
	if err := g.Check(ctx, s, nil); err != ErrWaiting {
		t.Fatal(err)
	}
	if n.current.Generation != 1 || n.current.Role != "agent" || n.current.Mode != "join" || n.current.Phase != "Selected" || n.current.ClusterID != s.ClusterID {
		t.Fatal("returning node retained control identity", n.current)
	}
	if err := n.Restore(ctx); err != nil {
		t.Fatal("transition did not survive restart", err)
	}
	a.Assignment.Generation = 0
	if err := g.Check(ctx, n.current, nil); err != ErrConflict {
		t.Fatal("old generation authorized", err)
	}
}
