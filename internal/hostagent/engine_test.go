package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"auto-cluster-rke2/internal/bootstrap"
	"auto-cluster-rke2/internal/identity"
	"auto-cluster-rke2/internal/state"
)

func nonce(t *testing.T) string {
	t.Helper()
	s, err := challenge()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type lostResponse struct {
	*bootstrap.FileAuthority
	issueLost, consumeLost bool
}

func (r *lostResponse) AuthorizeBootstrap(ctx context.Context, req bootstrap.BootstrapRequest) (bootstrap.BootstrapGrant, error) {
	g, err := r.FileAuthority.AuthorizeBootstrap(ctx, req)
	if err == nil && r.issueLost {
		r.issueLost = false
		return bootstrap.BootstrapGrant{}, bootstrap.ErrUnavailable
	}
	return g, err
}
func (r *lostResponse) ConsumeBootstrapGrant(ctx context.Context, g bootstrap.BootstrapGrant) error {
	err := r.FileAuthority.ConsumeBootstrapGrant(ctx, g)
	if err == nil && r.consumeLost {
		r.consumeLost = false
		return bootstrap.ErrUnavailable
	}
	return err
}

func engineFixture(t *testing.T) (Engine, *fakeRuntime, *bootstrap.FileAuthority) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	host := identity.NewFileStore(filepath.Join(root, "identity"))
	id, err := host.LoadOrCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, err := bootstrap.NewFileAuthority(ctx, bootstrap.Config{Directory: filepath.Join(root, "authority"), Signer: identity.NewFileStore(filepath.Join(root, "authority-key")), Policy: bootstrap.Policy{Hosts: map[string]bootstrap.HostPolicy{id.ID: {PublicKey: id.PublicKey, Role: bootstrap.RoleServer, Bootstrap: true}}}, Endpoint: "https://authority.example:9443"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	ad, err := a.Advertise(ctx, nonce(t))
	if err != nil {
		t.Fatal(err)
	}
	p := validPlan()
	p.ClusterID = ad.ClusterID
	p.PolicyDigest = a.PolicyDigest()
	runtime := &fakeRuntime{}
	return Engine{Plan: p, Identity: host, Journal: state.NewFileJournal(filepath.Join(root, "journal")), Authority: a, Verifier: a.Verifier(), Runtime: runtime, LockDirectory: filepath.Join(root, "execution")}, runtime, a
}

func TestLostAcknowledgmentsResumeWithoutDuplicateOperations(t *testing.T) {
	for _, kind := range []string{"issuance", "consumption"} {
		t.Run(kind, func(t *testing.T) {
			e, r, a := engineFixture(t)
			e.Authority = &lostResponse{FileAuthority: a, issueLost: kind == "issuance", consumeLost: kind == "consumption"}
			err := e.Run(context.Background())
			if kind == "issuance" && !errors.Is(err, bootstrap.ErrUnavailable) {
				t.Fatal(err)
			}
			if kind == "consumption" && err != nil {
				t.Fatal(err)
			}
			if err := e.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if r.prepares != 1 || r.starts != 1 {
				t.Fatalf("duplicate mutations: %d %d", r.prepares, r.starts)
			}
		})
	}
}

func TestExistingDataAndPlanDriftNeverMutateHost(t *testing.T) {
	for _, kind := range []string{"existing-data", "changed-plan", "changed-token", "stopped-healthy", "node-replaced"} {
		t.Run(kind, func(t *testing.T) {
			e, r, _ := engineFixture(t)
			if kind == "existing-data" {
				r.snapshot.HasData = true
			} else {
				if err := e.Run(context.Background()); err != nil {
					t.Fatal(err)
				}
				r.prepares = 0
				r.starts = 0
				switch kind {
				case "changed-plan":
					e.Plan.NodeName = "another-node"
				case "changed-token":
					r.snapshot.CredentialDigest = "changed"
				case "stopped-healthy":
					r.snapshot.Running = false
				case "node-replaced":
					id, err := e.Identity.LoadOrCreate(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					op, err := e.Journal.Get(context.Background(), "initial-"+id.ID)
					if err != nil {
						t.Fatal(err)
					}
					var c checkpoint
					if json.Unmarshal([]byte(op.Details), &c) != nil {
						t.Fatal("invalid checkpoint")
					}
					c.Evidence.NodeUID = "different-node"
					data, _ := json.Marshal(c)
					next := op
					next.Details = string(data)
					next.Revision++
					next.UpdatedAt = time.Now().UTC()
					if err := e.Journal.CompareAndSwap(context.Background(), op.Revision, next); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := e.Run(context.Background()); !errors.Is(err, ErrReconcile) {
				t.Fatalf("unsafe state: %v", err)
			}
			if r.prepares != 0 || r.starts != 0 {
				t.Fatal("unsafe host was mutated")
			}
		})
	}
}

func TestConcurrentAgentsConvergeOnOneHostOperation(t *testing.T) {
	e, r, _ := engineFixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for range 3 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- e.Run(context.Background()) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if r.prepares != 1 || r.starts != 1 {
		t.Fatalf("duplicate side effects: %d %d", r.prepares, r.starts)
	}
}
func validPlan() Plan {
	return Plan{ClusterID: "12345678-1234-4234-8234-123456789abc", PolicyDigest: strings.Repeat("a", 64), Mode: "bootstrap", Role: "server", NodeName: "cp01", NodeIP: "192.0.2.11", Interface: "rke2lab0", RegistrationURL: "https://register.example:9345", APIURL: "https://register.example:6443", TokenFile: "/etc/autonomous-rke2/credentials/server-token", AgentTokenFile: "/etc/autonomous-rke2/credentials/agent-token", CoreImageSHA256: strings.Repeat("a", 64), FlannelImageSHA256: strings.Repeat("b", 64), CoreDNSSHA256: strings.Repeat("c", 64), MinVotingServers: 1}
}

type fakeRuntime struct {
	snapshot         Snapshot
	prepares, starts int
	failHealth       bool
}

func (r *fakeRuntime) Inspect(context.Context, Plan, string) (Snapshot, error) {
	return r.snapshot, nil
}
func (r *fakeRuntime) Prepare(context.Context, Plan, string) error {
	r.prepares++
	r.snapshot.ConfigMatches = true
	return nil
}
func (r *fakeRuntime) Start(context.Context, string) error {
	r.starts++
	r.snapshot.Running = true
	r.snapshot.HasData = true
	return nil
}
func (r *fakeRuntime) Check(_ context.Context, p Plan, _ string, _ bool) (Evidence, error) {
	if r.failHealth {
		return Evidence{}, ErrWaiting
	}
	if p.Role == bootstrap.RoleAgent {
		return Evidence{NodeUID: "worker-uid"}, nil
	}
	return Evidence{NodeUID: "node-uid", EtcdClusterID: "etcd-id", EtcdMemberID: "member-id", VotingServers: 1}, nil
}

func TestJoinUsesOnlySignedEnrolledRole(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		ctx := context.Background()
		root := t.TempDir()
		server := identity.NewFileStore(filepath.Join(root, "server"))
		worker := identity.NewFileStore(filepath.Join(root, "worker"))
		sid, err := server.LoadOrCreate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		wid, err := worker.LoadOrCreate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		a, err := bootstrap.NewFileAuthority(ctx, bootstrap.Config{Directory: filepath.Join(root, "authority"), Signer: identity.NewFileStore(filepath.Join(root, "authority-key")), Endpoint: "https://authority.example:9443", Policy: bootstrap.Policy{Hosts: map[string]bootstrap.HostPolicy{sid.ID: {PublicKey: sid.PublicKey, Role: "server", Bootstrap: true}, wid.ID: {PublicKey: wid.PublicKey, Role: "agent"}}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
		req, err := bootstrap.SignRequest(ctx, server, a.PolicyDigest(), "bootstrap-fixture")
		if err != nil {
			t.Fatal(err)
		}
		g, err := a.AuthorizeBootstrap(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.ConsumeBootstrapGrant(ctx, g); err != nil {
			t.Fatal(err)
		}
		if err := a.ConfirmClusterActive(ctx, g.ClusterID); err != nil {
			t.Fatal(err)
		}
		p := validPlan()
		p.Mode = "join"
		p.Role = "agent"
		p.AgentTokenFile = ""
		p.ClusterID = g.ClusterID
		p.PolicyDigest = a.PolicyDigest()
		p.NodeName = "worker-01"
		p.NodeIP = "192.0.2.21"
		if mismatch {
			p.Role = "server"
			p.AgentTokenFile = "/etc/autonomous-rke2/credentials/agent-token"
		}
		r := &fakeRuntime{}
		e := Engine{Plan: p, Identity: worker, Journal: state.NewFileJournal(filepath.Join(root, "journal")), Authority: a, Verifier: a.Verifier(), Runtime: r, LockDirectory: filepath.Join(root, "execution")}
		err = e.Run(ctx)
		if mismatch {
			if !errors.Is(err, ErrReconcile) || r.prepares != 0 || r.starts != 0 {
				t.Fatalf("role mismatch mutated host: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Run(ctx); err != nil {
				t.Fatal(err)
			}
			if r.starts != 1 || r.prepares != 1 {
				t.Fatal("join repeated side effects")
			}
		}
	}
}

func TestBootstrapResumesWithoutReissuingGrant(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := identity.NewFileStore(filepath.Join(root, "identity"))
	id, err := host.LoadOrCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, err := bootstrap.NewFileAuthority(ctx, bootstrap.Config{Directory: filepath.Join(root, "authority"), Signer: identity.NewFileStore(filepath.Join(root, "authority-key")), Policy: bootstrap.Policy{Hosts: map[string]bootstrap.HostPolicy{id.ID: {PublicKey: id.PublicKey, Role: bootstrap.RoleServer, Bootstrap: true}}}, Endpoint: "https://authority.example:9443"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	ad, err := a.Advertise(ctx, nonce(t))
	if err != nil {
		t.Fatal(err)
	}
	p := validPlan()
	p.ClusterID = ad.ClusterID
	p.PolicyDigest = a.PolicyDigest()
	runtime := &fakeRuntime{failHealth: true}
	e := Engine{Plan: p, Identity: host, Journal: state.NewFileJournal(filepath.Join(root, "journal")), Authority: a, Verifier: a.Verifier(), Runtime: runtime, LockDirectory: filepath.Join(root, "execution")}
	if err := e.Run(ctx); !errors.Is(err, ErrWaiting) {
		t.Fatal(err)
	}
	runtime.failHealth = false
	if err := e.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if runtime.prepares != 1 || runtime.starts != 1 {
		t.Fatalf("prepares=%d starts=%d", runtime.prepares, runtime.starts)
	}
}
