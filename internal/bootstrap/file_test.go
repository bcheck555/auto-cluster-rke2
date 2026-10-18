package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"auto-cluster-rke2/internal/durable"
	"auto-cluster-rke2/internal/identity"
)

func TestAuthorityRequiresInitializationAndConsumesOnce(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	signer := identity.NewFileStore(filepath.Join(root, "authority-key"))
	if _, err := signer.LoadOrCreate(ctx); err != nil {
		t.Fatal(err)
	}
	host := identity.NewFileStore(filepath.Join(root, "host-key"))
	id, err := host.LoadOrCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{Hosts: map[string]HostPolicy{id.ID: {PublicKey: id.PublicKey, Role: RoleServer, Bootstrap: true}}}
	a, err := NewFileAuthority(ctx, Config{Directory: filepath.Join(root, "authority"), Signer: signer, Policy: policy, Endpoint: "https://authority.example:9443"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := SignRequest(ctx, host, a.PolicyDigest(), "first-request")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AuthorizeBootstrap(ctx, req); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("uninitialized: %v", err)
	}
	if err := a.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	grant, err := a.AuthorizeBootstrap(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyBootstrapGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if err := a.ConsumeBootstrapGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if err := a.ConsumeBootstrapGrant(ctx, grant); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
}

type fixture struct {
	a      *FileAuthority
	config Config
	hosts  []*identity.FileStore
}

func setupAt(t *testing.T, root string, n int) fixture {
	t.Helper()
	ctx := context.Background()
	policy := Policy{Hosts: map[string]HostPolicy{}}
	f := fixture{}
	for i := range n {
		host := identity.NewFileStore(filepath.Join(root, fmt.Sprintf("host-%d", i)))
		id, err := host.LoadOrCreate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		role := RoleServer
		if i > 0 {
			role = RoleAgent
		}
		policy.Hosts[id.ID] = HostPolicy{PublicKey: id.PublicKey, Role: role, Bootstrap: i == 0}
		f.hosts = append(f.hosts, host)
	}
	f.config = Config{Directory: filepath.Join(root, "authority"), Signer: identity.NewFileStore(filepath.Join(root, "authority-key")), Policy: policy, Endpoint: "https://authority.example:9443"}
	var err error
	f.a, err = NewFileAuthority(ctx, f.config)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) req(t *testing.T, host int, id string) BootstrapRequest {
	t.Helper()
	r, err := SignRequest(context.Background(), f.hosts[host], f.a.PolicyDigest(), id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f fixture) bootstrap(t *testing.T) BootstrapGrant {
	t.Helper()
	ctx := context.Background()
	if err := f.a.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	g, err := f.a.AuthorizeBootstrap(ctx, f.req(t, 0, "bootstrap-op"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestConcurrentBootstrapProcesses(t *testing.T) {
	root := t.TempDir()
	f := setupAt(t, root, 3)
	// Permit three different enrolled first-server candidates. Issuance still
	// chooses exactly one across independent authority processes.
	for id, rule := range f.config.Policy.Hosts {
		rule.Role = RoleServer
		rule.Bootstrap = true
		f.config.Policy.Hosts[id] = rule
	}
	// Child setup uses the same policy below via an explicit persisted fixture.
	policyData, err := json.Marshal(f.config.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "policy.json"), policyData, 0600); err != nil {
		t.Fatal(err)
	}
	// Keep each process's config policy identical through the dedicated helper.
	a, err := NewFileAuthority(context.Background(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	if err := a.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan string, 3)
	for i := range 3 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestBootstrapProcessHelper$")
			cmd.Env = append(os.Environ(), "AUTO_CLUSTER_BOOTSTRAP_CHILD="+root, "AUTO_CLUSTER_HOST="+fmt.Sprint(i), "AUTO_CLUSTER_REQUEST_ID="+fmt.Sprintf("request-%d", i))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("bootstrap process: %v: %s", err, out)
				return
			}
			results <- string(out)
		}(i)
	}
	wg.Wait()
	close(results)
	granted, count := 0, 0
	cluster := ""
	for result := range results {
		var got struct {
			Granted bool
			Cluster string
		}
		if err := json.Unmarshal([]byte(result), &got); err != nil {
			t.Fatal(err)
		}
		count++
		if got.Granted {
			granted++
		}
		if cluster != "" && cluster != got.Cluster {
			t.Fatal("multiple cluster identities")
		}
		cluster = got.Cluster
	}
	if count != 3 || granted != 1 || cluster == "" {
		t.Fatalf("responses=%d grants=%d", count, granted)
	}
	restarted, err := NewFileAuthority(context.Background(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	ad, err := restarted.Advertise(context.Background(), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if ad.ClusterID != cluster {
		t.Fatal("cluster changed on restart")
	}
	if _, err := restarted.AuthorizeBootstrap(context.Background(), f.req(t, 0, "another-request")); !errors.Is(err, ErrReplay) {
		t.Fatalf("restart reissued bootstrap: %v", err)
	}
}

func TestBootstrapProcessHelper(t *testing.T) {
	root := os.Getenv("AUTO_CLUSTER_BOOTSTRAP_CHILD")
	if root == "" {
		return
	}
	f := setupAt(t, root, 3)
	data, err := os.ReadFile(filepath.Join(root, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &f.config.Policy); err != nil {
		t.Fatal(err)
	}
	f.a, err = NewFileAuthority(context.Background(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	switch os.Getenv("AUTO_CLUSTER_HOST") {
	case "1":
		index = 1
	case "2":
		index = 2
	}
	g, err := f.a.AuthorizeBootstrap(context.Background(), f.req(t, index, os.Getenv("AUTO_CLUSTER_REQUEST_ID")))
	if err != nil && !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	ad, e := f.a.Advertise(context.Background(), strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	if err == nil && g.ClusterID != ad.ClusterID {
		t.Fatal("split identity")
	}
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		Granted bool
		Cluster string
	}{err == nil, ad.ClusterID})
	os.Exit(0)
}

func TestJoinLifecycleAndReplayAcrossRestart(t *testing.T) {
	f := setupAt(t, t.TempDir(), 2)
	ctx := context.Background()
	g := f.bootstrap(t)
	if err := f.a.ConfirmClusterActive(ctx, g.ClusterID); !errors.Is(err, ErrNotActive) {
		t.Fatalf("premature activation: %v", err)
	}
	req := f.req(t, 1, "join-op")
	if _, err := f.a.AuthorizeJoin(ctx, g.ClusterID, req); !errors.Is(err, ErrNotActive) {
		t.Fatalf("premature join: %v", err)
	}
	if err := f.a.ConsumeBootstrapGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := f.a.ConfirmClusterActive(ctx, "wrong-cluster"); !errors.Is(err, ErrClusterMismatch) {
		t.Fatal(err)
	}
	if err := f.a.ConfirmClusterActive(ctx, g.ClusterID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.AuthorizeJoin(ctx, "wrong-cluster", req); !errors.Is(err, ErrClusterMismatch) {
		t.Fatal(err)
	}
	j, err := f.a.AuthorizeJoin(ctx, g.ClusterID, req)
	if err != nil {
		t.Fatal(err)
	}
	if j.Role != RoleAgent || j.HostID != req.HostID || j.PolicyDigest != f.a.PolicyDigest() {
		t.Fatal("join binding changed")
	}
	if err := f.a.VerifyJoinGrant(ctx, j); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- f.a.ConsumeJoinGrant(ctx, j) }()
	}
	wg.Wait()
	close(results)
	wins, replays := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, ErrReplay) {
			replays++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || replays != 3 {
		t.Fatalf("consumption wins=%d replays=%d", wins, replays)
	}
	restarted, err := NewFileAuthority(ctx, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ConsumeBootstrapGrant(ctx, g); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	if err := restarted.ConsumeJoinGrant(ctx, j); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	if _, err := restarted.AuthorizeJoin(ctx, g.ClusterID, req); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	if _, err := restarted.AuthorizeJoin(ctx, g.ClusterID, f.req(t, 1, "new-id-same-host")); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate membership: %v", err)
	}
}

func TestRejectUnauthorizedAndTamperedMessages(t *testing.T) {
	f := setupAt(t, t.TempDir(), 2)
	ctx := context.Background()
	if err := f.a.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"unsigned", "wrong-policy", "wrong-host", "wrong-key", "stale", "future", "empty-id", "non-bootstrap-host"} {
		t.Run(kind, func(t *testing.T) {
			r := f.req(t, 0, "request-"+kind)
			switch kind {
			case "unsigned":
				r.Signature = nil
			case "wrong-policy":
				r.PolicyDigest = "wrong"
			case "wrong-host":
				r.HostID = "wrong"
			case "wrong-key":
				r.PublicKey = make([]byte, 32)
			case "stale":
				r.IssuedAt = time.Now().Add(-3 * time.Minute)
			case "future":
				r.IssuedAt = time.Now().Add(time.Minute)
			case "empty-id":
				r.RequestID = ""
			case "non-bootstrap-host":
				r = f.req(t, 1, "agent-bootstrap")
			}
			if _, err := f.a.AuthorizeBootstrap(ctx, r); err == nil {
				t.Fatal("unauthorized request accepted")
			}
		})
	}
	g, err := f.a.AuthorizeBootstrap(ctx, f.req(t, 0, "real"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"signature", "host", "cluster", "policy", "operation", "key", "expiry", "authority"} {
		t.Run(kind, func(t *testing.T) {
			copy := g
			switch kind {
			case "signature":
				copy.Signature = nil
			case "host":
				copy.HostID = "wrong"
			case "cluster":
				copy.ClusterID = "wrong"
			case "policy":
				copy.PolicyDigest = "wrong"
			case "operation":
				copy.OperationID = "wrong"
			case "key":
				copy.PublicKey = make([]byte, 32)
			case "expiry":
				copy.ExpiresAt = copy.ExpiresAt.Add(time.Hour)
			case "authority":
				copy.AuthorityID = "wrong"
			}
			if err := f.a.VerifyBootstrapGrant(ctx, copy); err == nil {
				t.Fatal("tampered grant accepted")
			}
			if err := f.a.ConsumeBootstrapGrant(ctx, copy); err == nil {
				t.Fatal("tampered grant consumed")
			}
		})
	}
	v := f.a.Verifier()
	v.now = func() time.Time { return g.ExpiresAt }
	if err := v.VerifyBootstrapGrant(ctx, g); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	_, wrongKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := NewVerifier(wrongKey.Public().(ed25519.PublicKey), f.a.PolicyDigest())
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.VerifyBootstrapGrant(ctx, g); err == nil {
		t.Fatal("wrong trust anchor accepted")
	}
}

func TestAuthorityMissingCorruptAndMismatchedStateFailsClosed(t *testing.T) {
	f := setupAt(t, t.TempDir(), 1)
	ctx := context.Background()
	g := f.bootstrap(t)
	if err := f.a.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	ad, err := f.a.Advertise(ctx, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if ad.ClusterID != g.ClusterID {
		t.Fatal("initialize reset state")
	}
	changed := f.config
	changed.Endpoint = "https://other.example:9443"
	other, err := NewFileAuthority(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Initialize(ctx); !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("endpoint mismatch: %v", err)
	}
	file := filepath.Join(f.config.Directory, "authority.json")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("partial secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Initialize(ctx); !errors.Is(err, durable.ErrCorrupt) {
		t.Fatalf("corrupt initialize: %v", err)
	}
	if _, err := f.a.AuthorizeBootstrap(ctx, f.req(t, 0, "retry")); !errors.Is(err, durable.ErrCorrupt) {
		t.Fatalf("corrupt issuance: %v", err)
	}
	if err := os.WriteFile(file, before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.AuthorizeBootstrap(ctx, f.req(t, 0, "missing-retry")); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("missing state reinitialized: %v", err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("request recreated authority state")
	}
}

type unavailableSigner struct{ identity.Signer }

func (unavailableSigner) Sign(context.Context, []byte) ([]byte, error) { return nil, ErrUnavailable }

func TestSignerFailureCannotPartiallyIssueBootstrap(t *testing.T) {
	f := setupAt(t, t.TempDir(), 1)
	ctx := context.Background()
	if err := f.a.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := f.a.Advertise(ctx, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	f.a.signer = unavailableSigner{f.config.Signer}
	if _, err := f.a.AuthorizeBootstrap(ctx, f.req(t, 0, "failed-signing")); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	restarted, err := NewFileAuthority(ctx, f.config)
	if err != nil {
		t.Fatal(err)
	}
	g, err := restarted.AuthorizeBootstrap(ctx, f.req(t, 0, "after-signing-recovery"))
	if err != nil {
		t.Fatal(err)
	}
	if g.ClusterID != before.ClusterID {
		t.Fatal("signing failure changed reserved cluster")
	}
	// Even an authentic signature cannot consume a grant absent from the ledger.
	forged := g
	forged.OperationID = "unissued"
	forged.Signature = nil
	forged.Signature, err = restarted.sign(ctx, "bootstrap-grant", forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ConsumeBootstrapGrant(ctx, forged); !errors.Is(err, ErrDenied) {
		t.Fatalf("unissued grant consumed: %v", err)
	}
	if err := restarted.ConsumeBootstrapGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityRejectsUnsafeConfiguration(t *testing.T) {
	for _, kind := range []string{"shared-storage", "invalid-role", "agent-bootstrap", "invalid-key", "plaintext", "excessive-lifetime"} {
		t.Run(kind, func(t *testing.T) {
			f := setupAt(t, t.TempDir(), 1)
			c := f.config
			switch kind {
			case "shared-storage":
				c.Directory = c.Signer.(*identity.FileStore).StorageDirectory()
			case "invalid-role", "agent-bootstrap", "invalid-key":
				for id, rule := range c.Policy.Hosts {
					switch kind {
					case "invalid-role":
						rule.Role = "admin"
					case "agent-bootstrap":
						rule.Role = RoleAgent
					case "invalid-key":
						rule.PublicKey = []byte("bad")
					}
					c.Policy.Hosts[id] = rule
				}
			case "plaintext":
				c.Endpoint = "http://authority.example"
			case "excessive-lifetime":
				c.GrantLifetime = time.Hour
			}
			if _, err := NewFileAuthority(context.Background(), c); !errors.Is(err, ErrInvalid) {
				t.Fatalf("unsafe config: %v", err)
			}
		})
	}
}
