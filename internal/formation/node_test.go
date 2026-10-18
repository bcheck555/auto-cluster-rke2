package formation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auto-cluster-rke2/internal/hostagent"
	"auto-cluster-rke2/internal/identity"
	"auto-cluster-rke2/internal/state"
)

type fakeRuntime struct {
	snapshot        hostagent.Snapshot
	evidence        hostagent.Evidence
	starts          int
	bootstrapChecks int
	failCheck       bool
	unmanaged       bool
}

func (f *fakeRuntime) Existing(context.Context) (bool, error)              { return f.unmanaged, nil }
func (f *fakeRuntime) EnsureNetwork(context.Context, hostagent.Plan) error { return nil }
func (f *fakeRuntime) Inspect(context.Context, hostagent.Plan, string) (hostagent.Snapshot, error) {
	return f.snapshot, nil
}
func (f *fakeRuntime) Prepare(context.Context, hostagent.Plan, string) error {
	f.snapshot.ConfigMatches = true
	return nil
}
func (f *fakeRuntime) Start(context.Context, string) error {
	f.starts++
	f.snapshot.Running = true
	f.snapshot.HasData = true
	f.snapshot.DataIntact = true
	return nil
}
func (f *fakeRuntime) Check(_ context.Context, p hostagent.Plan, id string, bootstrap bool) (hostagent.Evidence, error) {
	if bootstrap {
		f.bootstrapChecks++
	}
	if f.failCheck {
		return hostagent.Evidence{}, ErrWaiting
	}
	f.evidence = hostagent.Evidence{NodeUID: "uid-" + id}
	if p.Role == "server" {
		f.evidence.EtcdClusterID = "etcd-cluster"
		f.evidence.EtcdMemberID = "etcd-" + id
		f.evidence.VotingServers = 1
	}
	return f.evidence, nil
}

type fakeCluster struct {
	catalog   Catalog
	nodes     []*Node
	ca        []byte
	key       ed25519.PrivateKey
	issuer    *x509.Certificate
	lostReply bool
}

func newCluster(t *testing.T) *fakeCluster {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(2, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(der)
	return &fakeCluster{ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key: key, issuer: issuer}
}
func (c *fakeCluster) Init(_ context.Context, m Member) error {
	if c.catalog.Members == nil {
		c.catalog.Members = map[string]Member{m.ID: m}
	}
	return nil
}
func (c *fakeCluster) Claim(_ context.Context, m Member) (Member, error) { return c.catalog.Reserve(m) }
func (c *fakeCluster) Complete(_ context.Context, m Member) (Member, error) {
	record, ok := c.catalog.Members[m.ID]
	if !ok || !sameMember(record, m) {
		return Member{}, ErrConflict
	}
	record.Complete = true
	record.NodeUID = "uid-" + m.ID
	if record.Role == "server" {
		record.EtcdMemberID = "etcd-" + m.ID
	}
	c.catalog.Members[m.ID] = record
	return record, nil
}
func (c *fakeCluster) Credentials(_ context.Context, m Member) (Credentials, error) {
	sum := sha256.Sum256(c.ca)
	prefix := "K10" + hex.EncodeToString(sum[:]) + "::"
	result := Credentials{Member: m, ServerCA: c.ca, AgentToken: prefix + "node:" + strings.Repeat("a", 64)}
	if m.Role == "server" {
		result.ServerToken = prefix + "server:" + strings.Repeat("s", 64)
	} else {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "autonomous-rke2-health"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, c.issuer, ed25519.PublicKey(m.PublicKey), c.key)
		if err != nil {
			return result, err
		}
		result.ReaderCertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return result, nil
}
func (c *fakeCluster) Enroll(ctx context.Context, _ Peer, m Member) (Credentials, error) {
	record, err := c.Claim(ctx, m)
	if err != nil {
		return Credentials{}, err
	}
	if c.lostReply {
		c.lostReply = false
		return Credentials{}, ErrWaiting
	}
	return c.Credentials(ctx, record)
}

type fakeClient struct{ cluster *fakeCluster }

func (c fakeClient) Enroll(ctx context.Context, p Peer, m Member) (Credentials, error) {
	return c.cluster.Enroll(ctx, p, m)
}
func (c fakeClient) Complete(ctx context.Context, _ Peer, m Member) (Member, error) {
	return c.cluster.Complete(ctx, m)
}

func newNode(t *testing.T, c *fakeCluster, index int) *Node {
	t.Helper()
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	s := Settings{StateDirectory: directory, SecretFile: filepath.Join(directory, "secret"), Interface: "eth0", CoreImageSHA256: strings.Repeat("a", 64), FlannelImageSHA256: strings.Repeat("b", 64), CoreDNSSHA256: strings.Repeat("c", 64), BootstrapDelaySeconds: 5}
	signer := identity.NewFileStore(filepath.Join(directory, "identity"))
	id, err := signer.LoadOrCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{Settings: s, Auth: Auth{Secret: []byte(strings.Repeat("k", 32)), Signer: signer, Self: Peer{ID: id.ID, PublicKey: id.PublicKey, Address: "192.168.10." + big.NewInt(int64(10+index)).String(), Policy: s.Policy()}}, Journal: state.NewFileJournal(filepath.Join(directory, "formation")), Runtime: &fakeRuntime{}, Client: fakeClient{c}, Backend: func(State) Backend { return c }, StartedAt: time.Now().Add(-time.Minute)}
	n.Find = func(context.Context) ([]Peer, error) {
		var peers []Peer
		for _, other := range c.nodes {
			if other != n {
				peers = append(peers, other.Current())
			}
		}
		return peers, nil
	}
	if err := n.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	c.nodes = append(c.nodes, n)
	return n
}

func TestUniversalNodesFormThreeServersThenWorkersAndResume(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	var cluster string
	for i := 0; i < 5; i++ {
		n := newNode(t, c, i)
		if err := n.Step(ctx); err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
		p := n.Current()
		if i == 0 {
			cluster = p.ClusterID
		}
		if p.ClusterID != cluster {
			t.Fatal("different clusters")
		}
		want := "server"
		if i >= 3 {
			want = "agent"
		}
		if p.Role != want {
			t.Fatalf("node %d role %s", i, p.Role)
		}
		origin, err := url.Parse(n.current.RegistrationURL)
		if err != nil || origin.Port() != "9345" || origin.Hostname() == "127.0.0.1" {
			t.Fatal("native client load balancer would cache an unusable supervisor port")
		}
		if i > 0 && want == "server" {
			token, err := os.ReadFile(n.plan(n.current).AgentTokenFile)
			if err != nil || string(token) != strings.Repeat("a", 64)+"\n" {
				t.Fatal("server needs raw distinct agent password")
			}
		}
	}
	for _, n := range c.nodes {
		old := n.current
		runtime := n.Runtime.(*fakeRuntime)
		runtime.snapshot.Running = false
		// Recreate controller using only durable identity/journal/runtime. Workers
		// still have saved endpoints when discovery temporarily returns nothing.
		restarted := &Node{Settings: n.Settings, Auth: n.Auth, Journal: n.Journal, Runtime: runtime, Client: n.Client, Backend: n.Backend, Find: func(context.Context) ([]Peer, error) { return nil, nil }, StartedAt: time.Now()}
		if err := restarted.Step(ctx); err != nil {
			t.Fatal(err)
		}
		if restarted.current.ClusterID != old.ClusterID || restarted.current.Role != old.Role || restarted.current.RegistrationURL != old.RegistrationURL || runtime.starts != 2 {
			t.Fatal("reboot changed assignment or did not start known runtime")
		}
		if old.Role == "agent" && len(restarted.current.Servers) == 0 {
			t.Fatal("lost saved server endpoints")
		}
		runtime.snapshot.HasData = false
		runtime.snapshot.Running = false
		if err := restarted.Step(ctx); !errors.Is(err, ErrConflict) {
			t.Fatal("missing completed data allowed restart", err)
		}
		if runtime.starts != 2 {
			t.Fatal("data loss restarted runtime")
		}
	}
}

func TestPendingBootstrapAndLostEnrollmentResponse(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	first := newNode(t, c, 0)
	first.Runtime.(*fakeRuntime).failCheck = true
	if err := first.Step(ctx); !errors.Is(err, ErrWaiting) {
		t.Fatal(err)
	}
	second := newNode(t, c, 1)
	if err := second.Step(ctx); !errors.Is(err, ErrWaiting) || second.current.ClusterID != "" {
		t.Fatal("pending first node caused another bootstrap", err)
	}
	first.Runtime.(*fakeRuntime).failCheck = false
	if err := first.Step(ctx); err != nil {
		t.Fatal(err)
	}
	c.lostReply = true
	if err := second.Step(ctx); !errors.Is(err, ErrWaiting) {
		t.Fatal(err)
	}
	reserved := c.catalog.Members[second.Auth.Self.ID]
	if reserved.Role != "server" || reserved.Complete {
		t.Fatal("reservation not durable")
	}
	third := newNode(t, c, 2)
	if err := third.Step(ctx); !errors.Is(err, ErrWaiting) {
		t.Fatal("concurrent pending membership allowed", err)
	}
	if err := second.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if second.current.Mode != "join" || second.current.ClusterID != first.current.ClusterID {
		t.Fatal("resume changed cluster")
	}
	if err := third.Step(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestUnmanagedRuntimeAndPolicyMismatchNeverBootstrap(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	n := newNode(t, c, 0)
	n.Runtime.(*fakeRuntime).unmanaged = true
	if err := n.Step(ctx); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if n.current.ClusterID != "" {
		t.Fatal("adopted unmanaged data")
	}
	n.Runtime.(*fakeRuntime).unmanaged = false
	n.Find = func(context.Context) ([]Peer, error) { return []Peer{{ID: "other", Policy: "different"}}, nil }
	if err := n.Step(ctx); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

func TestChangedDeploymentSecretStopsKnownNode(t *testing.T) {
	c := newCluster(t)
	n := newNode(t, c, 0)
	ctx := context.Background()
	if err := n.Step(ctx); err != nil {
		t.Fatal(err)
	}
	n.Auth.Deployment = "different-deployment-key"
	if err := n.Step(ctx); !errors.Is(err, ErrConflict) {
		t.Fatal("changed enrollment key adopted", err)
	}
	if n.Current().Serving {
		t.Fatal("conflicted node advertises enrollment")
	}
}

func TestCompletedBootstrapNeverRecreatesMissingMembershipLedger(t *testing.T) {
	c := newCluster(t)
	n := newNode(t, c, 0)
	ctx := context.Background()
	if err := n.Step(ctx); err != nil {
		t.Fatal(err)
	}
	c.catalog.Members = nil
	if err := n.Step(ctx); !errors.Is(err, ErrConflict) {
		t.Fatal("lost membership ledger was not rejected", err)
	}
	if c.catalog.Members != nil || n.Current().Serving {
		t.Fatal("membership ledger silently recreated")
	}
}

func TestHealthyServerWithPartialDataNeverStartsReplacementEtcd(t *testing.T) {
	c := newCluster(t)
	n := newNode(t, c, 0)
	ctx := context.Background()
	if err := n.Step(ctx); err != nil {
		t.Fatal(err)
	}
	runtime := n.Runtime.(*fakeRuntime)
	runtime.snapshot.Running = false
	runtime.snapshot.HasData = true
	runtime.snapshot.DataIntact = false
	if err := n.Step(ctx); !errors.Is(err, ErrConflict) {
		t.Fatal("partial completed state accepted", err)
	}
	if runtime.starts != 1 {
		t.Fatal("replacement datastore could be started")
	}
}

func TestCatalogReservationBindingAndCapacity(t *testing.T) {
	c := newCluster(t)
	first := newNode(t, c, 0)
	m := first.member(first.current)
	m.Role = "server"
	m.Complete = true
	c.catalog.Members = map[string]Member{m.ID: m}
	for i := 1; i < 5; i++ {
		n := newNode(t, c, i)
		request := n.member(n.current)
		reserved, err := c.catalog.Reserve(request)
		if err != nil {
			t.Fatal(err)
		}
		again, err := c.catalog.Reserve(request)
		if err != nil || again.Role != reserved.Role {
			t.Fatal("retry changed reservation")
		}
		request.Address = "192.168.10.200"
		if _, err := c.catalog.Reserve(request); !errors.Is(err, ErrConflict) {
			t.Fatal("changed binding accepted")
		}
		reserved.Complete = true
		c.catalog.Members[reserved.ID] = reserved
	}
	servers := 0
	for _, m := range c.catalog.Members {
		if m.Role == "server" {
			servers++
		}
	}
	if servers != 3 {
		t.Fatal("unexpected server count", servers)
	}
}
