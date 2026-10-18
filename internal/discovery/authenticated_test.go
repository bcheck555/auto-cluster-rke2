package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"auto-cluster-rke2/internal/bootstrap"
	"auto-cluster-rke2/internal/durable"
	"auto-cluster-rke2/internal/identity"
)

type probeFunc func(context.Context, string, string) (bootstrap.Advertisement, error)

func (p probeFunc) Fetch(ctx context.Context, endpoint, challenge string) (bootstrap.Advertisement, error) {
	return p(ctx, endpoint, challenge)
}

type discoveryFixture struct {
	a        *bootstrap.FileAuthority
	config   bootstrap.Config
	host     *identity.FileStore
	server   *httptest.Server
	probe    *HTTPProbe
	resolver Resolver
}

func hintsFor(t *testing.T, endpoint string) StaticProvider {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return StaticProvider{{Address: u.Hostname(), Port: uint16(port), Transport: "https"}}
}

func probeFor(t *testing.T, s *httptest.Server) *HTTPProbe {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	p, err := NewHTTPProbe(&tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func discoverySetup(t *testing.T) discoveryFixture {
	t.Helper()
	root := t.TempDir()
	ctx := context.Background()
	host := identity.NewFileStore(filepath.Join(root, "host"))
	id, err := host.LoadOrCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(nil)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	c := bootstrap.Config{Directory: filepath.Join(root, "authority"), Signer: identity.NewFileStore(filepath.Join(root, "authority-key")), Policy: bootstrap.Policy{Hosts: map[string]bootstrap.HostPolicy{id.ID: {PublicKey: id.PublicKey, Role: bootstrap.RoleServer, Bootstrap: true}}}, Endpoint: "https://" + s.Listener.Addr().String()}
	a, err := bootstrap.NewFileAuthority(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	s.Config.Handler = Handler(a)
	s.StartTLS()
	t.Cleanup(s.Close)
	p := probeFor(t, s)
	r := Resolver{Hints: hintsFor(t, s.URL), Probe: p, Verifier: a.Verifier(), Directory: filepath.Join(root, "pin")}
	return discoveryFixture{a: a, config: c, host: host, server: s, probe: p, resolver: r}
}

func TestTLSDiscoveryPinsSignedClusterAcrossRestart(t *testing.T) {
	f := discoverySetup(t)
	ctx := context.Background()
	var events []AuditEvent
	f.resolver.Audit = func(e AuditEvent) { events = append(events, e) }
	got, err := f.resolver.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClusterID == "" || got.URL != f.server.URL || got.Active {
		t.Fatal("incorrect verified identity")
	}
	if len(events) != 1 || events[0].Decision != "verified" {
		t.Fatal("missing public audit event")
	}
	restarted := Resolver{Hints: f.resolver.Hints, Probe: f.probe, Verifier: f.a.Verifier(), Directory: f.resolver.Directory}
	again, err := restarted.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again != got {
		t.Fatal("cluster identity changed")
	}
	// Discovery is read-only at the authority: it has not issued bootstrap.
	req, err := bootstrap.SignRequest(ctx, f.host, f.a.PolicyDigest(), "explicit-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	g, err := f.a.AuthorizeBootstrap(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if g.ClusterID != got.ClusterID {
		t.Fatal("bootstrap changed discovered identity")
	}
	public, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), "Signature") || strings.Contains(string(public), "PrivateKey") || strings.Contains(string(public), "Token") {
		t.Fatal("discovery exposed credentials")
	}
}

func TestRejectSpoofedReplayedAndWrongClusterStatements(t *testing.T) {
	f := discoverySetup(t)
	ctx := context.Background()
	for _, kind := range []string{"unsigned", "cluster", "endpoint", "challenge", "policy", "authority", "expired", "role-state"} {
		t.Run(kind, func(t *testing.T) {
			r := f.resolver
			r.Directory = filepath.Join(t.TempDir(), "pin")
			r.Probe = probeFunc(func(ctx context.Context, endpoint, challenge string) (bootstrap.Advertisement, error) {
				a, err := f.a.Advertise(ctx, challenge)
				if err != nil {
					return a, err
				}
				switch kind {
				case "unsigned":
					a.Signature = nil
				case "cluster":
					a.ClusterID = "spoofed"
				case "endpoint":
					a.Endpoint = "https://evil.example:9443"
				case "challenge":
					a.Challenge = strings.Repeat("0", 64)
				case "policy":
					a.PolicyDigest = "wrong"
				case "authority":
					a.AuthorityID = "wrong"
				case "expired":
					a.ExpiresAt = a.IssuedAt
				case "role-state":
					a.Active = !a.Active
				}
				return a, nil
			})
			if _, err := r.Resolve(ctx); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("tampered discovery: %v", err)
			}
			if _, err := os.Stat(r.Directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unverified advertisement created trust state")
			}
		})
	}
	var cached bootstrap.Advertisement
	r := f.resolver
	r.Probe = probeFunc(func(ctx context.Context, endpoint, challenge string) (bootstrap.Advertisement, error) {
		if cached.ClusterID == "" {
			var err error
			cached, err = f.a.Advertise(ctx, challenge)
			return cached, err
		}
		return cached, nil
	})
	if _, err := r.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("replayed response: %v", err)
	}
	// A different valid cluster signed by the same authority is still rejected
	// once a local cluster pin exists (e.g. an accidental authority reset).
	changed := f.config
	changed.Directory = filepath.Join(t.TempDir(), "reset-authority")
	a2, err := bootstrap.NewFileAuthority(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := a2.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	r.Probe = probeFunc(func(ctx context.Context, endpoint, challenge string) (bootstrap.Advertisement, error) {
		return a2.Advertise(ctx, challenge)
	})
	if _, err := r.Resolve(ctx); !errors.Is(err, bootstrap.ErrClusterMismatch) {
		t.Fatalf("signed cluster reset: %v", err)
	}
	if err := os.WriteFile(filepath.Join(r.Directory, "cluster-pin.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	r.Probe = f.probe
	if _, err := r.Resolve(ctx); !errors.Is(err, durable.ErrCorrupt) {
		t.Fatalf("corrupt pin: %v", err)
	}
}

func TestUnavailableDiscoveryNeverBootstraps(t *testing.T) {
	f := discoverySetup(t)
	ctx := context.Background()
	for _, kind := range []string{"empty", "unreachable", "wrong-tls-root", "wrong-advertised-cluster", "invalid-hint"} {
		t.Run(kind, func(t *testing.T) {
			r := f.resolver
			r.Directory = filepath.Join(t.TempDir(), "pin")
			switch kind {
			case "empty":
				r.Hints = StaticProvider{}
			case "unreachable":
				r.Probe = probeFunc(func(context.Context, string, string) (bootstrap.Advertisement, error) {
					return bootstrap.Advertisement{}, errors.New("secret error never logged")
				})
			case "wrong-tls-root":
				p, err := NewHTTPProbe(&tls.Config{RootCAs: x509.NewCertPool()})
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				r.Probe = p
			case "wrong-advertised-cluster":
				h := hintsFor(t, f.server.URL)
				h[0].ClusterID = "spoofed"
				r.Hints = h
			case "invalid-hint":
				r.Hints = StaticProvider{{Address: "http://secret@evil", Port: 1, Transport: "http"}}
			}
			var events []AuditEvent
			r.Audit = func(e AuditEvent) { events = append(events, e) }
			if _, err := r.Resolve(ctx); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unavailable: %v", err)
			}
			data, _ := json.Marshal(events)
			if strings.Contains(string(data), "secret") {
				t.Fatal("audit leaked raw input or error")
			}
			if _, err := os.Stat(r.Directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unavailable discovery changed trust state")
			}
		})
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.resolver.Resolve(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	req, err := bootstrap.SignRequest(ctx, f.host, f.a.PolicyDigest(), "explicit-after-failures")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.AuthorizeBootstrap(ctx, req); err != nil {
		t.Fatalf("discovery issued a grant: %v", err)
	}
}

func TestHTTPProbeRejectsRedirectsMalformedAndOversizedResponses(t *testing.T) {
	for _, kind := range []string{"redirect", "malformed", "oversized", "unknown-field", "unauthorized"} {
		t.Run(kind, func(t *testing.T) {
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "redirect":
					http.Redirect(w, r, "https://other.example:9443", http.StatusFound)
				case "malformed":
					_, _ = io.WriteString(w, "{")
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat("x", maxResponse+1))
				case "unknown-field":
					_, _ = io.WriteString(w, `{"Token":"secret"}`)
				case "unauthorized":
					http.Error(w, "secret", http.StatusUnauthorized)
				}
			}))
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			s.StartTLS()
			defer s.Close()
			p := probeFor(t, s)
			if _, err := p.Fetch(context.Background(), s.URL, strings.Repeat("a", 64)); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("bad HTTP response: %v", err)
			}
		})
	}
	for _, config := range []*tls.Config{nil, {RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}, {RootCAs: x509.NewCertPool(), ServerName: "override"}, {}} {
		if _, err := NewHTTPProbe(config); err == nil {
			t.Fatal("insecure or implicit TLS trust accepted")
		}
	}
}

func TestDiscoveryHandlerHasNoGrantOrPlaintextAPI(t *testing.T) {
	f := discoverySetup(t)
	for _, kind := range []string{"plaintext", "method", "grant-path", "duplicate-challenge", "unknown-query", "malformed-challenge"} {
		t.Run(kind, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://authority.example"+identityPath+"?challenge="+strings.Repeat("a", 64), nil)
			r.TLS = &tls.ConnectionState{}
			want := http.StatusBadRequest
			switch kind {
			case "plaintext":
				r.TLS = nil
				want = http.StatusUpgradeRequired
			case "method":
				r.Method = http.MethodPost
				want = http.StatusMethodNotAllowed
			case "grant-path":
				r.URL.Path = "/v1/bootstrap"
				want = http.StatusNotFound
			case "duplicate-challenge":
				r.URL.RawQuery += "&challenge=" + strings.Repeat("b", 64)
			case "unknown-query":
				r.URL.RawQuery += "&token=secret"
			case "malformed-challenge":
				r.URL.RawQuery = "challenge=" + strings.Repeat("z", 64)
			}
			w := httptest.NewRecorder()
			Handler(f.a).ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("status=%d want=%d", w.Code, want)
			}
			if strings.Contains(w.Body.String(), "secret") {
				t.Fatal("error echoed request")
			}
		})
	}
}

type srvStub struct {
	records []*net.SRV
	err     error
}

func (s srvStub) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	if service != "auto-cluster" || proto != "tcp" || name != "example.test" {
		return "", nil, errors.New("unexpected lookup")
	}
	return "", s.records, s.err
}

func TestDNSSDResultsRemainUntrustedHints(t *testing.T) {
	p := DNSProvider{Resolver: srvStub{records: []*net.SRV{nil, {Target: ".", Port: 9443}, {Target: "authority.example.", Port: 9443}}}, Domain: "example.test"}
	hints, err := p.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 1 || hints[0].Address != "authority.example" || hints[0].ClusterID != "" || hints[0].Transport != "https" {
		t.Fatalf("unexpected DNS hints: %#v", hints)
	}
	p.Resolver = srvStub{err: errors.New("DNS unavailable")}
	if _, err := p.Discover(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
