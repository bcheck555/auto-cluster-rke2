package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"autonomous-rke2/internal/identity"
)

type httpFixture struct {
	fixture
	server  *httptest.Server
	clients []*HTTPClient
	configs []*tls.Config
	cluster string
}

func httpSetup(t *testing.T) httpFixture {
	t.Helper()
	f := setupAt(t, t.TempDir(), 2)
	ctx := context.Background()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-host-ca"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca)
	s := httptest.NewUnstartedServer(nil)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.config.Endpoint = "https://" + s.Listener.Addr().String()
	f.a, err = NewFileAuthority(ctx, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.a.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	s.Config.Handler = HTTPHandler(f.a)
	s.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientRoots, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	ad, err := f.a.Advertise(ctx, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	result := httpFixture{fixture: f, server: s, cluster: ad.ClusterID}
	for i, host := range f.hosts {
		signer, err := identity.NewCryptoSigner(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, signer.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		config := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: signer}}, MinVersion: tls.VersionTLS13}
		client, err := NewHTTPClient(s.URL, result.cluster, config, f.a.Verifier())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		result.clients = append(result.clients, client)
		result.configs = append(result.configs, config)
	}
	return result
}

func TestMTLSGrantLifecycle(t *testing.T) {
	f := httpSetup(t)
	ctx := context.Background()
	g, err := f.clients[0].AuthorizeBootstrap(ctx, f.req(t, 0, "remote-bootstrap"))
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.clients[0].GrantStatus(ctx, g.HostID, g.OperationID, strings.Repeat("d", 64))
	if err != nil || status.Consumed {
		t.Fatalf("issued status: %v", err)
	}
	if err := f.clients[1].ConsumeBootstrapGrant(ctx, g); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong host consumed: %v", err)
	}
	if err := f.clients[0].ConsumeBootstrapGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	status, err = f.clients[0].GrantStatus(ctx, g.HostID, g.OperationID, strings.Repeat("e", 64))
	if err != nil || !status.Consumed {
		t.Fatalf("consumed status: %v", err)
	}
	if _, err := f.clients[1].GrantStatus(ctx, g.HostID, g.OperationID, strings.Repeat("f", 64)); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong-host status: %v", err)
	}
	if err := f.clients[0].ConsumeBootstrapGrant(ctx, g); !errors.Is(err, ErrReplay) {
		t.Fatalf("remote replay: %v", err)
	}
	if err := f.a.ConfirmClusterActive(ctx, g.ClusterID); err != nil {
		t.Fatal(err)
	}
	j, err := f.clients[1].AuthorizeJoin(ctx, g.ClusterID, f.req(t, 1, "remote-join"))
	if err != nil {
		t.Fatal(err)
	}
	if j.Role != RoleAgent {
		t.Fatal("role escalation")
	}
	if err := f.clients[1].ConsumeJoinGrant(ctx, j); err != nil {
		t.Fatal(err)
	}
	if err := f.clients[1].ConsumeJoinGrant(ctx, j); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	f.server.Close()
	if _, err := f.clients[0].AuthorizeBootstrap(ctx, f.req(t, 0, "partition")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("network failure: %v", err)
	}
	// Authority's persisted decision survives failed remote calls.
	if _, err := f.a.AuthorizeBootstrap(ctx, f.req(t, 0, "local-after-partition")); !errors.Is(err, ErrReplay) {
		t.Fatalf("partition reset cluster: %v", err)
	}
}

func TestMTLSRejectsMissingAndWrongHostCertificates(t *testing.T) {
	f := httpSetup(t)
	for _, kind := range []string{"no-certificate", "wrong-host", "unknown-field", "oversized", "activation-api"} {
		t.Run(kind, func(t *testing.T) {
			config := f.configs[1].Clone()
			if kind == "no-certificate" {
				config.Certificates = nil
			}
			transport := &http.Transport{TLSClientConfig: config}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			data, err := json.Marshal(f.req(t, 0, "other-host"))
			if err != nil {
				t.Fatal(err)
			}
			path := "/v1/bootstrap"
			want := http.StatusForbidden
			switch kind {
			case "unknown-field":
				data = []byte(`{"Token":"secret"}`)
				want = http.StatusBadRequest
			case "oversized":
				data = []byte(strings.Repeat("x", maxMessage+1))
				want = http.StatusBadRequest
			case "activation-api":
				path = "/v1/activate"
				want = http.StatusBadRequest
			}
			response, err := client.Post(f.server.URL+path, "application/json", bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != want {
				t.Fatalf("status=%d want=%d body=%s", response.StatusCode, want, body)
			}
			if strings.Contains(string(body), "secret") {
				t.Fatal("error echoed credentials")
			}
		})
	}
}

func TestHTTPClientRejectsImplicitTrustAndWrongHostRequests(t *testing.T) {
	f := httpSetup(t)
	for _, kind := range []string{"insecure", "no-roots", "no-certificate", "server-name", "plaintext"} {
		t.Run(kind, func(t *testing.T) {
			c := f.configs[0].Clone()
			endpoint := f.server.URL
			switch kind {
			case "insecure":
				c.InsecureSkipVerify = true
			case "no-roots":
				c.RootCAs = nil
			case "no-certificate":
				c.Certificates = nil
			case "server-name":
				c.ServerName = "override"
			case "plaintext":
				endpoint = "http://authority.example"
			}
			if _, err := NewHTTPClient(endpoint, f.cluster, c, f.a.Verifier()); err == nil {
				t.Fatal("unsafe client accepted")
			}
		})
	}
	if _, err := f.clients[0].AuthorizeBootstrap(context.Background(), f.req(t, 1, "wrong-host-request")); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if _, err := f.clients[1].AuthorizeJoin(context.Background(), "different-cluster", f.req(t, 1, "wrong-cluster")); !errors.Is(err, ErrClusterMismatch) {
		t.Fatal(err)
	}
}
