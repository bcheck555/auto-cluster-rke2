package formation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"auto-cluster-rke2/internal/hostagent"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestKubernetesReservationsUseCASAcrossServers(t *testing.T) {
	c := newCluster(t)
	first := newNode(t, c, 0)
	initial := first.member(first.current)
	initial.Role = "server"
	initial.Complete = true
	initial.NodeUID = "uid"
	initial.EtcdMemberID = "member"
	catalog := Catalog{ClusterID: "cluster", Policy: "policy", Members: map[string]Member{initial.ID: initial}}
	cm := catalogMap(catalog)
	cm.Metadata.ResourceVersion = "1"
	var mu sync.Mutex
	puts := 0
	forceConflict := true
	missingVersion := false
	unavailable := false
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if unavailable {
			w.WriteHeader(503)
			return
		}
		if strings.HasSuffix(r.URL.Path, "autonomous-rke2-identity") {
			_ = json.NewEncoder(w).Encode(map[string]any{"immutable": true, "data": map[string]string{"clusterID": "cluster", "policyDigest": "policy"}})
			return
		}
		if r.URL.Path != catalogPath {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if r.Method == http.MethodGet {
			value := cm
			if missingVersion {
				value.Metadata.ResourceVersion = ""
			}
			_ = json.NewEncoder(w).Encode(value)
			return
		}
		if r.Method != http.MethodPut {
			w.WriteHeader(405)
			return
		}
		puts++
		var next configMap
		if json.NewDecoder(r.Body).Decode(&next) != nil {
			w.WriteHeader(400)
			return
		}
		if forceConflict {
			forceConflict = false
			cm.Metadata.ResourceVersion = "2"
			w.WriteHeader(409)
			return
		}
		if next.Metadata.ResourceVersion == "" || next.Metadata.ResourceVersion != cm.Metadata.ResourceVersion {
			w.WriteHeader(409)
			return
		}
		cm = next
		cm.Metadata.ResourceVersion = "3"
		_ = json.NewEncoder(w).Encode(cm)
	}))
	defer s.Close()
	target, _ := url.Parse(s.URL)
	base := s.Client()
	k := KubeBackend{ClusterID: "cluster", Policy: "policy", client: func(hostagent.TLSFiles) (*http.Client, error) {
		return &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			r.URL.Scheme = target.Scheme
			r.URL.Host = target.Host
			return base.Transport.RoundTrip(r)
		})}, nil
	}}
	requests := []Member{}
	for i := 1; i < 7; i++ {
		n := newNode(t, c, i)
		requests = append(requests, n.member(n.current))
	}
	var wg sync.WaitGroup
	results := make(chan error, len(requests))
	for _, m := range requests {
		wg.Add(1)
		go func(m Member) { defer wg.Done(); _, err := k.Claim(context.Background(), m); results <- err }(m)
	}
	wg.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if !errors.Is(err, ErrWaiting) {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || puts < 2 {
		t.Fatal("CAS did not serialize/retry", succeeded, puts)
	}
	var saved Catalog
	if json.Unmarshal([]byte(cm.Data["catalog"]), &saved) != nil || len(saved.Members) != 2 {
		t.Fatal("membership overwritten")
	}
	mu.Lock()
	missingVersion = true
	mu.Unlock()
	if _, err := k.Claim(context.Background(), requests[0]); !errors.Is(err, ErrConflict) {
		t.Fatal("missing CAS version accepted", err)
	}
	mu.Lock()
	missingVersion = false
	unavailable = true
	mu.Unlock()
	if _, err := k.Claim(context.Background(), requests[0]); !errors.Is(err, ErrWaiting) {
		t.Fatal("quorum/API outage accepted", err)
	}
}

func TestReaderCertificateUsesHostPublicKeyWithoutExportingCAKey(t *testing.T) {
	c := newCluster(t)
	n := newNode(t, c, 0)
	m := n.member(n.current)
	key, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		t.Fatal(err)
	}
	k := KubeBackend{read: func(path string, private bool, _ int64) ([]byte, error) {
		if strings.HasSuffix(path, "client-ca.crt") && !private {
			return c.ca, nil
		}
		if strings.HasSuffix(path, "client-ca.key") && private {
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), nil
		}
		return nil, ErrInvalid
	}}
	data, err := k.readerCertificate(m)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(rest) > 0 || strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatal("exported key or extra material")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.issuer)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "autonomous-rke2-health" || len(cert.Subject.Organization) != 0 {
		t.Fatal("reader has unexpected privileges")
	}
	credentials, _ := c.Credentials(context.Background(), Member{ID: m.ID, PublicKey: m.PublicKey, NodeName: m.NodeName, Address: m.Address, RequestID: m.RequestID, Role: "agent"})
	credentials.ReaderCertificate = data
	if err := validateCredentials(credentials, n.Auth.Self); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerEnrollmentCannotRequestServerCredentials(t *testing.T) {
	c := newCluster(t)
	first := newNode(t, c, 0)
	worker := newNode(t, c, 1)
	serverMember := first.member(first.current)
	serverMember.Role = "server"
	serverMember.Complete = true
	member := worker.member(worker.current)
	member.Role = "agent"
	cm := catalogMap(Catalog{ClusterID: "cluster", Policy: "policy", Members: map[string]Member{serverMember.ID: serverMember, member.ID: member}})
	cm.Metadata.ResourceVersion = "1"
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == catalogPath {
			_ = json.NewEncoder(w).Encode(cm)
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"immutable": true, "data": map[string]string{"clusterID": "cluster", "policyDigest": "policy"}})
		}
	}))
	defer s.Close()
	target, _ := url.Parse(s.URL)
	client := s.Client()
	privateKey, _ := x509.MarshalPKCS8PrivateKey(c.key)
	credentials, _ := c.Credentials(context.Background(), member)
	k := KubeBackend{ClusterID: "cluster", Policy: "policy", client: func(hostagent.TLSFiles) (*http.Client, error) {
		return &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			r.URL.Scheme = target.Scheme
			r.URL.Host = target.Host
			return client.Transport.RoundTrip(r)
		})}, nil
	}, read: func(path string, private bool, _ int64) ([]byte, error) {
		switch path {
		case "/var/lib/rancher/rke2/server/tls/server-ca.crt", "/var/lib/rancher/rke2/server/tls/client-ca.crt":
			return c.ca, nil
		case "/var/lib/rancher/rke2/server/agent-token":
			if !private {
				t.Fatal("token not read privately")
			}
			return []byte(credentials.AgentToken), nil
		case "/var/lib/rancher/rke2/server/tls/client-ca.key":
			if !private {
				t.Fatal("CA not read privately")
			}
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), nil
		default:
			t.Fatalf("worker enrollment read forbidden file %s", path)
			return nil, ErrInvalid
		}
	}}
	request := member
	request.Role = "server"
	result, err := k.Credentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Member.Role != "agent" || result.ServerToken != "" {
		t.Fatal("worker obtained server role/token")
	}
	if err := validateCredentials(result, worker.Auth.Self); err != nil {
		t.Fatal(err)
	}
}
