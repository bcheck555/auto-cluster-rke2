package hostagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"autonomous-rke2/internal/bootstrap"
	"autonomous-rke2/internal/identity"
)

const clusterIdentityPath = "/api/v1/namespaces/kube-system/configmaps/autonomous-rke2-identity"

// Pinned RKE2 separates etcd's HTTPS gateway from its gRPC client listener.
const EtcdHTTPURL = "https://127.0.0.1:2382"

type TLSFiles struct {
	CA   string
	Cert string
	Key  string
}

// TLSClient uses explicit roots/client credentials, TLS 1.3, no redirects or
// proxy inheritance, bounded headers/responses, and fixed request timeouts.
func TLSClient(files TLSFiles) (*http.Client, error) {
	ca, err := ReadFile(files.CA, false, 1<<20)
	if err != nil {
		return nil, ErrWaiting
	}
	cert, err := ReadFile(files.Cert, false, 1<<20)
	if err != nil {
		return nil, ErrWaiting
	}
	key, err := ReadFile(files.Key, true, 1<<20)
	if err != nil {
		return nil, ErrWaiting
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, ErrReconcile
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, ErrReconcile
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}, Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 16384}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

type HealthChecker struct {
	Observer       TLSFiles        // read-only Kubernetes identity for agents
	ObserverSigner identity.Signer // node-resident enrollment never exports a host key
	client         func(TLSFiles) (*http.Client, error)
	apiURL         string // tests only; production uses fixed local server or pinned API origin
	etcdURL        string
}

func (h *HealthChecker) newClient(files TLSFiles) (*http.Client, error) {
	if h.client != nil {
		return h.client(files)
	}
	if h.ObserverSigner != nil && files.Cert == h.Observer.Cert && files.CA == h.Observer.CA {
		ca, err := ReadFile(files.CA, false, 1<<20)
		if err != nil {
			return nil, ErrWaiting
		}
		cert, err := ReadFile(files.Cert, false, 1<<20)
		if err != nil {
			return nil, ErrWaiting
		}
		chain, err := CertificateChain(cert)
		if err != nil {
			return nil, ErrReconcile
		}
		signer, err := identity.NewCryptoSigner(context.Background(), h.ObserverSigner)
		if err != nil {
			return nil, ErrReconcile
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, ErrReconcile
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: signer}}, MinVersion: tls.VersionTLS13}, Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 16384}
		return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
	}
	return TLSClient(files)
}

func request(ctx context.Context, client *http.Client, method, endpoint, path string, body any) ([]byte, int, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, 0, ErrInvalid
		}
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return nil, 0, ErrInvalid
	}
	u.Path = path
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, 0, ErrInvalid
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, ErrWaiting
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, response.StatusCode, ErrWaiting
	}
	return data, response.StatusCode, nil
}

type kubeNode struct {
	Metadata struct {
		UID    string
		Labels map[string]string
	}
	Spec struct {
		Unschedulable bool
		Taints        []struct{ Effect string }
	}
	Status struct {
		Conditions []struct {
			Type   string
			Status string
		}
		Addresses []struct {
			Type    string
			Address string
		}
	}
}

type clusterIdentity struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Immutable bool              `json:"immutable"`
	Data      map[string]string `json:"data"`
}

func (h *HealthChecker) Check(ctx context.Context, p Plan, host string, initialize bool) (Evidence, error) {
	var evidence Evidence
	if p.Validate() != nil || !hashValid(host) {
		return evidence, ErrInvalid
	}
	files := h.Observer
	endpoint := p.APIURL
	if p.Role == bootstrap.RoleServer {
		endpoint = "https://127.0.0.1:6443"
		files = TLSFiles{CA: "/var/lib/rancher/rke2/server/tls/server-ca.crt", Cert: "/var/lib/rancher/rke2/server/tls/client-admin.crt", Key: "/var/lib/rancher/rke2/server/tls/client-admin.key"}
	}
	if h.apiURL != "" {
		endpoint = h.apiURL
	}
	client, err := h.newClient(files)
	if err != nil {
		return evidence, err
	}
	defer client.CloseIdleConnections()
	data, status, err := request(ctx, client, http.MethodGet, endpoint, "/readyz", nil)
	if err != nil || status != http.StatusOK || strings.TrimSpace(string(data)) != "ok" {
		return evidence, ErrWaiting
	}
	data, status, err = request(ctx, client, http.MethodGet, endpoint, "/api/v1/nodes/"+p.NodeName, nil)
	if err != nil || status != http.StatusOK {
		return evidence, ErrWaiting
	}
	var node kubeNode
	if json.Unmarshal(data, &node) != nil {
		return evidence, ErrWaiting
	}
	if node.Metadata.UID == "" || node.Metadata.Labels["autonomous-rke2.io/host-id"] != host[:32] || node.Metadata.Labels["autonomous-rke2.io/cluster-id"] != p.ClusterID {
		return evidence, ErrReconcile
	}
	_, server := node.Metadata.Labels["node-role.kubernetes.io/control-plane"]
	_, etcd := node.Metadata.Labels["node-role.kubernetes.io/etcd"]
	if p.Role == bootstrap.RoleServer && (!server || !etcd) {
		// RKE2 applies these labels after kubelet first registers the node.
		return evidence, ErrWaiting
	}
	if p.Role == bootstrap.RoleAgent && (server || etcd) {
		return evidence, ErrReconcile
	}
	ready, ip := false, false
	for _, condition := range node.Status.Conditions {
		if condition.Type == "Ready" && condition.Status == "True" {
			ready = true
		}
	}
	for _, address := range node.Status.Addresses {
		if address.Type == "InternalIP" && address.Address == p.NodeIP {
			ip = true
		}
	}
	if !ready || !ip || node.Spec.Unschedulable {
		return evidence, ErrWaiting
	}
	for _, taint := range node.Spec.Taints {
		if taint.Effect == "NoSchedule" || taint.Effect == "NoExecute" {
			return evidence, ErrWaiting
		}
	}
	if p.Role == bootstrap.RoleServer {
		evidence, err = h.etcd(ctx, p)
		if err != nil {
			return Evidence{}, err
		}
	}
	data, status, err = request(ctx, client, http.MethodGet, endpoint, clusterIdentityPath, nil)
	if err != nil {
		return Evidence{}, err
	}
	if status == http.StatusNotFound && initialize && p.Mode == "bootstrap" && p.Role == bootstrap.RoleServer {
		marker := clusterIdentity{APIVersion: "v1", Kind: "ConfigMap", Immutable: true, Data: map[string]string{"clusterID": p.ClusterID, "policyDigest": p.PolicyDigest, "bootstrapHostID": host}}
		marker.Metadata.Name = "autonomous-rke2-identity"
		marker.Metadata.Namespace = "kube-system"
		_, created, err := request(ctx, client, http.MethodPost, endpoint, "/api/v1/namespaces/kube-system/configmaps", marker)
		if err != nil || (created != http.StatusCreated && created != http.StatusConflict) {
			return Evidence{}, ErrWaiting
		}
		data, status, err = request(ctx, client, http.MethodGet, endpoint, clusterIdentityPath, nil)
		if err != nil {
			return Evidence{}, err
		}
	}
	if status != http.StatusOK {
		return Evidence{}, ErrWaiting
	}
	var marker clusterIdentity
	if json.Unmarshal(data, &marker) != nil {
		return Evidence{}, ErrReconcile
	}
	if !marker.Immutable || marker.Data["clusterID"] != p.ClusterID || marker.Data["policyDigest"] != p.PolicyDigest {
		return Evidence{}, ErrReconcile
	}
	evidence.NodeUID = node.Metadata.UID
	return evidence, nil
}

type etcdHeader struct {
	ClusterID string `json:"cluster_id"`
	MemberID  string `json:"member_id"`
}

func (h *HealthChecker) etcd(ctx context.Context, p Plan) (Evidence, error) {
	var evidence Evidence
	client, err := h.newClient(TLSFiles{CA: "/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt", Cert: "/var/lib/rancher/rke2/server/tls/etcd/server-client.crt", Key: "/var/lib/rancher/rke2/server/tls/etcd/server-client.key"})
	if err != nil {
		return evidence, err
	}
	defer client.CloseIdleConnections()
	endpoint := EtcdHTTPURL
	if h.etcdURL != "" {
		endpoint = h.etcdURL
	}
	data, status, err := request(ctx, client, http.MethodGet, endpoint, "/readyz", nil)
	if err != nil || status != http.StatusOK || strings.TrimSpace(string(data)) != "ok" {
		return evidence, ErrWaiting
	}
	data, status, err = request(ctx, client, http.MethodPost, endpoint, "/v3/maintenance/status", struct{}{})
	if err != nil || status != http.StatusOK {
		return evidence, ErrWaiting
	}
	var local struct {
		Header etcdHeader
		Leader string
		Errors []string
	}
	if json.Unmarshal(data, &local) != nil || local.Header.ClusterID == "" || local.Header.ClusterID == "0" || local.Header.MemberID == "" || local.Leader == "" || local.Leader == "0" || len(local.Errors) > 0 {
		return evidence, ErrWaiting
	}
	data, status, err = request(ctx, client, http.MethodPost, endpoint, "/v3/cluster/member/list", struct{}{})
	if err != nil || status != http.StatusOK {
		return evidence, ErrWaiting
	}
	var membership struct {
		Header  etcdHeader
		Members []struct {
			ID        string
			PeerURLs  []string
			IsLearner bool
		}
	}
	if json.Unmarshal(data, &membership) != nil || membership.Header.ClusterID != local.Header.ClusterID {
		return evidence, ErrReconcile
	}
	found := 0
	for _, member := range membership.Members {
		if !member.IsLearner {
			evidence.VotingServers++
		}
		for _, peer := range member.PeerURLs {
			if peer == "https://"+net.JoinHostPort(p.NodeIP, "2380") {
				if member.ID != local.Header.MemberID {
					return evidence, ErrReconcile
				}
				if member.IsLearner {
					return evidence, ErrWaiting
				}
				found++
			}
		}
	}
	if found != 1 || evidence.VotingServers < p.MinVotingServers || evidence.VotingServers > 3 {
		return evidence, ErrWaiting
	}
	evidence.EtcdClusterID = local.Header.ClusterID
	evidence.EtcdMemberID = local.Header.MemberID
	return evidence, nil
}
