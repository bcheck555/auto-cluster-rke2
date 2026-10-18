package formation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"auto-cluster-rke2/internal/hostagent"
)

const catalogPath = "/api/v1/namespaces/kube-system/configmaps/autonomous-rke2-membership"

type KubeBackend struct {
	ClusterID string
	Policy    string
	client    func(hostagent.TLSFiles) (*http.Client, error)
	read      func(string, bool, int64) ([]byte, error)
}

type configMap struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion,omitempty"`
	} `json:"metadata"`
	Data map[string]string `json:"data"`
}

func (k KubeBackend) tls(files hostagent.TLSFiles) (*http.Client, error) {
	if k.client != nil {
		return k.client(files)
	}
	return hostagent.TLSClient(files)
}
func (k KubeBackend) file(path string, private bool) ([]byte, error) {
	if k.read != nil {
		return k.read(path, private, 1<<20)
	}
	return hostagent.ReadFile(path, private, 1<<20)
}

func (k KubeBackend) call(ctx context.Context, etcd bool, method, path string, value any) ([]byte, int, error) {
	files := hostagent.TLSFiles{CA: "/var/lib/rancher/rke2/server/tls/server-ca.crt", Cert: "/var/lib/rancher/rke2/server/tls/client-admin.crt", Key: "/var/lib/rancher/rke2/server/tls/client-admin.key"}
	endpoint := "https://127.0.0.1:6443"
	if etcd {
		files = hostagent.TLSFiles{CA: "/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt", Cert: "/var/lib/rancher/rke2/server/tls/etcd/server-client.crt", Key: "/var/lib/rancher/rke2/server/tls/etcd/server-client.key"}
		endpoint = hostagent.EtcdHTTPURL
	}
	client, err := k.tls(files)
	if err != nil {
		return nil, 0, ErrWaiting
	}
	defer client.CloseIdleConnections()
	var data []byte
	if value != nil {
		data, err = json.Marshal(value)
		if err != nil {
			return nil, 0, ErrInvalid
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, bytes.NewReader(data))
	if err != nil {
		return nil, 0, ErrInvalid
	}
	if value != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, ErrWaiting
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, response.StatusCode, ErrInvalid
	}
	return data, response.StatusCode, nil
}

func (k KubeBackend) marker(ctx context.Context) error {
	data, status, err := k.call(ctx, false, http.MethodGet, "/api/v1/namespaces/kube-system/configmaps/autonomous-rke2-identity", nil)
	if err != nil || status != 200 {
		return ErrWaiting
	}
	var marker struct {
		Immutable bool
		Data      map[string]string
	}
	if json.Unmarshal(data, &marker) != nil || !marker.Immutable || marker.Data["clusterID"] != k.ClusterID || marker.Data["policyDigest"] != k.Policy {
		return ErrConflict
	}
	return nil
}

func (k KubeBackend) load(ctx context.Context) (Catalog, configMap, int, error) {
	if err := k.marker(ctx); err != nil {
		return Catalog{}, configMap{}, 0, err
	}
	data, status, err := k.call(ctx, false, http.MethodGet, catalogPath, nil)
	if err != nil {
		return Catalog{}, configMap{}, status, err
	}
	if status == 404 {
		return Catalog{}, configMap{}, status, nil
	}
	if status != 200 {
		return Catalog{}, configMap{}, status, ErrWaiting
	}
	var cm configMap
	var c Catalog
	if json.Unmarshal(data, &cm) != nil || json.Unmarshal([]byte(cm.Data["catalog"]), &c) != nil || c.ClusterID != k.ClusterID || c.Policy != k.Policy || c.Members == nil || len(c.Members) == 0 || len(c.Members) > 1024 {
		return c, cm, status, ErrConflict
	}
	if cm.Metadata.ResourceVersion == "" {
		return c, cm, status, ErrConflict
	}
	servers, pending := 0, 0
	for id, m := range c.Members {
		if id != m.ID || !validMember(m) || (m.Role != "server" && m.Role != "agent") {
			return c, cm, status, ErrConflict
		}
		if m.Role == "server" {
			servers++
		}
		if !m.Complete {
			pending++
		}
	}
	if servers < 1 || servers > 7 || pending > 1 || !controlTargetValid(c.controlTarget()) {
		return c, cm, status, ErrConflict
	}
	return c, cm, status, nil
}

func catalogMap(c Catalog) configMap {
	cm := configMap{APIVersion: "v1", Kind: "ConfigMap", Data: map[string]string{}}
	cm.Metadata.Name = "autonomous-rke2-membership"
	cm.Metadata.Namespace = "kube-system"
	data, _ := json.Marshal(c)
	cm.Data["catalog"] = string(data)
	return cm
}

func (k KubeBackend) Init(ctx context.Context, first Member) error {
	if !validMember(first) || first.Role != "server" || !first.Complete || first.NodeUID == "" || first.EtcdMemberID == "" {
		return ErrInvalid
	}
	c, _, status, err := k.load(ctx)
	if err != nil {
		return err
	}
	if status == 404 {
		cm := catalogMap(Catalog{ClusterID: k.ClusterID, Policy: k.Policy, Members: map[string]Member{first.ID: first}})
		_, status, err = k.call(ctx, false, http.MethodPost, "/api/v1/namespaces/kube-system/configmaps", cm)
		if err != nil {
			return err
		}
		if status != 201 && status != 409 {
			return ErrWaiting
		}
		c, _, _, err = k.load(ctx)
		if err != nil {
			return err
		}
	}
	existing, ok := c.Members[first.ID]
	if !ok || !sameMember(existing, first) || existing.Role != "server" || !existing.Complete || existing.NodeUID != first.NodeUID || existing.EtcdMemberID != first.EtcdMemberID {
		return ErrConflict
	}
	return k.readerRBAC(ctx)
}

func (k KubeBackend) change(ctx context.Context, request Member, complete bool) (Member, error) {
	for range 8 {
		c, cm, status, err := k.load(ctx)
		if err != nil {
			return Member{}, err
		}
		if status != 200 {
			return Member{}, ErrWaiting
		}
		var record Member
		if complete {
			var ok bool
			record, ok = c.Members[request.ID]
			if !ok || !sameMember(record, request) || record.Retiring {
				return Member{}, ErrConflict
			}
			evidence, err := k.observed(ctx, record)
			if err != nil {
				return Member{}, err
			}
			if record.Complete {
				if record.NodeUID != evidence.NodeUID || record.EtcdMemberID != evidence.EtcdMemberID {
					return Member{}, ErrConflict
				}
				return record, nil
			}
			record.Complete = true
			record.NodeUID = evidence.NodeUID
			record.EtcdMemberID = evidence.EtcdMemberID
			c.Members[record.ID] = record
		} else {
			record, err = c.Reserve(request)
			if err != nil {
				return Member{}, err
			}
		}
		next := catalogMap(c)
		next.Metadata.ResourceVersion = cm.Metadata.ResourceVersion
		_, status, err = k.call(ctx, false, http.MethodPut, catalogPath, next)
		if err != nil {
			return Member{}, err
		}
		if status == 409 {
			continue
		}
		if status != 200 {
			return Member{}, ErrWaiting
		}
		return record, nil
	}
	return Member{}, ErrWaiting
}

func (k KubeBackend) Claim(ctx context.Context, m Member) (Member, error) {
	return k.change(ctx, m, false)
}
func (k KubeBackend) Complete(ctx context.Context, m Member) (Member, error) {
	return k.change(ctx, m, true)
}

func (k KubeBackend) observed(ctx context.Context, m Member) (Member, error) {
	data, status, err := k.call(ctx, false, http.MethodGet, "/api/v1/nodes/"+m.NodeName, nil)
	if err != nil || status != 200 {
		return Member{}, ErrWaiting
	}
	var node struct {
		Metadata struct {
			UID    string
			Labels map[string]string
		}
		Spec struct {
			Unschedulable bool
			Taints        []struct{ Effect string }
		}
		Status struct {
			Conditions []struct{ Type, Status string }
			Addresses  []struct{ Type, Address string }
		}
	}
	if json.Unmarshal(data, &node) != nil || node.Metadata.UID == "" || node.Metadata.Labels["autonomous-rke2.io/host-id"] != m.ID[:32] || node.Metadata.Labels["autonomous-rke2.io/cluster-id"] != k.ClusterID {
		return Member{}, ErrConflict
	}
	_, server := node.Metadata.Labels["node-role.kubernetes.io/control-plane"]
	_, etcd := node.Metadata.Labels["node-role.kubernetes.io/etcd"]
	if (m.Role == "server" && (!server || !etcd)) || (m.Role == "agent" && (server || etcd)) {
		return Member{}, ErrConflict
	}
	ready, address := false, false
	for _, c := range node.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			ready = true
		}
	}
	for _, a := range node.Status.Addresses {
		if a.Type == "InternalIP" && a.Address == m.Address {
			address = true
		}
	}
	if !ready || !address || node.Spec.Unschedulable {
		return Member{}, ErrWaiting
	}
	for _, taint := range node.Spec.Taints {
		if taint.Effect == "NoSchedule" || taint.Effect == "NoExecute" {
			return Member{}, ErrWaiting
		}
	}
	m.NodeUID = node.Metadata.UID
	if m.Role == "server" {
		data, status, err = k.call(ctx, true, http.MethodGet, "/readyz", nil)
		if err != nil || status != 200 || strings.TrimSpace(string(data)) != "ok" {
			return Member{}, ErrWaiting
		}
		data, status, err = k.call(ctx, true, http.MethodPost, "/v3/cluster/member/list", struct{}{})
		if err != nil || status != 200 {
			return Member{}, ErrWaiting
		}
		var members struct {
			Members []struct {
				ID        string
				PeerURLs  []string
				IsLearner bool
			}
		}
		if json.Unmarshal(data, &members) != nil {
			return Member{}, ErrInvalid
		}
		found, voters := 0, 0
		for _, member := range members.Members {
			if !member.IsLearner {
				voters++
			}
			for _, peer := range member.PeerURLs {
				if peer == "https://"+m.Address+":2380" {
					if member.IsLearner {
						return Member{}, ErrWaiting
					}
					m.EtcdMemberID = member.ID
					found++
				}
			}
		}
		if found != 1 || m.EtcdMemberID == "" || voters > 7 {
			return Member{}, ErrWaiting
		}
	}
	return m, nil
}

func (k KubeBackend) Credentials(ctx context.Context, request Member) (Credentials, error) {
	c, _, status, err := k.load(ctx)
	if err != nil || status != 200 {
		if err == nil {
			err = ErrWaiting
		}
		return Credentials{}, err
	}
	m, ok := c.Members[request.ID]
	if !ok || !sameMember(m, request) || m.Retiring {
		return Credentials{}, ErrConflict
	}
	result := Credentials{Member: m}
	ca, err := k.file("/var/lib/rancher/rke2/server/tls/server-ca.crt", false)
	if err != nil {
		return result, ErrWaiting
	}
	result.ServerCA = ca
	agent, err := k.file("/var/lib/rancher/rke2/server/agent-token", true)
	if err != nil {
		return result, ErrWaiting
	}
	result.AgentToken = strings.TrimSpace(string(agent))
	if m.Role == "server" {
		server, err := k.file("/var/lib/rancher/rke2/server/token", true)
		if err != nil {
			return Credentials{}, ErrWaiting
		}
		result.ServerToken = strings.TrimSpace(string(server))
	} else {
		result.ReaderCertificate, err = k.readerCertificate(m)
		if err != nil {
			return Credentials{}, err
		}
	}
	return result, nil
}

func (k KubeBackend) readerCertificate(m Member) ([]byte, error) {
	ca, err := k.file("/var/lib/rancher/rke2/server/tls/client-ca.crt", false)
	if err != nil {
		return nil, ErrWaiting
	}
	key, err := k.file("/var/lib/rancher/rke2/server/tls/client-ca.key", true)
	if err != nil {
		return nil, ErrWaiting
	}
	pair, err := tls.X509KeyPair(ca, key)
	if err != nil {
		return nil, ErrInvalid
	}
	issuer, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, ErrInvalid
	}
	var serial [16]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(serial[:]), Subject: pkix.Name{CommonName: "autonomous-rke2-health"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, ed25519.PublicKey(m.PublicKey), pair.PrivateKey)
	if err != nil {
		return nil, ErrInvalid
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (k KubeBackend) readerRBAC(ctx context.Context) error {
	objects := []struct {
		path, kind, name string
		body             map[string]any
	}{
		{"/apis/rbac.authorization.k8s.io/v1/clusterroles", "ClusterRole", "autonomous-rke2-health", map[string]any{"rules": []any{map[string]any{"apiGroups": []string{""}, "resources": []string{"nodes"}, "verbs": []string{"get"}}, map[string]any{"nonResourceURLs": []string{"/readyz"}, "verbs": []string{"get"}}}}},
		{"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "ClusterRoleBinding", "autonomous-rke2-health", map[string]any{"subjects": []any{map[string]string{"kind": "User", "name": "autonomous-rke2-health", "apiGroup": "rbac.authorization.k8s.io"}}, "roleRef": map[string]string{"kind": "ClusterRole", "name": "autonomous-rke2-health", "apiGroup": "rbac.authorization.k8s.io"}}},
		{"/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/roles", "Role", "autonomous-rke2-health-identity", map[string]any{"rules": []any{map[string]any{"apiGroups": []string{""}, "resources": []string{"configmaps"}, "resourceNames": []string{"autonomous-rke2-identity"}, "verbs": []string{"get"}}}}},
		{"/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/rolebindings", "RoleBinding", "autonomous-rke2-health-identity", map[string]any{"subjects": []any{map[string]string{"kind": "User", "name": "autonomous-rke2-health", "apiGroup": "rbac.authorization.k8s.io"}}, "roleRef": map[string]string{"kind": "Role", "name": "autonomous-rke2-health-identity", "apiGroup": "rbac.authorization.k8s.io"}}},
	}
	for _, object := range objects {
		body := object.body
		body["apiVersion"] = "rbac.authorization.k8s.io/v1"
		body["kind"] = object.kind
		metadata := map[string]string{"name": object.name}
		if strings.Contains(object.path, "namespaces") {
			metadata["namespace"] = "kube-system"
		}
		body["metadata"] = metadata
		_, status, err := k.call(ctx, false, http.MethodPost, object.path, body)
		if err != nil {
			return err
		}
		if status != 201 && status != 409 {
			return ErrWaiting
		}
		if status == 409 {
			data, status, err := k.call(ctx, false, http.MethodGet, object.path+"/"+object.name, nil)
			if err != nil || status != 200 {
				return ErrWaiting
			}
			var existing map[string]any
			if json.Unmarshal(data, &existing) != nil {
				return ErrInvalid
			}
			for _, field := range []string{"rules", "subjects", "roleRef"} {
				if digest(existing[field]) != digest(body[field]) {
					return ErrConflict
				}
			}
		}
	}
	return nil
}
