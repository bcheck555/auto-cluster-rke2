package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type healthFixture struct {
	marker           *clusterIdentity
	markerWrites     int
	ready, etcdReady bool
	role             string
	memberID         string
	learner          bool
	checker          *HealthChecker
	plan             Plan
	host             string
}

func healthSetup(t *testing.T) *healthFixture {
	t.Helper()
	f := &healthFixture{ready: true, etcdReady: true, role: "server", memberID: "member-1", plan: validPlan(), host: strings.Repeat("a", 64)}
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/readyz":
			_, _ = w.Write([]byte("ok"))
		case "/api/v1/nodes/" + f.plan.NodeName:
			labels := map[string]string{"autonomous-rke2.io/host-id": f.host[:32], "autonomous-rke2.io/cluster-id": f.plan.ClusterID}
			if f.role == "server" {
				labels["node-role.kubernetes.io/control-plane"] = ""
				labels["node-role.kubernetes.io/etcd"] = ""
			}
			ready := "False"
			if f.ready {
				ready = "True"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"uid": "node-uid", "labels": labels}, "spec": map[string]any{}, "status": map[string]any{"conditions": []map[string]string{{"type": "Ready", "status": ready}}, "addresses": []map[string]string{{"type": "InternalIP", "address": f.plan.NodeIP}}}})
		case clusterIdentityPath:
			if f.marker == nil {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(f.marker)
		case "/api/v1/namespaces/kube-system/configmaps":
			if r.Method != http.MethodPost {
				t.Error("unexpected marker method")
				http.Error(w, "denied", 405)
				return
			}
			var marker clusterIdentity
			if json.NewDecoder(r.Body).Decode(&marker) != nil {
				http.Error(w, "invalid", 400)
				return
			}
			f.marker = &marker
			f.markerWrites++
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(marker)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	etcd := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/readyz":
			if !f.etcdReady {
				http.Error(w, "not ready", 503)
				return
			}
			_, _ = w.Write([]byte("ok"))
		case "/v3/maintenance/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"header": map[string]string{"cluster_id": "etcd-1", "member_id": "member-1"}, "leader": "member-1"})
		case "/v3/cluster/member/list":
			_ = json.NewEncoder(w).Encode(map[string]any{"header": map[string]string{"cluster_id": "etcd-1", "member_id": "member-1"}, "members": []map[string]any{{"ID": f.memberID, "peerURLs": []string{"https://" + f.plan.NodeIP + ":2380"}, "isLearner": f.learner}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(etcd.Close)
	f.checker = &HealthChecker{apiURL: api.URL, etcdURL: etcd.URL, client: func(files TLSFiles) (*http.Client, error) {
		if strings.Contains(files.Cert, "/etcd/") {
			return etcd.Client(), nil
		}
		return api.Client(), nil
	}}
	return f
}

func TestHealthRequiresIndependentEtcdAndImmutableClusterIdentity(t *testing.T) {
	f := healthSetup(t)
	ctx := context.Background()
	f.etcdReady = false
	if _, err := f.checker.Check(ctx, f.plan, f.host, true); !errors.Is(err, ErrWaiting) {
		t.Fatal(err)
	}
	if f.markerWrites != 0 {
		t.Fatal("Node Ready alone created cluster identity")
	}
	f.etcdReady = true
	evidence, err := f.checker.Check(ctx, f.plan, f.host, true)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.NodeUID != "node-uid" || evidence.EtcdClusterID != "etcd-1" || evidence.VotingServers != 1 || f.markerWrites != 1 || !f.marker.Immutable {
		t.Fatal("missing independent health evidence")
	}
	if _, err := f.checker.Check(ctx, f.plan, f.host, false); err != nil {
		t.Fatal(err)
	}
	if f.markerWrites != 1 {
		t.Fatal("identity recreated")
	}
	f.marker.Data["clusterID"] = "wrong"
	if _, err := f.checker.Check(ctx, f.plan, f.host, true); !errors.Is(err, ErrReconcile) {
		t.Fatal(err)
	}
	if f.markerWrites != 1 {
		t.Fatal("foreign identity overwritten")
	}
}

func TestHealthRejectsMissingIdentityWrongMembershipAndUnreadyNodes(t *testing.T) {
	for _, kind := range []string{"missing-marker", "unready-node", "wrong-role", "wrong-etcd-member", "learner", "not-three-voters"} {
		t.Run(kind, func(t *testing.T) {
			f := healthSetup(t)
			switch kind {
			case "unready-node":
				f.ready = false
			case "wrong-role":
				f.role = "agent"
			case "wrong-etcd-member":
				f.memberID = "other"
			case "learner":
				f.learner = true
			case "not-three-voters":
				f.plan.MinVotingServers = 3
			}
			if _, err := f.checker.Check(context.Background(), f.plan, f.host, false); err == nil {
				t.Fatal("ambiguous health accepted")
			}
			if f.markerWrites != 0 {
				t.Fatal("read-only check mutated cluster")
			}
		})
	}
}

func TestWorkerHealthCannotBootstrapClusterIdentity(t *testing.T) {
	f := healthSetup(t)
	f.plan.Mode = "join"
	f.plan.Role = "agent"
	f.plan.AgentTokenFile = ""
	f.role = "agent"
	if _, err := f.checker.Check(context.Background(), f.plan, f.host, true); !errors.Is(err, ErrWaiting) {
		t.Fatal(err)
	}
	if f.markerWrites != 0 {
		t.Fatal("worker created cluster identity")
	}
	f.marker = &clusterIdentity{Immutable: true, Data: map[string]string{"clusterID": f.plan.ClusterID, "policyDigest": f.plan.PolicyDigest}}
	evidence, err := f.checker.Check(context.Background(), f.plan, f.host, false)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.NodeUID == "" || evidence.EtcdClusterID != "" {
		t.Fatal("worker claimed server health")
	}
}
