package formation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"auto-cluster-rke2/internal/hostagent"
)

func TestControlTargetsRetirementAndAdmissionLock(t *testing.T) {
	for _, target := range []int{3, 5, 7} {
		t.Run(fmt.Sprint(target), func(t *testing.T) {
			cluster := newCluster(t)
			catalog := Catalog{ControlNodes: target, Members: map[string]Member{}, Retired: map[string]Member{}}
			var last Member
			for i := 0; i < target+2; i++ {
				n := newNode(t, cluster, i)
				m, err := catalog.Reserve(n.member(n.current))
				if err != nil {
					t.Fatal(err)
				}
				want := "agent"
				if i < target {
					want = "server"
				}
				if m.Role != want {
					t.Fatalf("member %d: %s", i, m.Role)
				}
				m.Complete = true
				catalog.Members[m.ID] = m
				last = m
			}
			delete(catalog.Members, last.ID)
			catalog.Retired[last.ID] = last
			if _, err := catalog.Reserve(last); err != ErrConflict {
				t.Fatal("retired identity re-enrolled", err)
			}
			n := newNode(t, cluster, target+3)
			m := n.member(n.current)
			catalog.Operation = &MembershipOperation{ID: strings.Repeat("a", 32)}
			if _, err := catalog.Reserve(m); err != ErrWaiting {
				t.Fatal("unapproved join", err)
			}
			catalog.Operation.Address = m.Address
			if _, err := catalog.Reserve(m); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagementCASRetirementRetriesAndQuorum(t *testing.T) {
	cluster := newCluster(t)
	c := Catalog{ClusterID: "cluster", Policy: "policy", ControlNodes: 3, Members: map[string]Member{}}
	voters := map[string]EtcdMember{}
	nodes := map[string]ManagementNode{}
	var victim Member
	for i := 0; i < 3; i++ {
		n := newNode(t, cluster, i)
		m := n.member(n.current)
		m.Role = "server"
		m.Complete = true
		m.NodeUID = fmt.Sprint("uid-", i)
		m.EtcdMemberID = fmt.Sprint(i + 1)
		c.Members[m.ID] = m
		voters[m.EtcdMemberID] = EtcdMember{ID: m.EtcdMemberID, PeerURLs: []string{"https://" + m.Address + ":2380"}}
		node := ManagementNode{}
		node.Metadata.Name = m.NodeName
		node.Metadata.UID = m.NodeUID
		nodes[m.NodeName] = node
		victim = m
	}
	cm := catalogMap(c)
	cm.Metadata.ResourceVersion = "1"
	version, removes := 1, 0
	conflict, quorum := true, true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/readyz":
			if !quorum {
				w.WriteHeader(503)
				return
			}
			fmt.Fprintln(w, "ok")
		case "/v3/cluster/member/list":
			list := []EtcdMember{}
			for _, v := range voters {
				list = append(list, v)
			}
			json.NewEncoder(w).Encode(map[string]any{"members": list})
		case "/v3/cluster/member/remove":
			var v struct{ ID string }
			json.NewDecoder(r.Body).Decode(&v)
			delete(voters, v.ID)
			removes++
			fmt.Fprint(w, "{}")
		case "/api/v1/namespaces/kube-system/configmaps/autonomous-rke2-identity":
			json.NewEncoder(w).Encode(map[string]any{"immutable": true, "data": map[string]string{"clusterID": "cluster", "policyDigest": "policy"}})
		case catalogPath:
			if r.Method == http.MethodPut {
				var next configMap
				json.NewDecoder(r.Body).Decode(&next)
				if conflict {
					conflict = false
					w.WriteHeader(409)
					return
				}
				if next.Metadata.ResourceVersion != cm.Metadata.ResourceVersion {
					w.WriteHeader(409)
					return
				}
				version++
				next.Metadata.ResourceVersion = fmt.Sprint(version)
				cm = next
			}
			json.NewEncoder(w).Encode(cm)
		case "/api/v1/nodes":
			list := []ManagementNode{}
			for _, n := range nodes {
				list = append(list, n)
			}
			json.NewEncoder(w).Encode(map[string]any{"items": list})
		default:
			name := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
			n, ok := nodes[name]
			if !ok {
				w.WriteHeader(404)
				return
			}
			if r.Method == http.MethodDelete {
				var options struct{ Preconditions struct{ UID string } }
				json.NewDecoder(r.Body).Decode(&options)
				if options.Preconditions.UID != n.Metadata.UID {
					w.WriteHeader(409)
					return
				}
				delete(nodes, name)
				fmt.Fprint(w, "{}")
				return
			}
			json.NewEncoder(w).Encode(n)
		}
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	k := KubeBackend{ClusterID: "cluster", Policy: "policy", client: func(hostagent.TLSFiles) (*http.Client, error) {
		return &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			r.URL.Scheme = target.Scheme
			r.URL.Host = target.Host
			return http.DefaultTransport.RoundTrip(r)
		})}, nil
	}}
	ctx := context.Background()
	id := strings.Repeat("a", 32)
	call := func(action string) error {
		_, err := k.Manage(ctx, ManagementRequest{Action: action, Operation: id, Nodes: 2, ControlNodes: 3, MemberID: victim.ID})
		return err
	}
	if err := call("begin"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Manage(ctx, ManagementRequest{Action: "begin", Operation: strings.Repeat("b", 32), Nodes: 2, ControlNodes: 3}); err != ErrConflict {
		t.Fatal("concurrent operation accepted", err)
	}
	quorum = false
	if err := call("retire"); err != ErrWaiting {
		t.Fatal("mutation without quorum", err)
	}
	quorum = true
	if err := call("retire"); err != nil {
		t.Fatal(err)
	}
	// An etcd removal followed by a catalog CAS conflict must not remove twice.
	conflict = true
	if err := call("remove"); err != nil {
		t.Fatal(err)
	}
	if err := call("remove"); err != nil {
		t.Fatal("retry", err)
	}
	if removes != 1 {
		t.Fatalf("removed %d times", removes)
	}
	if _, ok := nodes[victim.NodeName]; ok {
		t.Fatal("node retained")
	}
	if err := call("finish"); err != nil {
		t.Fatal(err)
	}
	var final Catalog
	json.Unmarshal([]byte(cm.Data["catalog"]), &final)
	if final.Operation != nil || len(final.Members) != 2 || final.Retired[victim.ID].ID != victim.ID {
		t.Fatal("incorrect retirement")
	}
	if _, err := final.Reserve(victim); err != ErrConflict {
		t.Fatal("retired identity admitted", err)
	}
}
