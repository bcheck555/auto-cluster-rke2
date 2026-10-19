package formation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"auto-cluster-rke2/internal/hostagent"
)

func TestConnectivityPeerExcludesStoppedButReadyControl(t *testing.T) {
	now := time.Now()
	h := HealingController{Seen: map[string]seenHeartbeat{}}
	s := ManagementStatus{Catalog: Catalog{Members: map[string]Member{}, Heartbeats: map[string]Heartbeat{}}}
	for i, id := range []string{"stopped", "healthy", "replacement", "later"} {
		m := Member{ID: id, Role: "server", Complete: true, Index: i + 1, NodeName: id, NodeUID: "uid-" + id}
		s.Catalog.Members[id] = m
		s.Catalog.Heartbeats[id] = Heartbeat{Sequence: 2}
		seen := seenHeartbeat{Sequence: 2, Observed: now, Confirmed: true}
		if id == "stopped" {
			seen.Observed = now.Add(-time.Minute)
		}
		h.Seen[incarnationKey(m)] = seen
		n := ManagementNode{}
		n.Metadata.Name, n.Metadata.UID = m.NodeName, m.NodeUID
		n.Status.Conditions = append(n.Status.Conditions, struct {
			Type   string
			Status string
		}{"Ready", "True"})
		s.Nodes = append(s.Nodes, n)
	}
	peer, ok := h.connectivityPeer(s, s.Catalog.Members["replacement"], now)
	if !ok || peer.ID != "healthy" {
		t.Fatal("selected stopped or nondeterministic peer", peer)
	}
	h.Seen["healthy"] = seenHeartbeat{Sequence: 2, Observed: now.Add(-time.Minute), Confirmed: true}
	peer, ok = h.connectivityPeer(s, s.Catalog.Members["replacement"], now)
	if !ok || peer.ID != "later" {
		t.Fatal("expired heartbeat selected", peer)
	}
	s.Nodes[3].Metadata.UID = "stale-uid"
	if _, ok := h.connectivityPeer(s, s.Catalog.Members["replacement"], now); ok {
		t.Fatal("stale node incarnation selected")
	}
}

func TestHealingProbeCleanupChecksOwnershipAndExactUID(t *testing.T) {
	for _, scenario := range []struct {
		name                       string
		foreign, finalizer, absent bool
		want                       error
	}{
		{name: "owned offline probe"},
		{name: "foreign resource", foreign: true, want: ErrConflict},
		{name: "unexpected finalizer", finalizer: true, want: ErrWaiting},
		{name: "retry after deletion", absent: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			deletes := 0
			labels := map[string]string{"autonomous-rke2.io/healing-operation": "operation"}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/namespaces/owned/pods/server" {
					t.Error("unexpected cleanup path", r.URL.Path)
					w.WriteHeader(404)
					return
				}
				if r.Method == http.MethodGet {
					if scenario.absent {
						w.WriteHeader(404)
						return
					}
					metadata := map[string]any{"uid": "exact-pod-uid", "labels": labels}
					if scenario.foreign {
						metadata["labels"] = map[string]string{"other": "owner"}
					}
					if scenario.finalizer {
						metadata["finalizers"] = []string{"protect"}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"metadata": metadata})
					return
				}
				if r.Method != http.MethodDelete {
					t.Error("unexpected cleanup method", r.Method)
					w.WriteHeader(405)
					return
				}
				deletes++
				var body struct {
					Grace         *int64 `json:"gracePeriodSeconds"`
					Preconditions struct {
						UID string `json:"uid"`
					} `json:"preconditions"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.Grace == nil || *body.Grace != 0 || body.Preconditions.UID != "exact-pod-uid" {
					t.Error("cleanup lacked exact UID or bounded probe deletion", body)
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			target, _ := url.Parse(srv.URL)
			k := KubeBackend{client: func(hostagent.TLSFiles) (*http.Client, error) {
				return &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
					r.URL.Scheme = target.Scheme
					r.URL.Host = target.Host
					return http.DefaultTransport.RoundTrip(r)
				})}, nil
			}}
			if err := k.cleanupHealingProbe(context.Background(), "owned", "pods/server", labels); err != scenario.want {
				t.Fatal(err, scenario.want)
			}
			if (deletes == 1) != (!scenario.foreign && !scenario.finalizer && !scenario.absent) {
				t.Fatal("unsafe or duplicate cleanup", deletes)
			}
		})
	}
}
