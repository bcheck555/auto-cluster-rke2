package formation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"auto-cluster-rke2/internal/hostagent"
)

func TestHealingPolicyAndGenerationAuthorization(t *testing.T) {
	for _, v := range []string{"", "1m", "5m", "24h"} {
		if _, err := (HealingPolicy{FailureTimeout: v}).timeout(); err != nil {
			t.Fatal(v, err)
		}
	}
	for _, v := range []string{"0s", "59s", "25h", "bad"} {
		if _, err := (HealingPolicy{FailureTimeout: v}).timeout(); err == nil {
			t.Fatal("accepted", v)
		}
	}
	n := newNode(t, newCluster(t), 0)
	m := n.member(n.current)
	c := Catalog{Members: map[string]Member{}, Retired: map[string]Member{m.ID: m}, Hosts: map[string]HostAssignment{}}
	if _, err := c.Reserve(m); err != ErrConflict {
		t.Fatal("retired generation accepted", err)
	}
	newMember := m
	newMember.Generation = 1
	newMember.NodeName = incarnationName(m.ID, 1)
	newMember.RequestID = incarnationRequest(m.ID, 1)
	if _, err := c.Reserve(newMember); err != ErrConflict {
		t.Fatal("unauthorized generation accepted", err)
	}
	c.Hosts[m.ID] = HostAssignment{Generation: 1, Role: "agent", Address: m.Address, Previous: m, Operation: strings.Repeat("a", 32)}
	registered, err := c.Reserve(newMember)
	if err != nil || registered.Role != "agent" {
		t.Fatal("authorized worker return", registered, err)
	}
	if _, err := c.Reserve(m); err != ErrConflict {
		t.Fatal("old identity resurrected", err)
	}
}

func TestFailureWindowRequiresThreeIndependentSignals(t *testing.T) {
	m := Member{ID: "physical", Generation: 2, NodeName: "node", NodeUID: "uid"}
	n := ManagementNode{}
	n.Metadata.Name = "node"
	n.Metadata.UID = "uid"
	s := ManagementStatus{Catalog: Catalog{Heartbeats: map[string]Heartbeat{}}, Nodes: []ManagementNode{n}}
	now := time.Now()
	h := HealingController{Probe: func(context.Context, Member) bool { return false }}
	if h.failed(context.Background(), s, m, now, time.Minute) {
		t.Fatal("instant failure")
	}
	if !h.failed(context.Background(), s, m, now.Add(time.Minute), time.Minute) {
		t.Fatal("timeout not honored")
	}
	s.Catalog.Heartbeats[m.ID] = Heartbeat{At: now.Add(time.Minute), Generation: 2, Sequence: 1}
	if h.failed(context.Background(), s, m, now.Add(time.Minute), time.Minute) {
		t.Fatal("fresh heartbeat ignored")
	}
	delete(s.Catalog.Heartbeats, m.ID)
	if h.failed(context.Background(), s, m, now.Add(61*time.Second), time.Minute) {
		t.Fatal("heartbeat did not reset timeout")
	}
	h.Probe = func(context.Context, Member) bool { return true }
	if h.failed(context.Background(), s, m, now.Add(3*time.Minute), time.Minute) {
		t.Fatal("healthy voter replaced for API/agent failure")
	}
	h.Probe = func(context.Context, Member) bool { return false }
	s.Nodes[0].Status.Conditions = append(s.Nodes[0].Status.Conditions, struct {
		Type   string
		Status string
	}{"Ready", "True"})
	if h.failed(context.Background(), s, m, now.Add(4*time.Minute), time.Minute) {
		t.Fatal("ready node replaced")
	}
	h = HealingController{Probe: h.Probe}
	s.Nodes[0].Status.Conditions = nil
	if h.failed(context.Background(), s, m, now.Add(10*time.Minute), time.Minute) {
		t.Fatal("controller restart reused old observation")
	}
}

type healingFixture struct {
	mu          sync.Mutex
	c           Catalog
	nodes       map[string]ManagementNode
	voters      map[string]EtcdMember
	version     int
	quorum      bool
	conflicts   int
	removes     []string
	k           KubeBackend
	members     []Member
	pods        []map[string]any
	pvs         []map[string]any
	pvcs        map[string]map[string]any
	nodeCreates int
}

func newHealingFixture(t *testing.T) *healingFixture {
	t.Helper()
	f := &healingFixture{c: Catalog{ClusterID: "cluster", Policy: "policy", Members: map[string]Member{}, ControlNodes: 3, DesiredNodes: 5, SelfHealing: HealingPolicy{Enabled: true, FailureTimeout: "1m"}, Heartbeats: map[string]Heartbeat{}}, nodes: map[string]ManagementNode{}, voters: map[string]EtcdMember{}, quorum: true, version: 1}
	cluster := newCluster(t)
	for i := 0; i < 5; i++ {
		n := newNode(t, cluster, i)
		m := n.member(n.current)
		m.Role = "agent"
		if i < 3 {
			m.Role = "server"
			m.EtcdMemberID = fmt.Sprint(i + 1)
			f.voters[m.EtcdMemberID] = EtcdMember{ID: m.EtcdMemberID, PeerURLs: []string{"https://" + m.Address + ":2380"}}
		}
		m.Complete = true
		m.Index = i + 1
		m.PodCIDR = fmt.Sprintf("10.42.%d.0/24", i)
		m.PodCIDRs = []string{m.PodCIDR}
		m.NodeUID = fmt.Sprint("uid-", i)
		f.c.Members[m.ID] = m
		f.members = append(f.members, m)
		node := ManagementNode{}
		node.Metadata.Name = m.NodeName
		node.Metadata.UID = m.NodeUID
		node.Spec.PodCIDR = m.PodCIDR
		node.Spec.PodCIDRs = m.PodCIDRs
		if i != 2 {
			node.Status.Conditions = append(node.Status.Conditions, struct {
				Type   string
				Status string
			}{"Ready", "True"})
		}
		f.nodes[m.NodeName] = node
	}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	target, _ := url.Parse(server.URL)
	f.k = KubeBackend{ClusterID: "cluster", Policy: "policy", connectivity: func(context.Context, HealingOperation) error { return nil }, client: func(hostagent.TLSFiles) (*http.Client, error) {
		return &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			r.URL.Scheme = target.Scheme
			r.URL.Host = target.Host
			return http.DefaultTransport.RoundTrip(r)
		})}, nil
	}}
	return f
}
func (f *healingFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/readyz":
		if !f.quorum {
			w.WriteHeader(503)
			return
		}
		fmt.Fprint(w, "ok")
	case "/v3/cluster/member/list":
		v := []EtcdMember{}
		for _, m := range f.voters {
			v = append(v, m)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"members": v})
	case "/v3/cluster/member/remove":
		var v struct{ ID string }
		_ = json.NewDecoder(r.Body).Decode(&v)
		if _, exists := f.voters[v.ID]; !exists {
			w.WriteHeader(404)
			return
		}
		delete(f.voters, v.ID)
		f.removes = append(f.removes, v.ID)
		fmt.Fprint(w, "{}")
	case "/api/v1/namespaces/kube-system/configmaps/autonomous-rke2-identity":
		_ = json.NewEncoder(w).Encode(map[string]any{"immutable": true, "data": map[string]string{"clusterID": "cluster", "policyDigest": "policy"}})
	case catalogPath:
		if r.Method == http.MethodPut {
			var cm configMap
			_ = json.NewDecoder(r.Body).Decode(&cm)
			if f.conflicts > 0 {
				f.conflicts--
				w.WriteHeader(409)
				return
			}
			if cm.Metadata.ResourceVersion != fmt.Sprint(f.version) {
				w.WriteHeader(409)
				return
			}
			f.c = Catalog{}
			_ = json.Unmarshal([]byte(cm.Data["catalog"]), &f.c)
			f.version++
		}
		cm := catalogMap(f.c)
		cm.Metadata.ResourceVersion = fmt.Sprint(f.version)
		_ = json.NewEncoder(w).Encode(cm)
	case "/api/v1/nodes":
		if r.Method == http.MethodPost {
			var node ManagementNode
			_ = json.NewDecoder(r.Body).Decode(&node)
			if _, exists := f.nodes[node.Metadata.Name]; exists {
				w.WriteHeader(409)
				return
			}
			f.nodeCreates++
			node.Metadata.UID = fmt.Sprint("reserved-node-", f.nodeCreates)
			f.nodes[node.Metadata.Name] = node
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(node)
			return
		}
		list := []ManagementNode{}
		for _, n := range f.nodes {
			list = append(list, n)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": list})
	case "/api/v1/pods":
		_ = json.NewEncoder(w).Encode(map[string]any{"items": f.pods})
	case "/api/v1/persistentvolumes":
		_ = json.NewEncoder(w).Encode(map[string]any{"items": f.pvs})
	default:
		if strings.Contains(r.URL.Path, "/persistentvolumeclaims/") {
			value, ok := f.pvcs[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(value)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
		n, exists := f.nodes[name]
		if !exists {
			w.WriteHeader(404)
			return
		}
		if r.Method == http.MethodDelete {
			var options struct{ Preconditions struct{ UID string } }
			_ = json.NewDecoder(r.Body).Decode(&options)
			if options.Preconditions.UID != n.Metadata.UID {
				w.WriteHeader(409)
				return
			}
			delete(f.nodes, name)
			fmt.Fprint(w, "{}")
			return
		}
		if r.Method == http.MethodPatch {
			var changes []struct {
				Op    string
				Path  string
				Value any
			}
			_ = json.NewDecoder(r.Body).Decode(&changes)
			if len(changes) != 2 || changes[0].Value != n.Metadata.UID {
				w.WriteHeader(409)
				return
			}
			n.Spec.Unschedulable, _ = changes[1].Value.(bool)
			f.nodes[name] = n
		}
		_ = json.NewEncoder(w).Encode(n)
	}
}
func (f *healingFixture) beat(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, m := range f.c.Members {
		if id != f.members[2].ID {
			f.c.Heartbeats[id] = Heartbeat{At: now, Generation: m.Generation, Eligible: true, Sequence: f.c.Heartbeats[id].Sequence + 1}
		}
	}
}
func (f *healingFixture) snapshot() Catalog {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, _ := json.Marshal(f.c)
	var c Catalog
	_ = json.Unmarshal(data, &c)
	return c
}

func (f *healingFixture) prime(h *HealingController, now time.Time) {
	for _, m := range f.members {
		h.fresh(m, Heartbeat{Generation: m.Generation}, now.Add(-time.Second))
	}
}

func TestHeartbeatProgressUsesLocalTimeDespiteRemoteClockSkew(t *testing.T) {
	h := HealingController{}
	m := Member{ID: "physical", Generation: 1}
	now := time.Now()
	b := Heartbeat{Sequence: 10, Generation: 1, At: now.Add(24 * time.Hour)}
	if h.fresh(m, b, now) {
		t.Fatal("old sequence trusted on controller restart")
	}
	if h.fresh(m, b, now.Add(time.Minute)) {
		t.Fatal("future remote timestamp kept dead member fresh")
	}
	b.Sequence++
	if !h.fresh(m, b, now.Add(time.Minute)) {
		t.Fatal("committed sequence progress not observed")
	}
	if h.fresh(m, b, now.Add(2*time.Minute)) {
		t.Fatal("unchanged sequence stayed fresh")
	}
}

func TestHealingResumesExactMembersAndReturningWorker(t *testing.T) {
	f := newHealingFixture(t)
	now := time.Now()
	f.beat(now)
	var healthy []string
	for i := 0; i < 2; i++ {
		healthy = append(healthy, f.members[i].ID)
	}
	sort.Strings(healthy)
	h := &HealingController{ID: healthy[0], Now: func() time.Time { return now }, Probe: func(_ context.Context, m Member) bool { return m.ID != f.members[2].ID }, Drain: func(context.Context, Member) error { return nil }}
	f.prime(h, now)
	tick := func() {
		t.Helper()
		f.beat(now)
		leaders := []string{}
		for id, m := range f.snapshot().Members {
			if m.Role == "server" && m.Complete && id != f.members[2].ID {
				leaders = append(leaders, id)
			}
		}
		sort.Strings(leaders)
		h.ID = leaders[0]
		err := h.Tick(context.Background(), f.k)
		if err != nil && err != ErrWaiting {
			t.Fatal(err)
		}
	}
	tick()
	now = now.Add(61 * time.Second)
	tick()
	if f.snapshot().Healing == nil {
		t.Fatal("no healing after timeout")
	}
	// Every tick uses a fresh controller after commitment, simulating process
	// replacement. Durable phases, not controller memory, drive recovery.
	for i := 0; i < 8; i++ {
		c := f.snapshot()
		if c.Healing == nil {
			break
		}
		h.Since = nil
		if c.Healing.Phase == "promote" {
			if _, exists := c.Members[c.Healing.Candidate.ID]; !exists {
				t.Fatal("worker removed before stop acknowledgement")
			}
			if err := f.k.acknowledgeStop(context.Background(), c.Healing.Candidate); err != nil {
				t.Fatal(err)
			}
		}
		if c.Healing.Phase == "verify" {
			old := c.Healing.Candidate
			m := old
			m.Generation++
			m.NodeName = incarnationName(m.ID, m.Generation)
			m.RequestID = incarnationRequest(m.ID, m.Generation)
			m.Role = "server"
			m.NodeUID = "replacement-node"
			m.EtcdMemberID = "replacement-voter"
			f.mu.Lock()
			f.c.Members[m.ID] = m
			n := ManagementNode{}
			n.Metadata.Name = m.NodeName
			n.Metadata.UID = m.NodeUID
			n.Metadata.Labels = map[string]string{"autonomous-rke2.io/generation": fmt.Sprint(m.Generation)}
			n.Status.Conditions = append(n.Status.Conditions, struct {
				Type   string
				Status string
			}{"Ready", "True"})
			f.nodes[m.NodeName] = n
			f.voters[m.EtcdMemberID] = EtcdMember{ID: m.EtcdMemberID, PeerURLs: []string{"https://" + m.Address + ":2380"}}
			f.mu.Unlock()
		}
		f.mu.Lock()
		f.conflicts = 1
		f.mu.Unlock()
		tick()
	}
	c := f.snapshot()
	if c.Healing != nil || c.Operation != nil || len(c.History) != 1 || c.History[0].Phase != "completed" {
		t.Fatalf("incomplete healing: %+v", c.Healing)
	}
	if c.History[0].Candidate.ID != f.members[3].ID {
		t.Fatal("lowest worker index not selected")
	}
	if len(f.removes) != 1 || f.removes[0] != f.members[2].EtcdMemberID {
		t.Fatal("wrong/repeated voter removal", f.removes)
	}
	old := f.members[2]
	if _, err := c.Reserve(old); err != ErrConflict {
		t.Fatal("retired control rejoined", err)
	}
	returned := old
	returned.Generation++
	returned.NodeName = incarnationName(old.ID, returned.Generation)
	returned.RequestID = incarnationRequest(old.ID, returned.Generation)
	if m, err := c.Reserve(returned); err != nil || m.Role != "agent" {
		t.Fatal("return did not become worker", m, err)
	}
}

func TestHealingBlocksLostQuorumConcurrentResizeAndNoSpare(t *testing.T) {
	f := newHealingFixture(t)
	now := time.Now()
	f.beat(now)
	leader := f.members[0].ID
	if f.members[1].ID < leader {
		leader = f.members[1].ID
	}
	h := HealingController{ID: leader, Now: func() time.Time { return now }, Probe: func(_ context.Context, m Member) bool { return m.ID != f.members[2].ID }, Drain: func(context.Context, Member) error { return ErrWaiting }}
	f.prime(&h, now)
	f.mu.Lock()
	f.quorum = false
	f.mu.Unlock()
	if err := h.Tick(context.Background(), f.k); err != ErrWaiting {
		t.Fatal("lost quorum", err)
	}
	f.mu.Lock()
	f.quorum = true
	f.c.Operation = &MembershipOperation{ID: strings.Repeat("b", 32)}
	f.mu.Unlock()
	if err := h.Tick(context.Background(), f.k); err != nil {
		t.Fatal(err)
	}
	if f.snapshot().Healing != nil {
		t.Fatal("overlapped manual resize")
	}
	f.mu.Lock()
	f.c.Operation = nil
	f.mu.Unlock()
	_ = h.Tick(context.Background(), f.k)
	now = now.Add(time.Minute)
	f.beat(now)
	_ = h.Tick(context.Background(), f.k)
	for i := 0; i < 6; i++ {
		f.beat(now)
		_ = h.Tick(context.Background(), f.k)
	}
	c := f.snapshot()
	if c.Healing == nil || c.Healing.Phase != "blocked" || len(c.Healing.Blocked) != 2 || len(f.removes) != 0 {
		t.Fatal("protected drains bypassed", c.Healing, f.removes)
	}
}

func TestDisableCancelsBeforeCommitAndFinishesAfterCommit(t *testing.T) {
	for _, phase := range []string{"select", "drain", "blocked", "retire", "promote"} {
		t.Run(phase, func(t *testing.T) {
			f := newHealingFixture(t)
			now := time.Now()
			f.beat(now)
			leader := f.members[0].ID
			if f.members[1].ID < leader {
				leader = f.members[1].ID
			}
			f.mu.Lock()
			f.c.SelfHealing.Enabled = false
			f.c.Operation = &MembershipOperation{ID: strings.Repeat("c", 32), Nodes: 5, ControlNodes: 3}
			f.c.Healing = &HealingOperation{ID: f.c.Operation.ID, Phase: phase, Failed: f.members[2], Candidate: f.members[3], Blocked: map[string]string{}, Evidence: map[string]string{}}
			if phase == "promote" {
				delete(f.c.Members, f.members[2].ID)
				delete(f.voters, f.members[2].EtcdMemberID)
				delete(f.nodes, f.members[2].NodeName)
			}
			f.mu.Unlock()
			h := HealingController{ID: leader, Now: func() time.Time { return now }, Probe: func(context.Context, Member) bool { return false }}
			f.prime(&h, now)
			err := h.Tick(context.Background(), f.k)
			if phase == "promote" {
				if err != ErrWaiting || f.snapshot().Healing == nil {
					t.Fatal("committed healing was abandoned", err)
				}
			} else {
				if err != nil || f.snapshot().Healing != nil || f.snapshot().Operation != nil || len(f.removes) != 0 {
					t.Fatal("uncommitted operation not cancelled", err)
				}
			}
		})
	}
}
