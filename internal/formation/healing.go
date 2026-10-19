package formation

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"

	"auto-cluster-rke2/internal/hostagent"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

const HealingCapability = "control-self-healing-v1"

// A recovery blocker must not shut down a healthy coordinator's own role.
type HealingBlocked struct{ Cause error }

func (e HealingBlocked) Error() string { return "self-healing blocked: " + e.Cause.Error() }
func (e HealingBlocked) Unwrap() error { return ErrWaiting }

type HealingPolicy struct {
	Enabled        bool   `json:"enabled"`
	FailureTimeout string `json:"failure_timeout"`
}

func (p HealingPolicy) timeout() (time.Duration, error) {
	value := p.FailureTimeout
	if value == "" {
		value = "5m"
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < time.Minute || d > 24*time.Hour {
		return 0, ErrInvalid
	}
	return d, nil
}

type Heartbeat struct {
	At         time.Time
	Generation uint64
	Eligible   bool
	Sequence   uint64
}

type FailureObservation struct {
	Controller string
	Session    string
	Since      time.Time
	Generation uint64
}

// ID is the stable physical signer identity. Generation identifies an RKE2
// incarnation; authorization never resurrects an earlier incarnation.
type HostAssignment struct {
	Generation uint64
	Role       string
	Address    string
	Previous   Member
	Operation  string
	Action     string
	Stopped    bool
}

type HealingOperation struct {
	ID        string
	Phase     string
	Failed    Member
	Candidate Member
	Blocked   map[string]string
	Evidence  map[string]string
	Started   time.Time
	Completed time.Time
}

type RoleAuthorization struct {
	ClusterID  string
	Policy     string
	Assignment HostAssignment
	Member     Member
	Blocked    string
}

func incarnationName(id string, generation uint64) string {
	if len(id) < 16 {
		return ""
	}
	// Names and subnet affinity belong to the physical host. UID, credentials,
	// role generation and etcd voter ID identify its fresh incarnation.
	return "rke2-" + id[:16]
}
func incarnationRequest(id string, generation uint64) string {
	if generation == 0 {
		return "initial-" + id
	}
	return fmt.Sprintf("generation-%s-%d", id, generation)
}
func incarnationKey(m Member) string {
	if m.Generation == 0 {
		return m.ID
	}
	return fmt.Sprintf("%s@%d", m.ID, m.Generation)
}
func memberIndex(m Member) uint32 {
	if m.Index > 0 {
		return uint32(m.Index)
	}
	ip := net.ParseIP(m.Address).To4()
	if ip == nil {
		return ^uint32(0)
	}
	return binary.BigEndian.Uint32(ip)
}

// updateCatalog always checks the immutable marker and a writable datastore.
// Retried callbacks must have idempotent side effects pinned to exact IDs.
func (k KubeBackend) updateCatalog(ctx context.Context, change func(*Catalog) error) error {
	if _, err := k.etcdMembers(ctx); err != nil {
		return err
	}
	for range 8 {
		c, cm, status, err := k.load(ctx)
		if err != nil {
			return err
		}
		if status != 200 {
			return ErrWaiting
		}
		if err := change(&c); err != nil {
			return err
		}
		next := catalogMap(c)
		next.Metadata.ResourceVersion = cm.Metadata.ResourceVersion
		_, status, err = k.call(ctx, false, http.MethodPut, catalogPath, next)
		if err != nil {
			return err
		}
		if status == 409 {
			continue
		}
		if status != 200 {
			return ErrWaiting
		}
		return nil
	}
	return ErrWaiting
}

func (k KubeBackend) authorization(ctx context.Context, request Member, pulse, eligible bool) (RoleAuthorization, error) {
	var result RoleAuthorization
	err := k.updateCatalog(ctx, func(c *Catalog) error {
		m, exists := c.Members[request.ID]
		assignment, assigned := c.Hosts[request.ID]
		if !exists && !assigned {
			return ErrConflict
		}
		if exists && (m.Address != request.Address || digest(m.PublicKey) != digest(request.PublicKey)) {
			return ErrConflict
		}
		if assigned && (assignment.Address != request.Address || digest(assignment.Previous.PublicKey) != digest(request.PublicKey)) {
			return ErrConflict
		}
		if !assigned {
			assignment = HostAssignment{Generation: m.Generation, Role: m.Role, Address: m.Address, Previous: m}
		}
		if request.Generation > assignment.Generation {
			return ErrConflict
		}
		result = RoleAuthorization{ClusterID: c.ClusterID, Policy: c.Policy, Assignment: assignment, Member: m}
		if c.Healing != nil && c.Healing.Blocked != nil {
			result.Blocked = c.Healing.Blocked[request.ID]
		}
		if pulse {
			if !exists || !m.Complete || m.Retiring || !sameMember(m, request) || request.Generation != assignment.Generation || m.NodeUID != request.NodeUID || m.EtcdMemberID != request.EtcdMemberID {
				return ErrConflict
			}
			if c.Heartbeats == nil {
				c.Heartbeats = map[string]Heartbeat{}
			}
			previous := c.Heartbeats[m.ID]
			sequence := uint64(1)
			if previous.Generation == m.Generation {
				sequence = previous.Sequence + 1
			}
			c.Heartbeats[m.ID] = Heartbeat{At: time.Now().UTC(), Generation: m.Generation, Eligible: eligible, Sequence: sequence}
		}
		return nil
	})
	return result, err
}

func (k KubeBackend) acknowledgeStop(ctx context.Context, m Member) error {
	return k.updateCatalog(ctx, func(c *Catalog) error {
		a, ok := c.Hosts[m.ID]
		if !ok || a.Action != "stop" || a.Generation != m.Generation || !sameMember(a.Previous, m) || c.Healing == nil || c.Healing.ID != a.Operation {
			return ErrConflict
		}
		a.Stopped = true
		c.Hosts[m.ID] = a
		return nil
	})
}

type HealingController struct {
	ID         string
	Session    string
	Since      map[string]time.Time
	Now        func() time.Time
	Probe      func(context.Context, Member) bool
	Drain      func(context.Context, Member) error
	Seen       map[string]seenHeartbeat
	RetrySince map[string]time.Time
}

func (h *HealingController) Run(ctx context.Context, n *Node, report func(error)) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		current := n.Current()
		if !current.Serving || current.Phase != "Healthy" || current.Role != "server" {
			continue
		}
		attempt, cancel := context.WithTimeout(ctx, 90*time.Second)
		err := h.Tick(attempt, KubeBackend{ClusterID: current.ClusterID, Policy: n.Settings.Policy()})
		cancel()
		if err != nil && report != nil {
			report(HealingBlocked{Cause: err})
		}
	}
}

type seenHeartbeat struct {
	Sequence  uint64
	Observed  time.Time
	Confirmed bool
}

// Freshness is elapsed local monotonic time since a quorum-committed sequence
// change, never a subtraction of clocks belonging to different machines.
func (h *HealingController) fresh(m Member, b Heartbeat, now time.Time) bool {
	if h.Seen == nil {
		h.Seen = map[string]seenHeartbeat{}
	}
	sequence := b.Sequence
	if b.Generation != m.Generation {
		sequence = 0
	}
	key := incarnationKey(m)
	seen, exists := h.Seen[key]
	if !exists {
		h.Seen[key] = seenHeartbeat{Sequence: sequence, Observed: now}
		return false
	}
	if sequence > seen.Sequence {
		seen = seenHeartbeat{Sequence: sequence, Observed: now, Confirmed: true}
		h.Seen[key] = seen
	}
	return sequence > 0 && seen.Confirmed && !seen.Observed.IsZero() && now.Sub(seen.Observed) < 30*time.Second
}

func nodeReady(n ManagementNode) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == "Ready" {
			return c.Status == "True"
		}
	}
	return false
}

func validateHealingMembership(s ManagementStatus) error {
	expected := map[string]Member{}
	pending := map[string]bool{}
	nodes := map[string]Member{}
	for _, m := range s.Catalog.Members {
		nodes[m.NodeName] = m
		if m.Role == "server" {
			if m.Complete {
				expected[m.EtcdMemberID] = m
			} else {
				pending["https://"+m.Address+":2380"] = true
			}
		}
	}
	for _, node := range s.Nodes {
		m, owned := nodes[node.Metadata.Name]
		if !owned || m.Complete && m.NodeUID != node.Metadata.UID {
			return ErrConflict
		}
		if m.Complete && m.Generation > 0 && node.Metadata.Labels["autonomous-rke2.io/generation"] != fmt.Sprint(m.Generation) {
			return ErrConflict
		}
	}
	for _, voter := range s.Voters {
		if len(voter.PeerURLs) != 1 {
			return ErrConflict
		}
		if m, owned := expected[voter.ID]; owned {
			if voter.IsLearner || voter.PeerURLs[0] != "https://"+m.Address+":2380" {
				return ErrConflict
			}
			delete(expected, voter.ID)
		} else if !pending[voter.PeerURLs[0]] {
			return ErrConflict
		}
	}
	for _, missing := range expected {
		op := s.Catalog.Healing
		if op == nil || !missing.Retiring || op.Phase != "retire" || missing.ID != op.Failed.ID {
			return ErrConflict
		}
	}
	return nil
}

func (h *HealingController) failed(ctx context.Context, s ManagementStatus, m Member, now time.Time, timeout time.Duration) bool {
	if h.Since == nil {
		h.Since = map[string]time.Time{}
	}
	heartbeat := s.Catalog.Heartbeats[m.ID]
	key := incarnationKey(m)
	ready := false
	for _, n := range s.Nodes {
		if n.Metadata.Name == m.NodeName && n.Metadata.UID == m.NodeUID {
			ready = nodeReady(n)
		}
	}
	if ready || h.fresh(m, heartbeat, now) || h.Probe(ctx, m) {
		delete(h.Since, key)
		return false
	}
	if h.Since[key].IsZero() {
		h.Since[key] = now
	}
	return now.Sub(h.Since[key]) >= timeout
}

func (k KubeBackend) probeMember(ctx context.Context, m Member) bool {
	client, err := k.tls(etcdTLS())
	if err != nil {
		return false
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		return false
	}
	endpoint := "https://" + net.JoinHostPort(m.Address, "2379")
	peer, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, TLS: transport.TLSClientConfig.Clone(), DialTimeout: 2 * time.Second, Context: ctx, Logger: zap.NewNop(), DialOptions: []grpc.DialOption{grpc.WithNoProxy()}})
	if err != nil {
		return false
	}
	defer peer.Close()
	response, err := peer.Get(ctx, "/autonomous-rke2/health-probe", clientv3.WithLimit(1))
	if err != nil || response.Header == nil || fmt.Sprint(response.Header.MemberId) != m.EtcdMemberID {
		return false
	}
	data, status, err := k.call(ctx, true, http.MethodPost, "/v3/maintenance/status", struct{}{})
	var local struct {
		Header struct {
			ClusterID string `json:"cluster_id"`
		}
	}
	return err == nil && status == 200 && json.Unmarshal(data, &local) == nil && local.Header.ClusterID == fmt.Sprint(response.Header.ClusterId)
}

func etcdTLS() hostagent.TLSFiles {
	return hostagent.TLSFiles{CA: "/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt", Cert: "/var/lib/rancher/rke2/server/tls/etcd/server-client.crt", Key: "/var/lib/rancher/rke2/server/tls/etcd/server-client.key"}
}

func (h *HealingController) Tick(ctx context.Context, k KubeBackend) error {
	status, err := k.managementStatus(ctx)
	if err != nil {
		h.Since = nil
		return err
	}
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	if h.Probe == nil {
		h.Probe = k.probeMember
	}
	if h.Drain == nil {
		h.Drain = k.drainCandidate
	}
	c := status.Catalog
	active := map[string]bool{}
	for id, m := range c.Members {
		key := incarnationKey(m)
		active[key] = true
		h.fresh(m, c.Heartbeats[id], now)
	}
	for key := range h.Seen {
		if !active[key] {
			delete(h.Seen, key)
		}
	}
	for key := range h.Since {
		if !active[key] {
			delete(h.Since, key)
		}
	}
	// The lowest currently heartbeating control acts; an interrupted operation
	// remains cluster-owned and is resumed by its successor after failover.
	leader := ""
	for id, m := range c.Members {
		b := c.Heartbeats[id]
		if m.Role == "server" && m.Complete && !m.Retiring && h.fresh(m, b, now) && (leader == "" || id < leader) {
			leader = id
		}
	}
	if leader != h.ID {
		h.Since = nil
		return nil
	}
	if c.Healing != nil {
		if err := validateHealingMembership(status); err != nil {
			return err
		}
		return h.advance(ctx, k, status, now)
	}
	if !c.SelfHealing.Enabled || c.Operation != nil {
		h.Since = nil
		return nil
	}
	if err := validateHealingMembership(status); err != nil {
		return err
	}
	for _, m := range c.Members {
		if !m.Complete || m.Retiring {
			return ErrWaiting
		}
	}
	timeout, err := c.SelfHealing.timeout()
	if err != nil {
		return err
	}
	var failures []Member
	for _, m := range c.Members {
		if m.Role == "server" && m.Complete && !m.Retiring && h.failed(ctx, status, m, now, timeout) {
			failures = append(failures, m)
		}
	}
	sort.Slice(failures, func(i, j int) bool { return memberIndex(failures[i]) < memberIndex(failures[j]) })
	if len(failures) == 0 {
		return k.updateCatalog(ctx, func(c *Catalog) error {
			c.Observations = map[string]FailureObservation{}
			for _, m := range c.Members {
				if since := h.Since[incarnationKey(m)]; m.Role == "server" && !since.IsZero() {
					c.Observations[m.ID] = FailureObservation{Controller: h.ID, Session: h.Session, Since: since.UTC(), Generation: m.Generation}
				}
			}
			return nil
		})
	}
	opID := digest(struct {
		ID         string
		Generation uint64
	}{failures[0].ID, failures[0].Generation})[:32]
	return k.updateCatalog(ctx, func(c *Catalog) error {
		if c.Operation != nil || c.Healing != nil {
			return ErrWaiting
		}
		for _, m := range c.Members {
			if !m.Complete || m.Retiring {
				return ErrWaiting
			}
		}
		c.Healing = &HealingOperation{ID: opID, Phase: "select", Failed: failures[0], Started: now.UTC(), Blocked: map[string]string{}, Evidence: map[string]string{}}
		c.Operation = &MembershipOperation{ID: opID, Nodes: c.DesiredNodes, ControlNodes: c.controlTarget()}
		return nil
	})
}

func (h *HealingController) advance(ctx context.Context, k KubeBackend, s ManagementStatus, now time.Time) error {
	op := *s.Catalog.Healing
	if s.Catalog.Operation == nil || s.Catalog.Operation.ID != op.ID {
		return ErrConflict
	}
	change := func(phase string, apply func(*Catalog) error) error {
		return k.updateCatalog(ctx, func(c *Catalog) error {
			if c.Healing == nil || c.Healing.ID != op.ID || c.Healing.Phase != op.Phase {
				return ErrWaiting
			}
			if apply != nil {
				if err := apply(c); err != nil {
					return err
				}
			}
			if c.Healing != nil {
				c.Healing.Phase = phase
			}
			return nil
		})
	}
	// A recovered old voter wins until retirement is committed. Afterwards its
	// tombstone wins permanently, even if it becomes reachable again.
	if op.Phase == "select" || op.Phase == "drain" || op.Phase == "blocked" {
		if !s.Catalog.SelfHealing.Enabled || h.Probe(ctx, op.Failed) {
			if op.Candidate.ID != "" {
				_ = k.nodeCordon(ctx, op.Candidate, false)
			}
			return change("cancelled", func(c *Catalog) error {
				c.Healing.Phase = "cancelled"
				c.Healing.Completed = now.UTC()
				c.History = append(c.History, *c.Healing)
				c.Healing = nil
				c.Operation = nil
				return nil
			})
		}
	}
	switch op.Phase {
	case "select":
		if !validPodSubnet(op.Failed.PodCIDR) {
			return change("blocked", func(c *Catalog) error {
				c.Healing.Evidence["blocker"] = "failed control pod subnet is unavailable or unsupported"
				return nil
			})
		}
		var candidates []Member
		for id, m := range s.Catalog.Members {
			b := s.Catalog.Heartbeats[id]
			ready := false
			for _, n := range s.Nodes {
				if n.Metadata.UID == m.NodeUID && n.Metadata.Name == m.NodeName {
					ready = nodeReady(n) && !n.Spec.Unschedulable
				}
			}
			if m.Role == "agent" && m.Complete && !m.Retiring && ready && validPodSubnet(m.PodCIDR) && h.fresh(m, b, now) && b.Eligible && op.Blocked[id] == "" {
				candidates = append(candidates, m)
			}
		}
		sort.Slice(candidates, func(i, j int) bool { return memberIndex(candidates[i]) < memberIndex(candidates[j]) })
		if len(candidates) == 0 {
			return change("blocked", func(c *Catalog) error {
				c.Healing.Evidence["blocker"] = "no healthy, drainable spare worker"
				return nil
			})
		}
		return change("drain", func(c *Catalog) error {
			delete(c.Healing.Evidence, "blocker")
			c.Healing.Candidate = candidates[0]
			return nil
		})
	case "blocked":
		// Retry candidates periodically; blockers may have been resolved by users.
		if h.RetrySince == nil {
			h.RetrySince = map[string]time.Time{}
		}
		if h.RetrySince[op.ID].IsZero() {
			h.RetrySince[op.ID] = now
		}
		if now.Sub(h.RetrySince[op.ID]) < time.Minute {
			return nil
		}
		delete(h.RetrySince, op.ID)
		return change("select", func(c *Catalog) error {
			c.Healing.Blocked = map[string]string{}
			return nil
		})
	case "drain":
		if err := h.Drain(ctx, op.Candidate); err != nil {
			return change("select", func(c *Catalog) error {
				c.Healing.Blocked[op.Candidate.ID] = "protected drain blocked"
				c.Healing.Candidate = Member{}
				return nil
			})
		}
		return change("retire", nil)
	case "retire":
		if old, exists := s.Catalog.Members[op.Failed.ID]; exists && !old.Retiring && (!s.Catalog.SelfHealing.Enabled || h.Probe(ctx, op.Failed)) {
			if op.Candidate.ID != "" {
				_ = k.nodeCordon(ctx, op.Candidate, false)
			}
			return change("cancelled", func(c *Catalog) error {
				c.Healing.Phase = "cancelled"
				c.Healing.Completed = now.UTC()
				c.History = append(c.History, *c.Healing)
				c.Healing = nil
				c.Operation = nil
				return nil
			})
		}
		if _, err := k.Manage(ctx, ManagementRequest{Action: "retire", Operation: op.ID, MemberID: op.Failed.ID, MemberGeneration: op.Failed.Generation}); err != nil {
			return err
		}
		if _, err := k.Manage(ctx, ManagementRequest{Action: "remove", Operation: op.ID, MemberID: op.Failed.ID, MemberGeneration: op.Failed.Generation}); err != nil {
			return err
		}
		return change("promote", func(c *Catalog) error {
			if c.Hosts == nil {
				c.Hosts = map[string]HostAssignment{}
			}
			c.Hosts[op.Failed.ID] = HostAssignment{Generation: op.Failed.Generation + 1, Role: "agent", Address: op.Failed.Address, Previous: op.Failed, Operation: op.ID}
			c.Hosts[op.Candidate.ID] = HostAssignment{Generation: op.Candidate.Generation, Role: "agent", Address: op.Candidate.Address, Previous: op.Candidate, Operation: op.ID, Action: "stop"}
			c.Healing.Evidence["retired_etcd_id"] = op.Failed.EtcdMemberID
			return nil
		})
	case "promote":
		if m, ok := s.Catalog.Members[op.Candidate.ID]; ok && m.Generation > op.Candidate.Generation {
			if m.Role != "server" {
				return ErrConflict
			}
			return change("verify", nil)
		}
		if assignment := s.Catalog.Hosts[op.Candidate.ID]; assignment.Operation != op.ID || !assignment.Stopped {
			return ErrWaiting
		}
		if _, err := k.Manage(ctx, ManagementRequest{Action: "retire", Operation: op.ID, MemberID: op.Candidate.ID, MemberGeneration: op.Candidate.Generation}); err != nil {
			return err
		}
		if _, err := k.Manage(ctx, ManagementRequest{Action: "remove", Operation: op.ID, MemberID: op.Candidate.ID, MemberGeneration: op.Candidate.Generation}); err != nil {
			return err
		}
		return change("verify", func(c *Catalog) error {
			if c.Hosts == nil {
				c.Hosts = map[string]HostAssignment{}
			}
			c.Hosts[op.Candidate.ID] = HostAssignment{Generation: op.Candidate.Generation + 1, Role: "server", Address: op.Candidate.Address, Previous: op.Candidate, Operation: op.ID}
			c.Operation.Address = op.Candidate.Address
			return nil
		})
	case "verify":
		m, ok := s.Catalog.Members[op.Candidate.ID]
		if !ok || !m.Complete || m.Role != "server" || m.Generation != op.Candidate.Generation+1 || !h.Probe(ctx, m) {
			return ErrWaiting
		}
		ready := false
		for _, node := range s.Nodes {
			if node.Metadata.Name == m.NodeName && node.Metadata.UID == m.NodeUID {
				ready = nodeReady(node)
			}
		}
		if !ready {
			return ErrWaiting
		}
		voters, err := k.etcdMembers(ctx)
		if err != nil {
			return err
		}
		expected := map[string]bool{}
		for _, m := range s.Catalog.Members {
			if m.Role == "server" && m.Complete {
				expected[m.EtcdMemberID] = true
			}
		}
		if len(voters) != len(expected) {
			return ErrWaiting
		}
		for _, v := range voters {
			if v.IsLearner || !expected[v.ID] || v.ID == op.Failed.EtcdMemberID {
				return ErrWaiting
			}
		}
		other, ok := h.connectivityPeer(s, m, now)
		if !ok {
			return ErrWaiting
		}
		if err := k.checkConnectivity(ctx, op, other); err != nil {
			return err
		}
		return change("completed", func(c *Catalog) error {
			c.Healing.Phase = "completed"
			c.Healing.Completed = now.UTC()
			c.Healing.Evidence["replacement_etcd_id"] = m.EtcdMemberID
			c.Healing.Evidence["workload_connectivity"] = "verified"
			c.History = append(c.History, *c.Healing)
			c.Healing = nil
			c.Operation = nil
			return nil
		})
	default:
		return ErrConflict
	}
}

// A restricted control may still report Node Ready and retain a healthy vote.
// Require advancing authenticated agent heartbeats as well before placing a
// workload probe there. Controller failover must not depend on a stopped agent.
func (h *HealingController) connectivityPeer(s ManagementStatus, replacement Member, now time.Time) (Member, bool) {
	var selected Member
	for _, m := range s.Catalog.Members {
		if m.ID == replacement.ID || m.Role != "server" || !m.Complete || m.Retiring || !h.fresh(m, s.Catalog.Heartbeats[m.ID], now) {
			continue
		}
		for _, n := range s.Nodes {
			if n.Metadata.Name == m.NodeName && n.Metadata.UID == m.NodeUID && nodeReady(n) && (selected.ID == "" || memberIndex(m) < memberIndex(selected)) {
				selected = m
			}
		}
	}
	return selected, selected.ID != ""
}

// decodeList keeps API transport generic while preserving malformed-data errors.
func decodeList(data []byte) ([]map[string]any, error) {
	var v struct{ Items []map[string]any }
	if json.Unmarshal(data, &v) != nil {
		return nil, ErrConflict
	}
	return v.Items, nil
}
