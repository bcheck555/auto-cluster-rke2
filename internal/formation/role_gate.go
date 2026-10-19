package formation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"auto-cluster-rke2/internal/durable"
	"auto-cluster-rke2/internal/hostagent"
	"auto-cluster-rke2/internal/state"
)

type roleRuntime interface {
	RestrictControl(context.Context) error
	AuthorizeControl(context.Context) error
	QuarantineRole(context.Context, uint64) error
	StopRole(context.Context) error
	ControlDataIntact() bool
}

type roleGate struct {
	node              *Node
	runtime           roleRuntime
	mu                sync.Mutex
	lastAuthorization time.Time
	restricted        bool
	request           func(context.Context, State, []Peer, bool) (RoleAuthorization, error)
}

func (g *roleGate) authorize(ctx context.Context, s State, peers []Peer, pulse bool) (RoleAuthorization, error) {
	if g.request != nil {
		return g.request(ctx, s, peers, pulse)
	}
	m := g.node.member(s)
	if s.Role == "server" {
		k := KubeBackend{ClusterID: s.ClusterID, Policy: s.Policy}
		if value, err := k.authorization(ctx, m, pulse, promotionResources()); err == nil {
			return value, nil
		}
	}
	client, ok := g.node.Client.(Client)
	if !ok {
		return RoleAuthorization{}, ErrInvalid
	}
	for _, peer := range peers {
		if peer.ID == g.node.Auth.Self.ID {
			continue
		}
		if value, err := client.Authorize(ctx, peer, m, pulse, promotionResources()); err == nil {
			return value, nil
		}
	}
	return RoleAuthorization{}, ErrWaiting
}

func (g *roleGate) Check(ctx context.Context, s State, peers []Peer) error {
	value, err := g.authorize(ctx, s, peers, false)
	if err != nil {
		return err
	}
	assignment := value.Assignment
	if value.ClusterID != s.ClusterID || value.Policy != s.Policy || assignment.Address != s.Address || assignment.Previous.ID != g.node.Auth.Self.ID || assignment.Generation < s.Generation {
		return ErrConflict
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if assignment.Action == "stop" {
		if assignment.Generation != s.Generation || assignment.Role != "agent" || s.Role != "agent" {
			return ErrConflict
		}
		if err := g.runtime.StopRole(ctx); err != nil {
			return err
		}
		client := g.node.Client.(Client)
		for _, peer := range peers {
			var result map[string]bool
			if client.call(ctx, peer, "stopped", g.node.member(s), &result) == nil && result["stopped"] {
				return ErrWaiting
			}
		}
		return ErrWaiting
	}
	if assignment.Generation > s.Generation {
		if assignment.Generation != s.Generation+1 || assignment.Operation == "" || assignment.Previous.Generation != s.Generation || !sameMember(assignment.Previous, g.node.member(s)) || assignment.Role == s.Role {
			return ErrConflict
		}
		// Intent reaches durable storage before stopping native services or moving
		// any credentials. Repeated moves are safe across every crash window.
		data, _ := json.Marshal(assignment)
		if err := hostagent.WritePrivateFile(filepath.Join(g.node.Settings.StateDirectory, "role-transition.json"), data); err != nil {
			return err
		}
		if err := g.runtime.QuarantineRole(ctx, assignment.Generation); err != nil {
			return err
		}
		next := State{Phase: "Selected", ClusterID: s.ClusterID, Mode: "join", Role: assignment.Role, NodeName: incarnationName(g.node.Auth.Self.ID, assignment.Generation), Address: s.Address, Interface: s.Interface, Policy: s.Policy, Deployment: s.Deployment, Generation: assignment.Generation, Transition: true, Servers: peers}
		if err := g.node.save(ctx, next); err != nil {
			return err
		}
		g.restricted = false
		return ErrWaiting
	}
	if assignment.Role != s.Role || !sameMember(value.Member, g.node.member(s)) || value.Member.Retiring || value.Member.NodeUID != s.Evidence.NodeUID || value.Member.EtcdMemberID != s.Evidence.EtcdMemberID {
		return ErrWaiting
	}
	g.lastAuthorization = time.Now()
	if s.Role == "server" && g.restricted {
		if !g.runtime.ControlDataIntact() {
			return ErrWaiting
		}
		if err := g.runtime.AuthorizeControl(ctx); err != nil {
			return err
		}
		g.restricted = false
		return ErrWaiting
	}
	return nil
}

func (g *roleGate) Pulse(ctx context.Context) error {
	g.node.mu.RLock()
	s := g.node.current
	g.node.mu.RUnlock()
	if s.Phase != "Healthy" {
		return nil
	}
	value, err := g.authorize(ctx, s, s.Servers, true)
	if err != nil {
		return err
	}
	if value.Assignment.Generation != s.Generation || value.Assignment.Role != s.Role {
		return ErrWaiting
	}
	g.mu.Lock()
	g.lastAuthorization = time.Now()
	g.mu.Unlock()
	return nil
}

func (g *roleGate) Watch(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		g.node.mu.RLock()
		s := g.node.current
		g.node.mu.RUnlock()
		if s.Phase != "Healthy" || s.Role != "server" {
			continue
		}
		g.mu.Lock()
		if !g.restricted && time.Since(g.lastAuthorization) >= time.Minute {
			attempt, cancel := context.WithTimeout(ctx, 20*time.Second)
			if g.runtime.RestrictControl(attempt) == nil {
				g.restricted = true
			}
			cancel()
			g.node.mu.Lock()
			g.node.serving = false
			g.node.mu.Unlock()
		}
		g.mu.Unlock()
	}
}

// Heartbeats must continue while a controller drains/probes a candidate. Each
// renewal independently verifies native identity; cached journal health alone
// cannot keep a failed member alive or extend its role authorization.
func (g *roleGate) Maintain(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		g.node.mu.RLock()
		s := g.node.current
		g.node.mu.RUnlock()
		if s.Phase != "Healthy" {
			continue
		}
		g.mu.Lock()
		restricted := g.restricted
		g.mu.Unlock()
		if restricted {
			continue
		}
		attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
		evidence, err := g.node.Runtime.Check(attempt, g.node.plan(s), g.node.Auth.Self.ID, false)
		if err == nil && evidence.NodeUID == s.Evidence.NodeUID && evidence.EtcdMemberID == s.Evidence.EtcdMemberID {
			_ = g.Pulse(attempt)
		}
		cancel()
	}
}

// All candidates use the same signed image. Resource admission uses actual
// guest capacity, not a hypervisor promise; runtime data is retained on role
// transitions so sufficient disk is required without reclaiming workloads.
func promotionResources() bool {
	if runtime.NumCPU() < 2 {
		return false
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return false
	}
	var total uint64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				total, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}
	var stat syscall.Statfs_t
	if syscall.Statfs("/var/lib/rancher/rke2", &stat) != nil {
		return false
	}
	return total >= 3*1024*1024 && stat.Bavail*uint64(stat.Bsize) >= 8*1024*1024*1024
}

func clearTransition(s Settings) error {
	err := os.Remove(filepath.Join(s.StateDirectory, "role-transition.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Restrict is also ExecStopPost: loss of the coordinator process must not leave
// an indefinitely authorized full control plane behind. A deliberate managed
// retirement retains its vote until the owner commits exact-ID removal.
func Restrict(ctx context.Context, s Settings) error {
	if err := notRetired(s); err != nil {
		return nil
	}
	op, err := state.NewFileJournal(filepath.Join(s.StateDirectory, "formation")).Get(ctx, "formation")
	if errors.Is(err, state.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved State
	if durable.Decode([]byte(op.Details), &saved) != nil || saved.Policy != s.Policy() {
		return ErrConflict
	}
	if saved.Role != "server" || saved.Phase != "Healthy" {
		return nil
	}
	err = hostagent.NewLinuxRuntime(nil).RestrictControl(ctx)
	if errors.Is(err, hostagent.ErrRoleDataMissing) {
		return nil
	}
	return err
}
