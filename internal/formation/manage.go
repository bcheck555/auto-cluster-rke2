package formation

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"auto-cluster-rke2/internal/durable"
	"auto-cluster-rke2/internal/hostagent"
	"auto-cluster-rke2/internal/state"
)

// Management requests are accepted only by the root-only local CLI, never by
// the enrollment HTTP service. Their operation ID fences concurrent operators.
type ManagementRequest struct {
	Action           string         `json:"action"`
	Operation        string         `json:"operation"`
	Nodes            int            `json:"nodes"`
	ControlNodes     int            `json:"control_nodes"`
	Address          string         `json:"address"`
	MemberID         string         `json:"member_id"`
	MemberGeneration uint64         `json:"member_generation"`
	SelfHealing      *HealingPolicy `json:"self_healing,omitempty"`
}

type EtcdMember struct {
	ID        string
	PeerURLs  []string
	IsLearner bool
}

type ManagementNode struct {
	Metadata struct {
		Name   string
		UID    string
		Labels map[string]string
	}
	Spec struct {
		Unschedulable bool
		PodCIDR       string
		PodCIDRs      []string
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

type ManagementStatus struct {
	Catalog Catalog          `json:"catalog"`
	Voters  []EtcdMember     `json:"etcd"`
	Nodes   []ManagementNode `json:"nodes"`
}

func Manage(ctx context.Context, s Settings, request ManagementRequest) (ManagementStatus, error) {
	op, err := state.NewFileJournal(filepath.Join(s.StateDirectory, "formation")).Get(ctx, "formation")
	if err != nil {
		return ManagementStatus{}, err
	}
	var saved State
	if durable.Decode([]byte(op.Details), &saved) != nil || saved.Phase != "Healthy" || saved.Policy != s.Policy() {
		return ManagementStatus{}, ErrConflict
	}
	if request.Action == "fence-local" {
		if request.MemberID != op.HostID || request.MemberGeneration != saved.Generation {
			return ManagementStatus{}, ErrConflict
		}
		if err := hostagent.WritePrivateFile(filepath.Join(s.StateDirectory, "retired"), []byte(op.HostID+"\n")); err != nil {
			return ManagementStatus{}, err
		}
		return ManagementStatus{}, nil
	}
	if saved.Role != "server" {
		return ManagementStatus{}, ErrConflict
	}
	return (KubeBackend{ClusterID: saved.ClusterID, Policy: saved.Policy}).Manage(ctx, request)
}

func notRetired(s Settings) error {
	_, err := os.Lstat(filepath.Join(s.StateDirectory, "retired"))
	if os.IsNotExist(err) {
		return nil
	}
	return ErrConflict
}

func (k KubeBackend) etcdMembers(ctx context.Context) ([]EtcdMember, error) {
	data, status, err := k.call(ctx, true, http.MethodGet, "/readyz", nil)
	if err != nil || status != 200 || strings.TrimSpace(string(data)) != "ok" {
		return nil, ErrWaiting
	}
	data, status, err = k.call(ctx, true, http.MethodPost, "/v3/cluster/member/list", map[string]bool{"linearizable": true})
	if err != nil || status != 200 {
		return nil, ErrWaiting
	}
	var result struct{ Members []EtcdMember }
	if json.Unmarshal(data, &result) != nil || len(result.Members) == 0 {
		return nil, ErrConflict
	}
	return result.Members, nil
}

func (k KubeBackend) managementStatus(ctx context.Context) (ManagementStatus, error) {
	c, _, status, err := k.load(ctx)
	if err != nil {
		return ManagementStatus{}, err
	}
	if status != 200 {
		return ManagementStatus{}, ErrWaiting
	}
	voters, err := k.etcdMembers(ctx)
	if err != nil {
		return ManagementStatus{}, err
	}
	data, status, err := k.call(ctx, false, http.MethodGet, "/api/v1/nodes", nil)
	if err != nil || status != 200 {
		return ManagementStatus{}, ErrWaiting
	}
	var nodes struct{ Items []ManagementNode }
	if json.Unmarshal(data, &nodes) != nil {
		return ManagementStatus{}, ErrConflict
	}
	return ManagementStatus{Catalog: c, Voters: voters, Nodes: nodes.Items}, nil
}

func (k KubeBackend) Manage(ctx context.Context, r ManagementRequest) (ManagementStatus, error) {
	if r.Action == "status" {
		return k.managementStatus(ctx)
	}
	if r.Action == "policy" {
		if r.SelfHealing == nil || r.Nodes < 1 || r.Nodes > 1024 {
			return ManagementStatus{}, ErrInvalid
		}
		if _, err := r.SelfHealing.timeout(); err != nil {
			return ManagementStatus{}, err
		}
		err := k.updateCatalog(ctx, func(c *Catalog) error {
			if c.Operation != nil && (c.DesiredNodes != r.Nodes || c.SelfHealing != *r.SelfHealing) && !(c.Healing != nil && c.DesiredNodes == r.Nodes && !r.SelfHealing.Enabled) {
				return ErrWaiting
			}
			c.DesiredNodes = r.Nodes
			c.SelfHealing = *r.SelfHealing
			return nil
		})
		if err != nil {
			return ManagementStatus{}, err
		}
		return k.managementStatus(ctx)
	}
	if len(r.Operation) != 32 {
		return ManagementStatus{}, ErrInvalid
	}
	// A writable API marker/catalog and a ready etcd majority are prerequisites
	// even for forced retirement. Force is solely a workload-eviction decision.
	if _, err := k.etcdMembers(ctx); err != nil {
		return ManagementStatus{}, err
	}
	for range 8 {
		c, cm, status, err := k.load(ctx)
		if err != nil {
			return ManagementStatus{}, err
		}
		if status != 200 {
			return ManagementStatus{}, ErrWaiting
		}
		if r.Action == "begin" {
			if !controlTargetValid(r.ControlNodes) || r.Nodes < 1 || r.Nodes > 1024 {
				return ManagementStatus{}, ErrInvalid
			}
			if c.Operation != nil && (c.Operation.ID != r.Operation || c.Operation.Nodes != r.Nodes || c.Operation.ControlNodes != r.ControlNodes) {
				return ManagementStatus{}, ErrConflict
			}
			if c.Operation == nil {
				c.Operation = &MembershipOperation{ID: r.Operation, Nodes: r.Nodes, ControlNodes: r.ControlNodes}
			}
			c.ControlNodes = r.ControlNodes
		} else {
			if c.Operation == nil {
				if r.Action == "finish" {
					return k.managementStatus(ctx)
				}
				return ManagementStatus{}, ErrConflict
			}
			if c.Operation.ID != r.Operation {
				return ManagementStatus{}, ErrConflict
			}
			switch r.Action {
			case "admit":
				ip := net.ParseIP(r.Address)
				if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
					return ManagementStatus{}, ErrInvalid
				}
				if c.Operation.Address != "" && c.Operation.Address != r.Address {
					return ManagementStatus{}, ErrConflict
				}
				for _, m := range c.Members {
					if m.Retiring {
						return ManagementStatus{}, ErrWaiting
					}
				}
				c.Operation.Address = r.Address
			case "admitted":
				found := false
				for _, m := range c.Members {
					if m.Address == r.Address && m.Complete && !m.Retiring {
						found = true
					}
				}
				if !found || (c.Operation.Address != "" && c.Operation.Address != r.Address) {
					return ManagementStatus{}, ErrWaiting
				}
				c.Operation.Address = ""
			case "retire":
				m, ok := c.Members[r.MemberID]
				if !ok {
					if _, done := c.Retired[incarnationKey(Member{ID: r.MemberID, Generation: r.MemberGeneration})]; done {
						return k.managementStatus(ctx)
					}
					return ManagementStatus{}, ErrConflict
				}
				if m.Generation != r.MemberGeneration {
					return ManagementStatus{}, ErrConflict
				}
				if !m.Complete || c.Operation.Address != "" {
					return ManagementStatus{}, ErrWaiting
				}
				servers := 0
				for _, other := range c.Members {
					if !other.Complete || (other.Retiring && other.ID != m.ID) {
						return ManagementStatus{}, ErrWaiting
					}
					if other.Role == "server" {
						servers++
					}
				}
				if m.Role == "server" && servers <= 1 {
					return ManagementStatus{}, ErrConflict
				}
				m.Retiring = true
				c.Members[m.ID] = m
			case "remove":
				m, ok := c.Members[r.MemberID]
				if !ok {
					if _, done := c.Retired[incarnationKey(Member{ID: r.MemberID, Generation: r.MemberGeneration})]; done {
						return k.managementStatus(ctx)
					}
					return ManagementStatus{}, ErrConflict
				}
				if m.Generation != r.MemberGeneration {
					return ManagementStatus{}, ErrConflict
				}
				if !m.Retiring {
					return ManagementStatus{}, ErrConflict
				}
				if err := k.removeMember(ctx, m); err != nil {
					return ManagementStatus{}, err
				}
				if c.Retired == nil {
					c.Retired = map[string]Member{}
				}
				c.Retired[incarnationKey(m)] = m
				delete(c.Members, m.ID)
			case "finish":
				servers := 0
				for _, m := range c.Members {
					if !m.Complete || m.Retiring {
						return ManagementStatus{}, ErrWaiting
					}
					if m.Role == "server" {
						servers++
					}
				}
				if len(c.Members) != c.Operation.Nodes || servers != min(c.Operation.Nodes, c.Operation.ControlNodes) || c.Operation.Address != "" {
					return ManagementStatus{}, ErrConflict
				}
				c.Operation = nil
			default:
				return ManagementStatus{}, ErrInvalid
			}
		}
		next := catalogMap(c)
		next.Metadata.ResourceVersion = cm.Metadata.ResourceVersion
		_, status, err = k.call(ctx, false, http.MethodPut, catalogPath, next)
		if err != nil {
			return ManagementStatus{}, err
		}
		if status == 409 {
			continue
		}
		if status != 200 {
			return ManagementStatus{}, ErrWaiting
		}
		return k.managementStatus(ctx)
	}
	return ManagementStatus{}, ErrWaiting
}

// The caller must durably fence the owned VM before requesting remove. Node UID
// and exact etcd ID/peer URL prevent deleting a replacement with a reused name.
func (k KubeBackend) removeMember(ctx context.Context, m Member) error {
	if m.Role == "server" {
		members, err := k.etcdMembers(ctx)
		if err != nil {
			return err
		}
		for _, v := range members {
			if v.ID != m.EtcdMemberID {
				continue
			}
			if len(v.PeerURLs) != 1 || v.PeerURLs[0] != "https://"+m.Address+":2380" {
				return ErrConflict
			}
			_, status, err := k.call(ctx, true, http.MethodPost, "/v3/cluster/member/remove", map[string]string{"ID": m.EtcdMemberID})
			if err != nil || status != 200 {
				return ErrWaiting
			}
		}
		members, err = k.etcdMembers(ctx)
		if err != nil {
			return err
		}
		for _, v := range members {
			if v.ID == m.EtcdMemberID {
				return ErrWaiting
			}
		}
	}
	data, status, err := k.call(ctx, false, http.MethodGet, "/api/v1/nodes/"+m.NodeName, nil)
	if err != nil {
		return err
	}
	if status == 404 {
		return nil
	}
	if status != 200 {
		return ErrWaiting
	}
	var node ManagementNode
	if json.Unmarshal(data, &node) != nil || node.Metadata.UID != m.NodeUID {
		return ErrConflict
	}
	_, status, err = k.call(ctx, false, http.MethodDelete, "/api/v1/nodes/"+m.NodeName, map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": map[string]string{"uid": m.NodeUID}})
	if err != nil || (status != 200 && status != 202 && status != 404) {
		return ErrWaiting
	}
	_, status, err = k.call(ctx, false, http.MethodGet, "/api/v1/nodes/"+m.NodeName, nil)
	if err != nil || status != 404 {
		return ErrWaiting
	}
	return nil
}
