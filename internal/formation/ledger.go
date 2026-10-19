package formation

import (
	"context"
	"crypto/ed25519"
	"net"

	"auto-cluster-rke2/internal/identity"
)

type Catalog struct {
	ClusterID    string
	Policy       string
	Members      map[string]Member
	ControlNodes int
	Retired      map[string]Member
	Operation    *MembershipOperation
	DesiredNodes int
	SelfHealing  HealingPolicy
	Healing      *HealingOperation
	History      []HealingOperation
	Hosts        map[string]HostAssignment
	Heartbeats   map[string]Heartbeat
	Observations map[string]FailureObservation
}

// MembershipOperation is a durable, non-expiring lock. Only its owner may
// authorize an admission or retirement; an interrupted owner resumes its ID.
type MembershipOperation struct {
	ID           string
	Nodes        int
	ControlNodes int
	Address      string
}

func (c Catalog) controlTarget() int {
	if c.ControlNodes == 0 {
		return 3
	}
	return c.ControlNodes
}

func controlTargetValid(n int) bool { return n == 3 || n == 5 || n == 7 }

type Backend interface {
	Init(context.Context, Member) error
	Claim(context.Context, Member) (Member, error)
	Complete(context.Context, Member) (Member, error)
	Credentials(context.Context, Member) (Credentials, error)
}

func validMember(m Member) bool {
	ip := net.ParseIP(m.Address)
	return len(m.PublicKey) == ed25519.PublicKeySize && identity.PublicKeyID(m.PublicKey) == m.ID && m.NodeName == incarnationName(m.ID, m.Generation) && m.RequestID == incarnationRequest(m.ID, m.Generation) && ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func sameMember(a, b Member) bool {
	return a.ID == b.ID && a.Generation == b.Generation && digest(a.PublicKey) == digest(b.PublicKey) && a.NodeName == b.NodeName && a.Address == b.Address && a.RequestID == b.RequestID
}

// Reserve serializes initial membership. All servers use Kubernetes resourceVersion
// CAS, including this reservation in the same cluster-scoped ConfigMap. An
// interrupted reservation belongs to that host until resumed or reconciled;
// expiry never silently frees an uncertain server slot.
func (c *Catalog) Reserve(request Member) (Member, error) {
	if !validMember(request) || c.Members == nil || len(c.Members) > 1024 {
		return Member{}, ErrInvalid
	}
	if _, retired := c.Retired[incarnationKey(request)]; retired {
		return Member{}, ErrConflict
	}
	if request.Generation > 0 {
		assignment, ok := c.Hosts[request.ID]
		if !ok || assignment.Generation != request.Generation || assignment.Address != request.Address || assignment.Role == "" {
			return Member{}, ErrConflict
		}
	}
	if !controlTargetValid(c.controlTarget()) {
		return Member{}, ErrInvalid
	}
	if existing, ok := c.Members[request.ID]; ok {
		if !sameMember(existing, request) || existing.Retiring {
			return Member{}, ErrConflict
		}
		return existing, nil
	}
	if c.Operation != nil && c.Operation.Address != request.Address {
		return Member{}, ErrWaiting
	}
	servers := 0
	for _, member := range c.Members {
		if member.Retiring {
			return Member{}, ErrWaiting
		}
		if member.Role == "server" {
			servers++
		}
		if !member.Complete {
			return Member{}, ErrWaiting
		}
		if member.NodeName == request.NodeName || member.Address == request.Address {
			return Member{}, ErrConflict
		}
	}
	if len(c.Members) >= 1024 || servers > 7 {
		return Member{}, ErrConflict
	}
	request.Role = "agent"
	if servers < c.controlTarget() {
		request.Role = "server"
	}
	if assignment, ok := c.Hosts[request.ID]; ok && request.Generation > 0 {
		request.Role = assignment.Role
		if request.Role == "server" && servers >= c.controlTarget() {
			return Member{}, ErrConflict
		}
	}
	request.Complete = false
	request.NodeUID = ""
	request.EtcdMemberID = ""
	c.Members[request.ID] = request
	return request, nil
}
