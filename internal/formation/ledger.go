package formation

import (
	"context"
	"crypto/ed25519"
	"net"

	"autonomous-rke2/internal/identity"
)

type Catalog struct {
	ClusterID string
	Policy    string
	Members   map[string]Member
}

type Backend interface {
	Init(context.Context, Member) error
	Claim(context.Context, Member) (Member, error)
	Complete(context.Context, Member) (Member, error)
	Credentials(context.Context, Member) (Credentials, error)
}

func validMember(m Member) bool {
	ip := net.ParseIP(m.Address)
	return len(m.PublicKey) == ed25519.PublicKeySize && identity.PublicKeyID(m.PublicKey) == m.ID && m.NodeName == "rke2-"+m.ID[:16] && m.RequestID == "initial-"+m.ID && ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func sameMember(a, b Member) bool {
	return a.ID == b.ID && digest(a.PublicKey) == digest(b.PublicKey) && a.NodeName == b.NodeName && a.Address == b.Address && a.RequestID == b.RequestID
}

// Reserve serializes initial membership. All servers use Kubernetes resourceVersion
// CAS, including this reservation in the same cluster-scoped ConfigMap. An
// interrupted reservation belongs to that host until resumed or reconciled;
// expiry never silently frees an uncertain server slot.
func (c *Catalog) Reserve(request Member) (Member, error) {
	if !validMember(request) || c.Members == nil || len(c.Members) > 1024 {
		return Member{}, ErrInvalid
	}
	if existing, ok := c.Members[request.ID]; ok {
		if !sameMember(existing, request) {
			return Member{}, ErrConflict
		}
		return existing, nil
	}
	servers := 0
	for _, member := range c.Members {
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
	if len(c.Members) >= 1024 || servers > 3 {
		return Member{}, ErrConflict
	}
	request.Role = "agent"
	if servers < 3 {
		request.Role = "server"
	}
	request.Complete = false
	request.NodeUID = ""
	request.EtcdMemberID = ""
	c.Members[request.ID] = request
	return request, nil
}
