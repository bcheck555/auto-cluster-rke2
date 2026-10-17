package bootstrap

import (
	"context"
	"errors"
	"time"

	"autonomous-rke2/internal/durable"
	"autonomous-rke2/internal/identity"
)

var ErrGrantNotFound = errors.New("grant not found for host and operation")

// GrantStatus is fresh signed evidence of a particular issuance/consumption.
// It recovers lost acknowledgments; it never issues or consumes a grant.
type GrantStatus struct {
	AuthorityID  string
	ClusterID    string
	PolicyDigest string
	HostID       string
	OperationID  string
	Challenge    string
	Consumed     bool
	Bootstrap    *BootstrapGrant
	Join         *JoinGrant
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Signature    []byte
}

type StatusReader interface {
	GrantStatus(context.Context, string, string, string) (GrantStatus, error)
}

func (a *FileAuthority) GrantStatus(ctx context.Context, host, operation, challenge string) (GrantStatus, error) {
	var result GrantStatus
	if !text(operation) || !ValidChallenge(challenge) {
		return result, ErrInvalid
	}
	if _, ok := a.policy.Hosts[host]; !ok {
		return result, ErrDenied
	}
	err := durable.WithLock(ctx, a.directory, func(d *durable.Directory) error {
		r, err := a.read(d)
		if err != nil {
			return err
		}
		now := a.now().UTC()
		s := GrantStatus{AuthorityID: r.AuthorityID, ClusterID: r.ClusterID, PolicyDigest: r.PolicyDigest, HostID: host, OperationID: operation, Challenge: challenge, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
		if r.Bootstrap != nil && r.Bootstrap.HostID == host && r.Bootstrap.OperationID == operation {
			s.Bootstrap = r.Bootstrap
			s.Consumed = r.BootstrapConsumed
		} else if entry, ok := r.Joins[operation]; ok && entry.Grant.HostID == host {
			g := entry.Grant
			s.Join = &g
			s.Consumed = entry.Consumed
		} else {
			return ErrGrantNotFound
		}
		s.Signature, err = a.sign(ctx, "grant-status", s)
		if err != nil {
			return err
		}
		result = s
		return nil
	})
	return result, err
}

func (v Verifier) VerifyGrantStatus(ctx context.Context, s GrantStatus, host, operation, challenge string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.AuthorityID != identity.PublicKeyID(v.publicKey) || s.PolicyDigest != v.policyDigest {
		return ErrTrustMismatch
	}
	if !text(s.ClusterID) || s.HostID != host || s.OperationID != operation || !ValidChallenge(challenge) || s.Challenge != challenge || ((s.Bootstrap == nil) == (s.Join == nil)) {
		return ErrInvalid
	}
	sig := s.Signature
	s.Signature = nil
	if err := v.verify("grant-status", s, sig); err != nil {
		return err
	}
	if err := v.lifetime(s.IssuedAt, s.ExpiresAt); err != nil {
		return err
	}
	var issued, expires time.Time
	if s.Bootstrap != nil {
		g := *s.Bootstrap
		if g.HostID != host || g.OperationID != operation || g.ClusterID != s.ClusterID {
			return ErrInvalid
		}
		if err := v.bootstrapSignature(g); err != nil {
			return err
		}
		issued, expires = g.IssuedAt, g.ExpiresAt
	} else {
		g := *s.Join
		if g.HostID != host || g.OperationID != operation || g.ClusterID != s.ClusterID {
			return ErrInvalid
		}
		if err := v.joinSignature(g); err != nil {
			return err
		}
		issued, expires = g.IssuedAt, g.ExpiresAt
	}
	if issued.IsZero() || !expires.After(issued) || expires.Sub(issued) > maxLifetime || issued.After(v.now().Add(clockSkew)) {
		return ErrInvalid
	}
	if !s.Consumed {
		return v.lifetime(issued, expires)
	}
	return nil
}
