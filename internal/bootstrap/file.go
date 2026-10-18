package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"auto-cluster-rke2/internal/durable"
	"auto-cluster-rke2/internal/identity"
)

// HostPolicy is explicit enrollment, not permission inferred from discovery.
type HostPolicy struct {
	PublicKey []byte
	Role      string
	Bootstrap bool
}

type Policy struct{ Hosts map[string]HostPolicy }

type Config struct {
	Directory     string
	Signer        identity.Signer
	Policy        Policy
	Endpoint      string
	GrantLifetime time.Duration
}

// FileAuthority is a local, non-HA authority. Never restore an older snapshot of
// this directory: that would roll back the single-use ledger. Grant APIs are
// trusted in-process calls, not unauthenticated network handlers.
type FileAuthority struct {
	directory string
	signer    identity.Signer
	policy    Policy
	endpoint  string
	lifetime  time.Duration
	verifier  Verifier
	now       func() time.Time
}

var _ Authority = (*FileAuthority)(nil)
var _ Consumer = (*FileAuthority)(nil)

const maxJoinGrants = 512

type storedJoin struct {
	Grant    JoinGrant
	Consumed bool
}
type authorityRecord struct {
	AuthorityID       string
	PolicyDigest      string
	Endpoint          string
	ClusterID         string
	Bootstrap         *BootstrapGrant
	BootstrapConsumed bool
	Active            bool
	Joins             map[string]storedJoin
}

func NewFileAuthority(ctx context.Context, c Config) (*FileAuthority, error) {
	if c.Signer == nil || !filepath.IsAbs(c.Directory) || !ValidEndpoint(c.Endpoint) || len(c.Policy.Hosts) == 0 || len(c.Policy.Hosts) > maxJoinGrants {
		return nil, ErrInvalid
	}
	if storage, ok := c.Signer.(interface{ StorageDirectory() string }); ok && filepath.Clean(storage.StorageDirectory()) == filepath.Clean(c.Directory) {
		return nil, ErrInvalid
	}
	if c.GrantLifetime == 0 {
		c.GrantLifetime = 2 * time.Minute
	}
	if c.GrantLifetime <= 0 || c.GrantLifetime > maxLifetime {
		return nil, ErrInvalid
	}
	policy := Policy{Hosts: make(map[string]HostPolicy, len(c.Policy.Hosts))}
	for id, rule := range c.Policy.Hosts {
		if len(rule.PublicKey) != ed25519.PublicKeySize || id != identity.PublicKeyID(rule.PublicKey) ||
			(rule.Role != RoleAgent && rule.Role != RoleServer) || (rule.Bootstrap && rule.Role != RoleServer) {
			return nil, ErrInvalid
		}
		rule.PublicKey = append([]byte(nil), rule.PublicKey...)
		policy.Hosts[id] = rule
	}
	id, err := c.Signer.LoadOrCreate(ctx)
	if err != nil {
		return nil, err
	}
	if storage, ok := c.Signer.(interface{ StorageDirectory() string }); ok {
		keyInfo, keyErr := os.Stat(storage.StorageDirectory())
		stateInfo, stateErr := os.Stat(c.Directory)
		if keyErr == nil && stateErr == nil && os.SameFile(keyInfo, stateInfo) {
			return nil, ErrInvalid
		}
	}
	c.Endpoint = strings.TrimSuffix(c.Endpoint, "/")
	v, err := NewVerifier(id.PublicKey, digest(policy))
	if err != nil {
		return nil, err
	}
	return &FileAuthority{directory: c.Directory, signer: c.Signer, policy: policy, endpoint: c.Endpoint, lifetime: c.GrantLifetime, verifier: v, now: time.Now}, nil
}

func (a *FileAuthority) PolicyDigest() string { return a.verifier.policyDigest }
func (a *FileAuthority) Verifier() Verifier   { return a.verifier }

func clusterUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	s := hex.EncodeToString(raw[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

func (a *FileAuthority) read(d *durable.Directory) (authorityRecord, error) {
	var r authorityRecord
	if err := d.Read("authority.json", &r); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return r, ErrUninitialized
		}
		return r, err
	}
	if r.AuthorityID != identity.PublicKeyID(a.verifier.publicKey) || r.PolicyDigest != a.PolicyDigest() || r.Endpoint != a.endpoint {
		return r, ErrTrustMismatch
	}
	if !text(r.ClusterID) || r.Joins == nil || len(r.Joins) > maxJoinGrants || (r.Bootstrap == nil && r.BootstrapConsumed) || (r.Active && !r.BootstrapConsumed) {
		return r, durable.ErrCorrupt
	}
	if r.Bootstrap != nil {
		g := *r.Bootstrap
		if g.ClusterID != r.ClusterID || a.verifier.bootstrapSignature(g) != nil {
			return r, durable.ErrCorrupt
		}
		rule, ok := a.policy.Hosts[g.HostID]
		if !ok || !rule.Bootstrap {
			return r, durable.ErrCorrupt
		}
	}
	for requestID, entry := range r.Joins {
		g := entry.Grant
		rule, ok := a.policy.Hosts[g.HostID]
		if !r.Active || !ok || rule.Role != g.Role || requestID != g.OperationID || g.ClusterID != r.ClusterID || a.verifier.joinSignature(g) != nil || (r.Bootstrap != nil && requestID == r.Bootstrap.OperationID) {
			return r, durable.ErrCorrupt
		}
	}
	return r, nil
}

// Initialize is an explicit operator provisioning step. Ordinary requests never
// create missing authority state, even if discovery or the cluster is offline.
func (a *FileAuthority) Initialize(ctx context.Context) error {
	return durable.WithLock(ctx, a.directory, func(d *durable.Directory) error {
		_, err := a.read(d)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrUninitialized) {
			return err
		}
		cluster, err := clusterUUID()
		if err != nil {
			return err
		}
		r := authorityRecord{AuthorityID: identity.PublicKeyID(a.verifier.publicKey), PolicyDigest: a.PolicyDigest(), Endpoint: a.endpoint, ClusterID: cluster, Joins: make(map[string]storedJoin)}
		return d.Write(ctx, "authority.json", r)
	})
}

func (a *FileAuthority) request(req BootstrapRequest) (HostPolicy, error) {
	rule, ok := a.policy.Hosts[req.HostID]
	if !ok || req.PolicyDigest != a.PolicyDigest() || len(req.PublicKey) != ed25519.PublicKeySize || req.HostID != identity.PublicKeyID(req.PublicKey) || !ed25519.PublicKey(rule.PublicKey).Equal(ed25519.PublicKey(req.PublicKey)) || !text(req.RequestID) {
		return HostPolicy{}, ErrDenied
	}
	now := a.now()
	if req.IssuedAt.IsZero() || req.IssuedAt.After(now.Add(clockSkew)) || !req.IssuedAt.Add(requestLifetime).After(now) {
		return HostPolicy{}, ErrExpired
	}
	sig := req.Signature
	req.Signature = nil
	data, err := message("host-request", req)
	if err != nil {
		return HostPolicy{}, err
	}
	if !ed25519.Verify(req.PublicKey, data, sig) {
		return HostPolicy{}, ErrDenied
	}
	return rule, nil
}

func (a *FileAuthority) sign(ctx context.Context, kind string, value any) ([]byte, error) {
	data, err := message(kind, value)
	if err != nil {
		return nil, err
	}
	sig, err := a.signer.Sign(ctx, data)
	if err != nil {
		return nil, err
	}
	// Detect an accidentally replaced authority key before persisting anything.
	if !ed25519.Verify(a.verifier.publicKey, data, sig) {
		return nil, ErrTrustMismatch
	}
	return sig, nil
}

func (a *FileAuthority) AuthorizeBootstrap(ctx context.Context, req BootstrapRequest) (BootstrapGrant, error) {
	var grant BootstrapGrant
	err := durable.WithLock(ctx, a.directory, func(d *durable.Directory) error {
		rule, err := a.request(req)
		if err != nil {
			return err
		}
		if !rule.Bootstrap {
			return ErrDenied
		}
		r, err := a.read(d)
		if err != nil {
			return err
		}
		if r.Bootstrap != nil {
			return ErrReplay
		}
		now := a.now().UTC()
		g := BootstrapGrant{AuthorityID: r.AuthorityID, ClusterID: r.ClusterID, HostID: req.HostID, OperationID: req.RequestID, PublicKey: append([]byte(nil), req.PublicKey...), PolicyDigest: r.PolicyDigest, IssuedAt: now, ExpiresAt: now.Add(a.lifetime)}
		g.Signature, err = a.sign(ctx, "bootstrap-grant", g)
		if err != nil {
			return err
		}
		r.Bootstrap = &g
		if err := d.Write(ctx, "authority.json", r); err != nil {
			return err
		}
		grant = g
		return nil
	})
	return grant, err
}

func (a *FileAuthority) AuthorizeJoin(ctx context.Context, cluster string, req BootstrapRequest) (JoinGrant, error) {
	var grant JoinGrant
	err := durable.WithLock(ctx, a.directory, func(d *durable.Directory) error {
		rule, err := a.request(req)
		if err != nil {
			return err
		}
		r, err := a.read(d)
		if err != nil {
			return err
		}
		if cluster != r.ClusterID {
			return ErrClusterMismatch
		}
		if !r.Active {
			return ErrNotActive
		}
		if r.Bootstrap.HostID == req.HostID {
			return ErrDenied
		}
		if _, ok := r.Joins[req.RequestID]; ok || req.RequestID == r.Bootstrap.OperationID {
			return ErrReplay
		}
		if len(r.Joins) >= maxJoinGrants {
			return ErrDenied
		}
		// An enrollment authorizes initial membership, never role promotion or
		// repeated membership creation for an already authorized host.
		for _, entry := range r.Joins {
			if entry.Grant.HostID == req.HostID {
				return ErrReplay
			}
		}
		now := a.now().UTC()
		g := JoinGrant{AuthorityID: r.AuthorityID, ClusterID: r.ClusterID, HostID: req.HostID, Role: rule.Role, OperationID: req.RequestID, PublicKey: append([]byte(nil), req.PublicKey...), PolicyDigest: r.PolicyDigest, IssuedAt: now, ExpiresAt: now.Add(a.lifetime)}
		g.Signature, err = a.sign(ctx, "join-grant", g)
		if err != nil {
			return err
		}
		r.Joins[req.RequestID] = storedJoin{Grant: g}
		if err := d.Write(ctx, "authority.json", r); err != nil {
			return err
		}
		grant = g
		return nil
	})
	return grant, err
}

func (a *FileAuthority) VerifyBootstrapGrant(ctx context.Context, g BootstrapGrant) error {
	return a.verifier.VerifyBootstrapGrant(ctx, g)
}
func (a *FileAuthority) VerifyJoinGrant(ctx context.Context, g JoinGrant) error {
	return a.verifier.VerifyJoinGrant(ctx, g)
}

func (a *FileAuthority) ConsumeBootstrapGrant(ctx context.Context, g BootstrapGrant) error {
	return durable.WithLock(ctx, a.directory, func(d *durable.Directory) error {
		if err := a.VerifyBootstrapGrant(ctx, g); err != nil {
			return err
		}
		r, err := a.read(d)
		if err != nil {
			return err
		}
		if g.ClusterID != r.ClusterID {
			return ErrClusterMismatch
		}
		if r.Bootstrap == nil || digest(*r.Bootstrap) != digest(g) {
			return ErrDenied
		}
		if r.BootstrapConsumed {
			return ErrReplay
		}
		r.BootstrapConsumed = true
		return d.Write(ctx, "authority.json", r)
	})
}

func (a *FileAuthority) ConsumeJoinGrant(ctx context.Context, g JoinGrant) error {
	return durable.WithLock(ctx, a.directory, func(d *durable.Directory) error {
		if err := a.VerifyJoinGrant(ctx, g); err != nil {
			return err
		}
		r, err := a.read(d)
		if err != nil {
			return err
		}
		if g.ClusterID != r.ClusterID {
			return ErrClusterMismatch
		}
		entry, ok := r.Joins[g.OperationID]
		if !ok || digest(entry.Grant) != digest(g) {
			return ErrDenied
		}
		if entry.Consumed {
			return ErrReplay
		}
		entry.Consumed = true
		r.Joins[g.OperationID] = entry
		return d.Write(ctx, "authority.json", r)
	})
}

// ConfirmClusterActive is a trusted local administrative action after the
// executor independently proves the initialized cluster's identity and health.
// This API is deliberately absent from the public discovery HTTP handler.
func (a *FileAuthority) ConfirmClusterActive(ctx context.Context, cluster string) error {
	return durable.WithLock(ctx, a.directory, func(d *durable.Directory) error {
		r, err := a.read(d)
		if err != nil {
			return err
		}
		if cluster != r.ClusterID {
			return ErrClusterMismatch
		}
		if !r.BootstrapConsumed {
			return ErrNotActive
		}
		r.Active = true
		return d.Write(ctx, "authority.json", r)
	})
}

func (a *FileAuthority) Advertise(ctx context.Context, challenge string) (Advertisement, error) {
	var result Advertisement
	if !ValidChallenge(challenge) {
		return result, ErrInvalid
	}
	err := durable.WithLock(ctx, a.directory, func(d *durable.Directory) error {
		r, err := a.read(d)
		if err != nil {
			return err
		}
		now := a.now().UTC()
		ad := Advertisement{AuthorityID: r.AuthorityID, ClusterID: r.ClusterID, PolicyDigest: r.PolicyDigest, Endpoint: r.Endpoint, Challenge: challenge, Active: r.Active, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
		ad.Signature, err = a.sign(ctx, "advertisement", ad)
		if err != nil {
			return err
		}
		result = ad
		return nil
	})
	return result, err
}
