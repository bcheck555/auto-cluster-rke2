package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"autonomous-rke2/internal/identity"
)

var (
	ErrDenied          = errors.New("authority denied request")
	ErrInvalid         = errors.New("invalid signed message")
	ErrExpired         = errors.New("signed message expired or not yet valid")
	ErrReplay          = errors.New("grant or request already used")
	ErrUninitialized   = errors.New("authority requires explicit initialization")
	ErrClusterMismatch = errors.New("persistent cluster identity mismatch")
	ErrTrustMismatch   = errors.New("authority key, endpoint, or policy mismatch")
	ErrNotActive       = errors.New("cluster has not been confirmed active")
)

const (
	RoleServer      = "server"
	RoleAgent       = "agent"
	maxLifetime     = 5 * time.Minute
	requestLifetime = 2 * time.Minute
	clockSkew       = 5 * time.Second
)

func message(kind string, value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalid
	}
	return append([]byte("autonomous-rke2/"+kind+"/v1\x00"), data...), nil
}

func digest(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func text(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n")
}

func ValidChallenge(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func ValidEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && (u.Path == "" || u.Path == "/") && u.RawPath == ""
}

// SignRequest binds an enrolled host's key, policy, fresh timestamp, and operation.
func SignRequest(ctx context.Context, signer identity.Signer, policyDigest, requestID string) (BootstrapRequest, error) {
	id, err := signer.LoadOrCreate(ctx)
	if err != nil {
		return BootstrapRequest{}, err
	}
	req := BootstrapRequest{HostID: id.ID, PublicKey: id.PublicKey, PolicyDigest: policyDigest, RequestID: requestID, IssuedAt: time.Now().UTC()}
	if !text(requestID) || !text(policyDigest) {
		return BootstrapRequest{}, ErrInvalid
	}
	data, err := message("host-request", req)
	if err != nil {
		return BootstrapRequest{}, err
	}
	req.Signature, err = signer.Sign(ctx, data)
	return req, err
}

// Advertisement is a public, challenge-bound statement, never a join credential.
type Advertisement struct {
	AuthorityID  string
	ClusterID    string
	PolicyDigest string
	Endpoint     string
	Challenge    string
	Active       bool
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Signature    []byte
}

// Verifier uses an operator-provisioned key and policy digest. It performs no
// discovery-based trust enrollment and no state mutation or grant consumption.
type Verifier struct {
	publicKey    ed25519.PublicKey
	policyDigest string
	now          func() time.Time
}

func NewVerifier(key ed25519.PublicKey, policyDigest string) (Verifier, error) {
	if len(key) != ed25519.PublicKeySize || !text(policyDigest) {
		return Verifier{}, ErrInvalid
	}
	return Verifier{publicKey: append(ed25519.PublicKey(nil), key...), policyDigest: policyDigest, now: time.Now}, nil
}

func (v Verifier) verify(kind string, value any, signature []byte) error {
	if len(v.publicKey) != ed25519.PublicKeySize || v.now == nil {
		return ErrInvalid
	}
	data, err := message(kind, value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(v.publicKey, data, signature) {
		return ErrInvalid
	}
	return nil
}

func (v Verifier) binding(authority, policy, cluster, host string, public []byte) error {
	if authority != identity.PublicKeyID(v.publicKey) || policy != v.policyDigest {
		return ErrTrustMismatch
	}
	if !text(cluster) || len(public) != ed25519.PublicKeySize || host != identity.PublicKeyID(public) {
		return ErrInvalid
	}
	return nil
}

func (v Verifier) lifetime(issued, expires time.Time) error {
	if issued.IsZero() || !expires.After(issued) || expires.Sub(issued) > maxLifetime {
		return ErrInvalid
	}
	now := v.now()
	if issued.After(now.Add(clockSkew)) || !expires.After(now) {
		return ErrExpired
	}
	return nil
}

func (v Verifier) bootstrapSignature(g BootstrapGrant) error {
	sig := g.Signature
	g.Signature = nil
	if err := v.binding(g.AuthorityID, g.PolicyDigest, g.ClusterID, g.HostID, g.PublicKey); err != nil {
		return err
	}
	if !text(g.OperationID) {
		return ErrInvalid
	}
	return v.verify("bootstrap-grant", g, sig)
}

func (v Verifier) VerifyBootstrapGrant(ctx context.Context, g BootstrapGrant) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := v.bootstrapSignature(g); err != nil {
		return err
	}
	return v.lifetime(g.IssuedAt, g.ExpiresAt)
}

func (v Verifier) joinSignature(g JoinGrant) error {
	sig := g.Signature
	g.Signature = nil
	if err := v.binding(g.AuthorityID, g.PolicyDigest, g.ClusterID, g.HostID, g.PublicKey); err != nil {
		return err
	}
	if !text(g.OperationID) || (g.Role != RoleAgent && g.Role != RoleServer) {
		return ErrInvalid
	}
	return v.verify("join-grant", g, sig)
}

func (v Verifier) VerifyJoinGrant(ctx context.Context, g JoinGrant) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := v.joinSignature(g); err != nil {
		return err
	}
	return v.lifetime(g.IssuedAt, g.ExpiresAt)
}

func (v Verifier) VerifyAdvertisement(ctx context.Context, a Advertisement, endpoint, challenge string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.AuthorityID != identity.PublicKeyID(v.publicKey) || a.PolicyDigest != v.policyDigest {
		return ErrTrustMismatch
	}
	if !text(a.ClusterID) || !ValidEndpoint(a.Endpoint) || a.Endpoint != endpoint || !ValidChallenge(challenge) || a.Challenge != challenge {
		return ErrInvalid
	}
	sig := a.Signature
	a.Signature = nil
	if err := v.verify("advertisement", a, sig); err != nil {
		return err
	}
	return v.lifetime(a.IssuedAt, a.ExpiresAt)
}
