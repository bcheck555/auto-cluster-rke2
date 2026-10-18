package discovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"auto-cluster-rke2/internal/bootstrap"
	"auto-cluster-rke2/internal/durable"
)

var ErrUnavailable = errors.New("no authenticated discovery endpoint available")

// StaticProvider supplies explicitly provisioned endpoints. Even configured
// hints pass through the same transport, signature, and cluster-pin checks.
type StaticProvider []EndpointHint

func (s StaticProvider) Discover(ctx context.Context) ([]EndpointHint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]EndpointHint(nil), s...), nil
}

type SRVResolver interface {
	LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error)
}

// DNSProvider adapts DNS-SD SRV results into untrusted hints. The resolver must
// be explicitly configured. Go's DNS resolver does not itself browse multicast.
// An mDNS/DNS-SD browser can implement Provider directly with the same boundary.
type DNSProvider struct {
	Resolver SRVResolver
	Domain   string
}

func (p DNSProvider) Discover(ctx context.Context) ([]EndpointHint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.Resolver == nil || strings.TrimSpace(p.Domain) == "" {
		return nil, ErrUnavailable
	}
	_, records, err := p.Resolver.LookupSRV(ctx, "auto-cluster", "tcp", p.Domain)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnavailable
	}
	if len(records) > 32 {
		return nil, ErrUnavailable
	}
	var hints []EndpointHint
	for _, r := range records {
		if r != nil && r.Target != "." && r.Port != 0 {
			hints = append(hints, EndpointHint{Address: strings.TrimSuffix(r.Target, "."), Port: r.Port, Transport: "https", ObservedAt: time.Now().UTC()})
		}
	}
	return hints, nil
}

// Probe performs an authenticated exchange; production callers use HTTPProbe.
type Probe interface {
	Fetch(context.Context, string, string) (bootstrap.Advertisement, error)
}

type VerifiedEndpoint struct {
	URL          string
	ClusterID    string
	AuthorityID  string
	PolicyDigest string
	Active       bool
}

// AuditEvent contains only public endpoint and fixed decision-code fields.
type AuditEvent struct {
	Endpoint string
	Decision string
}

// Resolver verifies every endpoint and persists the first authority-signed
// cluster identity. It never calls bootstrap, including on timeout or emptiness.
// Each probe is bounded; no more than 32 candidates are processed per call.
type Resolver struct {
	Hints     Provider
	Probe     Probe
	Verifier  bootstrap.Verifier
	Directory string
	Audit     func(AuditEvent)
}

func (r Resolver) audit(endpoint, decision string) {
	if r.Audit != nil {
		r.Audit(AuditEvent{Endpoint: endpoint, Decision: decision})
	}
}

type clusterPin struct {
	AuthorityID  string
	ClusterID    string
	PolicyDigest string
}

func (r Resolver) pin(ctx context.Context, a bootstrap.Advertisement) error {
	return durable.WithLock(ctx, r.Directory, func(d *durable.Directory) error {
		var pin clusterPin
		err := d.Read("cluster-pin.json", &pin)
		next := clusterPin{AuthorityID: a.AuthorityID, ClusterID: a.ClusterID, PolicyDigest: a.PolicyDigest}
		if errors.Is(err, os.ErrNotExist) {
			return d.Write(ctx, "cluster-pin.json", next)
		}
		if err != nil {
			return err
		}
		if pin.AuthorityID == "" || pin.ClusterID == "" || pin.PolicyDigest == "" {
			return durable.ErrCorrupt
		}
		if pin != next {
			return bootstrap.ErrClusterMismatch
		}
		return nil
	})
}

func hintURL(h EndpointHint) (string, error) {
	if h.Transport != "https" || h.Port == 0 || strings.TrimSpace(h.Address) == "" || strings.ContainsAny(h.Address, "/?#@\\ \t\r\n") {
		return "", bootstrap.ErrInvalid
	}
	u := url.URL{Scheme: "https", Host: net.JoinHostPort(h.Address, strconv.Itoa(int(h.Port)))}
	if !bootstrap.ValidEndpoint(u.String()) {
		return "", bootstrap.ErrInvalid
	}
	return u.String(), nil
}

func (r Resolver) Resolve(ctx context.Context) (VerifiedEndpoint, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedEndpoint{}, err
	}
	if r.Hints == nil || r.Probe == nil {
		return VerifiedEndpoint{}, ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	hints, err := r.Hints.Discover(bounded)
	if err != nil {
		if ctx.Err() != nil {
			return VerifiedEndpoint{}, ctx.Err()
		}
		return VerifiedEndpoint{}, ErrUnavailable
	}
	if len(hints) > 32 {
		return VerifiedEndpoint{}, ErrUnavailable
	}
	seen := make(map[string]bool)
	for _, hint := range hints {
		endpoint, err := hintURL(hint)
		if err != nil {
			r.audit("", "invalid-hint")
			continue
		}
		if seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return VerifiedEndpoint{}, ErrUnavailable
		}
		challenge := hex.EncodeToString(nonce[:])
		probeCtx, stop := context.WithTimeout(bounded, 2*time.Second)
		ad, err := r.Probe.Fetch(probeCtx, endpoint, challenge)
		stop()
		if err != nil {
			r.audit(endpoint, "probe-unavailable")
			continue
		}
		if err := r.Verifier.VerifyAdvertisement(bounded, ad, endpoint, challenge); err != nil {
			r.audit(endpoint, "invalid-statement")
			continue
		}
		if hint.ClusterID != "" && hint.ClusterID != ad.ClusterID {
			r.audit(endpoint, "hint-cluster-mismatch")
			continue
		}
		if err := r.pin(bounded, ad); err != nil {
			r.audit(endpoint, "pin-rejected")
			return VerifiedEndpoint{}, err
		}
		r.audit(endpoint, "verified")
		return VerifiedEndpoint{URL: endpoint, ClusterID: ad.ClusterID, AuthorityID: ad.AuthorityID, PolicyDigest: ad.PolicyDigest, Active: ad.Active}, nil
	}
	if err := ctx.Err(); err != nil {
		return VerifiedEndpoint{}, err
	}
	return VerifiedEndpoint{}, ErrUnavailable
}
