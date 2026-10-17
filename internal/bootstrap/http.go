package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"autonomous-rke2/internal/durable"
	"autonomous-rke2/internal/identity"
)

var ErrUnavailable = errors.New("bootstrap authority unavailable")

const maxMessage = 16 << 10

type joinRequest struct {
	ClusterID string
	Request   BootstrapRequest
}
type wireError struct{ Code string }

type statusRequest struct {
	HostID      string
	OperationID string
	Challenge   string
}

func errorCode(err error) (int, string) {
	switch {
	case errors.Is(err, ErrGrantNotFound):
		return http.StatusNotFound, "grant-not-found"
	case errors.Is(err, ErrReplay):
		return http.StatusConflict, "replay"
	case errors.Is(err, ErrClusterMismatch):
		return http.StatusConflict, "cluster-mismatch"
	case errors.Is(err, ErrDenied):
		return http.StatusForbidden, "denied"
	case errors.Is(err, ErrTrustMismatch):
		return http.StatusForbidden, "trust-mismatch"
	case errors.Is(err, ErrInvalid):
		return http.StatusBadRequest, "invalid"
	case errors.Is(err, ErrExpired):
		return http.StatusGone, "expired"
	case errors.Is(err, ErrNotActive):
		return http.StatusServiceUnavailable, "not-active"
	case errors.Is(err, ErrUninitialized):
		return http.StatusServiceUnavailable, "uninitialized"
	default:
		return http.StatusServiceUnavailable, "unavailable"
	}
}

func fromCode(code string) error {
	switch code {
	case "grant-not-found":
		return ErrGrantNotFound
	case "replay":
		return ErrReplay
	case "cluster-mismatch":
		return ErrClusterMismatch
	case "denied":
		return ErrDenied
	case "trust-mismatch":
		return ErrTrustMismatch
	case "invalid":
		return ErrInvalid
	case "expired":
		return ErrExpired
	case "not-active":
		return ErrNotActive
	case "uninitialized":
		return ErrUninitialized
	default:
		return ErrUnavailable
	}
}

// HTTPHandler exposes only enrolled-host grant operations. Serve with TLS 1.3
// and VerifyClientCertIfGiven (if sharing public discovery) or
// RequireAndVerifyClientCert. Verified client keys must match enrolled host keys.
// Configure server header/read/write/idle timeouts before deployment.
func HTTPHandler(a *FileAuthority) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		reply := func(err error) {
			status, code := errorCode(err)
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(wireError{Code: code})
		}
		if a == nil || r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			reply(ErrDenied)
			return
		}
		key, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
		if !ok {
			reply(ErrDenied)
			return
		}
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			reply(ErrInvalid)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMessage))
		if err != nil {
			reply(ErrInvalid)
			return
		}
		decode := func(value any) bool {
			if durable.Decode(body, value) != nil {
				reply(ErrInvalid)
				return false
			}
			return true
		}
		matches := func(host string, public []byte) bool {
			return host == identity.PublicKeyID(key) && ed25519.PublicKey(public).Equal(key)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var response any = struct{}{}
		switch r.URL.Path {
		case "/v1/grant-status":
			var query statusRequest
			if !decode(&query) {
				return
			}
			if query.HostID != identity.PublicKeyID(key) {
				reply(ErrDenied)
				return
			}
			response, err = a.GrantStatus(ctx, query.HostID, query.OperationID, query.Challenge)
		case "/v1/bootstrap":
			var req BootstrapRequest
			if !decode(&req) {
				return
			}
			if !matches(req.HostID, req.PublicKey) {
				reply(ErrDenied)
				return
			}
			response, err = a.AuthorizeBootstrap(ctx, req)
		case "/v1/join":
			var req joinRequest
			if !decode(&req) {
				return
			}
			if !matches(req.Request.HostID, req.Request.PublicKey) {
				reply(ErrDenied)
				return
			}
			response, err = a.AuthorizeJoin(ctx, req.ClusterID, req.Request)
		case "/v1/bootstrap/consume":
			var g BootstrapGrant
			if !decode(&g) {
				return
			}
			if !matches(g.HostID, g.PublicKey) {
				reply(ErrDenied)
				return
			}
			err = a.ConsumeBootstrapGrant(ctx, g)
		case "/v1/join/consume":
			var g JoinGrant
			if !decode(&g) {
				return
			}
			if !matches(g.HostID, g.PublicKey) {
				reply(ErrDenied)
				return
			}
			err = a.ConsumeJoinGrant(ctx, g)
		default:
			reply(ErrInvalid)
			return
		}
		if err != nil {
			reply(err)
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	})
}

// HTTPClient requires independently provisioned server CA roots, a host client
// certificate, and the pinned signing key/policy verifier. It never initializes
// authority state and never falls back to a local authority on network failure.
type HTTPClient struct {
	endpoint  string
	cluster   string
	client    *http.Client
	transport *http.Transport
	verifier  Verifier
	host      string
	public    ed25519.PublicKey
}

var _ Authority = (*HTTPClient)(nil)
var _ Consumer = (*HTTPClient)(nil)

func NewHTTPClient(endpoint, pinnedCluster string, c *tls.Config, v Verifier) (*HTTPClient, error) {
	if !ValidEndpoint(endpoint) || !text(pinnedCluster) || c == nil || c.InsecureSkipVerify || c.RootCAs == nil || c.ServerName != "" || len(c.Certificates) != 1 || len(c.Certificates[0].Certificate) == 0 || len(v.publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	leaf, err := x509.ParseCertificate(c.Certificates[0].Certificate[0])
	if err != nil {
		return nil, ErrInvalid
	}
	key, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalid
	}
	config := c.Clone()
	config.MinVersion = tls.VersionTLS13
	// Select only the enrolled certificate supplied above, including when the
	// caller's config contains a dynamic certificate selection callback.
	config.GetClientCertificate = nil
	tr := &http.Transport{TLSClientConfig: config, Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: maxMessage, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 4}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &HTTPClient{endpoint: strings.TrimSuffix(endpoint, "/"), cluster: pinnedCluster, client: client, transport: tr, verifier: v, host: identity.PublicKeyID(key), public: append(ed25519.PublicKey(nil), key...)}, nil
}

func (c *HTTPClient) Close() { c.transport.CloseIdleConnections() }

func (c *HTTPClient) GrantStatus(ctx context.Context, host, operation, challenge string) (GrantStatus, error) {
	var s GrantStatus
	if host != c.host {
		return s, ErrDenied
	}
	if err := c.call(ctx, "/v1/grant-status", statusRequest{HostID: host, OperationID: operation, Challenge: challenge}, &s); err != nil {
		return GrantStatus{}, err
	}
	if s.ClusterID != c.cluster {
		return GrantStatus{}, ErrClusterMismatch
	}
	if err := c.verifier.VerifyGrantStatus(ctx, s, host, operation, challenge); err != nil {
		return GrantStatus{}, err
	}
	return s, nil
}

func (c *HTTPClient) call(ctx context.Context, path string, input, output any) error {
	data, err := json.Marshal(input)
	if err != nil || len(data) > maxMessage {
		return ErrInvalid
	}
	u, _ := url.Parse(c.endpoint)
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMessage+1))
	if err != nil || len(body) > maxMessage {
		return ErrUnavailable
	}
	if response.StatusCode != http.StatusOK {
		var failure wireError
		if durable.Decode(body, &failure) != nil {
			return ErrUnavailable
		}
		status, _ := errorCode(fromCode(failure.Code))
		if status != response.StatusCode {
			return ErrUnavailable
		}
		return fromCode(failure.Code)
	}
	if durable.Decode(body, output) != nil {
		return ErrInvalid
	}
	return nil
}

func (c *HTTPClient) own(host string, key []byte) bool {
	return c.host == host && ed25519.PublicKey(key).Equal(c.public)
}

func (c *HTTPClient) AuthorizeBootstrap(ctx context.Context, req BootstrapRequest) (BootstrapGrant, error) {
	var g BootstrapGrant
	if !c.own(req.HostID, req.PublicKey) {
		return g, ErrDenied
	}
	if err := c.call(ctx, "/v1/bootstrap", req, &g); err != nil {
		return BootstrapGrant{}, err
	}
	if !c.own(g.HostID, g.PublicKey) || g.OperationID != req.RequestID {
		return BootstrapGrant{}, ErrDenied
	}
	if err := c.VerifyBootstrapGrant(ctx, g); err != nil {
		return BootstrapGrant{}, err
	}
	return g, nil
}

func (c *HTTPClient) AuthorizeJoin(ctx context.Context, cluster string, req BootstrapRequest) (JoinGrant, error) {
	var g JoinGrant
	if cluster != c.cluster {
		return g, ErrClusterMismatch
	}
	if !c.own(req.HostID, req.PublicKey) {
		return g, ErrDenied
	}
	if err := c.call(ctx, "/v1/join", joinRequest{ClusterID: cluster, Request: req}, &g); err != nil {
		return JoinGrant{}, err
	}
	if !c.own(g.HostID, g.PublicKey) || g.OperationID != req.RequestID || g.ClusterID != cluster {
		return JoinGrant{}, ErrDenied
	}
	if err := c.VerifyJoinGrant(ctx, g); err != nil {
		return JoinGrant{}, err
	}
	return g, nil
}

func (c *HTTPClient) VerifyBootstrapGrant(ctx context.Context, g BootstrapGrant) error {
	if g.ClusterID != c.cluster {
		return ErrClusterMismatch
	}
	return c.verifier.VerifyBootstrapGrant(ctx, g)
}
func (c *HTTPClient) VerifyJoinGrant(ctx context.Context, g JoinGrant) error {
	if g.ClusterID != c.cluster {
		return ErrClusterMismatch
	}
	return c.verifier.VerifyJoinGrant(ctx, g)
}

func (c *HTTPClient) ConsumeBootstrapGrant(ctx context.Context, g BootstrapGrant) error {
	if !c.own(g.HostID, g.PublicKey) {
		return ErrDenied
	}
	if err := c.VerifyBootstrapGrant(ctx, g); err != nil {
		return err
	}
	return c.call(ctx, "/v1/bootstrap/consume", g, &struct{}{})
}

func (c *HTTPClient) ConsumeJoinGrant(ctx context.Context, g JoinGrant) error {
	if !c.own(g.HostID, g.PublicKey) {
		return ErrDenied
	}
	if err := c.VerifyJoinGrant(ctx, g); err != nil {
		return err
	}
	return c.call(ctx, "/v1/join/consume", g, &struct{}{})
}
