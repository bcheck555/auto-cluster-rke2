package discovery

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"auto-cluster-rke2/internal/bootstrap"
	"auto-cluster-rke2/internal/durable"
)

const identityPath = "/v1/cluster-identity"
const maxResponse = 16 << 10

type Advertiser interface {
	Advertise(context.Context, string) (bootstrap.Advertisement, error)
}

// Handler serves public signed identity only. It exposes no initialization,
// grant issuance/consumption, activation, credentials, or generic command API.
// Deploy with a TLS server that sets header/read/write/idle timeouts.
func Handler(authority Advertiser) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusUpgradeRequired)
			return
		}
		if r.URL.Path != identityPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method denied", http.StatusMethodNotAllowed)
			return
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(q) != 1 || len(q["challenge"]) != 1 || !bootstrap.ValidChallenge(q.Get("challenge")) {
			http.Error(w, "invalid challenge", http.StatusBadRequest)
			return
		}
		if authority == nil {
			http.Error(w, "authority unavailable", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		ad, err := authority.Advertise(ctx, q.Get("challenge"))
		if err != nil {
			http.Error(w, "authority unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Do not echo errors, request fields, or storage paths into responses.
		_ = json.NewEncoder(w).Encode(ad)
	})
}

// HTTPProbe owns its transport to forbid insecure TLS, proxy inheritance, and
// redirects. Trust roots must be provisioned independently of discovered hints.
type HTTPProbe struct {
	client    *http.Client
	transport *http.Transport
}

func NewHTTPProbe(config *tls.Config) (*HTTPProbe, error) {
	if config == nil || config.InsecureSkipVerify || config.RootCAs == nil || config.ServerName != "" {
		return nil, bootstrap.ErrInvalid
	}
	c := config.Clone()
	c.MinVersion = tls.VersionTLS13
	// Public discovery never presents host credentials to an unverified hint.
	c.Certificates = nil
	c.GetClientCertificate = nil
	transport := &http.Transport{TLSClientConfig: c, Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: maxResponse, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &HTTPProbe{client: client, transport: transport}, nil
}

func (p *HTTPProbe) Close() { p.transport.CloseIdleConnections() }

func (p *HTTPProbe) Fetch(ctx context.Context, endpoint, challenge string) (bootstrap.Advertisement, error) {
	var ad bootstrap.Advertisement
	if p == nil || p.client == nil || !bootstrap.ValidEndpoint(endpoint) || !bootstrap.ValidChallenge(challenge) {
		return ad, ErrUnavailable
	}
	u, _ := url.Parse(endpoint)
	u.Path = identityPath
	u.RawQuery = url.Values{"challenge": {challenge}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ad, ErrUnavailable
	}
	response, err := p.client.Do(req)
	if err != nil {
		return ad, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ad, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return ad, ErrUnavailable
	}
	if err := durable.Decode(data, &ad); err != nil {
		return ad, ErrUnavailable
	}
	return ad, nil
}
