package hostagent

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"path/filepath"
	"strconv"

	"autonomous-rke2/internal/bootstrap"
	"autonomous-rke2/internal/discovery"
	"autonomous-rke2/internal/durable"
	"autonomous-rke2/internal/identity"
	"autonomous-rke2/internal/state"
)

type Settings struct {
	Plan                 Plan
	StateDirectory       string
	AuthorityEndpoints   []string
	AuthorityCA          string
	AuthorityCertificate string
	AuthoritySigningKey  []byte
	Observer             TLSFiles
}

func LoadSettings(path string) (Settings, error) {
	var settings Settings
	data, err := ReadFile(path, true, 128<<10)
	if err != nil {
		return settings, err
	}
	if durable.Decode(data, &settings) != nil || settings.Validate() != nil {
		return Settings{}, ErrInvalid
	}
	return settings, nil
}

func (s Settings) Validate() error {
	if s.Plan.Validate() != nil || !filepath.IsAbs(s.StateDirectory) || filepath.Clean(s.StateDirectory) != s.StateDirectory || s.StateDirectory == "/" || len(s.AuthoritySigningKey) != ed25519.PublicKeySize || len(s.AuthorityEndpoints) < 1 || len(s.AuthorityEndpoints) > 8 {
		return ErrInvalid
	}
	for _, endpoint := range s.AuthorityEndpoints {
		if !bootstrap.ValidEndpoint(endpoint) {
			return ErrInvalid
		}
		u, _ := url.Parse(endpoint)
		if u.Port() == "" {
			return ErrInvalid
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return ErrInvalid
		}
	}
	for _, path := range []string{s.AuthorityCA, s.AuthorityCertificate} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return ErrInvalid
		}
	}
	if s.Plan.Role == bootstrap.RoleAgent {
		for _, path := range []string{s.Observer.CA, s.Observer.Cert, s.Observer.Key} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return ErrInvalid
			}
		}
	}
	return nil
}

func (s Settings) Identity() *identity.FileStore {
	return identity.NewFileStore(filepath.Join(s.StateDirectory, "identity"))
}

// PrepareState provisions only the agent's private parent; leaf stores retain
// their own restrictive permissions and locks. It does not initialize authority.
func (s Settings) PrepareState() error { return ensureDirectory(s.StateDirectory) }

func (s Settings) Execute(ctx context.Context) error {
	if s.Validate() != nil {
		return ErrInvalid
	}
	if err := s.PrepareState(); err != nil {
		return err
	}
	signer := s.Identity()
	adapter, err := identity.NewCryptoSigner(ctx, signer)
	if err != nil {
		return err
	}
	cert, err := ReadFile(s.AuthorityCertificate, false, 1<<20)
	if err != nil {
		return ErrWaiting
	}
	// TLS certificates are PEM; parse public chains without a private-key file.
	chain, err := CertificateChain(cert)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return ErrInvalid
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !public.Equal(adapter.Public()) {
		return ErrReconcile
	}
	ca, err := ReadFile(s.AuthorityCA, false, 1<<20)
	if err != nil {
		return ErrWaiting
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return ErrInvalid
	}
	tlsConfig := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: adapter}}, MinVersion: tls.VersionTLS13}
	verifier, err := bootstrap.NewVerifier(s.AuthoritySigningKey, s.Plan.PolicyDigest)
	if err != nil {
		return err
	}
	probe, err := discovery.NewHTTPProbe(tlsConfig)
	if err != nil {
		return err
	}
	defer probe.Close()
	var hints discovery.StaticProvider
	for _, endpoint := range s.AuthorityEndpoints {
		u, _ := url.Parse(endpoint)
		port, _ := strconv.Atoi(u.Port())
		hints = append(hints, discovery.EndpointHint{Address: u.Hostname(), Port: uint16(port), Transport: "https"})
	}
	resolver := discovery.Resolver{Hints: hints, Probe: probe, Verifier: verifier, Directory: filepath.Join(s.StateDirectory, "cluster-pin")}
	endpoint, err := resolver.Resolve(ctx)
	if err != nil {
		return err
	}
	if endpoint.ClusterID != s.Plan.ClusterID {
		return ErrReconcile
	}
	remote, err := bootstrap.NewHTTPClient(endpoint.URL, endpoint.ClusterID, tlsConfig, verifier)
	if err != nil {
		return err
	}
	defer remote.Close()
	runtime := NewLinuxRuntime(&HealthChecker{Observer: s.Observer})
	engine := Engine{Plan: s.Plan, Identity: signer, Journal: state.NewFileJournal(filepath.Join(s.StateDirectory, "journal")), Authority: remote, Verifier: verifier, Runtime: runtime, LockDirectory: filepath.Join(s.StateDirectory, "execution")}
	return engine.Run(ctx)
}

func CertificateChain(data []byte) ([][]byte, error) {
	var chain [][]byte
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, ErrInvalid
		}
		data = rest
		if block.Type != "CERTIFICATE" || len(chain) >= 8 {
			return nil, ErrInvalid
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, ErrInvalid
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, ErrInvalid
	}
	return chain, nil
}
