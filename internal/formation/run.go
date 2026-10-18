package formation

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"auto-cluster-rke2/internal/durable"
	"auto-cluster-rke2/internal/hostagent"
	"auto-cluster-rke2/internal/identity"
	"auto-cluster-rke2/internal/state"
)

func LoadSettings(path string) (Settings, error) {
	var s Settings
	data, err := hostagent.ReadFile(path, false, 64<<10)
	if err != nil || durable.Decode(data, &s) != nil {
		return s, ErrInvalid
	}
	s.Defaults()
	return s, s.Validate()
}

// Run starts only node-local services. Each clone receives the same private
// deployment secret before first boot; no per-node role or endpoint is needed.
func Run(ctx context.Context, s Settings, once bool, report func(error)) error {
	if err := notRetired(s); err != nil {
		return err
	}
	if s.Validate() != nil {
		return ErrInvalid
	}
	secretFile, err := hostagent.ReadFile(s.SecretFile, true, 4096)
	if err != nil {
		return ErrInvalid
	}
	secret, err := deploymentSecret(secretFile)
	if err != nil {
		return err
	}
	iface, address, err := network(s.Interface)
	if err != nil {
		return err
	}
	s.Interface = iface
	if err := hostagent.EnsureDirectory(s.StateDirectory); err != nil {
		return err
	}
	if entries, err := os.ReadDir(filepath.Join(s.StateDirectory, "journal")); err == nil && len(entries) > 0 {
		return ErrConflict
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	signer := identity.NewFileStore(filepath.Join(s.StateDirectory, "identity"))
	id, err := signer.LoadOrCreate(ctx)
	if err != nil {
		return err
	}
	pair, cert, err := Certificate(ctx, signer, address)
	if err != nil {
		return err
	}
	auth := Auth{Secret: secret, Signer: signer, Deployment: Deployment(secret), Self: Peer{ID: id.ID, PublicKey: id.PublicKey, Address: address, Certificate: cert, Policy: s.Policy()}}
	health := &hostagent.HealthChecker{Observer: hostagent.TLSFiles{CA: filepath.Join(s.StateDirectory, "credentials/server-ca.crt"), Cert: filepath.Join(s.StateDirectory, "credentials/reader.crt")}, ObserverSigner: signer}
	n := &Node{Settings: s, Auth: auth, Journal: state.NewFileJournal(filepath.Join(s.StateDirectory, "formation")), Runtime: hostagent.NewLinuxRuntime(health), Client: Client{Auth: auth}, StartedAt: time.Now()}
	var certificate atomic.Pointer[tls.Certificate]
	certificate.Store(&pair)
	n.PublicCertificate = func() []byte { return certificate.Load().Certificate[0] }
	n.Backend = func(s State) Backend { return KubeBackend{ClusterID: s.ClusterID, Policy: s.Policy} }
	api := &Proxy{Port: "6443"}
	n.UpdateProxies = api.Update
	if err := n.Restore(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ready := make(chan struct{})
	d := Discovery{Auth: auth, Interface: iface, Current: n.Current, Ready: ready}
	n.Find = d.Find
	errorsCh := make(chan error, 4)
	go func() { errorsCh <- d.Serve(ctx) }()
	select {
	case <-ready:
	case err := <-errorsCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(address, "9443"))
	if err != nil {
		return ErrWaiting
	}
	defer listener.Close()
	apiListener, err := net.Listen("tcp4", API)
	if err != nil {
		return ErrWaiting
	}
	defer apiListener.Close()
	server := &http.Server{Handler: (Service{Auth: auth, Current: n.Current, Backend: n.CurrentBackend}).Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certificate.Load(), nil }}}
	defer server.Close()
	go func() { errorsCh <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	go func() { errorsCh <- api.serve(ctx, apiListener) }()
	for {
		if time.Until(certificate.Load().Leaf.NotAfter) < 7*24*time.Hour {
			fresh, _, err := Certificate(ctx, signer, address)
			if err != nil {
				return err
			}
			certificate.Store(&fresh)
		}
		select {
		case err := <-errorsCh:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		default:
		}
		attempt, stop := context.WithTimeout(ctx, 2*time.Minute)
		err := n.Step(attempt)
		stop()
		if report != nil {
			report(err)
		}
		if Permanent(err) {
			return err
		}
		if once {
			return err
		}
		timer := time.NewTimer(10 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case err := <-errorsCh:
			timer.Stop()
			return err
		case <-timer.C:
		}
	}
}

func Permanent(err error) bool {
	return errors.Is(err, ErrConflict) || errors.Is(err, ErrInvalid) || errors.Is(err, hostagent.ErrReconcile) || errors.Is(err, hostagent.ErrInvalid) || errors.Is(err, durable.ErrCorrupt) || errors.Is(err, durable.ErrUnsafe) || errors.Is(err, state.ErrConflict)
}

func deploymentSecret(data []byte) ([]byte, error) {
	secret, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(secret) != 32 {
		return nil, ErrInvalid
	}
	return secret, nil
}
