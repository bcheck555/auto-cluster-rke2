package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"auto-cluster-rke2/internal/bootstrap"
	"auto-cluster-rke2/internal/discovery"
	"auto-cluster-rke2/internal/durable"
	"auto-cluster-rke2/internal/hostagent"
	"auto-cluster-rke2/internal/identity"
)

type settings struct {
	StateDirectory string
	KeyDirectory   string
	Endpoint       string
	ListenAddress  string
	Policy         bootstrap.Policy
	ServerTLS      hostagent.TLSFiles
	ClientCA       string
}

func main() { os.Exit(run()) }
func run() int {
	config := flag.String("config", "/etc/autonomous-rke2/authority.json", "private authority configuration")
	initialize := flag.Bool("initialize", false, "explicitly reserve one cluster identity")
	activate := flag.String("confirm-cluster-active", "", "operator confirmation after independent cluster identity and health checks")
	flag.Parse()
	if flag.NArg() != 0 || (*initialize && *activate != "") {
		fmt.Fprintln(os.Stderr, "bootstrap-authority: invalid arguments")
		return 2
	}
	data, err := hostagent.ReadFile(*config, true, 128<<10)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap-authority: configuration unavailable")
		return 2
	}
	var c settings
	if durable.Decode(data, &c) != nil || !filepath.IsAbs(c.StateDirectory) || !filepath.IsAbs(c.KeyDirectory) || filepath.Dir(c.StateDirectory) != filepath.Dir(c.KeyDirectory) {
		fmt.Fprintln(os.Stderr, "bootstrap-authority: invalid configuration")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Provision the private common parent only during explicit initialization.
	if *initialize {
		if err := os.Mkdir(filepath.Dir(c.StateDirectory), 0700); err != nil && !os.IsExist(err) {
			return 2
		}
	}
	signer := identity.NewFileStore(c.KeyDirectory)
	a, err := bootstrap.NewFileAuthority(ctx, bootstrap.Config{Directory: c.StateDirectory, Signer: signer, Policy: c.Policy, Endpoint: c.Endpoint})
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap-authority: trust or storage invalid")
		return 2
	}
	if *initialize {
		if err := a.Initialize(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap-authority: initialization denied")
			return 2
		}
	}
	if *activate != "" {
		if err := a.ConfirmClusterActive(ctx, *activate); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap-authority: activation denied")
			return 2
		}
	}
	ad, err := a.Advertise(ctx, strings.Repeat("a", 64))
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap-authority: initialization or operator reconciliation required")
		return 2
	}
	if *initialize || *activate != "" {
		id, err := signer.LoadOrCreate(ctx)
		if err != nil {
			return 2
		}
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			ClusterID, AuthorityID, PolicyDigest string
			SigningPublicKey                     []byte
			Active                               bool
		}{ad.ClusterID, ad.AuthorityID, ad.PolicyDigest, id.PublicKey, ad.Active})
		return 0
	}
	_, listenPort, err := net.SplitHostPort(c.ListenAddress)
	if err != nil {
		return 2
	}
	endpoint, _ := url.Parse(c.Endpoint)
	if endpoint.Port() != listenPort {
		return 2
	}
	cert, err := hostagent.ReadFile(c.ServerTLS.Cert, false, 1<<20)
	if err != nil {
		return 2
	}
	key, err := hostagent.ReadFile(c.ServerTLS.Key, true, 1<<20)
	if err != nil {
		return 2
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return 2
	}
	clientCA, err := hostagent.ReadFile(c.ClientCA, false, 1<<20)
	if err != nil {
		return 2
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(clientCA) {
		return 2
	}
	mux := http.NewServeMux()
	grants := bootstrap.HTTPHandler(a)
	for _, path := range []string{"/v1/bootstrap", "/v1/join", "/v1/bootstrap/consume", "/v1/join/consume", "/v1/grant-status"} {
		mux.Handle(path, grants)
	}
	mux.Handle("/", discovery.Handler(a))
	server := &http.Server{Addr: c.ListenAddress, Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots, MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS("", "") }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		return 0
	case <-done:
		fmt.Fprintln(os.Stderr, "bootstrap-authority: listener unavailable")
		return 2
	}
}
