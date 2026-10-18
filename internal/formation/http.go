package formation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"auto-cluster-rke2/internal/durable"
)

type Service struct {
	Auth    Auth
	Current func() Peer
	Backend func() Backend
}

func (s Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		fail := func(code int) { w.WriteHeader(code); _, _ = w.Write([]byte(`{"status":"formation-unavailable"}`)) }
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || r.Method != http.MethodPost || r.URL.RawQuery != "" {
			fail(403)
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			fail(400)
			return
		}
		var m Message
		if durable.Decode(data, &m) != nil || s.Auth.Verify(m) != nil || !validMember(m.Member) || m.Member.ID != m.Peer.ID || digest(m.Member.PublicKey) != digest(m.Peer.PublicKey) || m.Member.Address != m.Peer.Address {
			fail(403)
			return
		}
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || net.ParseIP(ip) == nil || net.ParseIP(ip).String() != m.Member.Address {
			fail(403)
			return
		}
		current := s.Current()
		if !current.Serving || current.Role != "server" || current.ClusterID == "" || current.ClusterID != m.Peer.ClusterID || current.Policy != m.Peer.Policy {
			fail(503)
			return
		}
		backend := s.Backend()
		if backend == nil {
			fail(503)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		switch r.URL.Path {
		case "/v1/enroll":
			if m.Kind != "enroll" {
				fail(400)
				return
			}
			member, err := backend.Claim(ctx, m.Member)
			if err != nil {
				fail(409)
				return
			}
			credentials, err := backend.Credentials(ctx, member)
			if err != nil {
				fail(503)
				return
			}
			_ = json.NewEncoder(w).Encode(credentials)
		case "/v1/complete":
			if m.Kind != "complete" {
				fail(400)
				return
			}
			member, err := backend.Complete(ctx, m.Member)
			if err != nil {
				fail(409)
				return
			}
			_ = json.NewEncoder(w).Encode(member)
		default:
			fail(404)
		}
	})
}

type Client struct{ Auth Auth }

func (c Client) call(ctx context.Context, peer Peer, kind string, member Member, result any) error {
	cert, err := PeerCertificate(peer)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(c.Auth.Self.Address)}}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16384}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	challenge, err := nonce()
	if err != nil {
		return err
	}
	auth := c.Auth
	auth.Self.ClusterID = peer.ClusterID
	m, err := auth.Sign(ctx, Message{Kind: kind, Nonce: challenge, Member: member})
	if err != nil {
		return err
	}
	data, _ := json.Marshal(m)
	u := "https://" + net.JoinHostPort(peer.Address, strconv.Itoa(Port)) + "/v1/" + kind
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(data))
	if err != nil {
		return ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return ErrWaiting
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return ErrInvalid
	}
	if response.StatusCode != 200 {
		return ErrWaiting
	}
	if durable.Decode(data, result) != nil {
		return ErrInvalid
	}
	return nil
}

func (c Client) Enroll(ctx context.Context, peer Peer, member Member) (Credentials, error) {
	var credentials Credentials
	if err := c.call(ctx, peer, "enroll", member, &credentials); err != nil {
		return credentials, err
	}
	if !sameMember(credentials.Member, member) || (credentials.Member.Role != "server" && credentials.Member.Role != "agent") {
		return Credentials{}, ErrConflict
	}
	return credentials, nil
}

func (c Client) Complete(ctx context.Context, peer Peer, member Member) (Member, error) {
	var result Member
	if err := c.call(ctx, peer, "complete", member, &result); err != nil {
		return result, err
	}
	if !sameMember(result, member) || !result.Complete || result.Role != member.Role {
		return Member{}, ErrConflict
	}
	return result, nil
}
