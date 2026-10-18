package formation

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedDiscoveryRejectsTamperingWrongSecretAndStaleMessages(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	n := newNode(t, c, 0)
	a := n.Auth
	a.Deployment = Deployment(a.Secret)
	_, cert, err := Certificate(ctx, a.Signer, a.Self.Address)
	if err != nil {
		t.Fatal(err)
	}
	a.Self.Certificate = cert
	challenge, _ := nonce()
	message, err := a.Sign(ctx, Message{Kind: "reply", Nonce: challenge})
	if err != nil || a.Verify(message) != nil {
		t.Fatal("valid signature rejected", err)
	}
	if _, err := PeerCertificate(message.Peer); err != nil {
		t.Fatal(err)
	}
	tampered := message
	tampered.Peer.Address = "192.168.10.200"
	if a.Verify(tampered) == nil {
		t.Fatal("tampered address accepted")
	}
	wrong := a
	wrong.Secret = []byte(strings.Repeat("x", 32))
	if wrong.Verify(message) == nil {
		t.Fatal("wrong secret accepted")
	}
	stale := a
	stale.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if stale.Verify(message) == nil {
		t.Fatal("stale reply accepted")
	}
	other := newNode(t, c, 1)
	wrongPeer := a.Self
	wrongPeer.PublicKey = other.Auth.Self.PublicKey
	if _, err := PeerCertificate(wrongPeer); err == nil {
		t.Fatal("certificate/key mismatch accepted")
	}
	data, _ := json.Marshal(message)
	if len(data) > 4096 {
		t.Fatal("advertisement exceeds datagram limit")
	}
	if strings.Contains(string(data), string(a.Secret)) {
		t.Fatal("deployment secret leaked")
	}
}

func TestEnrollmentRequiresAuthenticatedIdentitySourceAndCluster(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	server := newNode(t, c, 0)
	if err := server.Step(ctx); err != nil {
		t.Fatal(err)
	}
	joiner := newNode(t, c, 1)
	service := Service{Auth: server.Auth, Current: server.Current, Backend: server.CurrentBackend}
	call := func(m Message, remote string, secure bool) *httptest.ResponseRecorder {
		data, _ := json.Marshal(m)
		request := httptest.NewRequest(http.MethodPost, "https://node/v1/enroll", strings.NewReader(string(data)))
		request.RemoteAddr = remote + ":12345"
		if secure {
			request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		} else {
			request.TLS = nil
		}
		response := httptest.NewRecorder()
		service.Handler().ServeHTTP(response, request)
		return response
	}
	a := joiner.Auth
	a.Self.ClusterID = server.Current().ClusterID
	challenge, _ := nonce()
	m, err := a.Sign(ctx, Message{Kind: "enroll", Nonce: challenge, Member: joiner.member(joiner.current)})
	if err != nil {
		t.Fatal(err)
	}
	if response := call(m, a.Self.Address, true); response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	for _, test := range []struct {
		remote string
		secure bool
	}{{"192.168.10.222", true}, {a.Self.Address, false}} {
		if response := call(m, test.remote, test.secure); response.Code != 403 {
			t.Fatal("request bypassed source/TLS binding", response.Code)
		}
	}
	m.Member.PublicKey = server.Auth.Self.PublicKey
	if response := call(m, a.Self.Address, true); response.Code != 403 {
		t.Fatal("tampered signature accepted")
	}
}

func TestCredentialsBindHostRoleAndClusterCA(t *testing.T) {
	c := newCluster(t)
	n := newNode(t, c, 0)
	m := n.member(n.current)
	m.Role = "agent"
	credentials, err := c.Credentials(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCredentials(credentials, n.Auth.Self); err != nil {
		t.Fatal(err)
	}
	bad := credentials
	bad.ServerToken = "server secret"
	if err := validateCredentials(bad, n.Auth.Self); !errors.Is(err, ErrInvalid) {
		t.Fatal("server secret sent to worker", err)
	}
	bad = credentials
	bad.AgentToken = strings.Replace(bad.AgentToken, "node:", "server:", 1)
	if validateCredentials(bad, n.Auth.Self) == nil {
		t.Fatal("worker given server credential")
	}
	other := newNode(t, c, 1)
	bad = credentials
	otherMember := other.member(other.current)
	otherMember.Role = "agent"
	otherCredentials, _ := c.Credentials(context.Background(), otherMember)
	bad.ReaderCertificate = otherCredentials.ReaderCertificate
	if validateCredentials(bad, n.Auth.Self) == nil {
		t.Fatal("foreign reader certificate accepted")
	}
	bad = credentials
	bad.ServerCA = otherCredentials.ReaderCertificate
	if validateCredentials(bad, n.Auth.Self) == nil {
		t.Fatal("non-CA accepted")
	}
	bad = credentials
	bad.AgentToken = "K10" + strings.Repeat("0", 64) + "::node:" + strings.Repeat("a", 64)
	if validateCredentials(bad, n.Auth.Self) == nil {
		t.Fatal("wrong CA hash accepted")
	}
}

func TestDeploymentSecretNormalizesHexAndRejectsPlaceholder(t *testing.T) {
	a, err := deploymentSecret([]byte(strings.Repeat("ab", 32)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := deploymentSecret([]byte(strings.Repeat("AB", 32) + "\n"))
	if err != nil || Deployment(a) != Deployment(b) {
		t.Fatal("equivalent hex encodings split deployment", err)
	}
	for _, invalid := range []string{"REPLACE_WITH_ONE_COMMON_64_CHARACTER_RANDOM_HEX_SECRET", strings.Repeat("a", 32), strings.Repeat("x", 64)} {
		if _, err := deploymentSecret([]byte(invalid)); err == nil {
			t.Fatal("invalid deployment key accepted")
		}
	}
}
