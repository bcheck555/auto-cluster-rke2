package formation

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"time"

	"auto-cluster-rke2/internal/identity"
)

type Auth struct {
	Secret     []byte
	Signer     identity.Signer
	Self       Peer
	Deployment string
	Now        func() time.Time
}

type Message struct {
	Kind       string
	Deployment string
	Nonce      string
	IssuedAt   time.Time
	Peer       Peer
	Member     Member
	Signature  []byte
	MAC        []byte
}

func nonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (a Auth) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func signingBytes(m Message) []byte {
	m.Signature = nil
	m.MAC = nil
	b, _ := json.Marshal(m)
	return append([]byte("autonomous-rke2/formation/v1\x00"), b...)
}

func (a Auth) Sign(ctx context.Context, m Message) (Message, error) {
	if len(a.Secret) < 32 || a.Signer == nil {
		return Message{}, ErrInvalid
	}
	m.Deployment = a.Deployment
	m.IssuedAt = a.now().UTC()
	m.Peer = a.Self
	data := signingBytes(m)
	sig, err := a.Signer.Sign(ctx, data)
	if err != nil {
		return Message{}, err
	}
	m.Signature = sig
	mac := hmac.New(sha256.New, a.Secret)
	_, _ = mac.Write(data)
	_, _ = mac.Write(sig)
	m.MAC = mac.Sum(nil)
	return m, nil
}

func (a Auth) Verify(m Message) error {
	if len(a.Secret) < 32 || m.Deployment != a.Deployment || len(m.Nonce) != 64 || len(m.Peer.PublicKey) != 32 || identity.PublicKeyID(m.Peer.PublicKey) != m.Peer.ID {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(m.Nonce); err != nil {
		return ErrInvalid
	}
	now := a.now()
	if m.IssuedAt.IsZero() || m.IssuedAt.After(now.Add(5*time.Second)) || m.IssuedAt.Before(now.Add(-time.Minute)) {
		return ErrInvalid
	}
	data := signingBytes(m)
	mac := hmac.New(sha256.New, a.Secret)
	_, _ = mac.Write(data)
	_, _ = mac.Write(m.Signature)
	if !hmac.Equal(m.MAC, mac.Sum(nil)) || !ed25519.Verify(m.Peer.PublicKey, data, m.Signature) {
		return ErrInvalid
	}
	return nil
}

func Certificate(ctx context.Context, signer identity.Signer, address string) (tls.Certificate, []byte, error) {
	key, err := identity.NewCryptoSigner(ctx, signer)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	var serial [16]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return tls.Certificate{}, nil, err
	}
	template := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(serial[:]), Subject: pkix.Name{CommonName: identity.PublicKeyID(key.Public().(ed25519.PublicKey))}, IPAddresses: []net.IP{net.ParseIP(address)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if template.IPAddresses[0] == nil {
		return tls.Certificate{}, nil, ErrInvalid
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, nil, ErrInvalid
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, ErrInvalid
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, der, nil
}

func PeerCertificate(p Peer) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(p.Certificate)
	if err != nil {
		return nil, ErrInvalid
	}
	key, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || identity.PublicKeyID(key) != p.ID || !key.Equal(ed25519.PublicKey(p.PublicKey)) || cert.VerifyHostname(p.Address) != nil {
		return nil, ErrInvalid
	}
	return cert, nil
}
