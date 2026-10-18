package formation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"
)

func validateCredentials(c Credentials, self Peer) error {
	if !validMember(c.Member) || c.Member.ID != self.ID {
		return ErrConflict
	}
	var root *x509.Certificate
	remaining := c.ServerCA
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return ErrInvalid
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return ErrInvalid
		}
		root = cert
		remaining = rest
	}
	if root == nil {
		return ErrInvalid
	}
	pemHash, derHash := sha256.Sum256(c.ServerCA), sha256.Sum256(root.Raw)
	checkToken := func(token, role string) bool {
		if len(token) < 104 || strings.ContainsAny(token, " \r\n\t") || !strings.HasPrefix(token, "K10") || token[67:69] != "::" || !strings.HasPrefix(token[69:], role+":") {
			return false
		}
		hash := token[3:67]
		return (hash == hex.EncodeToString(pemHash[:]) || hash == hex.EncodeToString(derHash[:])) && len(strings.TrimPrefix(token[69:], role+":")) >= 32
	}
	if !checkToken(c.AgentToken, "node") {
		return ErrInvalid
	}
	if c.Member.Role == "server" {
		if !checkToken(c.ServerToken, "server") {
			return ErrInvalid
		}
		return nil
	}
	if c.Member.Role != "agent" || c.ServerToken != "" {
		return ErrInvalid
	}
	block, rest := pem.Decode(c.ReaderCertificate)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return ErrInvalid
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ErrInvalid
	}
	key, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !key.Equal(ed25519.PublicKey(self.PublicKey)) || cert.IsCA || cert.Subject.CommonName != "autonomous-rke2-health" || len(cert.Subject.Organization) > 0 || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return ErrInvalid
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return nil
		}
	}
	return ErrInvalid
}
