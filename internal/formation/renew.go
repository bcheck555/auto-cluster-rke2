package formation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"time"

	"auto-cluster-rke2/internal/hostagent"
)

func (n *Node) renewReader(ctx context.Context, s State, servers []Peer) error {
	path := filepath.Join(n.Settings.StateDirectory, "credentials/reader.crt")
	data, err := hostagent.ReadFile(path, false, 1<<20)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ErrConflict
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ErrConflict
	}
	if time.Until(certificate.NotAfter) > 7*24*time.Hour {
		return nil
	}
	for _, server := range servers {
		credentials, err := n.Client.Enroll(ctx, server, n.member(s))
		if err != nil {
			continue
		}
		if !credentials.Member.Complete || credentials.Member.Role != "agent" || credentials.Member.NodeUID != s.Evidence.NodeUID || !sameMember(credentials.Member, n.member(s)) {
			return ErrConflict
		}
		if err := validateCredentials(credentials, n.Auth.Self); err != nil {
			return err
		}
		// Certificate renewal cannot rotate cluster roots or registration secrets.
		token, err := hostagent.ReadFile(n.plan(s).TokenFile, true, 4096)
		if err != nil {
			return err
		}
		if !bytes.Equal(bytes.TrimSpace(token), []byte(credentials.AgentToken)) {
			return ErrConflict
		}
		ca, err := hostagent.ReadFile(filepath.Join(n.Settings.StateDirectory, "credentials/server-ca.crt"), false, 1<<20)
		if err != nil {
			return err
		}
		if !bytes.Equal(ca, credentials.ServerCA) {
			return ErrConflict
		}
		return hostagent.WritePrivateFile(path, credentials.ReaderCertificate)
	}
	return ErrWaiting
}
