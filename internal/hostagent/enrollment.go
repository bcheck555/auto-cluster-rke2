package hostagent

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	"auto-cluster-rke2/internal/identity"
)

type Enrollment struct {
	identity.HostIdentity
	CSR string
}

// Enroll produces a signed public CSR for the operator's host-client CA. The
// persistent key remains in its original identity store throughout enrollment.
func Enroll(ctx context.Context, store identity.Signer) (Enrollment, error) {
	id, err := store.LoadOrCreate(ctx)
	if err != nil {
		return Enrollment{}, err
	}
	signer, err := identity.NewCryptoSigner(ctx, store)
	if err != nil {
		return Enrollment{}, err
	}
	der, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.ID, Organization: []string{"autonomous-rke2-hosts"}}}, signer)
	if err != nil {
		return Enrollment{}, ErrInvalid
	}
	return Enrollment{HostIdentity: id, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}, nil
}
