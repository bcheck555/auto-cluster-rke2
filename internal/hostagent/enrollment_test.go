package hostagent

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"

	"autonomous-rke2/internal/identity"
)

func TestEnrollmentCSRUsesExistingPersistentKey(t *testing.T) {
	store := identity.NewFileStore(filepath.Join(t.TempDir(), "identity"))
	enrollment, err := Enroll(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(enrollment.CSR))
	if block == nil {
		t.Fatal("missing public CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != enrollment.ID || !csr.PublicKey.(ed25519.PublicKey).Equal(ed25519.PublicKey(enrollment.PublicKey)) {
		t.Fatal("CSR not bound to persistent identity")
	}
	again, err := Enroll(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.ID != again.ID {
		t.Fatal("enrollment changed identity")
	}
}
