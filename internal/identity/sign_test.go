package identity

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistentSigningAndTLSAdapter(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "identity")
	store := NewFileStore(dir)
	if _, err := store.Sign(ctx, []byte("before initialization")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sign generated identity: %v", err)
	}
	id, err := store.LoadOrCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("host proof")
	sig, err := NewFileStore(dir).Sign(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(id.PublicKey, data, sig) {
		t.Fatal("signature mismatch")
	}
	tlsSigner, err := NewCryptoSigner(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	sig, err = tlsSigner.Sign(nil, data, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(tlsSigner.Public().(ed25519.PublicKey), data, sig) {
		t.Fatal("TLS signature mismatch")
	}
	for _, opts := range []crypto.SignerOpts{nil, crypto.SHA256, &ed25519.Options{Context: "unexpected"}} {
		if _, err := tlsSigner.Sign(nil, data, opts); err == nil {
			t.Fatal("unsupported signature options accepted")
		}
	}
	if err := os.Remove(filepath.Join(dir, "identity.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsSigner.Sign(nil, data, crypto.Hash(0)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing signing key regenerated: %v", err)
	}
}
