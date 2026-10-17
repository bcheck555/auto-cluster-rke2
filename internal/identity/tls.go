package identity

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"io"
	"time"
)

// CryptoSigner adapts a persistent identity to TLS without exporting its key.
// Provision a client certificate for Public() through the operator's CA.
// Only plain Ed25519 is supported; prehashed and contextual variants are denied.
type CryptoSigner struct {
	store  Signer
	public ed25519.PublicKey
}

func NewCryptoSigner(ctx context.Context, store Signer) (*CryptoSigner, error) {
	if store == nil {
		return nil, errors.New("identity signer required")
	}
	id, err := store.LoadOrCreate(ctx)
	if err != nil {
		return nil, err
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrCorrupt
	}
	return &CryptoSigner{store: store, public: append(ed25519.PublicKey(nil), id.PublicKey...)}, nil
}

func (s *CryptoSigner) Public() crypto.PublicKey { return append(ed25519.PublicKey(nil), s.public...) }

func (s *CryptoSigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("unsupported identity signature options")
	}
	if options, ok := opts.(*ed25519.Options); ok && options.Context != "" {
		return nil, errors.New("unsupported identity signature context")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sig, err := s.store.Sign(ctx, message)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(s.public, message, sig) {
		return nil, ErrCorrupt
	}
	return sig, nil
}
