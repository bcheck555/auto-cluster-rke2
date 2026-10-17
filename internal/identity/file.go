package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"autonomous-rke2/internal/durable"
)

var (
	ErrCorrupt = durable.ErrCorrupt
	ErrUnsafe  = durable.ErrUnsafe
)

// FileStore holds one Ed25519 host identity in a private local directory.
// Its parent must already exist and have trusted ancestors. Never copy an
// initialized store into a VM image: every host needs its own private key.
type FileStore struct{ directory string }

func NewFileStore(directory string) *FileStore { return &FileStore{directory: directory} }

var _ Store = (*FileStore)(nil)

type identityRecord struct {
	Identity   HostIdentity
	PrivateKey []byte
}

func keyID(public []byte) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:])
}

func (s *FileStore) LoadOrCreate(ctx context.Context) (HostIdentity, error) {
	var result HostIdentity
	err := durable.WithLock(ctx, s.directory, func(d *durable.Directory) error {
		var record identityRecord
		err := d.Read("identity.json", &record)
		if errors.Is(err, os.ErrNotExist) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			record = identityRecord{Identity: HostIdentity{ID: keyID(public), PublicKey: public, CreatedAt: time.Now().UTC()}, PrivateKey: private}
			if err := d.Write(ctx, "identity.json", record); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if len(record.PrivateKey) != ed25519.PrivateKeySize || len(record.Identity.PublicKey) != ed25519.PublicKeySize || record.Identity.CreatedAt.IsZero() {
			return ErrCorrupt
		}
		derived := ed25519.NewKeyFromSeed(record.PrivateKey[:ed25519.SeedSize])
		if !ed25519.PrivateKey(record.PrivateKey).Equal(derived) ||
			!ed25519.PublicKey(record.Identity.PublicKey).Equal(derived.Public()) || record.Identity.ID != keyID(record.Identity.PublicKey) {
			return ErrCorrupt
		}
		result = record.Identity
		return nil
	})
	return result, err
}
