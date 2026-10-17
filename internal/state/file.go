package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"strings"

	"autonomous-rke2/internal/durable"
)

var (
	ErrNotFound = errors.New("operation not found")
	ErrConflict = errors.New("operation revision conflict")
	ErrInvalid  = errors.New("invalid operation")
	ErrCorrupt  = durable.ErrCorrupt
	ErrUnsafe   = durable.ErrUnsafe
)

// FileJournal serializes updates across processes on a local Linux filesystem.
// The directory's parent must exist and have trusted ancestors. Revision zero
// means absent; creation requires revision one, updates expectedRevision+1.
type FileJournal struct{ directory string }

func NewFileJournal(directory string) *FileJournal { return &FileJournal{directory: directory} }

var _ Journal = (*FileJournal)(nil)

func operationFile(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "operation-" + hex.EncodeToString(sum[:]) + ".json"
}

func valid(op Operation) bool {
	for _, v := range []string{op.ID, op.ClusterID, op.HostID, op.Kind, op.Phase} {
		if strings.TrimSpace(v) == "" || len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
			return false
		}
	}
	return op.Revision > 0 && !op.UpdatedAt.IsZero()
}

func readOperation(d *durable.Directory, id string) (Operation, error) {
	var op Operation
	if err := d.Read(operationFile(id), &op); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return op, ErrNotFound
		}
		return Operation{}, err
	}
	if !valid(op) || op.ID != id {
		return Operation{}, ErrCorrupt
	}
	return op, nil
}

func (j *FileJournal) Get(ctx context.Context, id string) (Operation, error) {
	var op Operation
	if strings.TrimSpace(id) == "" || len(id) > 4096 {
		return op, ErrInvalid
	}
	err := durable.WithLock(ctx, j.directory, func(d *durable.Directory) error {
		var err error
		op, err = readOperation(d, id)
		return err
	})
	return op, err
}

func (j *FileJournal) CompareAndSwap(ctx context.Context, expected uint64, next Operation) error {
	if !valid(next) || expected == math.MaxUint64 || next.Revision != expected+1 {
		return ErrInvalid
	}
	return durable.WithLock(ctx, j.directory, func(d *durable.Directory) error {
		current, err := readOperation(d, next.ID)
		if errors.Is(err, ErrNotFound) {
			if expected != 0 {
				return ErrConflict
			}
		} else if err != nil {
			return err
		} else {
			if current.Revision != expected {
				return ErrConflict
			}
			if current.ClusterID != next.ClusterID || current.HostID != next.HostID || current.Kind != next.Kind || next.UpdatedAt.Before(current.UpdatedAt) {
				return ErrInvalid
			}
		}
		return d.Write(ctx, operationFile(next.ID), next)
	})
}
