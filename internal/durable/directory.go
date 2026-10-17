// Package durable implements private, atomic records on a local Linux filesystem.
// Callers must supply a path beneath trusted, non-writable-by-others ancestors.
package durable

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var (
	ErrCorrupt = errors.New("corrupt durable record")
	ErrUnsafe  = errors.New("unsafe storage permissions or file type")
)

const maxRecord = 1 << 20

// Directory is valid only within WithLock's callback.
type Directory struct{ root *os.Root }

func secure(info os.FileInfo, dir bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := os.FileMode(0600)
	if dir {
		mode = 0700
	}
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm() == mode &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		((dir && info.IsDir()) || (!dir && info.Mode().IsRegular() && stat.Nlink == 1))
}

// WithLock serializes readers and writers, including independent processes.
// Lock acquisition is cancellable. The lock file is never renamed or removed.
func WithLock(ctx context.Context, path string, fn func(*Directory) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("storage path must be absolute")
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !secure(info, true) {
		return fmt.Errorf("%w: directory mode %s, metadata %T", ErrUnsafe, info.Mode(), info.Sys())
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(info, opened) {
		return ErrUnsafe
	}
	// Persist a newly created directory's entry too. Every opener performs this
	// sync so a concurrent creator cannot return success ahead of it.
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return err
	}
	d := &Directory{root: root}
	lock, err := root.OpenFile(".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err = lock.Stat()
	if err != nil {
		return err
	}
	if !secure(info, false) {
		return ErrUnsafe
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := ctx.Err(); err != nil {
		return err
	}
	// Also settle any rename left visible by a prior failed directory sync.
	// A successful read of that record must have a durable directory entry.
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return err
	}
	return fn(d)
}

type envelope struct {
	Version int             `json:"version"`
	SHA256  string          `json:"sha256"`
	Payload json.RawMessage `json:"payload"`
}

// Decode rejects unknown fields and trailing input rather than accepting a
// partially understood record. Errors deliberately exclude record contents.
func Decode(data []byte, value any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return ErrCorrupt
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return ErrCorrupt
	}
	return nil
}

func (d *Directory) Read(name string, value any) error {
	f, err := d.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !secure(info, false) {
		return ErrUnsafe
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRecord+1))
	if err != nil {
		return err
	}
	if len(data) > maxRecord {
		return ErrCorrupt
	}
	var record envelope
	if err := Decode(data, &record); err != nil {
		return err
	}
	digest := sha256.Sum256(record.Payload)
	if record.Version != 1 || record.SHA256 != hex.EncodeToString(digest[:]) {
		return ErrCorrupt
	}
	return Decode(record.Payload, value)
}

// Write commits a complete record using file sync, atomic rename, then directory
// sync. A sync error may mean the new record is visible: callers must re-read.
// Orphan .pending-* files from interrupted writes are never treated as records.
func (d *Directory) Write(ctx context.Context, name string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	data, err := json.Marshal(envelope{Version: 1, SHA256: hex.EncodeToString(digest[:]), Payload: payload})
	if err != nil {
		return err
	}
	if len(data) > maxRecord {
		return fmt.Errorf("record exceeds size limit")
	}
	// Random temporary names also prevent collisions with abandoned writes.
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temp := ".pending-" + hex.EncodeToString(nonce[:])
	f, err := d.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer d.root.Remove(temp)
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.root.Rename(temp, name); err != nil {
		return err
	}
	dir, err := d.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
