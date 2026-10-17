package hostagent

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ReadFile accepts only owner-controlled regular files under trusted ancestors.
// It never includes path or contents in returned errors. Private files must
// have no group/other permissions. Callers must provision trusted parent paths.
func ReadFile(path string, private bool, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, os.ErrNotExist
			}
			return nil, ErrWaiting
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		sticky := ok && st.Uid == 0 && info.Mode()&os.ModeSticky != 0
		if !ok || !info.IsDir() || (info.Mode().Perm()&0022 != 0 && !sticky) || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
			return nil, ErrReconcile
		}
		if parent == "/" {
			break
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, ErrReconcile
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, ErrReconcile
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm()&0077 != 0) {
		return nil, ErrReconcile
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrInvalid
	}
	return data, nil
}

func ensureDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return ErrInvalid
	}
	if path == "/" {
		return nil
	}
	if err := ensureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrReconcile
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ErrReconcile
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	sticky := ok && st.Uid == 0 && info.Mode()&os.ModeSticky != 0
	if !ok || !info.IsDir() || (info.Mode().Perm()&0022 != 0 && !sticky) || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		return ErrReconcile
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrReconcile
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return ErrReconcile
	}
	return nil
}

func writePrivate(path string, data []byte) error {
	if err := ensureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := ReadFile(path, false, 1<<20); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".autonomous-pending-")
	if err != nil {
		return ErrReconcile
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return ErrReconcile
	}
	if _, err := f.Write(data); err != nil {
		return ErrReconcile
	}
	if err := f.Sync(); err != nil {
		return ErrReconcile
	}
	if err := f.Close(); err != nil {
		return ErrReconcile
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return ErrReconcile
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrReconcile
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return ErrReconcile
	}
	return nil
}

func baselineConfig(data []byte) bool {
	s := strings.TrimSpace(string(data))
	return s == "selinux: true" || s == "selinux: true\ncni: flannel"
}
