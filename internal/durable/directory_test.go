package durable

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestProcessExitDuringWrite(t *testing.T) {
	if dir := os.Getenv("AUTO_CLUSTER_CRASH_DIRECTORY"); dir != "" {
		err := WithLock(context.Background(), dir, func(d *Directory) error {
			if os.Getenv("AUTO_CLUSTER_CRASH_STAGE") == "after" {
				if err := d.Write(context.Background(), "record.json", "new"); err != nil {
					return err
				}
			} else {
				f, err := d.root.OpenFile(".pending-crashed", os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
				if err != nil {
					return err
				}
				if _, err = f.Write([]byte("incomplete secret")); err != nil {
					return err
				}
				if err = f.Sync(); err != nil {
					return err
				}
			}
			// No deferred close/unlock/cleanup: model abrupt process death.
			os.Exit(23)
			return nil
		})
		t.Fatal(err)
	}
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")
			ctx := context.Background()
			if err := WithLock(ctx, dir, func(d *Directory) error { return d.Write(ctx, "record.json", "old") }); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			childCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(childCtx, executable, "-test.run=^TestProcessExitDuringWrite$")
			cmd.Env = append(os.Environ(), "AUTO_CLUSTER_CRASH_DIRECTORY="+dir, "AUTO_CLUSTER_CRASH_STAGE="+stage)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatalf("crash helper: %v: %s", err, out)
			}
			readCtx, stop := context.WithTimeout(ctx, time.Second)
			defer stop()
			if err := WithLock(readCtx, dir, func(d *Directory) error {
				var got string
				if err := d.Read("record.json", &got); err != nil {
					return err
				}
				want := "old"
				if stage == "after" {
					want = "new"
				}
				if got != want {
					t.Fatalf("want %s, got %s", want, got)
				}
				return d.Write(ctx, "record.json", "resumed")
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAtomicRecordAndInterruptedWrites(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := WithLock(ctx, dir, func(d *Directory) error { return d.Write(ctx, "record.json", "committed") }); err != nil {
		t.Fatal(err)
	}
	// Model a crash before rename: an incomplete temporary file must never
	// replace the last committed record, including after a fresh open.
	if err := os.WriteFile(filepath.Join(dir, ".pending-crashed"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WithLock(ctx, dir, func(d *Directory) error {
		var got string
		if err := d.Read("record.json", &got); err != nil {
			return err
		}
		if got != "committed" {
			t.Fatalf("read interrupted record: %s", got)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if err := d.Write(cancelled, "record.json", "cancelled"); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
		if err := d.Read("record.json", &got); err != nil {
			return err
		}
		if got != "committed" {
			t.Fatal("cancel changed record")
		}
		return d.Write(ctx, "record.json", "replacement")
	}); err != nil {
		t.Fatal(err)
	}
	// Model restart after rename: the complete replacement remains visible.
	if err := WithLock(ctx, dir, func(d *Directory) error {
		var got string
		if err := d.Read("record.json", &got); err != nil {
			return err
		}
		if got != "replacement" {
			t.Fatal("replacement lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectUnsafeStorage(t *testing.T) {
	for _, kind := range []string{"directory-mode", "directory-link", "file-mode", "file-link", "hardlink", "fifo", "lock-mode", "lock-link"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "store")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "record.json")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "directory-mode":
				must(os.Chmod(dir, 0755))
			case "directory-link":
				must(os.Symlink(dir, filepath.Join(parent, "link")))
				dir = filepath.Join(parent, "link")
			case "file-mode":
				must(os.WriteFile(file, []byte("secret"), 0644))
			case "file-link":
				must(os.Symlink(filepath.Join(parent, "missing"), file))
			case "hardlink":
				must(os.WriteFile(file, []byte("secret"), 0600))
				must(os.Link(file, filepath.Join(parent, "alias")))
			case "fifo":
				must(syscall.Mkfifo(file, 0600))
			case "lock-mode":
				must(os.WriteFile(filepath.Join(dir, ".lock"), nil, 0644))
			case "lock-link":
				must(os.Symlink(filepath.Join(parent, "missing"), filepath.Join(dir, ".lock")))
			}
			err := WithLock(context.Background(), dir, func(d *Directory) error { var v string; return d.Read("record.json", &v) })
			if err == nil || errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe storage accepted: %v", err)
			}
		})
	}
}

func TestCorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{`{`, `{"version":2,"sha256":"bad","payload":"secret"}`, `{"version":1,"sha256":"bad","payload":"secret"}`, `{}`} {
		if err := os.WriteFile(filepath.Join(dir, "record.json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		err := WithLock(ctx, dir, func(d *Directory) error { var v string; return d.Read("record.json", &v) })
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corruption: %v", err)
		}
		if err.Error() != "corrupt durable record" {
			t.Fatal("record contents leaked")
		}
	}
}

func TestLockWaitHonorsCancellation(t *testing.T) {
	dir := t.TempDir()
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	go func() {
		done <- WithLock(context.Background(), dir, func(*Directory) error { close(held); <-release; return nil })
	}()
	select {
	case <-held:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("lock setup timed out")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := WithLock(ctx, dir, func(*Directory) error { t.Error("entered held lock"); return nil })
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait: %v", err)
	}
}
