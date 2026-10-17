package state

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileJournalRevisionGuard(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j := NewFileJournal(dir)
	ctx := context.Background()
	op := Operation{ID: "install-1", ClusterID: "cluster-1", HostID: "host-1", Kind: "install", Phase: "authorized", Revision: 1, UpdatedAt: time.Now().UTC()}
	if err := j.CompareAndSwap(ctx, 0, op); err != nil {
		t.Fatal(err)
	}
	if err := j.CompareAndSwap(ctx, 0, op); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale create: %v", err)
	}
	got, err := NewFileJournal(dir).Get(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != op {
		t.Fatalf("restart: %#v", got)
	}
	op.Revision++
	op.Phase = "configured"
	if err := j.CompareAndSwap(ctx, 1, op); err != nil {
		t.Fatal(err)
	}
}

func testOperation() Operation {
	return Operation{ID: "../install-1", ClusterID: "cluster-1", HostID: "host-1", Kind: "install", Phase: "authorized", Revision: 1, UpdatedAt: time.Unix(10, 0).UTC()}
}

func TestConcurrentJournalProcesses(t *testing.T) {
	if dir := os.Getenv("AUTO_CLUSTER_JOURNAL_CHILD"); dir != "" {
		op := testOperation()
		op.Revision = 2
		op.Phase = "configured"
		err := NewFileJournal(dir).CompareAndSwap(context.Background(), 1, op)
		switch {
		case err == nil:
			fmt.Println("updated")
		case errors.Is(err, ErrConflict):
			fmt.Println("conflict")
		default:
			t.Fatal(err)
		}
		os.Exit(0)
	}
	dir := filepath.Join(t.TempDir(), "journal")
	ctx := context.Background()
	if err := NewFileJournal(dir).CompareAndSwap(ctx, 0, testOperation()); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestConcurrentJournalProcesses$")
			cmd.Env = append(os.Environ(), "AUTO_CLUSTER_JOURNAL_CHILD="+dir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("journal process: %v: %s", err, out)
				return
			}
			results <- strings.TrimSpace(string(out))
		}()
	}
	wg.Wait()
	close(results)
	winners, conflicts := 0, 0
	for result := range results {
		switch result {
		case "updated":
			winners++
		case "conflict":
			conflicts++
		default:
			t.Errorf("unexpected process result: %s", result)
		}
	}
	if winners != 1 || conflicts != 7 {
		t.Fatalf("winners=%d conflicts=%d", winners, conflicts)
	}
	got, err := NewFileJournal(dir).Get(ctx, testOperation().ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 2 || got.Phase != "configured" {
		t.Fatal("committed revision lost")
	}
}

func TestJournalValidationAndCorruption(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	ctx := context.Background()
	j := NewFileJournal(dir)
	if _, err := j.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	op := testOperation()
	if err := j.CompareAndSwap(ctx, 0, op); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"cluster", "host", "kind", "timestamp", "empty-phase", "skip", "overflow"} {
		t.Run(kind, func(t *testing.T) {
			next := op
			next.Revision = 2
			expected := uint64(1)
			switch kind {
			case "cluster":
				next.ClusterID = "another"
			case "host":
				next.HostID = "another"
			case "kind":
				next.Kind = "another"
			case "timestamp":
				next.UpdatedAt = op.UpdatedAt.Add(-time.Second)
			case "empty-phase":
				next.Phase = ""
			case "skip":
				next.Revision = 3
			case "overflow":
				expected = math.MaxUint64
				next.Revision = 0
			}
			if err := j.CompareAndSwap(ctx, expected, next); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid update: %v", err)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(dir, operationFile(op.ID)), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Get(ctx, op.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt read: %v", err)
	}
	op.Revision = 2
	if err := j.CompareAndSwap(ctx, 1, op); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt update: %v", err)
	}
	if err := j.CompareAndSwap(ctx, 0, testOperation()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt create: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := j.Get(cancelled, op.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}
