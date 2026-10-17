package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"autonomous-rke2/internal/durable"
)

func TestFileStoreSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	first, err := NewFileStore(dir).LoadOrCreate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	again, err := NewFileStore(dir).LoadOrCreate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, again) {
		t.Fatal("identity changed across restart")
	}
}

func TestConcurrentIdentityProcesses(t *testing.T) {
	if dir := os.Getenv("AUTO_CLUSTER_IDENTITY_CHILD"); dir != "" {
		id, err := NewFileStore(dir).LoadOrCreate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(id.ID)
		os.Exit(0)
	}
	dir := filepath.Join(t.TempDir(), "identity")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestConcurrentIdentityProcesses$")
			cmd.Env = append(os.Environ(), "AUTO_CLUSTER_IDENTITY_CHILD="+dir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("identity process: %v: %s", err, out)
				return
			}
			ids <- strings.TrimSpace(string(out))
		}()
	}
	wg.Wait()
	close(ids)
	id, err := NewFileStore(dir).LoadOrCreate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for got := range ids {
		count++
		if got != id.ID {
			t.Fatal("competing host identities")
		}
	}
	if count != 8 || len(id.PublicKey) != ed25519.PublicKeySize || len(id.ID) != 64 {
		t.Fatal("incomplete identity creation")
	}
	for _, name := range []string{"identity.json", ".lock"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %s", name, info.Mode())
		}
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatal("directory not private")
	}
	data, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PrivateKey") {
		t.Fatal("private key exposed")
	}
}

func TestIdentityCorruptionNeverRegenerates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	ctx := context.Background()
	if _, err := NewFileStore(dir).LoadOrCreate(ctx); err != nil {
		t.Fatal(err)
	}
	// Valid envelope with inconsistent key material must fail semantic validation.
	if err := durable.WithLock(ctx, dir, func(d *durable.Directory) error {
		var record identityRecord
		if err := d.Read("identity.json", &record); err != nil {
			return err
		}
		record.PrivateKey[0] ^= 1
		return d.Write(ctx, "identity.json", record)
	}); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []bool{false, true} {
		if raw {
			if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte("partial secret"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		before, err := os.ReadFile(filepath.Join(dir, "identity.json"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileStore(dir).LoadOrCreate(ctx); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corruption: %v", err)
		}
		after, err := os.ReadFile(filepath.Join(dir, "identity.json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("corrupt identity overwritten")
		}
	}
}
