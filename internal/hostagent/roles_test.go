package hostagent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func roleFile(t *testing.T, r *LinuxRuntime, path, content string) {
	t.Helper()
	p := r.path(path)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryRequiresIntactDatastoreAndRestartsAfterBoot(t *testing.T) {
	r, _, _ := linuxFixture(t)
	var calls []string
	r.command = func(_ context.Context, p string, args ...string) ([]byte, error) {
		calls = append(calls, p+" "+strings.Join(args, " "))
		return nil, nil
	}
	if err := r.RestrictControl(context.Background()); err != ErrRoleDataMissing {
		t.Fatal("missing initialized datastore restarted", err)
	}
	roleFile(t, r, "/var/lib/rancher/rke2/server/db/etcd/member/snap/db", "db")
	roleFile(t, r, "/var/lib/rancher/rke2/server/db/etcd/member/wal/000.wal", "wal")
	for i := 0; i < 2; i++ {
		if err := r.RestrictControl(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	starts := 0
	for _, call := range calls {
		if strings.Contains(call, "start --no-block") {
			starts++
		}
	}
	if starts != 2 {
		t.Fatal("persistent recovery config prevented post-reboot start", calls)
	}
	data, err := os.ReadFile(r.path(recoveryConfig))
	if err != nil || !strings.Contains(string(data), "127.0.0.1") || !strings.Contains(string(data), "disable-controller-manager") {
		t.Fatal("unrestricted recovery", string(data), err)
	}
	if err := r.AuthorizeControl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.path(recoveryConfig)); !os.IsNotExist(err) {
		t.Fatal("recovery config survived authorization", err)
	}
}

func TestRoleQuarantinePreservesWorkloadsAndResumes(t *testing.T) {
	r, _, _ := linuxFixture(t)
	r.command = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	files := map[string]string{"/var/lib/rancher/rke2/server/db/etcd/member/snap/db": "old-db", "/var/lib/rancher/rke2/agent/client-kubelet.crt": "old-cert", "/var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml": "old-static-pod", "/var/lib/rancher/rke2/agent/containerd/workload": "container-state", "/var/lib/rancher/rke2/storage/local-pv/data": "application-data", "/etc/rancher/node/password": "old-password"}
	for p, data := range files {
		roleFile(t, r, p, data)
	}
	if err := r.QuarantineRole(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := r.QuarantineRole(context.Background(), 1); err != nil {
		t.Fatal("interrupted transition retry", err)
	}
	for _, p := range []string{"/var/lib/rancher/rke2/agent/containerd/workload", "/var/lib/rancher/rke2/storage/local-pv/data"} {
		data, err := os.ReadFile(r.path(p))
		if err != nil || string(data) != files[p] {
			t.Fatal("workload modified", p, err)
		}
	}
	for _, p := range []string{"/etc/rancher/node/password", "/var/lib/rancher/rke2/agent/client-kubelet.crt"} {
		if _, err := os.Stat(r.path(p)); !os.IsNotExist(err) {
			t.Fatal("stale credential active", p, err)
		}
	}
	p := "/var/lib/rancher/rke2/.autonomous-role-history/generation-1/server/db/etcd/member/snap/db"
	if data, err := os.ReadFile(r.path(p)); err != nil || string(data) != "old-db" {
		t.Fatal("old state not retained", err)
	}
}
