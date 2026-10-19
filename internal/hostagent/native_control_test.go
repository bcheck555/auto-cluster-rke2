package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const controlTestNode = "rke2-aaaaaaaaaaaaaaaa"

func controlBundle(t *testing.T, r *LinuxRuntime, id, component, namespace, node, uid string) {
	t.Helper()
	value := map[string]any{"annotations": map[string]string{
		"io.kubernetes.cri.container-name":    component,
		"io.kubernetes.cri.container-type":    "container",
		"io.kubernetes.cri.sandbox-namespace": namespace,
		"io.kubernetes.cri.sandbox-name":      component + "-" + node,
		"io.kubernetes.cri.sandbox-uid":       uid,
	}, "process": map[string]any{"args": []string{"/usr/local/bin/" + component}}}
	data, _ := json.Marshal(value)
	roleFile(t, r, filepath.Join(nativeBundles, id, "config.json"), string(data))
	roleFile(t, r, filepath.Join(nativeRuncRoot, id, "state.json"), "state")
}

func TestNativeControlCleanupPreservesVotersAndApplications(t *testing.T) {
	for _, retire := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovery", true: "retirement"}[retire], func(t *testing.T) {
			r, _, _ := linuxFixture(t)
			roleFile(t, r, configPath, `{"node-name":"`+controlTestNode+`"}`)
			api, etcd, app, network := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
			for _, item := range []struct{ id, name, namespace, node, uid string }{
				{api, "kube-apiserver", "kube-system", controlTestNode, strings.Repeat("a", 32)},
				{etcd, "etcd", "kube-system", controlTestNode, strings.Repeat("b", 32)},
				{app, "kube-apiserver", "application", controlTestNode, "application-uid"},
				{network, "kube-flannel", "kube-system", controlTestNode, "network-uid"},
			} {
				controlBundle(t, r, item.id, item.name, item.namespace, item.node, item.uid)
			}
			roleFile(t, r, "/var/lib/rancher/rke2/storage/application/data", "retained")
			roleFile(t, r, "/var/lib/rancher/rke2/server/db/etcd/member/snap/db", "voter-data")
			roleFile(t, r, "/var/lib/rancher/rke2/server/db/etcd/member/wal/000.wal", "voter-wal")
			running := map[string]bool{api: true, etcd: true, app: true, network: true}
			kills := map[string]int{}
			r.command = func(_ context.Context, p string, args ...string) ([]byte, error) {
				if p == "/usr/bin/systemctl" {
					return nil, nil
				}
				if p != nativeRunc || len(args) < 4 || args[0] != "--root" || args[1] != nativeRuncRoot {
					t.Fatal("unexpected native cleanup command", p, args)
				}
				id := args[3]
				if args[2] == "state" {
					status := "stopped"
					if running[id] {
						status = "running"
					}
					return json.Marshal(map[string]any{"id": id, "pid": 42, "bundle": filepath.Join(nativeBundles, id), "status": status})
				}
				if args[2] != "kill" || len(args) != 5 || args[4] != "TERM" {
					t.Fatal("unexpected container signal", args)
				}
				kills[id]++
				running[id] = false
				return nil, nil
			}
			var err error
			if retire {
				err = r.StopRole(context.Background())
			} else {
				err = r.RestrictControl(context.Background())
			}
			if err != nil {
				t.Fatal(err)
			}
			if running[api] || (running[etcd] == retire) || !running[app] || !running[network] {
				t.Fatal("wrong containers stopped", running)
			}
			if kills[api] != 1 || kills[app] != 0 || kills[network] != 0 {
				t.Fatal("application or duplicate termination", kills)
			}
			if err := r.stopNativeControl(context.Background(), retire); err != nil || kills[api] != 1 {
				t.Fatal("retry duplicated termination", err, kills)
			}
			if data, err := os.ReadFile(r.path("/var/lib/rancher/rke2/storage/application/data")); err != nil || string(data) != "retained" {
				t.Fatal("application storage changed", err)
			}
		})
	}
}

func TestNativeControlCleanupRejectsUnprovenIdentity(t *testing.T) {
	for _, scenario := range []struct{ name, uid, bundle string }{
		{"API-created pod", "11111111-2222-4333-8444-555555555555", ""},
		{"runtime bundle mismatch", strings.Repeat("a", 32), "/another/bundle"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			r, _, _ := linuxFixture(t)
			roleFile(t, r, configPath, `{"node-name":"`+controlTestNode+`"}`)
			id := strings.Repeat("a", 64)
			controlBundle(t, r, id, "kube-apiserver", "kube-system", controlTestNode, scenario.uid)
			kills := 0
			r.command = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[2] == "kill" {
					kills++
				}
				return json.Marshal(map[string]any{"id": id, "pid": 42, "bundle": scenario.bundle, "status": "running"})
			}
			if err := r.stopNativeControl(context.Background(), true); err != ErrReconcile || kills != 0 {
				t.Fatal("unproven container terminated", err, kills)
			}
		})
	}
}

func TestNativeControlCleanupResumesAfterSignalFailureAndConfigQuarantine(t *testing.T) {
	r, _, _ := linuxFixture(t)
	if err := os.Remove(r.path(configPath)); err != nil {
		t.Fatal(err)
	}
	roleFile(t, r, "/var/lib/autonomous-rke2/role-transition.json", `{"Previous":{"NodeName":"`+controlTestNode+`"}}`)
	id := strings.Repeat("a", 64)
	controlBundle(t, r, id, "kube-apiserver", "kube-system", controlTestNode, strings.Repeat("a", 32))
	alive, fail := true, true
	kills := 0
	r.command = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[2] == "state" {
			status := "stopped"
			if alive {
				status = "running"
			}
			return json.Marshal(map[string]any{"id": id, "pid": 42, "bundle": filepath.Join(nativeBundles, id), "status": status})
		}
		kills++
		if fail {
			return nil, errors.New("injected runtime failure")
		}
		alive = false
		return nil, nil
	}
	if err := r.stopNativeControl(context.Background(), true); err != ErrWaiting || !alive {
		t.Fatal("failed stop advanced", err)
	}
	fail = false
	if err := r.stopNativeControl(context.Background(), true); err != nil || alive || kills != 2 {
		t.Fatal("stop did not resume exact container", err, kills)
	}
}
