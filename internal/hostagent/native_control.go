package hostagent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const nativeBundles = "/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io"
const nativeRuncRoot = "/run/containerd/runc/k8s.io"
const nativeRunc = "/var/lib/rancher/rke2/bin/runc"

type nativeControlContainer struct{ ID, Bundle string }

func hexLength(value string, length int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == length && len(decoded)*2 == length
}

func (r *LinuxRuntime) nativeNodeName() (string, error) {
	if data, err := ReadFile(r.path(configPath), true, 64<<10); err == nil {
		var value struct {
			Name string `json:"node-name"`
		}
		if json.Unmarshal(data, &value) != nil || !nodePattern.MatchString(value.Name) {
			return "", ErrReconcile
		}
		return value.Name, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// A crash can follow quarantine of the config and precede the new local
	// generation journal. The already-synced transition retains its exact name.
	data, err := ReadFile(r.path("/var/lib/autonomous-rke2/role-transition.json"), true, 64<<10)
	var intent struct{ Previous struct{ NodeName string } }
	if err != nil || json.Unmarshal(data, &intent) != nil || !nodePattern.MatchString(intent.Previous.NodeName) {
		return "", ErrReconcile
	}
	return intent.Previous.NodeName, nil
}

func (r *LinuxRuntime) nativeControlContainers(includeEtcd bool) ([]nativeControlContainer, error) {
	entries, err := os.ReadDir(r.path(nativeBundles))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result []nativeControlContainer
	name := ""
	for _, entry := range entries {
		if !entry.IsDir() || !hexLength(entry.Name(), 64) {
			continue
		}
		bundle := filepath.Join(nativeBundles, entry.Name())
		data, err := ReadFile(r.path(filepath.Join(bundle, "config.json")), false, 1<<20)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var spec struct {
			Annotations map[string]string
			Process     struct{ Args []string }
		}
		if json.Unmarshal(data, &spec) != nil {
			return nil, ErrReconcile
		}
		a := spec.Annotations
		component := a["io.kubernetes.cri.container-name"]
		owned := component == "kube-apiserver" || component == "kube-controller-manager" || component == "kube-scheduler" || component == "cloud-controller-manager" || (includeEtcd && component == "etcd")
		if !owned || a["io.kubernetes.cri.container-type"] != "container" || a["io.kubernetes.cri.sandbox-namespace"] != "kube-system" {
			continue
		}
		if name == "" {
			name, err = r.nativeNodeName()
			if err != nil {
				return nil, err
			}
		}
		if a["io.kubernetes.cri.sandbox-name"] != component+"-"+name {
			continue
		}
		// Static-pod UIDs are hashes, unlike API-created application Pod UIDs.
		// Namespace/name alone never authorize terminating an application.
		if !hexLength(a["io.kubernetes.cri.sandbox-uid"], 32) || len(spec.Process.Args) == 0 || filepath.Base(spec.Process.Args[0]) != component {
			return nil, ErrReconcile
		}
		result = append(result, nativeControlContainer{entry.Name(), bundle})
	}
	return result, nil
}

func (r *LinuxRuntime) nativeControlRunning(ctx context.Context, c nativeControlContainer) (bool, error) {
	data, err := r.command(ctx, nativeRunc, "--root", nativeRuncRoot, "state", c.ID)
	if err != nil {
		if _, statErr := os.Lstat(r.path(filepath.Join(nativeRuncRoot, c.ID))); errors.Is(statErr, os.ErrNotExist) {
			return false, nil
		}
		return false, ErrWaiting
	}
	var state struct {
		ID, Status, Bundle string
		PID                int
	}
	if json.Unmarshal(data, &state) != nil || state.ID != c.ID || state.Bundle != c.Bundle {
		return false, ErrReconcile
	}
	if state.Status == "stopped" {
		return false, nil
	}
	if state.PID <= 1 || (state.Status != "running" && state.Status != "paused" && state.Status != "created") {
		return false, ErrReconcile
	}
	return true, nil
}

// RKE2 deliberately leaves container shims alive when its service stops. Stop
// only identity-checked native control containers through their OCI runtime;
// containerd need not be running. Never kill all shims or application pods.
// Recovery keeps existing etcd voters; a committed role retirement stops them.
func (r *LinuxRuntime) stopNativeControl(ctx context.Context, includeEtcd bool) error {
	containers, err := r.nativeControlContainers(includeEtcd)
	if err != nil || len(containers) == 0 {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	signal := func(c nativeControlContainer, value string) error {
		running, err := r.nativeControlRunning(ctx, c)
		if err != nil || !running {
			return err
		}
		if _, err := r.command(ctx, nativeRunc, "--root", nativeRuncRoot, "kill", c.ID, value); err != nil {
			if alive, stateErr := r.nativeControlRunning(ctx, c); stateErr != nil || alive {
				return ErrWaiting
			}
		}
		return nil
	}
	for _, c := range containers {
		if err := signal(c, "TERM"); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	killed := false
	for {
		alive := false
		for _, c := range containers {
			running, err := r.nativeControlRunning(ctx, c)
			if err != nil {
				return err
			}
			alive = alive || running
		}
		if !alive {
			// Catch an unexpected native restart rather than authorizing the new
			// role while an obsolete control container remains alive.
			current, err := r.nativeControlContainers(includeEtcd)
			if err != nil {
				return err
			}
			for _, c := range current {
				if running, err := r.nativeControlRunning(ctx, c); err != nil {
					return err
				} else if running {
					return ErrWaiting
				}
			}
			return nil
		}
		if !killed && time.Now().After(deadline) {
			for _, c := range containers {
				if err := signal(c, "KILL"); err != nil {
					return err
				}
			}
			killed = true
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
