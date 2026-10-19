package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const recoveryConfig = "/etc/rancher/rke2/config.yaml.d/99-autonomous-recovery.yaml"

var ErrRoleDataMissing = errors.New("initialized datastore unavailable; refusing bootstrap and awaiting role authorization")

func (r *LinuxRuntime) ControlDataIntact() bool { return r.requiredData("server") }

func (r *LinuxRuntime) StopRole(ctx context.Context) error {
	for _, role := range []string{"agent", "server"} {
		if _, err := r.system(ctx, "stop", role); err != nil {
			return err
		}
		if _, err := r.system(ctx, "mask", role); err != nil {
			return err
		}
	}
	return r.stopNativeControl(ctx, true)
}

// RestrictControl preserves the existing datastore and starts only a local
// recovery API. Existing voters can restore quorum without exposing a stale
// API, scheduler, supervisor, or controller to the network.
func (r *LinuxRuntime) RestrictControl(ctx context.Context) error {
	if !r.requiredData("server") {
		if _, err := r.system(ctx, "stop", "server"); err != nil {
			return err
		}
		if _, err := r.system(ctx, "mask", "server"); err != nil {
			return err
		}
		if err := r.stopNativeControl(ctx, false); err != nil {
			return err
		}
		return ErrRoleDataMissing
	}
	if err := EnsureDirectory(r.path(filepath.Dir(recoveryConfig))); err != nil {
		return err
	}
	value := map[string]any{"bind-address": "127.0.0.1", "disable-controller-manager": true, "disable-scheduler": true, "disable-cloud-controller": true, "kube-apiserver-arg": []string{"bind-address=127.0.0.1"}, "kubelet-arg": []string{"register-node=false"}}
	data, _ := json.Marshal(value)
	if old, err := ReadFile(r.path(recoveryConfig), true, 16384); err == nil && string(old) == string(data) {
		if _, err := r.system(ctx, "unmask", "server"); err != nil {
			return err
		}
		_, err := r.command(ctx, "/usr/bin/systemctl", "start", "--no-block", "rke2-server.service")
		return err
	}
	// Stop first so a failed config write cannot leave unrestricted services up.
	if _, err := r.command(ctx, "/usr/bin/systemctl", "stop", "rke2-server.service"); err != nil {
		return err
	}
	if err := r.stopNativeControl(ctx, false); err != nil {
		return err
	}
	if err := writePrivate(r.path(recoveryConfig), data); err != nil {
		return err
	}
	if _, err := r.system(ctx, "unmask", "server"); err != nil {
		return err
	}
	_, err := r.command(ctx, "/usr/bin/systemctl", "start", "--no-block", "rke2-server.service")
	return err
}

func (r *LinuxRuntime) AuthorizeControl(ctx context.Context) error {
	if _, err := os.Lstat(r.path(recoveryConfig)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return ErrReconcile
	}
	if _, err := r.command(ctx, "/usr/bin/systemctl", "stop", "rke2-server.service"); err != nil {
		return err
	}
	if err := r.stopNativeControl(ctx, false); err != nil {
		return err
	}
	if err := os.Remove(r.path(recoveryConfig)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, err := r.command(ctx, "/usr/bin/systemctl", "start", "--no-block", "rke2-server.service")
	return err
}

// QuarantineRole is idempotent and only moves known native role/credential
// paths. It never removes containerd state, application volumes, or image data.
// The caller must first persist and verify a quorum-authorized generation.
func (r *LinuxRuntime) QuarantineRole(ctx context.Context, generation uint64) error {
	if generation == 0 {
		return ErrInvalid
	}
	if err := r.StopRole(ctx); err != nil {
		return err
	}
	paths := []string{configPath, "/var/lib/rancher/rke2/server", "/var/lib/rancher/rke2/agent/pod-manifests", "/etc/rancher/node/password"}
	agent := "/var/lib/rancher/rke2/agent"
	entries, err := os.ReadDir(r.path(agent))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".crt") || strings.HasSuffix(entry.Name(), ".key") || strings.HasSuffix(entry.Name(), ".kubeconfig")) {
			paths = append(paths, filepath.Join(agent, entry.Name()))
		}
	}
	for _, path := range paths {
		source := r.path(path)
		info, err := os.Lstat(source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrReconcile
		}
		// Stay on the source mount: systemd ReadWritePaths uses separate bind
		// mounts, so moving into the agent's state directory can fail EXDEV.
		archive := filepath.Join(filepath.Dir(source), fmt.Sprintf(".autonomous-role-history/generation-%d", generation))
		if err := EnsureDirectory(archive); err != nil {
			return fmt.Errorf("quarantine directory %s: %w", archive, err)
		}
		dest := filepath.Join(archive, filepath.Base(source))
		if _, err := os.Lstat(dest); err == nil {
			return ErrReconcile
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(source, dest); err != nil {
			return err
		}
		for _, directory := range []string{filepath.Dir(source), archive} {
			f, err := os.Open(directory)
			if err != nil {
				return err
			}
			err = f.Sync()
			_ = f.Close()
			if err != nil {
				return err
			}
		}
	}
	if err := os.Remove(r.path(recoveryConfig)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
