package hostagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"autonomous-rke2/internal/bootstrap"
)

const configPath = "/etc/rancher/rke2/config.yaml"
const manifests = "/var/lib/rancher/rke2/server/manifests/"
const images = "/var/lib/rancher/rke2/agent/images/"
const offlineCoreDNS = "/opt/autonomous-rke2/offline/coredns-config.yaml"

// LinuxRuntime operates only on the preinstalled, pinned offline image. It
// never invokes a package manager, downloads an installer, or deletes RKE2 data.
type LinuxRuntime struct {
	root    string
	command func(context.Context, string, ...string) ([]byte, error)
	Health  *HealthChecker
	network func(Plan) error
}

func NewLinuxRuntime(health *HealthChecker) *LinuxRuntime {
	return &LinuxRuntime{root: "/", command: runCommand, Health: health, network: checkNetwork}
}

func checkNetwork(p Plan) error {
	iface, err := net.InterfaceByName(p.Interface)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return ErrReconcile
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return ErrWaiting
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.Equal(net.ParseIP(p.NodeIP)) {
			return nil
		}
	}
	return ErrReconcile
}
func (r *LinuxRuntime) path(path string) string {
	return filepath.Join(r.root, strings.TrimPrefix(path, "/"))
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (64 << 10) - b.Len()
	if remaining > 0 {
		if remaining > n {
			remaining = n
		}
		_, _ = b.Buffer.Write(p[:remaining])
	}
	return n, nil
}

func runCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var out boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return out.Bytes(), ErrWaiting
	}
	return out.Bytes(), nil
}

func unit(role string) (string, error) {
	if role != bootstrap.RoleServer && role != bootstrap.RoleAgent {
		return "", ErrInvalid
	}
	return "rke2-" + role + ".service", nil
}

func (r *LinuxRuntime) system(ctx context.Context, action, role string) (string, error) {
	u, err := unit(role)
	if err != nil {
		return "", err
	}
	var args []string
	switch action {
	case "is-active", "is-enabled", "unmask":
		args = []string{action, u}
	case "start":
		args = []string{"start", "--no-block", u}
	default:
		return "", ErrInvalid
	}
	out, err := r.command(ctx, "/usr/bin/systemctl", args...)
	return strings.TrimSpace(string(out)), err
}

func (r *LinuxRuntime) tokenDigest(p Plan) (string, error) {
	primary, err := ReadFile(r.path(p.TokenFile), true, 4096)
	if err != nil {
		return "", ErrWaiting
	}
	token := strings.TrimSpace(string(primary))
	if len(token) < 32 || strings.ContainsAny(token, " \r\n\t") {
		return "", ErrInvalid
	}
	if p.Mode == "join" {
		if len(token) < 104 || !strings.HasPrefix(token, "K10") || !hashValid(token[3:67]) || token[67:69] != "::" {
			return "", ErrInvalid
		}
		prefix := "server:"
		if p.Role == bootstrap.RoleAgent {
			prefix = "agent:"
		}
		if !strings.HasPrefix(token[69:], prefix) || len(strings.TrimPrefix(token[69:], prefix)) < 32 {
			return "", ErrInvalid
		}
	}
	secrets := []string{token}
	if p.Role == bootstrap.RoleServer {
		worker, err := ReadFile(r.path(p.AgentTokenFile), true, 4096)
		if err != nil {
			return "", ErrWaiting
		}
		agent := strings.TrimSpace(string(worker))
		if len(agent) < 32 || strings.ContainsAny(agent, " \r\n\t") || agent == token {
			return "", ErrInvalid
		}
		secrets = append(secrets, agent)
	}
	return fingerprint(secrets), nil
}

func (r *LinuxRuntime) desired(p Plan, host string) (map[string][]byte, error) {
	config, err := p.RenderConfig(host)
	if err != nil {
		return nil, err
	}
	registry, _ := json.MarshalIndent(map[string]any{"mirrors": map[string]any{"*": map[string]any{"endpoint": []string{"https://127.0.0.1:1"}}}}, "", "  ")
	files := map[string][]byte{configPath: config, "/etc/rancher/rke2/registries.yaml": registry}
	if p.Role == bootstrap.RoleServer {
		core, err := ReadFile(r.path(offlineCoreDNS), false, 64<<10)
		if err != nil {
			return nil, ErrWaiting
		}
		sum := sha256.Sum256(core)
		if hex.EncodeToString(sum[:]) != p.CoreDNSSHA256 {
			return nil, ErrReconcile
		}
		files[manifests+"rke2-coredns-config.yaml"] = core
		chart := map[string]any{"apiVersion": "helm.cattle.io/v1", "kind": "HelmChartConfig", "metadata": map[string]string{"name": "rke2-flannel", "namespace": "kube-system"}, "spec": map[string]string{"valuesContent": "flannel:\n  backend: vxlan\n  args:\n    - --ip-masq\n    - --kube-subnet-mgr\n    - --iface=" + p.Interface + "\nnetpol:\n  enabled: false\n"}}
		files[manifests+"rke2-flannel-config.yaml"], _ = json.MarshalIndent(chart, "", "  ")
	}
	return files, nil
}

func (r *LinuxRuntime) Inspect(ctx context.Context, p Plan, host string) (Snapshot, error) {
	var snapshot Snapshot
	if p.Validate() != nil {
		return snapshot, ErrInvalid
	}
	if r.network != nil {
		if err := r.network(p); err != nil {
			return snapshot, err
		}
	}
	osRelease, err := ReadFile(r.path("/usr/lib/os-release"), false, 16384)
	if err != nil {
		return snapshot, ErrWaiting
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(osRelease), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(value, "\"'")
		}
	}
	if values["ID"] != "rocky" || values["VERSION_ID"] != "9.8" {
		return snapshot, ErrReconcile
	}
	out, err := r.command(ctx, "/usr/sbin/getenforce")
	if err != nil || strings.TrimSpace(string(out)) != "Enforcing" {
		return snapshot, ErrReconcile
	}
	for name, want := range map[string]string{"rke2-" + p.Role: RKE2RPM, "rke2-selinux": PolicyRPM} {
		out, err := r.command(ctx, "/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}.%{ARCH}", name)
		if err != nil || strings.TrimSpace(string(out)) != want {
			return snapshot, ErrReconcile
		}
	}
	if _, err := r.command(ctx, "/usr/bin/rpm", "-q", "firewalld"); err != nil {
		return snapshot, ErrReconcile
	}
	nm, err := ReadFile(r.path("/etc/NetworkManager/conf.d/rke2-flannel.conf"), false, 16384)
	if err != nil {
		return snapshot, ErrReconcile
	}
	for _, rule := range []string{"interface-name:flannel*", "interface-name:cni*", "interface-name:veth*"} {
		if !strings.Contains(string(nm), rule) {
			return snapshot, ErrReconcile
		}
	}
	out, err = r.command(ctx, "/usr/bin/rke2", "--version")
	if err != nil || !strings.HasPrefix(string(out), "rke2 version "+RKE2Version+" ") {
		return snapshot, ErrReconcile
	}
	for action, want := range map[string]string{"is-active": "inactive", "is-enabled": "disabled"} {
		out, _ := r.command(ctx, "/usr/bin/systemctl", action, "firewalld.service")
		if strings.TrimSpace(string(out)) != want {
			return snapshot, ErrReconcile
		}
	}
	other := bootstrap.RoleAgent
	if p.Role == bootstrap.RoleAgent {
		other = bootstrap.RoleServer
	}
	active, _ := r.system(ctx, "is-active", other)
	enabled, _ := r.system(ctx, "is-enabled", other)
	if active != "inactive" || enabled != "masked" {
		return snapshot, ErrReconcile
	}
	active, _ = r.system(ctx, "is-active", p.Role)
	enabled, _ = r.system(ctx, "is-enabled", p.Role)
	if enabled != "masked" && enabled != "disabled" {
		return snapshot, ErrReconcile
	}
	// A mask can conceal a pre-existing enablement symlink. Reject boot-time
	// starts outside the journaled agent before removing either unit's mask.
	for _, directory := range []string{"/etc/systemd/system", "/run/systemd/system"} {
		entries, err := os.ReadDir(r.path(directory))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return snapshot, ErrReconcile
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".wants") && !strings.HasSuffix(entry.Name(), ".requires") {
				continue
			}
			for _, role := range []string{bootstrap.RoleServer, bootstrap.RoleAgent} {
				name, _ := unit(role)
				if _, err := os.Lstat(r.path(directory + "/" + entry.Name() + "/" + name)); err == nil {
					return snapshot, ErrReconcile
				} else if !errors.Is(err, os.ErrNotExist) {
					return snapshot, ErrReconcile
				}
			}
		}
	}
	if active != "active" && active != "activating" && active != "inactive" && active != "failed" {
		return snapshot, ErrReconcile
	}
	snapshot.Running = active == "active" || active == "activating"
	for _, path := range []string{"/var/lib/rancher/rke2/server/db", "/var/lib/rancher/rke2/agent/client-kubelet.crt"} {
		if _, err := os.Lstat(r.path(path)); err == nil {
			snapshot.HasData = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return snapshot, ErrReconcile
		}
	}
	if entries, err := os.ReadDir(r.path(configPath + ".d")); err == nil && len(entries) > 0 {
		return snapshot, ErrReconcile
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return snapshot, ErrReconcile
	}
	for _, base := range []string{"/etc/default/rke2-", "/etc/sysconfig/rke2-"} {
		data, err := ReadFile(r.path(base+p.Role), false, 16384)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return snapshot, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && line != "RKE2_SELINUX=true" && line != "RKE2_SELINUX=\"true\"" {
				return snapshot, ErrReconcile
			}
		}
	}
	snapshot.CredentialDigest, err = r.tokenDigest(p)
	if err != nil {
		return snapshot, err
	}
	files, err := r.desired(p, host)
	if err != nil {
		return snapshot, err
	}
	snapshot.ConfigMatches = true
	for path, want := range files {
		have, err := ReadFile(r.path(path), false, 1<<20)
		if errors.Is(err, os.ErrNotExist) {
			snapshot.ConfigMatches = false
			continue
		}
		if err != nil {
			return snapshot, err
		}
		if !bytes.Equal(bytes.TrimSpace(have), bytes.TrimSpace(want)) {
			snapshot.ConfigMatches = false
		}
	}
	return snapshot, nil
}

func (r *LinuxRuntime) Prepare(ctx context.Context, p Plan, host string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for name, want := range map[string]string{"rke2-images-core.linux-amd64.tar.zst": p.CoreImageSHA256, "rke2-images-flannel.linux-amd64.tar.zst": p.FlannelImageSHA256} {
		// Payloads are large: stream hashes; never load archives into memory.
		path := r.path(images + name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
			return ErrReconcile
		}
		f, err := os.Open(path)
		if err != nil {
			return ErrWaiting
		}
		h := sha256.New()
		buffer := make([]byte, 1<<20)
		for {
			if err := ctx.Err(); err != nil {
				f.Close()
				return err
			}
			n, err := f.Read(buffer)
			if n > 0 {
				_, _ = h.Write(buffer[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return ErrWaiting
			}
		}
		f.Close()
		if hex.EncodeToString(h.Sum(nil)) != want {
			return ErrReconcile
		}
	}
	files, err := r.desired(p, host)
	if err != nil {
		return err
	}
	for path, want := range files {
		have, err := ReadFile(r.path(path), false, 1<<20)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && !bytes.Equal(bytes.TrimSpace(have), bytes.TrimSpace(want)) && !(path == configPath && baselineConfig(have)) {
			return ErrReconcile
		}
		if err := writePrivate(r.path(path), want); err != nil {
			return err
		}
	}
	return nil
}

func (r *LinuxRuntime) Start(ctx context.Context, role string) error {
	if _, err := r.system(ctx, "unmask", role); err != nil {
		return err
	}
	if enabled, _ := r.system(ctx, "is-enabled", role); enabled != "disabled" {
		return ErrReconcile
	}
	_, err := r.system(ctx, "start", role)
	return err
}

func (r *LinuxRuntime) Check(ctx context.Context, p Plan, host string, initialize bool) (Evidence, error) {
	if r.Health == nil {
		return Evidence{}, ErrWaiting
	}
	return r.Health.Check(ctx, p, host, initialize)
}
