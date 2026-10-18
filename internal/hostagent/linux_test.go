package hostagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bytesHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func linuxFixture(t *testing.T) (*LinuxRuntime, Plan, *[]string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	p := validPlan()
	core := []byte("offline core")
	flannel := []byte("offline flannel")
	dns := []byte("apiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\n")
	p.CoreImageSHA256 = bytesHash(core)
	p.FlannelImageSHA256 = bytesHash(flannel)
	p.CoreDNSSHA256 = bytesHash(dns)
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(root, strings.TrimPrefix(path, "/"))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("/usr/lib/os-release", []byte("ID=rocky\nVERSION_ID=\"9.8\"\n"), 0644)
	write(configPath, []byte("selinux: true\ncni: flannel\n"), 0600)
	write("/etc/NetworkManager/conf.d/rke2-flannel.conf", []byte("[keyfile]\nunmanaged-devices=interface-name:flannel*;interface-name:cni*;interface-name:veth*\n"), 0644)
	write("/etc/sysconfig/rke2-server", []byte("# Packaged RPM environment\nHOME=/root\n"), 0644)
	write(p.TokenFile, []byte(strings.Repeat("s", 48)), 0600)
	write(p.AgentTokenFile, []byte(strings.Repeat("a", 48)), 0600)
	write(images+"rke2-images-core.linux-amd64.tar.zst", core, 0644)
	write(images+"rke2-images-flannel.linux-amd64.tar.zst", flannel, 0644)
	write(offlineCoreDNS, dns, 0644)
	var calls []string
	started := false
	unmasked := false
	r := &LinuxRuntime{root: root, command: func(_ context.Context, path string, args ...string) ([]byte, error) {
		calls = append(calls, path+" "+strings.Join(args, " "))
		switch path {
		case "/usr/sbin/ip":
			return nil, nil
		case "/usr/sbin/getenforce":
			return []byte("Enforcing\n"), nil
		case "/usr/bin/rpm":
			if args[len(args)-1] == "rke2-selinux" {
				return []byte(PolicyRPM), nil
			}
			return []byte(RKE2RPM), nil
		case "/usr/bin/rke2":
			return []byte("rke2 version " + RKE2Version + " (build)\n"), nil
		case "/usr/bin/systemctl":
			switch args[0] {
			case "is-active":
				if args[1] == "rke2-server.service" && started {
					return []byte("active"), nil
				}
				return []byte("inactive"), errors.New("inactive")
			case "is-enabled":
				if args[1] == "firewalld.service" || (args[1] == "rke2-server.service" && (started || unmasked)) {
					return []byte("disabled"), errors.New("disabled")
				}
				return []byte("masked"), errors.New("masked")
			case "unmask":
				unmasked = true
				return nil, nil
			case "start":
				started = true
				return nil, nil
			}
		}
		return nil, errors.New("unexpected command")
	}}
	return r, p, &calls
}

func TestLinuxOfflinePreparationAndAllowlistedStart(t *testing.T) {
	r, p, calls := linuxFixture(t)
	ctx := context.Background()
	host := strings.Repeat("a", 64)
	snapshot, err := r.Inspect(ctx, p, host)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ConfigMatches || snapshot.HasData || snapshot.Running {
		t.Fatal("unexpected baseline")
	}
	if err := r.Prepare(ctx, p, host); err != nil {
		t.Fatal(err)
	}
	if err := r.Prepare(ctx, p, host); err != nil {
		t.Fatalf("interrupted preparation resumption: %v", err)
	}
	snapshot, err = r.Inspect(ctx, p, host)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.ConfigMatches {
		t.Fatal("configuration mismatch")
	}
	data, err := os.ReadFile(r.path(configPath))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), strings.Repeat("s", 48)) || strings.Contains(string(data), strings.Repeat("a", 48)) {
		t.Fatal("registration credentials written into config")
	}
	var config map[string]any
	if json.Unmarshal(data, &config) != nil {
		t.Fatal("invalid config")
	}
	if config["server"] != nil || config["selinux"] != true || config["node-taint"] != nil || config["cluster-reset"] != nil {
		t.Fatal("unsafe bootstrap configuration")
	}
	if err := r.Start(ctx, "server"); err != nil {
		t.Fatal(err)
	}
	before := len(*calls)
	if err := r.Start(ctx, "server; reboot"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if len(*calls) != before {
		t.Fatal("arbitrary service reached executor")
	}
	for _, call := range *calls {
		if strings.Contains(call, "enable ") || strings.Contains(call, "dnf") || strings.Contains(call, "sh ") || strings.Contains(call, strings.Repeat("s", 48)) {
			t.Fatal("unsafe command invocation")
		}
	}
	info, err := os.Stat(r.path(configPath))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("configuration permissions")
	}
}

func TestSealedEmptyRPMDirectoriesAreNotRuntimeState(t *testing.T) {
	r, _, _ := linuxFixture(t)
	path := r.path("/var/lib/rancher/rke2/server/db/snapshots")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	if found, err := r.Existing(context.Background()); err != nil || found {
		t.Fatal("empty RPM directories blocked bootstrap", found, err)
	}
	if err := os.WriteFile(filepath.Join(path, "snapshot"), []byte("state"), 0600); err != nil {
		t.Fatal(err)
	}
	if found, err := r.Existing(context.Background()); err != nil || !found {
		t.Fatal("runtime state not detected", found, err)
	}
}

func TestRuntimeEnvironmentRejectsUnapprovedOverrides(t *testing.T) {
	for _, override := range []string{"HOME=/tmp", "RKE2_CONFIG_FILE=/tmp/config.yaml", "RKE2_TOKEN=override"} {
		t.Run(strings.Split(override, "=")[0], func(t *testing.T) {
			r, p, _ := linuxFixture(t)
			if err := os.WriteFile(r.path("/etc/sysconfig/rke2-server"), []byte(override+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Inspect(context.Background(), p, strings.Repeat("a", 64)); !errors.Is(err, ErrReconcile) {
				t.Fatal("unapproved environment override accepted", err)
			}
		})
	}
}

func TestLinuxHealthWaitsForNativeNotifyReadiness(t *testing.T) {
	for _, active := range []string{"activating", "inactive", "failed"} {
		t.Run(active, func(t *testing.T) {
			r, p, _ := linuxFixture(t)
			r.command = func(_ context.Context, path string, args ...string) ([]byte, error) {
				if path != "/usr/bin/systemctl" || strings.Join(args, " ") != "is-active rke2-server.service" {
					t.Fatal("unexpected readiness command", path, args)
				}
				return []byte(active), nil
			}
			r.Health = &HealthChecker{client: func(TLSFiles) (*http.Client, error) {
				t.Fatal("stale Kubernetes readiness consulted before local runtime started")
				return nil, ErrWaiting
			}}
			if _, err := r.Check(context.Background(), p, strings.Repeat("a", 64), false); err != ErrWaiting {
				t.Fatal("unfinished native runtime accepted", err)
			}
		})
	}
}

func TestNativeSupervisorPortWithLocalHealthProxy(t *testing.T) {
	p := validPlan()
	p.Mode = "join"
	p.RegistrationURL = "https://192.0.2.11:9345"
	p.APIURL = "https://127.0.0.1:7443"
	data, err := p.RenderConfig(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config["server"] != p.RegistrationURL || config["tls-san"].([]any)[0] != "127.0.0.1" {
		t.Fatal("native registration or local API TLS origin changed")
	}
	p.RegistrationURL = "https://127.0.0.1:9344"
	if p.Validate() == nil {
		t.Fatal("translated supervisor port would poison RKE2's cached endpoints")
	}
}

func TestWorkerRegistrationUsesRKE2NodeUsername(t *testing.T) {
	r, p, _ := linuxFixture(t)
	p.Mode = "join"
	p.Role = "agent"
	p.AgentTokenFile = ""
	prefix := "K10" + strings.Repeat("a", 64) + "::"
	for _, username := range []string{"node:", "agent:", "server:"} {
		if err := os.WriteFile(r.path(p.TokenFile), []byte(prefix+username+strings.Repeat("s", 64)), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := r.tokenDigest(p)
		if (username == "node:") != (err == nil) {
			t.Fatalf("username %s: %v", username, err)
		}
	}
}

func TestNodeNetworkPreparationOwnsOnlyClusterServiceRoute(t *testing.T) {
	r, p, calls := linuxFixture(t)
	if err := r.EnsureNetwork(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	want := "/usr/sbin/ip route replace 10.43.0.0/16 dev " + p.Interface + " scope link metric 42760"
	if len(*calls) != 1 || (*calls)[0] != want {
		t.Fatal("unexpected route mutation", *calls)
	}
	p.Interface = "eth0; reboot"
	if err := r.EnsureNetwork(context.Background(), p); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid interface accepted", err)
	}
	if len(*calls) != 1 {
		t.Fatal("invalid input reached network command")
	}
}

func TestCompletedServerRequiresEtcdDatabaseAndWALNotJustCertificates(t *testing.T) {
	r, _, _ := linuxFixture(t)
	write := func(path string) {
		t.Helper()
		full := r.path(path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("state"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("/var/lib/rancher/rke2/server/tls/server-ca.crt")
	if data, err := r.hasData(); err != nil || !data {
		t.Fatal("leftovers not detected", data, err)
	}
	if r.requiredData("server") {
		t.Fatal("certificates counted as an intact datastore")
	}
	db := "/var/lib/rancher/rke2/server/db/etcd/member/snap/db"
	write(db)
	if r.requiredData("server") {
		t.Fatal("database without WAL accepted")
	}
	write("/var/lib/rancher/rke2/server/db/etcd/member/wal/0000000000000000-0000000000000000.wal")
	if !r.requiredData("server") {
		t.Fatal("intact datastore rejected")
	}
	if err := os.Remove(r.path(db)); err != nil {
		t.Fatal(err)
	}
	if r.requiredData("server") {
		t.Fatal("lost database allowed automatic restart")
	}
}

func TestLinuxRejectsCorruptionOverridesAndUnsafeCredentials(t *testing.T) {
	for _, kind := range []string{"archive-corrupt", "archive-symlink", "credential-mode", "config-override", "drop-in", "selinux-disabled", "wrong-version", "hidden-enablement"} {
		t.Run(kind, func(t *testing.T) {
			r, p, calls := linuxFixture(t)
			ctx := context.Background()
			host := strings.Repeat("a", 64)
			prepare := false
			switch kind {
			case "hidden-enablement":
				directory := r.path("/etc/systemd/system/multi-user.target.wants")
				if err := os.MkdirAll(directory, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/usr/lib/systemd/system/rke2-server.service", filepath.Join(directory, "rke2-server.service")); err != nil {
					t.Fatal(err)
				}
			case "archive-corrupt":
				if err := os.WriteFile(r.path(images+"rke2-images-core.linux-amd64.tar.zst"), []byte("wrong"), 0644); err != nil {
					t.Fatal(err)
				}
				prepare = true
			case "archive-symlink":
				path := r.path(images + "rke2-images-core.linux-amd64.tar.zst")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
				prepare = true
			case "credential-mode":
				if err := os.Chmod(r.path(p.TokenFile), 0644); err != nil {
					t.Fatal(err)
				}
			case "config-override":
				if err := os.WriteFile(r.path(configPath), []byte("cluster-reset: true"), 0600); err != nil {
					t.Fatal(err)
				}
				prepare = true
			case "drop-in":
				if err := os.MkdirAll(r.path(configPath+".d"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(r.path(configPath+".d/unmanaged.yaml"), []byte("token: secret"), 0600); err != nil {
					t.Fatal(err)
				}
			case "selinux-disabled", "wrong-version":
				previous := r.command
				r.command = func(ctx context.Context, path string, args ...string) ([]byte, error) {
					if kind == "selinux-disabled" && path == "/usr/sbin/getenforce" {
						return []byte("Permissive"), nil
					}
					if kind == "wrong-version" && path == "/usr/bin/rke2" {
						return []byte("rke2 version v0.0.0"), nil
					}
					return previous(ctx, path, args...)
				}
			}
			var err error
			if prepare {
				err = r.Prepare(ctx, p, host)
			} else {
				_, err = r.Inspect(ctx, p, host)
			}
			if err == nil {
				t.Fatal("unsafe prerequisite accepted")
			}
			for _, call := range *calls {
				if strings.Contains(call, "start --no-block") {
					t.Fatal("failed validation started RKE2")
				}
			}
		})
	}
}

func TestPlanJoinConfigurationAndInvalidInputs(t *testing.T) {
	p := validPlan()
	p.Mode = "join"
	p.Role = "agent"
	p.AgentTokenFile = ""
	data, err := p.RenderConfig(strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	_ = json.Unmarshal(data, &config)
	if config["server"] != p.RegistrationURL || config["cni"] != nil || config["agent-token-file"] != nil {
		t.Fatal("worker configuration changed roles")
	}
	for _, kind := range []string{"shell-interface", "plaintext", "wrong-port", "role", "mode", "image-hash", "node-name", "cluster"} {
		t.Run(kind, func(t *testing.T) {
			bad := validPlan()
			switch kind {
			case "shell-interface":
				bad.Interface = "eth0;reboot"
			case "plaintext":
				bad.RegistrationURL = "http://register.example:9345"
			case "wrong-port":
				bad.APIURL = "https://register.example:9345"
			case "role":
				bad.Role = "admin"
			case "mode":
				bad.Mode = "auto"
			case "image-hash":
				bad.CoreImageSHA256 = "latest"
			case "node-name":
				bad.NodeName = "bad/name"
			case "cluster":
				bad.ClusterID = "not-a-uuid"
			}
			if bad.Validate() == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
}
