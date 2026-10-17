"""Guest-only image installation, sealing, attestation and explicit smoke test."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

OFFLINE = Path("/opt/autonomous-rke2/offline")
CONFIG = Path("/etc/autonomous-rke2")


def command(args, check=True, timeout=60):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(str(args[0]) + ": " + p.stderr[-500:] + p.stdout[-500:])
    return p


def write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


def offline_coredns():
    return """apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-coredns
  namespace: kube-system
spec:
  valuesContent: |-
    servers:
      - zones:
          - zone: .
        port: 53
        plugins:
          - name: errors
          - name: health
            configBlock: lameduck 5s
          - name: ready
          - name: kubernetes
            parameters: cluster.local in-addr.arpa ip6.arpa
            configBlock: |-
              pods insecure
              fallthrough in-addr.arpa ip6.arpa
          - name: prometheus
            parameters: 0.0.0.0:9153
          - name: cache
            parameters: 30
          - name: loop
          - name: reload
          - name: loadbalance
"""


def install(profile):
    assert profile in ("os", "server", "agent")
    payload = Path("/mnt/packer/payload")
    manifest = json.loads((payload / "input-metadata.json").read_text())
    command(["systemctl", "mask", "rke2-server.service", "rke2-agent.service"])
    if not OFFLINE.exists():
        shutil.copytree(payload / "rpms", OFFLINE / "rpms")
    write(OFFLINE / 'coredns-config.yaml', offline_coredns(), 0o644)
    command(["rpm", "--import", str(payload / "keys/rocky.key"), str(payload / "keys/rancher.key")])
    packages = manifest["packages"]["os"] if profile == "os" else manifest["packages"][profile]
    command(["dnf", "-y", "--disablerepo=*", "--repofrompath=image-offline,file://" + str(OFFLINE / "rpms"),
             "--enablerepo=image-offline", "--setopt=image-offline.gpgcheck=1", "install", *packages], timeout=900)
    if profile == "os":
        command(["systemctl", "enable", "--now", "firewalld"])
    else:
        command(["systemctl", "disable", "--now", "firewalld"])
        images = Path("/var/lib/rancher/rke2/agent/images")
        images.mkdir(parents=True, exist_ok=True)
        for source in (payload / "runtime").iterdir():
            if source.name.endswith((".tar.zst", ".tar")):
                shutil.copyfile(source, images / source.name)
        write("/etc/rancher/rke2/config.yaml", "selinux: true\n" + ("cni: flannel\n" if profile == "server" else ""))
        write("/etc/NetworkManager/conf.d/rke2-flannel.conf",
              "[keyfile]\nunmanaged-devices=interface-name:flannel*;interface-name:cni*;interface-name:veth*\n", 0o644)
    for service in ("nm-cloud-setup.service", "nm-cloud-setup.timer", "dnf-makecache.timer"):
        command(["systemctl", "disable", "--now", service], check=False)
    # Image consumers use the retained local repository; no public repo is enabled.
    for repo in Path("/etc/yum.repos.d").glob("*.repo"):
        text = repo.read_text()
        text = re.sub(r"(?m)^enabled\s*=.*$", "enabled=0", text)
        text = re.sub(r"(?m)^(\[[^]]+\])$", r"\1\nenabled=0", text)
        # Collapse duplicate enabled keys introduced by existing explicit settings.
        lines = []
        seen = False
        for line in text.splitlines():
            if line.startswith("["):
                seen = False
            if line.startswith("enabled="):
                if seen:
                    continue
                seen = True
            lines.append(line)
        write(repo, "\n".join(lines) + "\n", 0o644)
    write("/etc/yum.repos.d/autonomous-offline.repo",
          "[autonomous-offline]\nname=Locked image RPMs\nbaseurl=file://" + str(OFFLINE / "rpms") + "\nenabled=1\ngpgcheck=1\n", 0o644)
    chrony = Path("/etc/chrony.conf")
    if chrony.exists():
        write(chrony, "\n".join(l for l in chrony.read_text().splitlines() if not re.match(r"\s*(pool|server|peer)\s", l)) + "\n", 0o644)
    metadata = {"schema": 1, "profile": profile, "versions": manifest["versions"],
                "input_sha256": manifest["input_sha256"], "validation_image": manifest["validation_image"],
                "firewalld": "active" if profile == "os" else "disabled"}
    write(CONFIG / "image.json", json.dumps(metadata), 0o644)
    shutil.copyfile(__file__, "/usr/local/sbin/autonomous-image.py")
    write("/etc/systemd/system/autonomous-image-validation.service", """[Unit]
Description=Image validation and explicitly authorized disposable smoke test
After=cloud-final.service
ConditionPathExists=/etc/autonomous-rke2/instance.json
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/sbin/autonomous-image.py report
StandardOutput=journal+console
StandardError=journal
TimeoutStartSec=1800
""", 0o644)
    command(["systemctl", "enable", "qemu-guest-agent"])
    command(["restorecon", "-RF", "/opt/autonomous-rke2", "/etc/autonomous-rke2", "/usr/local/sbin/autonomous-image.py"])
    assert command(["getenforce"]).stdout.strip() == "Enforcing"
    inventory = {"image": metadata,
                 "rpms": sorted(command(["rpm", "-qa", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"]).stdout.splitlines())}
    write(CONFIG / 'rpm-inventory.sha256', hashlib.sha256(json.dumps(inventory['rpms']).encode()).hexdigest(), 0o644)
    write("/var/tmp/image-inventory.json", json.dumps(inventory, indent=2), 0o644)


def check_seal():
    assert os.geteuid() == 0
    metadata = json.loads((CONFIG / "image.json").read_text())
    for service in ("rke2-server", "rke2-agent"):
        assert command(["systemctl", "is-active", service], check=False).stdout.strip() != "active"
        assert command(["systemctl", "is-enabled", service], check=False).stdout.strip() == "masked"
    forbidden = [CONFIG / "instance.json", Path("/var/lib/autonomous-rke2/host-id")]
    if any(path.exists() for path in forbidden) or not cluster_state_absent():
        raise RuntimeError("image contains instance/cluster state")


def seal():
    check_seal()
    command(['systemctl', 'stop', 'NetworkManager'])
    command(["cloud-init", "clean", "--logs", "--machine-id", "--seed", "--configs", "network"])
    for directory in (Path('/etc/NetworkManager/system-connections'),):
        if directory.exists():
            for path in directory.iterdir():
                if path.is_file() or path.is_symlink():
                    path.unlink()
    for pattern in ('ifcfg-*', 'route-*', 'route6-*', 'rule-*'):
        for path in Path('/etc/sysconfig/network-scripts').glob(pattern):
            if path.name != 'ifcfg-lo':
                path.unlink()
    for path in Path('/var/lib/NetworkManager').glob('*lease*'):
        if path.is_file() or path.is_symlink():
            path.unlink()
    if Path('/var/lib/dhclient').exists():
        shutil.rmtree('/var/lib/dhclient')
    resolver = Path('/etc/resolv.conf')
    if resolver.is_symlink():
        resolver.unlink()
    write(resolver, '', 0o644)
    for key in Path("/etc/ssh").glob("ssh_host_*"):
        key.unlink()
    command(["userdel", "-f", "-r", "packer"])
    Path("/etc/sudoers.d/90-cloud-init-users").unlink(missing_ok=True)
    for path in (Path("/root/.ssh"), Path("/var/log/journal")):
        if path.exists():
            shutil.rmtree(path)
    for path in (Path("/var/log/wtmp"), Path("/var/log/btmp"), Path("/var/log/lastlog")):
        if path.exists():
            path.write_bytes(b"")
    dbus = Path("/var/lib/dbus/machine-id")
    if dbus.exists() and not dbus.is_symlink():
        dbus.unlink()
        dbus.symlink_to("/etc/machine-id")
    write("/etc/hostname", "localhost\n", 0o644)
    command(["dnf", "clean", "all"])
    command(["sync"])
    command(["shutdown", "-P", "now"])


def cluster_state_absent():
    # rke2-selinux ships empty datastore/snapshotter directories. Files or links are state.
    for root in (Path('/var/lib/rancher/rke2/server'), Path('/var/lib/rancher/rke2/agent/containerd')):
        if root.is_symlink() or (root.exists() and not root.is_dir()):
            return False
        if root.exists() and any(p.is_symlink() or not p.is_dir() for p in root.rglob('*')):
            return False
    return True


def kubectl(args, check=True, timeout=60):
    return command(["/var/lib/rancher/rke2/bin/kubectl", "--kubeconfig=/etc/rancher/rke2/rke2.yaml", *args], check, timeout)


def wait_until(action, timeout=600):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if action():
                return
        except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        time.sleep(3)
    raise RuntimeError("validation deadline exceeded")


def smoke(instance, image):
    grant_path = CONFIG / "test-grant.json"
    verifier = shutil.which("gpgv") or shutil.which("gpgv2")
    command([verifier, "--keyring", str(CONFIG / "test-authority.gpg"), str(grant_path) + ".sig", str(grant_path)])
    grant = json.loads(grant_path.read_text())
    if grant["purpose"] != "offline-image-smoke" or time.time() > grant["expires"] or instance["host_id"] not in grant["hosts"]:
        raise RuntimeError("test authorization missing, expired, or for a different host")
    marker = CONFIG / "consumed-test-grant"
    if marker.exists() and marker.read_text() != grant["nonce"]:
        raise RuntimeError("test grant differs from initialized test state")
    write(marker, grant["nonce"])
    role = image["profile"]
    if role not in ("server", "agent"):
        raise RuntimeError("OS baseline may not bootstrap RKE2")
    token = (CONFIG / "test-token").read_text().strip()
    config = "selinux: true\ntoken: " + json.dumps(token) + "\nnode-ip: " + instance['address'] + "\n"
    if role == "server":
        config += "cni: flannel\nadvertise-address: " + instance['address'] + "\ncluster-cidr: 10.42.0.0/16\nservice-cidr: 10.43.0.0/16\n"
        write('/var/lib/rancher/rke2/server/manifests/rke2-flannel-config.yaml', '''apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-flannel
  namespace: kube-system
spec:
  valuesContent: |-
    flannel:
      backend: vxlan
      args:
        - --ip-masq
        - --kube-subnet-mgr
        - --iface=rke2lab0
    netpol:
      enabled: false
''')
        # CoreDNS must start even when the node has no upstream resolver.
        write("/var/lib/rancher/rke2/server/manifests/rke2-coredns-config.yaml", """apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-coredns
  namespace: kube-system
spec:
  valuesContent: |-
    servers:
      - zones:
          - zone: .
        port: 53
        plugins:
          - name: errors
          - name: health
            configBlock: lameduck 5s
          - name: ready
          - name: kubernetes
            parameters: cluster.local in-addr.arpa ip6.arpa
            configBlock: |-
              pods insecure
              fallthrough in-addr.arpa ip6.arpa
          - name: prometheus
            parameters: 0.0.0.0:9153
          - name: cache
            parameters: 30
          - name: loop
          - name: reload
          - name: loadbalance
""")
    else:
        config += "server: https://" + instance["server_address"] + ":9345\n"
    write("/etc/rancher/rke2/config.yaml", config)
    command(["systemctl", "unmask", "rke2-" + role])
    command(["systemctl", "start", "--no-block", "rke2-" + role])
    wait_until(lambda: command(["systemctl", "is-active", "rke2-" + role], check=False).stdout.strip() == "active")
    # Imported OCI archive is also named by its digest; test pods never resolve a mutable tag.
    ctr = ['/var/lib/rancher/rke2/bin/ctr', '--address', '/run/k3s/containerd/containerd.sock', '--namespace', 'k8s.io']
    command([*ctr, 'images', 'tag', '--force', 'docker.io/library/busybox:1.37.0', image['validation_image']])
    if role != "server":
        wait_until(lambda: command(["systemctl", "is-active", "rke2-agent"], check=False).stdout.strip() == "active")
        return {"service": "active"}
    def ready():
        p = kubectl(["get", "nodes", "-o", "json"], check=False)
        if p.returncode:
            return False
        nodes = json.loads(p.stdout)["items"]
        return len(nodes) == 2 and all(any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"]) for n in nodes)
    wait_until(ready)
    # CoreDNS and the CNI must be ready before workload DNS/connectivity probes.
    def system_ready():
        pods = json.loads(kubectl(['-n', 'kube-system', 'get', 'pods', '-o', 'json']).stdout)['items']
        return pods and all(p['status'].get('phase') == 'Succeeded' or
                           (p['status'].get('phase') == 'Running' and p['status'].get('containerStatuses') and
                            all(c.get('ready') for c in p['status']['containerStatuses'])) for p in pods)
    wait_until(system_ready)
    workload = image["validation_image"]
    namespace = "image-validation"
    resources = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}}]
    for name, host, args in (("http", instance["name"], ["sh", "-c", "mkdir -p /www; echo image-ok >/www/index.html; exec httpd -f -p 8080 -h /www"]),
                             ("client", instance["agent_name"], ["sleep", "3600"])):
        resources.append({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace, "labels": {"app": name}},
            "spec": {"nodeName": host, "containers": [{"name": name, "image": workload, "imagePullPolicy": "Never", "command": args}]}})
    resources.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "http", "namespace": namespace},
                      "spec": {"selector": {"app": "http"}, "ports": [{"port": 8080, "targetPort": 8080}]}})
    file = CONFIG / "test-workload.json"
    write(file, json.dumps({"apiVersion": "v1", "kind": "List", "items": resources}))
    kubectl(["apply", "-f", str(file)])
    kubectl(["-n", namespace, "wait", "--for=condition=Ready", "pod", "--all", "--timeout=300s"], timeout=330)
    def connectivity():
        # Ready conditions can briefly retain their pre-reboot values while
        # kubelet's streaming endpoint reconnects. Require real probes to pass.
        dns = kubectl(["-n", namespace, "exec", "client", "--", "nslookup", '-type=A', "kubernetes.default.svc.cluster.local."]).stdout
        service_ip = json.loads(kubectl(['-n', namespace, 'get', 'service', 'http', '-o', 'json']).stdout)['spec']['clusterIP']
        service_dns = kubectl(['-n', namespace, 'exec', 'client', '--', 'nslookup', '-type=A',
                              'http.image-validation.svc.cluster.local.']).stdout
        http = kubectl(["-n", namespace, "exec", "client", "--", "sh", "-c",
                        "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | timeout 15 nc -w 5 " + service_ip + ' 8080']).stdout
        pod_ip = json.loads(kubectl(['-n', namespace, 'get', 'pod', 'http', '-o', 'json']).stdout)['status']['podIP']
        direct = kubectl(['-n', namespace, 'exec', 'client', '--', 'sh', '-c',
                         "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | timeout 15 nc -w 5 " + pod_ip + ' 8080']).stdout
        return "image-ok" in http and "image-ok" in direct and "Address" in dns and service_ip in service_dns
    wait_until(connectivity)
    wait_until(ready)
    wait_until(system_ready)
    maps = json.loads(kubectl(['-n', 'kube-system', 'get', 'configmaps', '-o', 'json']).stdout)['items']
    corefiles = [cm['data']['Corefile'] for cm in maps if 'Corefile' in cm.get('data', {})]
    if not corefiles or any(re.search(r'(?m)^\s*forward\s', text) for text in corefiles):
        raise RuntimeError('CoreDNS has external forwarding or no Corefile')
    cluster_uid = json.loads(kubectl(['get', 'namespace', 'kube-system', '-o', 'json']).stdout)['metadata']['uid']
    return {"nodes_ready": 2, "dns": True, "cross_node_service": True, "cross_node_pod": True,
            "system_pods": True, 'cluster_uid': cluster_uid, 'external_dns_forwarding': False}


def report():
    instance = json.loads((CONFIG / "instance.json").read_text())
    image = json.loads((CONFIG / "image.json").read_text())
    errors = []
    if instance.get('profile') != image['profile']:
        errors.append('deployment profile differs from image policy')
    smoke_result = None
    try:
        if instance.get("smoke"):
            smoke_result = smoke(instance, image)
        if image["profile"] == "os":
            command(["firewall-cmd", "--reload"])
    except Exception as exc:
        # Do not report secret-bearing commands, configuration, or tokens.
        errors.append("runtime validation failed: " + type(exc).__name__)
        write("/var/tmp/image-validation-error.txt", str(exc))
    def output(args):
        return command(args, check=False).stdout.strip()
    pings = {target: command(["ping", "-n", "-c", "1", "-W", "1", target], check=False).returncode
             for target in instance.get("probe_targets", [])}
    host_id = Path("/var/lib/autonomous-rke2/host-id")
    report = {"image": image, "hostname": output(["hostname"]), "host_id": host_id.read_text().strip(),
        'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        "identity_uid": host_id.stat().st_uid, "identity_mode": oct(host_id.stat().st_mode & 0o777),
        "machine_id": Path("/etc/machine-id").read_text().strip(),
        "ssh_fingerprint": output(["ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub"]).split()[1],
        "authorized_keys": Path("/home/rke2lab/.ssh/authorized_keys").read_text().splitlines(),
        "operator_password": output(["passwd", "-S", "rke2lab"]).split()[1],
        "selinux": output(["getenforce"]), "firewalld_active": output(["systemctl", "is-active", "firewalld"]),
        "firewalld_enabled": output(["systemctl", "is-enabled", "firewalld"]),
        "rke2_units": {role: {"active": output(["systemctl", "is-active", "rke2-" + role]),
                              "enabled": output(["systemctl", "is-enabled", "rke2-" + role])} for role in ("server", "agent")},
        "cloud_init": json.loads(output(["cloud-init", "status", "--format", "json"])),
        "addresses": json.loads(output(["ip", "-j", "address"])),
        "routes": json.loads(output(["ip", "-j", "route", "show", "table", "all"])),
        'rpm_inventory_sha256': hashlib.sha256(json.dumps(sorted(output(['rpm', '-qa', '--qf',
             '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n']).splitlines())).encode()).hexdigest(),
        'packages': {name: command(['rpm', '-q', name], check=False).returncode == 0
                     for name in ('firewalld', 'rke2-server', 'rke2-agent', 'rke2-selinux')},
        'cluster_state_absent': cluster_state_absent(),
        "pings": pings, "smoke": smoke_result, "errors": errors}
    write("/var/tmp/image-boot-report.json", json.dumps(report))
    print("IMAGE_REPORT=" + base64.b64encode(json.dumps(report).encode()).decode(), flush=True)


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("guest image operations require root")
    if sys.argv[1] == "install":
        install(sys.argv[2])
    elif sys.argv[1] == "seal":
        seal()
    elif sys.argv[1] == 'check-seal':
        check_seal()
    elif sys.argv[1] == "report":
        report()
    else:
        raise SystemExit("unknown guest operation")
