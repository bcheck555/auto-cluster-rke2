"""Phase 1 guest checks via guest-agent or an explicitly selected serial console."""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path


GUEST_PROBE = r'''
import json, os, pathlib, subprocess, sys
targets = json.loads(sys.argv[1])
def command(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return {"rc": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as e:
        return {"rc": -1, "stdout": "", "stderr": str(e)}
identity = pathlib.Path("/var/lib/autonomous-rke2/host-id")
release = dict(line.split("=", 1) for line in pathlib.Path("/etc/os-release").read_text().splitlines() if "=" in line)
report = {
    "hostname": command(["hostname"]) ["stdout"],
    "machine_id": pathlib.Path("/etc/machine-id").read_text().strip(),
    "host_id": identity.read_text().strip(),
    "identity_owner": identity.stat().st_uid,
    "identity_mode": oct(identity.stat().st_mode & 0o777),
    "release": {k: v.strip('"') for k, v in release.items()},
    "ssh_key": command(["ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub"]),
    "cloud_init": command(["cloud-init", "status", "--format", "json"]),
    "selinux": command(["getenforce"]),
    "firewalld": command(["systemctl", "is-active", "firewalld"]),
    "firewalld_enabled": command(["systemctl", "is-enabled", "firewalld"]),
    "rke2_units": {role: {"active": command(["systemctl", "is-active", "rke2-" + role])["stdout"],
                          "enabled": command(["systemctl", "is-enabled", "rke2-" + role])["stdout"]}
                   for role in ("server", "agent")},
    "addresses": command(["ip", "-j", "address"]),
    "routes_v4": command(["ip", "-j", "route", "show", "table", "all"]),
    "routes_v6": command(["ip", "-j", "-6", "route", "show", "table", "all"]),
    "pings": {target: command(["ping", "-n", "-c", "1", "-W", "1", target])["rc"] for target in targets},
    "operator_password": command(["passwd", "-S", "rke2lab"]),
    "authorized_keys": pathlib.Path('/home/rke2lab/.ssh/authorized_keys').read_text().splitlines(),
}
print(json.dumps(report))
'''


def agent(domain: str, payload: dict) -> dict:
    try:
        result = subprocess.run(
            ["virsh", "--connect", "qemu:///system", "qemu-agent-command", domain, json.dumps(payload)],
            check=True, capture_output=True, text=True, timeout=15,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"{domain}: {exc.stderr.strip()}") from None
    return json.loads(result.stdout)["return"]


def probe(domain: str, targets: list[str]) -> dict:
    process = agent(domain, {"execute": "guest-exec", "arguments": {
        "path": "/usr/bin/python3", "arg": ["-c", GUEST_PROBE, json.dumps(targets)], "capture-output": True}})
    for _ in range(45):
        result = agent(domain, {"execute": "guest-exec-status", "arguments": {"pid": process["pid"]}})
        if result.get("exited"):
            if result.get("exitcode") != 0:
                raise RuntimeError(base64.b64decode(result.get("err-data", "")).decode())
            return json.loads(base64.b64decode(result["out-data"]))
        time.sleep(1)
    raise TimeoutError(f"guest probe did not finish: {domain}")


def console_probe(domain: str, targets: list[str], setup: str = "") -> dict:
    """Use a temporary in-memory console credential; always re-lock the account."""
    import pexpect
    if domain not in {"rke2-r9-cp01", "rke2-r9-cp02", "rke2-r9-cp03"}:
        raise ValueError("console validation is restricted to the approved lab")
    password = secrets.token_urlsafe(32)
    def set_password(value: str, crypted: bool) -> None:
        agent(domain, {"execute": "guest-set-user-password", "arguments": {
            "username": "rke2lab", "password": base64.b64encode(value.encode()).decode(), "crypted": crypted}})
    child = None
    stage = "credential setup"
    try:
        set_password(password, False)
        child = pexpect.spawn("virsh", ["--connect", "qemu:///system", "console", domain, "--safe"],
                              encoding="utf-8", timeout=180)
        child.expect("Escape character")
        stage = "login prompt"
        child.sendcontrol("c")
        child.send("\r")
        prompt = child.expect(["login: ", r"\$ "])
        if prompt == 0:
            stage = "password prompt"
            child.send("rke2lab\r")
            child.expect("Password:")
            child.send(password + "\r")
            stage = "operator shell"
            child.expect(r"\$ ")
        # Lock before running the probe; the current session remains usable.
        child.send("sudo -n passwd -l rke2lab; printf '\\nPHASE1_LOCKED=%s\\n' \"$?\"\r")
        stage = "password lock"
        child.expect(r"[\r\n]+PHASE1_LOCKED=([0-9]+)")
        if child.match.group(1) != "0":
            raise RuntimeError(domain + ": could not lock operator password")
        if setup:
            setup_encoded = base64.b64encode(setup.encode()).decode()
            setup_expression = "import base64;exec(base64.b64decode(" + repr(setup_encoded) + "))"
            setup_command = "sudo -n /usr/bin/python3 -c " + shlex.quote(setup_expression)
            child.send(setup_command + "; printf '\\nPHASE1_SETUP_DONE=%s\\n' \"$?\"\r")
            stage = "guest setup"
            child.expect(r"[\r\n]+PHASE1_SETUP_DONE=([0-9]+)")
            if child.match.group(1) != "0":
                log = Path("lab/results") / (domain + "-setup.log")
                log.write_text(child.before)
                details = [line for line in child.before.splitlines() if any(term in line.lower()
                           for term in ("error:", "requires", "problem", "conflict", "nothing provides", "gpg", "failed"))]
                raise RuntimeError(domain + ": guest setup failed: " + "\n".join(details[:20]) + "; log: " + str(log))
        source = GUEST_PROBE.replace("print(json.dumps(report))",
            "import base64; print('PHASE1_RESULT=' + base64.b64encode(json.dumps(report).encode()).decode())")
        encoded = base64.b64encode(source.encode()).decode()
        expression = "import base64;exec(base64.b64decode(" + repr(encoded) + "))"
        command = "sudo -n /usr/bin/python3 -c " + shlex.quote(expression) + " " + shlex.quote(json.dumps(targets))
        if len(command) > 4000:
            raise ValueError("console probe exceeds terminal line limit")
        child.send(command + "\r")
        stage = "probe result"
        child.expect(r"[\r\n]+PHASE1_RESULT=([A-Za-z0-9+/=]+)[\r\n]+")
        report = json.loads(base64.b64decode(child.match.group(1)))
        child.expect(r"\$ ")
        child.send("exit\r")
        child.expect("login: ")
        return report
    except (pexpect.TIMEOUT, pexpect.EOF):
        detail = (child.before or "")[-500:] if child is not None and stage == "probe result" else ""
        raise RuntimeError(f"{domain}: serial console probe failed at {stage}; {detail}") from None
    finally:
        try:
            set_password("!", True)
        finally:
            if child is not None:
                child.sendcontrol("]")
                child.close(force=True)


def validate(config: dict, reports: dict, forbidden: list[str]) -> list[str]:
    errors = []
    for node in config["nodes"]:
        name = node["name"]
        report = reports[name]
        profile = node.get('profile', config.get('image', {}).get('profile', 'os'))
        checks = {
            "hostname": report["hostname"] == name,
            "host ID": report["host_id"] == node["host_id"],
            "identity file permissions": report["identity_owner"] == 0 and report["identity_mode"] == "0o600",
            "Rocky 9.8": report["release"].get("ID") == "rocky" and report["release"].get("VERSION_ID") == "9.8",
            "cloud-init": report["cloud_init"]["rc"] == 0 and json.loads(report["cloud_init"]["stdout"]).get("status") == "done",
            "SELinux Enforcing": report["selinux"]["stdout"] == "Enforcing",
            "firewalld": report["firewalld"]["stdout"] == ('active' if profile == 'os' else 'inactive'),
            "SSH host key": report["ssh_key"]["rc"] == 0,
            "operator account locked": report["operator_password"]["rc"] == 0 and report["operator_password"]["stdout"].split()[1] == "LK",
        }
        if 'firewalld_enabled' in report:
            checks['firewalld enable policy'] = report['firewalld_enabled']['stdout'] == ('enabled' if profile == 'os' else 'disabled')
        if config.get('image', {}).get('kind') == 'derived':
            checks['unjoined RKE2'] = all(x['enabled'] == 'masked' and x['active'] != 'active' for x in report['rke2_units'].values())
        addresses = json.loads(report["addresses"]["stdout"])
        checks["static address"] = any(
            addr.get("local") == node["address"] and addr.get("prefixlen") == 24
            for interface in addresses for addr in interface.get("addr_info", []))
        for family in ("v4", "v6"):
            routes = json.loads(report["routes_" + family]["stdout"])
            checks["no default route " + family] = not any(route.get("dst") == "default" for route in routes)
        checks["peer connectivity"] = all(report["pings"][peer["address"]] == 0 for peer in config["nodes"] if peer != node)
        checks["no host/external ping"] = all(report["pings"][target] != 0 for target in forbidden)
        checks["operator SSH key"] = Path(config["ssh_public_key_file"]).read_text().strip() in report["authorized_keys"]
        errors.extend(f"{name}: {check}" for check, ok in checks.items() if not ok)
    for field in ("machine_id", "host_id", "hostname"):
        values = [report[field] for report in reports.values()]
        if len(set(values)) != 3 or any(not value for value in values):
            errors.append("guest identities not unique: " + field)
    fingerprints = [report["ssh_key"]["stdout"].split()[1] for report in reports.values() if report["ssh_key"]["rc"] == 0]
    if len(set(fingerprints)) != 3:
        errors.append("SSH host keys not unique")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("lab/libvirt/lab-config.example.json"))
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--console", action="store_true",
                        help="use temporary serial login and always re-lock the lab account")
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    baseline = json.loads(args.baseline.read_text())
    forbidden = sorted({"1.1.1.1"} | {
        address["local"] for interface in baseline["links"] for address in interface.get("addr_info", [])
        if address.get("family") == "inet" and address.get("scope") != "host"} | {
        address["local"] + ("%rke2lab0" if address.get("scope") == "link" else "")
        for interface in baseline["links"] for address in interface.get("addr_info", [])
        if address.get("family") == "inet6" and address.get("scope") != "host"})
    reports = {}
    for node in config["nodes"]:
        targets = [peer["address"] for peer in config["nodes"] if peer != node] + forbidden
        reports[node["name"]] = (console_probe if args.console else probe)(node["name"], targets)
        print("probed " + node["name"], flush=True)
    errors = validate(config, reports, forbidden)
    for node in config["nodes"]:
        result = subprocess.run(["virsh", "--connect", "qemu:///system", "dumpxml", node["name"]],
                                check=True, capture_output=True, text=True)
        domain = ET.fromstring(result.stdout)
        interfaces = domain.findall("devices/interface")
        if len(interfaces) != 1 or interfaces[0].find("source").get("network") != config["network"]["name"]:
            errors.append(node["name"] + ": unexpected network attachment")
        if len(interfaces) != 1 or interfaces[0].find("filterref") is None or interfaces[0].find("filterref").get("filter") != "autonomous-rke2-ipv4-only":
            errors.append(node["name"] + ": IPv6 packet filter missing")
        if domain.find("devices/graphics") is not None:
            errors.append(node["name"] + ": diagnostic display still attached")
    evidence = {"forbidden_ping_targets": forbidden, "guests": reports, "errors": errors}
    with args.output.open("x") as output:
        json.dump(evidence, output, indent=2)
        output.write("\n")
    print(json.dumps({"errors": errors, "report": str(args.output)}))
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
