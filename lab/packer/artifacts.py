"""Artifact trust and resource boundaries shared by image and lab operations."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "lab/artifacts/packer"
STATE = ROOT / "lab/state/packer"
RESULTS = ROOT / "lab/results/packer"
CREDENTIALS = Path(os.environ.get("AUTONOMOUS_IMAGE_TRUST_DIR", str(ROOT / "lab/credentials/artifact-signing"))).resolve()
GIB = 1024**3
PROFILES = ("os", "node")
VERSIONS = {"rocky": "9.8", "rke2": "v1.37.1+rke2r1", "packer": "1.15.3", "qemu_plugin": "1.1.4", "cni": "flannel"}


class ImageError(ValueError):
    pass


def run(command, *, cwd=None, env=None, timeout=None):
    result = subprocess.run([str(x) for x in command], cwd=cwd, env=env, timeout=timeout,
                            capture_output=True, text=True)
    if result.returncode:
        raise ImageError(f"{Path(str(command[0])).name} failed ({result.returncode}): {result.stderr[-2500:] or result.stdout[-2500:]}")
    return result.stdout


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def validation_sources(validator):
    paths = {Path(validator).resolve(), *(ROOT / 'lab/libvirt').glob('*.py')}
    paths.update(ROOT / 'lab/packer' / name for name in
                 ('artifacts.py', 'runtime.py', 'pipeline.py', 'guest.py'))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w") as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def relative_file(root, name):
    if not isinstance(name, str) or not name or Path(name).is_absolute() or ".." in Path(name).parts:
        raise ImageError("unsafe artifact path")
    root = Path(root).resolve()
    candidate = root / name
    if root not in candidate.resolve().parents or any(p.is_symlink() for p in (candidate, *candidate.parents) if p != root):
        raise ImageError("artifact path escapes its root or contains a symlink")
    if not candidate.is_file():
        raise ImageError(f"artifact missing: {name}")
    return candidate


def inventory(root):
    root = Path(root)
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ImageError(f"symlink in artifact tree: {path}")
        if path.is_file():
            files[str(path.relative_to(root))] = {"sha256": digest(path), "size": path.stat().st_size}
    return files


def trust():
    metadata = json.loads((CREDENTIALS / "trust.json").read_text())
    return metadata["fingerprint"], CREDENTIALS / "public.gpg"


def init_signer():
    CREDENTIALS.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(CREDENTIALS, 0o700)
    home = CREDENTIALS / "gnupg"
    home.mkdir(mode=0o700, exist_ok=True)
    if not (CREDENTIALS / "trust.json").exists():
        if any(home.iterdir()):
            raise ImageError("signing home exists without a trust record; refusing implicit key selection")
        run(["gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-generate-key", "Autonomous RKE2 image artifacts", "ed25519", "sign", "0"])
        listing = run(["gpg", "--homedir", home, "--batch", "--with-colons", "--list-secret-keys"])
        fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
        if len(fingerprints) != 1:
            raise ImageError("expected exactly one dedicated signing key")
        fingerprint = fingerprints[0]
        public = subprocess.run(["gpg", "--homedir", str(home), "--export", fingerprint], check=True, capture_output=True).stdout
        (CREDENTIALS / "public.gpg").write_bytes(public)
        write_json(CREDENTIALS / "trust.json", {"fingerprint": fingerprint})
    return trust()


def sign(path):
    fingerprint, _ = trust()
    command = ["gpg", "--homedir", str(CREDENTIALS / "gnupg"), "--batch", "--yes", "--local-user", fingerprint,
               "--detach-sign", "--output", "-"]
    owner = CREDENTIALS.stat()
    if os.geteuid() == 0 and owner.st_uid != 0:
        command = ["setpriv", "--reuid", str(owner.st_uid), "--regid", str(owner.st_gid), "--init-groups", *command]
    result = subprocess.run(command, input=Path(path).read_bytes(), capture_output=True)
    if result.returncode:
        raise ImageError("artifact signing failed: " + result.stderr.decode()[-1000:])
    Path(str(path) + ".sig").write_bytes(result.stdout)


def verify_signature(path, keyring, fingerprint):
    if not re.fullmatch(r"[0-9A-Fa-f]{40,64}", fingerprint):
        raise ImageError("signer fingerprint is not pinned")
    with tempfile.TemporaryDirectory(prefix="artifact-gpg-") as home:
        status = run(["gpgv", "--homedir", home, "--status-fd=1", "--keyring", Path(keyring).resolve(),
                      str(path) + ".sig", path])
    signers = set()
    for line in status.splitlines():
        parts = line.split()
        if len(parts) > 2 and parts[:2] == ["[GNUPG:]", "VALIDSIG"]:
            signers.add(parts[2].upper())
            signers.add(parts[-1].upper())
    if fingerprint.upper() not in signers:
        raise ImageError("artifact signer differs from pinned fingerprint")


def verify_manifest(path, keyring=None, fingerprint=None):
    path = Path(path).resolve()
    if keyring is None or fingerprint is None:
        fingerprint, keyring = trust()
    verify_signature(path, keyring, fingerprint)
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != 1 or not isinstance(manifest.get("files"), dict) or not manifest["files"]:
        raise ImageError("invalid or empty artifact manifest")
    for name, pin in manifest["files"].items():
        file = relative_file(path.parent, name)
        if file.stat().st_size != pin["size"] or digest(file) != pin["sha256"]:
            raise ImageError(f"artifact hash/size mismatch: {name}")
    if manifest.get("kind") == "input":
        if any(p.is_symlink() for p in path.parent.rglob('*')):
            raise ImageError('input contains a symlink')
        actual = {str(p.relative_to(path.parent)) for p in path.parent.rglob("*") if p.is_file()}
        expected = set(manifest["files"]) | {path.name, path.name + ".sig"}
        if actual != expected:
            raise ImageError("input contains unlisted or missing files")
    return manifest


@contextlib.contextmanager
def operation_lock():
    STATE.mkdir(parents=True, exist_ok=True)
    with (STATE / "operation.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ImageError("another image/lab operation is active") from None
        yield


def preflight(extra_disk=0, extra_memory_mib=0):
    """Account for remaining writable lab disk commitments, not just current df."""
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    available = shutil.disk_usage(ARTIFACTS).free
    memory = next(int(line.split()[1]) // 1024 for line in Path("/proc/meminfo").read_text().splitlines()
                  if line.startswith("MemAvailable:"))
    committed = 0
    memory_committed = 0
    pool = Path("/var/lib/libvirt/images/autonomous-rke2-lab")
    for name in ("rke2-r9-cp01", "rke2-r9-cp02", "rke2-r9-cp03"):
        import xml.etree.ElementTree as ET
        result = subprocess.run(["virsh", "-c", "qemu:///system", "dumpxml", name], capture_output=True, text=True)
        if result.returncode:
            listing = run(["virsh", "-c", "qemu:///system", "list", "--all", "--name"])
            if name not in listing.split():
                continue
            raise ImageError(f"cannot inspect existing lab disk commitments: {name}")
        domain = ET.fromstring(result.stdout)
        if domain.get('id') is not None:
            configured = domain.find('currentMemory')
            if configured is None:
                configured = domain.find('memory')
            if configured is None or configured.get('unit', 'KiB') != 'KiB':
                raise ImageError('cannot inspect existing lab RAM commitments')
            stats = run(['virsh', '-c', 'qemu:///system', 'dommemstat', name])
            values = {line.split()[0]: int(line.split()[1]) for line in stats.splitlines() if len(line.split()) == 2}
            memory_committed += max(0, int(configured.text) // 1024 - values.get('rss', 0) // 1024)
        for node in domain.findall("devices/disk[@device='disk']/source"):
            path = Path(node.get("file", ""))
            if pool not in path.parents:
                raise ImageError(f"unexpected current lab disk: {name}")
            result = run(["virsh", "-c", "qemu:///system", "domblkinfo", name, str(path)])
            stats = {line.split(":")[0]: int(line.split(":")[1]) for line in result.splitlines() if ":" in line}
            committed += max(0, stats["Capacity"] - stats["Allocation"])
    if available - committed - extra_disk < 300 * GIB:
        raise ImageError("insufficient disk after existing lab commitments and 300 GiB host reserve")
    if memory - memory_committed - extra_memory_mib < 32768:
        raise ImageError("insufficient RAM after 32 GiB host reserve")
    return {"free_bytes": available, "remaining_lab_commitment": committed, "available_memory_mib": memory,
            'remaining_lab_memory_mib': memory_committed}
