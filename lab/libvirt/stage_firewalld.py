"""Download signed guest RPMs in a disposable Rocky container, not on the host OS."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
destination = ROOT / "lab/artifacts/rocky9-firewalld"
destination.mkdir(mode=0o700, exist_ok=False)
key = ROOT / "lab/artifacts/RPM-GPG-KEY-Rocky-9"
script = """set -e
dnf -y install dnf-plugins-core createrepo_c
dnf download --resolve --alldeps --destdir=/out firewalld
rpm --dbpath /tmp/verification --initdb
rpm --dbpath /tmp/verification --import /keys/RPM-GPG-KEY-Rocky-9
rpmkeys --dbpath /tmp/verification --checksig /out/*.rpm
createrepo_c /out
"""
result = subprocess.run(["docker", "run", "--rm", "--network", "bridge",
    "--volume", f"{destination}:/out", "--volume", f"{key}:/keys/RPM-GPG-KEY-Rocky-9:ro",
    "rockylinux:9", "bash", "-c", script], capture_output=True, text=True)
log = ROOT / "lab/results/firewalld-staging.log"
log.write_text(result.stdout + result.stderr)
if result.returncode:
    print(f"RPM staging failed; log: {log}")
    raise SystemExit(result.returncode)
files = {}
for rpm in sorted(destination.glob("*.rpm")):
    with rpm.open("rb") as source:
        files[rpm.name] = hashlib.file_digest(source, "sha256").hexdigest()
assert files
image = subprocess.run(["docker", "image", "inspect", "rockylinux:9", "--format", "{{json .RepoDigests}}"],
                       check=True, capture_output=True, text=True)
report = {"container_image": json.loads(image.stdout), "rpms_sha256": files,
          "verification": "rpmkeys against an isolated database containing only the pinned Rocky 9 key"}
(ROOT / "lab/results/firewalld-rpms.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"verified {len(files)} RPMs; evidence: lab/results/firewalld-rpms.json")
