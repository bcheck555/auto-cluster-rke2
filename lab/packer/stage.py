"""Connected preparation. Nothing in this module is used by offline builds."""
from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import subprocess
import tempfile
import tarfile
import urllib.request
import zipfile
from pathlib import Path

from .artifacts import ARTIFACTS, CREDENTIALS, ROOT, VERSIONS, ImageError, digest, init_signer, inventory, preflight, run, sign, verify_manifest, write_json

COMMON = ["cloud-init", "qemu-guest-agent", "firewalld", "openssh-server", "openssh-clients", "policycoreutils-python-utils",
          "container-selinux", "iptables-nft", "nftables", "conntrack-tools", "iproute", "iputils",
          "bind-utils", "ethtool", "socat", "tar", "gzip", "zstd", "gnupg2"]
STAGING_IMAGE = 'rockylinux@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6'
REPOS = """[rke2-common]
name=RKE2 common
baseurl=https://rpm.rancher.io/rke2/stable/common/centos/9/noarch
enabled=1
gpgcheck=1
gpgkey=file:///keys/rancher.key
[rke2-version]
name=RKE2 1.37
baseurl=https://rpm.rancher.io/rke2/stable/1.37/centos/9/x86_64
enabled=1
gpgcheck=1
gpgkey=file:///keys/rancher.key
"""


def download(url, destination, maximum=4 * 1024**3):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise ImageError("unsafe cached download")
        return
    partial = destination.with_name(destination.name + ".part")
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 autonomous-rke2-image-builder"})
        with partial.open("xb") as output, urllib.request.urlopen(request, timeout=120) as response:
            if not response.url.startswith("https://"):
                raise ImageError("artifact redirected away from HTTPS")
            count = 0
            while data := response.read(1024 * 1024):
                count += len(data)
                if count > maximum:
                    raise ImageError("download exceeds artifact size ceiling")
                output.write(data)
        os.link(partial, destination)
    finally:
        partial.unlink(missing_ok=True)


def vendor_key(path):
    with tempfile.TemporaryDirectory(prefix="vendor-key-") as home:
        listing = run(["gpg", "--homedir", home, "--with-colons", "--show-keys", path])
        fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
        if not fingerprints:
            raise ImageError("empty vendor key")
        run(["gpg", "--homedir", home, "--batch", "--import", path])
        result = subprocess.run(["gpg", "--homedir", home, "--export"], check=True, capture_output=True)
    keyring = path.with_suffix(".gpg")
    keyring.write_bytes(result.stdout)
    return fingerprints, keyring


def prepare(destination, resume=False):
    """Create a signed, exact input lock; never silently refresh an existing lock."""
    from lab.libvirt.provision import verify_image_artifacts
    destination = Path(destination).resolve()
    if destination.exists() and (not resume or (destination / "input.json").exists()):
        raise ImageError("input generation already exists; choose a new generation")
    preflight(extra_disk=16 * 1024**3)
    init_signer()
    destination.mkdir(parents=True, mode=0o700, exist_ok=resume)
    for directory in ("source", "keys", "tools", "runtime", "rpms", "recipe"):
        (destination / directory).mkdir(exist_ok=resume)
    config = json.loads((ROOT / "lab/libvirt/rocky-source.json").read_text())
    os.chdir(ROOT)
    verify_image_artifacts(config["image"])
    source = ROOT / config["image"]["staged_path"]
    shutil.copyfile(source, destination / "source/rocky.qcow2")
    for field in ("checksum_path", "signature_path"):
        shutil.copyfile(ROOT / config["image"][field], destination / "source" / Path(config["image"][field]).name)
    shutil.copyfile(ROOT / "lab/artifacts/RPM-GPG-KEY-Rocky-9", destination / "keys/rocky.key")
    tasks = [
        ("https://rpm.rancher.io/public.key", "keys/rancher.key"),
        ("https://www.hashicorp.com/.well-known/pgp-key.txt", "keys/hashicorp.key"),
    ]
    for product, version in (("packer", VERSIONS["packer"]), ("packer-plugin-qemu", VERSIONS["qemu_plugin"])):
        prefix = f"{product}_{version}"
        base = f"https://releases.hashicorp.com/{product}/{version}/"
        for suffix in ("linux_amd64.zip", "SHA256SUMS", "SHA256SUMS.sig"):
            tasks.append((base + prefix + "_" + suffix, "tools/" + prefix + "_" + suffix))
    base = "https://github.com/rancher/rke2/releases/download/v1.37.1%2Brke2r1/"
    for name in ("rke2-images-core.linux-amd64.tar.zst", "rke2-images-flannel.linux-amd64.tar.zst",
                 "rke2-images-core.linux-amd64.txt", "rke2-images-flannel.linux-amd64.txt", "sha256sum-amd64.txt"):
        tasks.append((base + name, "runtime/" + name))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(download, url, destination / name) for url, name in tasks]
        for future in futures:
            future.result()
    keys = {}
    for name in ("rocky", "rancher", "hashicorp"):
        keys[name], _ = vendor_key(destination / f"keys/{name}.key")
    if config["image"]["signing_fingerprint"] not in keys["rocky"]:
        raise ImageError("Rocky signing identity changed")
    for product, version in (("packer", VERSIONS["packer"]), ("packer-plugin-qemu", VERSIONS["qemu_plugin"])):
        prefix = f"{product}_{version}"
        sums = destination / "tools" / (prefix + "_SHA256SUMS")
        status = run(["gpgv", "--status-fd=1", "--keyring", destination / "keys/hashicorp.gpg",
                      str(sums) + ".sig", sums])
        if not any(fp in status for fp in keys["hashicorp"]):
            raise ImageError("tool checksum signer does not match vendor key")
        archive = destination / "tools" / (prefix + "_linux_amd64.zip")
        expected = next(line.split()[0] for line in sums.read_text().splitlines() if line.split()[-1] == archive.name)
        if digest(archive) != expected:
            raise ImageError("tool checksum mismatch")
        with zipfile.ZipFile(archive) as zipped:
            binaries = [name for name in zipped.namelist() if Path(name).name == "packer" or Path(name).name.startswith("packer-plugin-qemu_v")]
            if len(binaries) != 1:
                raise ImageError("unexpected tool archive layout")
            output = destination / "tools" / Path(binaries[0]).name
            output.write_bytes(zipped.read(binaries[0]))
            output.chmod(0o755)
    sums = {line.split()[-1].lstrip("*"): line.split()[0]
            for line in (destination / "runtime/sha256sum-amd64.txt").read_text().splitlines() if len(line.split()) == 2}
    for path in (destination / "runtime").glob("*.tar.zst"):
        if digest(path) != sums.get(path.name):
            raise ImageError("RKE2 archive differs from release checksum")
    (destination / "rke2.repo").write_text(REPOS)
    script = r'''
set -e
dnf -y install dnf-plugins-core createrepo_c
rpm --import /keys/rocky.key /keys/rancher.key
python3 - <<'PY'
import json, subprocess, pathlib
common = json.loads(pathlib.Path('/out/common.json').read_text())
def query(package):
    text = subprocess.check_output(['dnf','-q','repoquery','--latest-limit','1','--archlist=x86_64,noarch','--qf','%{name}-%{epoch}:%{version}-%{release}.%{arch}',package],text=True)
    lines = [l.strip() for l in text.splitlines() if l.strip().startswith(package+'-')]
    if len(lines) != 1: raise RuntimeError('ambiguous package: '+package+' '+text)
    return lines[0]
roles = {}
for role in ('server','agent'):
    output = subprocess.check_output(['dnf','-q','repoquery','--show-duplicates','--archlist=x86_64','--qf','%{name}-%{epoch}:%{version}-%{release}.%{arch}','rke2-'+role],text=True)
    versions = [l.strip() for l in output.splitlines() if '1.37.1' in l and 'rke2r1' in l]
    if len(versions) != 1: raise RuntimeError('pinned RKE2 RPM unavailable or ambiguous: '+repr(versions))
    roles[role] = versions[0]
packages = {'os':[query(p) for p in common],**{r:[p] for r,p in roles.items()}}
for role in ('server','agent'):
    subprocess.run(['dnf','download','--resolve','--alldeps','--destdir=/out/rpms',*packages['os'],*packages[role]],check=True)
pathlib.Path('/out/packages.json').write_text(json.dumps(packages,indent=2))
rpms = sorted(str(p) for p in pathlib.Path('/out/rpms').glob('*.rpm'))
subprocess.run(['rpm','--dbpath','/tmp/verification','--initdb'],check=True)
subprocess.run(['rpm','--dbpath','/tmp/verification','--import','/keys/rocky.key','/keys/rancher.key'],check=True)
subprocess.run(['rpmkeys','--dbpath','/tmp/verification','--checksig',*rpms],check=True)
nevras = subprocess.check_output(['rpm','-qp','--qf','%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n',*rpms],text=True).splitlines()
index = subprocess.check_output(['dnf','-q','repoquery','--location',*nevras],text=True)
pathlib.Path('/out/package-sources.tsv').write_text(index)
metadata = pathlib.Path('/out/source-metadata'); metadata.mkdir(exist_ok=True)
import shutil
for p in pathlib.Path('/var/cache/dnf').rglob('repomd.xml'):
    shutil.copyfile(p,metadata/(p.parent.parent.name+'-repomd.xml'))
PY
createrepo_c /out/rpms
'''
    (destination / "common.json").write_text(json.dumps(COMMON))
    image_pin = STAGING_IMAGE
    print("preparing signed RPM closures and runtime archives", flush=True)
    result = subprocess.run(["docker", "run", "--rm", "--platform", "linux/amd64",
        "-v", f"{destination}:/out", "-v", f"{destination / 'keys'}:/keys:ro",
        "-v", f"{destination / 'rke2.repo'}:/etc/yum.repos.d/rke2.repo:ro", image_pin,
        "bash", "-c", script], capture_output=True, text=True)
    (destination / "staging.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise ImageError("RPM preparation failed; see " + str(destination / "staging.log"))
    run(["docker", "pull", "--platform", "linux/amd64", "busybox:1.37.0"])
    workload = json.loads(run(["docker", "image", "inspect", "busybox:1.37.0"]))[0]
    run(["docker", "save", "--output", destination / "runtime/validation-workload.tar", "busybox:1.37.0"])
    workload_pin = workload_reference(destination / 'runtime/validation-workload.tar')
    # Copy only explicitly selected public build inputs, never credentials/state.
    recipe = destination / "recipe/lab/packer"
    recipe.mkdir(parents=True)
    for path in (ROOT / "lab/packer").glob("*"):
        if path.suffix in {".py", ".hcl"}:
            shutil.copyfile(path, recipe / path.name)
    manifest = {"schema": 1, "kind": "input", "versions": VERSIONS, "vendor_fingerprints": keys,
        "source_image_sha256": config["image"]["sha256"], "staging_container": image_pin,
        "packages": json.loads((destination / "packages.json").read_text()),
        "validation_image": workload_pin, "validation_image_digests": workload["RepoDigests"],
        "files": inventory(destination)}
    write_json(destination / "input.json", manifest)
    sign(destination / "input.json")
    print("signed input lock: " + str(destination / "input.json"), flush=True)
    return destination / "input.json"


def rebind_recipe(source, destination):
    """New signed generation from verified cached inputs; never rewrite old locks."""
    source, destination = Path(source).resolve(), Path(destination).resolve()
    manifest = verify_manifest(source)
    if manifest.get("kind") != "input" or manifest["versions"] != VERSIONS:
        raise ImageError("cached lock is not a matching input generation")
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    for name in manifest["files"]:
        if name.startswith("recipe/"):
            continue
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(source.parent / name, target)
        except OSError:
            shutil.copyfile(source.parent / name, target)
    recipe = destination / "recipe/lab/packer"
    recipe.mkdir(parents=True)
    for path in (ROOT / "lab/packer").glob("*"):
        if path.suffix in {".py", ".hcl"}:
            shutil.copyfile(path, recipe / path.name)
    manifest["parent_input_sha256"] = digest(source)
    manifest['validation_image'] = workload_reference(destination / 'runtime/validation-workload.tar')
    manifest["files"] = inventory(destination)
    write_json(destination / "input.json", manifest)
    sign(destination / "input.json")
    print("signed input recipe generation: " + str(destination / "input.json"), flush=True)


def workload_reference(path):
    with tarfile.open(path) as archive:
        index = json.load(archive.extractfile('index.json'))
        descriptor = index['manifests'][0]
        return 'docker.io/library/busybox@' + descriptor['digest']
