"""Offline build, validated release publication and input archive handling."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid
from pathlib import Path

from .artifacts import CREDENTIALS, GIB, PROFILES, ROOT, STATE, VERSIONS, ImageError, digest, inventory, preflight, relative_file, run, sign, verify_manifest, write_json


def unpack_bundle(path):
    """Never extract links, special files, duplicate paths, or traversal entries."""
    path = Path(path).resolve()
    if path.suffix != ".tar":
        return path
    output = STATE / ("unpacked-" + digest(path)[:16])
    if output.exists():
        verify_manifest(output / "input.json")
        return output / "input.json"
    output.mkdir(parents=True, mode=0o700)
    try:
        with tarfile.open(path) as archive:
            names = set()
            members = archive.getmembers()
            if sum(member.size for member in members) > 16 * GIB:
                raise ImageError("input bundle exceeds 16 GiB")
            for member in members:
                if (not member.isfile() or Path(member.name).is_absolute() or ".." in Path(member.name).parts
                        or member.name in names or not member.name):
                    raise ImageError("unsafe bundle member")
                names.add(member.name)
            preflight(extra_disk=sum(member.size for member in members))
            archive.extractall(output, members=members, filter="data")
        verify_manifest(output / "input.json")
        return output / "input.json"
    except Exception:
        shutil.rmtree(output)
        raise


def copy_link(source, destination):
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)
    return destination


def seed_for_build(input_path, work):
    manifest = verify_manifest(input_path)
    root = input_path.parent
    key = work / "ssh-key"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
    seed = work / "seed"
    seed.mkdir()
    payload = seed / "payload"
    payload.mkdir()
    for directory in ("keys", "rpms", "runtime", "node"):
        shutil.copytree(root / directory, payload / directory, copy_function=copy_link)
    shutil.copyfile(root / "recipe/lab/packer/guest.py", payload / "guest.py")
    metadata = {key: manifest[key] for key in ("versions", "packages", "validation_image")}
    metadata["input_sha256"] = digest(input_path)
    write_json(payload / "input-metadata.json", metadata)
    instance = str(uuid.uuid4())
    (seed / "meta-data").write_text("instance-id: " + instance + "\nlocal-hostname: packer-build\n")
    userdata = {"hostname": "packer-build", "preserve_hostname": False, "disable_root": True,
        "ssh_deletekeys": True, "users": [{"name": "packer", "shell": "/bin/bash", "lock_passwd": True,
            "sudo": ["ALL=(ALL) NOPASSWD: ALL"], "ssh_authorized_keys": [key.with_suffix(".pub").read_text().strip()]}],
        "package_update": False, "package_upgrade": False,
        "bootcmd": [["mkdir", "-p", "/mnt/packer"], ["mount", "-o", "ro", "/dev/disk/by-label/cidata", "/mnt/packer"]]}
    (seed / "user-data").write_text("#cloud-config\n" + json.dumps(userdata, indent=2))
    return seed, key


def build(input_path, output):
    input_path = unpack_bundle(input_path)
    manifest = verify_manifest(input_path)
    if manifest.get("kind") != "input" or manifest["versions"] != VERSIONS:
        raise ImageError("input version/profile selection differs from supported pins")
    required = ('source/rocky.qcow2', 'tools/packer', 'keys/rocky.key', 'keys/rancher.key',
                'rpms/repodata/repomd.xml', 'runtime/rke2-images-core.linux-amd64.tar.zst',
                'runtime/rke2-images-flannel.linux-amd64.tar.zst', 'runtime/validation-workload.tar',
                'recipe/lab/packer/guest.py', 'recipe/lab/packer/image.pkr.hcl', 'recipe/lab/packer/offline.py',
                'node/host-agent', 'node/host-agent.service')
    if any(name not in manifest['files'] for name in required):
        raise ImageError('input bundle missing required offline payloads')
    if not re.fullmatch(r'docker.io/library/busybox@sha256:[0-9a-f]{64}', manifest.get('validation_image', '')):
        raise ImageError('validation workload must be digest pinned')
    if set(manifest.get('packages', {})) != set(PROFILES):
        raise ImageError('input RPM profile closures incomplete')
    if manifest.get('capabilities'):
        capability_path = 'node/capabilities.json'
        if (capability_path not in manifest['files']
                or json.loads((input_path.parent / capability_path).read_text()).get('capabilities') != manifest['capabilities']):
            raise ImageError('input capabilities are not bound to the signed node payload')
    output = Path(output).resolve()
    if output.exists():
        raise ImageError("build output already exists; refusing overwrite")
    payload_size = sum(pin['size'] for name, pin in manifest['files'].items()
                       if name.startswith(('keys/', 'rpms/', 'runtime/')))
    build_budget = 84 * GIB + 2 * payload_size
    preflight(extra_disk=build_budget, extra_memory_mib=8192)
    output.mkdir(parents=True, mode=0o700)
    work = output / "workspace"
    work.mkdir()
    (work / 'tmp').mkdir()
    tool_root = input_path.parent / "tools"
    packer = relative_file(input_path.parent, "tools/packer")
    packer.chmod(0o755)
    plugin = next(tool_root.glob("packer-plugin-qemu_v1.1.4*"))
    plugin.chmod(0o755)
    env = os.environ.copy()
    config = work / "packer.config"
    config.write_text("{}\n")
    env.update({"CHECKPOINT_DISABLE": "1", "PACKER_NO_COLOR": "1", "PACKER_PLUGIN_PATH": str(work / "plugins"),
                "PACKER_CONFIG": str(config), "XDG_CONFIG_HOME": str(work / "config"), 'TMPDIR': str(work / 'tmp'),
                "PACKER_CACHE_DIR": str(work / "cache"), "AUTONOMOUS_IMAGE_TRUST_DIR": str(CREDENTIALS)})
    # No plugin registry lookup: install the checksummed binary from the bundle.
    offline_prefix = ["sudo", "-n", "--preserve-env=TMPDIR,PACKER_CONFIG,XDG_CONFIG_HOME,PACKER_PLUGIN_PATH,PACKER_CACHE_DIR,CHECKPOINT_DISABLE,PACKER_NO_COLOR,AUTONOMOUS_IMAGE_TRUST_DIR",
                      "unshare", "--net", "--fork", sys.executable,
                      str(input_path.parent / "recipe/lab/packer/offline.py"), "--uid", str(os.getuid()), "--gid", str(os.getgid()),
                      "--groups", ",".join(str(group) for group in os.getgroups()), "--"]
    run([*offline_prefix, str(packer), "plugins", "install", "--path", str(plugin), "github.com/hashicorp/qemu"], env=env)
    profiles = {}
    try:
        for profile in PROFILES:
            preflight(extra_disk=build_budget, extra_memory_mib=8192)
            profile_work = work / profile
            profile_work.mkdir()
            seed, key = seed_for_build(input_path, profile_work)
            source = input_path.parent / "source/rocky.qcow2" if profile == "os" else output / "os.qcow2"
            variables = {"source_image": str(source), "source_sha256": digest(source), "seed_dir": str(seed),
                "output_dir": str(profile_work / "qemu"), "inventory_path": str(output / (profile + "-inventory.json")),
                "ssh_key": str(key), "profile": profile}
            write_json(profile_work / "variables.json", variables)
            command = [*offline_prefix, str(packer), "build", "-on-error=cleanup", "-var-file=" + str(profile_work / "variables.json"),
                       str(input_path.parent / "recipe/lab/packer/image.pkr.hcl")]
            print("building offline profile: " + profile, flush=True)
            with (output / (profile + "-build.log")).open("w") as log:
                result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                raise ImageError(f"Packer {profile} failed; inspect {output / (profile + '-build.log')}")
            image = output / (profile + ".qcow2")
            run(["qemu-img", "convert", "-O", "qcow2", profile_work / "qemu/image.qcow2", image])
            info = json.loads(run(["qemu-img", "info", "--output=json", image]))
            if info["format"] != "qcow2" or info.get("backing-filename") or info["virtual-size"] != 32 * GIB or image.stat().st_size > 16 * GIB:
                raise ImageError("built image violates format/backing/size limits")
            profiles[profile] = {"file": image.name, "sha256": digest(image), "size": image.stat().st_size,
                "virtual_size": info["virtual-size"], "firewalld": "active" if profile == "os" else "disabled"}
            shutil.rmtree(profile_work)
        shutil.rmtree(work)
        files = inventory(output)
        candidate = {"schema": 1, "kind": "candidate", "versions": VERSIONS, "profiles": profiles,
                     "input_sha256": digest(input_path), "files": files, "offline_build": True,
                     "capabilities": manifest.get('capabilities', [])}
        write_json(output / "candidate.json", candidate)
        sign(output / "candidate.json")
        print("signed candidate: " + str(output / "candidate.json"), flush=True)
    except Exception:
        for profile in PROFILES:
            for suffix in ('', '.pub'):
                (work / profile / ('ssh-key' + suffix)).unlink(missing_ok=True)
        print("build failed; unpublished workspace retained for diagnosis", flush=True)
        raise


def test(input_path, output):
    from .runtime import test_candidate
    test_candidate(Path(input_path).resolve(), Path(output).resolve())


def validate_scaling_evidence(candidate, report):
    if 'membership-reconciliation-v1' not in candidate.get('capabilities', []):
        return
    evidence = report.get('scaling', {})
    required = {(3, 3), (5, 5), (7, 7), (8, 7), (5, 3), (2, 3), (1, 3)}
    covered = {(case.get('nodes'), case.get('control_nodes')) for case in evidence.get('cases', [])}
    if (evidence.get('passed') is not True
            or evidence.get('same_image_sha256') != candidate['profiles']['node']['sha256']
            or not required.issubset(covered)
            or any(evidence.get(key) is not True for key in
                   ('blocked_drain_preserved_vm', 'forced_drain_validated', 'source_inputs_preserved'))):
        raise ImageError('scaling-capable release requires complete signed scaling acceptance for this disk')


def validate_healing_evidence(candidate, report):
    if 'control-self-healing-v1' not in candidate.get('capabilities', []):
        return
    evidence = report.get('self_healing') or {}
    required = ('short_shutdown_preserved', 'worker_promoted', 'return_as_worker',
                'repeated_failure', 'controller_failover', 'partition_reconnect',
                'simultaneous_reboot', 'protected_drain', 'lost_quorum_blocked',
                'stable_cluster_identity', 'exact_voters', 'workload_connectivity',
                'source_inputs_preserved')
    if (evidence.get('passed') is not True
            or evidence.get('same_image_sha256') != candidate['profiles']['node']['sha256']
            or any(evidence.get(name) is not True for name in required)):
        raise ImageError('successful self-healing acceptance evidence missing or for another image')


def publish(input_path, output):
    input_path = Path(input_path).resolve()
    candidate = verify_manifest(input_path)
    if candidate.get("kind") != "candidate":
        raise ImageError("publication requires a signed candidate")
    if set(candidate.get('profiles', {})) != set(PROFILES):
        raise ImageError('candidate must contain OS base and universal node profiles')
    for profile in PROFILES:
        pin = candidate['profiles'][profile]
        if pin.get('firewalld') != ('active' if profile == 'os' else 'disabled'):
            raise ImageError('candidate profile policy differs')
        if candidate['files'].get(pin['file']) != {'sha256': pin['sha256'], 'size': pin['size']}:
            raise ImageError('candidate profile does not bind signed file inventory')
    test_path = input_path.parent / "validation.json"
    from .artifacts import trust, verify_signature
    fingerprint, keyring = trust()
    verify_signature(test_path, keyring, fingerprint)
    report = json.loads(test_path.read_text())
    if report.get("passed") is not True or report.get("candidate_sha256") != digest(input_path):
        raise ImageError("successful validation does not bind this candidate")
    if report.get('formation', {}).get('passed') is not True or report['formation'].get('same_image_sha256') != candidate['profiles']['node']['sha256']:
        raise ImageError('universal node formation validation missing or for another image')
    validate_scaling_evidence(candidate, report)
    validate_healing_evidence(candidate, report)
    output = Path(output).resolve()
    if output.exists():
        raise ImageError("release destination already exists")
    preflight(extra_disk=sum(profile["size"] for profile in candidate["profiles"].values()))
    output.mkdir(parents=True, mode=0o755)
    for profile in PROFILES:
        shutil.copyfile(relative_file(input_path.parent, candidate["profiles"][profile]["file"]), output / (profile + ".qcow2"))
        shutil.copyfile(input_path.parent / (profile + "-inventory.json"), output / (profile + "-inventory.json"))
    shutil.copyfile(test_path, output / "validation.json")
    release = {"schema": 1, "kind": "release", "versions": VERSIONS, "profiles": candidate["profiles"],
               "input_sha256": candidate["input_sha256"], "candidate_sha256": digest(input_path),
               "validation_sha256": digest(test_path), "files": inventory(output),
               "capabilities": candidate.get('capabilities', [])}
    release['host_tools'] = {name: run([name, '--version']).splitlines()[0]
                             for name in ('qemu-system-x86_64', 'qemu-img', 'virsh', 'gpgv')}
    release['firmware_sha256'] = {name: digest(Path('/usr/share/OVMF') / name)
                                 for name in ('OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd')}
    write_json(output / "release.json", release)
    sign(output / "release.json")
    os.chmod(output / 'release.json', 0o644)
    print("published signed release: " + str(output / "release.json"), flush=True)


def export(input_path, output):
    """Export the verified universal disk for physical-host imaging; never touch a device."""
    input_path, output = Path(input_path).resolve(), Path(output).absolute()
    release = verify_manifest(input_path)
    if release.get('kind') != 'release' or 'node' not in release.get('profiles', {}):
        raise ImageError('raw export requires a published universal node release')
    pin = release['profiles']['node']
    if release['files'].get(pin['file']) != {'sha256': pin['sha256'], 'size': pin['size']}:
        raise ImageError('node profile differs from signed inventory')
    image = relative_file(input_path.parent, pin['file'])
    info = json.loads(run(['qemu-img', 'info', '--output=json', image]))
    if info['format'] != 'qcow2' or info.get('backing-filename') or info['virtual-size'] != 32 * GIB:
        raise ImageError('node disk is not a standalone supported image')
    if output.exists() or output.is_symlink():
        raise ImageError('export destination already exists')
    preflight(extra_disk=info['virtual-size'])
    output.mkdir(mode=0o755)
    raw = output / 'node.raw'
    run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw', image, raw])
    exported = json.loads(run(['qemu-img', 'info', '--output=json', raw]))
    if exported['format'] != 'raw' or exported['virtual-size'] != info['virtual-size']:
        raise ImageError('exported raw geometry differs')
    run(['qemu-img', 'compare', '-f', 'qcow2', '-F', 'raw', image, raw])
    shutil.copyfile(input_path, output / 'source-release.json')
    shutil.copyfile(str(input_path) + '.sig', output / 'source-release.json.sig')
    manifest = {'schema': 1, 'kind': 'raw-node', 'source_release_sha256': digest(input_path),
                'source_node_sha256': pin['sha256'], 'virtual_size': info['virtual-size'],
                'files': inventory(output), 'capabilities': release.get('capabilities', [])}
    write_json(output / 'export.json', manifest)
    sign(output / 'export.json')
    print('signed universal raw disk: ' + str(output / 'export.json'), flush=True)
