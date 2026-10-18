from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


class LabError(ValueError):
    """Raised when lab configuration is unsafe or conflicts with the host."""


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_MAC = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_FINGERPRINT = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_MEMORY_RESERVE_MIB = 32 * 1024
_UEFI_CODE = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
_UEFI_VARS = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")


def _names(inventory: dict[str, Any], kind: str) -> set[str]:
    return {str(item) for item in inventory.get(kind, set())}


def _require_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise LabError(f"invalid {label}: {value!r}")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise LabError(f"{label} must be a positive integer")
    return value


def verify_image_artifacts(image: dict[str, Any]) -> bool:
    """Verify a local image against a checksum file signed by the pinned key."""
    if image.get("kind", "upstream") == "derived":
        verify_derived_image(image)
        return True
    if image.get("kind", "upstream") != "upstream":
        raise LabError("unsupported image kind")
    staged_path = image.get("staged_path")
    if isinstance(staged_path, str) and Path(staged_path).is_file():
        source_path = Path(staged_path)
    else:
        source_path = Path(str(image.get("path", "")))
    required_paths = {
        "path": source_path,
        "checksum_path": image.get("checksum_path"),
        "signature_path": image.get("signature_path"),
        "keyring_path": image.get("keyring_path"),
    }
    paths: dict[str, Path] = {}
    for name, raw_path in required_paths.items():
        if not isinstance(raw_path, (str, Path)) or not str(raw_path):
            raise LabError(f"image {name} is not configured")
        paths[name] = Path(raw_path)
        if not paths[name].is_file():
            raise LabError(f"image {name} does not exist")

    image_name = image.get("name")
    expected_sha256 = image.get("sha256")
    fingerprint = image.get("signing_fingerprint")
    max_size_bytes = _positive_int(image.get("max_size_bytes"), "image.max_size_bytes")
    if not isinstance(image_name, str) or Path(image_name).name != image_name:
        raise LabError("image.name must be a basename")
    if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
        raise LabError("image SHA-256 is not pinned")
    if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
        raise LabError("image signing-key fingerprint is not pinned")
    if paths["path"].stat().st_size > max_size_bytes:
        raise LabError("image exceeds the configured maximum size")

    try:
        result = subprocess.run(
            [
                "gpgv",
                "--status-fd=1",
                "--keyring",
                str(paths["keyring_path"]),
                str(paths["signature_path"]),
                str(paths["checksum_path"]),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise LabError(f"could not run gpgv: {exc}") from exc
    if result.returncode != 0:
        raise LabError("image checksum signature verification failed")

    pinned = fingerprint.upper()
    valid_signers: set[str] = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "[GNUPG:]" and fields[1] == "VALIDSIG":
            valid_signers.add(fields[2].upper())
            if _FINGERPRINT.fullmatch(fields[-1]):
                valid_signers.add(fields[-1].upper())
    if pinned not in valid_signers:
        raise LabError("image checksum signer fingerprint does not match the pinned fingerprint")

    checksum_matches: list[str] = []
    checksum_patterns = (
        re.compile(r"^SHA256\s*\((.+)\)\s*=\s*([0-9a-fA-F]{64})$", re.IGNORECASE),
        re.compile(r"^([0-9a-fA-F]{64})\s+[* ](.+)$"),
    )
    for raw_line in paths["checksum_path"].read_text().splitlines():
        line = raw_line.strip()
        for index, pattern in enumerate(checksum_patterns):
            match = pattern.fullmatch(line)
            if not match:
                continue
            filename, digest = (match.group(1), match.group(2)) if index == 0 else (match.group(2), match.group(1))
            if filename == image_name:
                checksum_matches.append(digest.lower())
    if len(checksum_matches) != 1:
        raise LabError("signed checksum file must contain exactly one entry for the pinned image")
    if checksum_matches[0] != expected_sha256.lower():
        raise LabError("pinned image SHA-256 does not match the signed checksum")

    actual_digest = hashlib.sha256()
    with paths["path"].open("rb") as image_file:
        for chunk in iter(lambda: image_file.read(1024 * 1024), b""):
            actual_digest.update(chunk)
    if actual_digest.hexdigest() != expected_sha256.lower():
        raise LabError("local image SHA-256 does not match the signed checksum")
    return True


def verify_derived_image(image: dict[str, Any]) -> dict[str, Any]:
    """Bind selected profile to an independently trusted, immutable release."""
    from lab.packer.artifacts import ImageError, VERSIONS, digest, verify_manifest
    try:
        path = Path(image['release_manifest']).resolve()
        if digest(path) != image['release_sha256']:
            raise LabError('release manifest digest differs from deployment pin')
        release = verify_manifest(path, image['keyring_path'], image['signing_fingerprint'])
        if release.get('kind') != 'release' or release.get('versions') != VERSIONS:
            raise LabError('incompatible derived image release')
        profile = image['profile']
        pin = release['profiles'][profile]
        if release['files'].get(pin['file']) != {'sha256': pin['sha256'], 'size': pin['size']}:
            raise LabError('release profile differs from signed file inventory')
        expected = 'active' if profile == 'os' else 'disabled'
        if profile not in ('os', 'server', 'agent', 'node') or pin['firewalld'] != expected:
            raise LabError('release profile firewalld policy invalid')
        if image.get('firewalld', expected) != expected:
            raise LabError('deployment cannot override profile firewalld policy')
        if pin['sha256'] != image['sha256'] or digest(Path(image.get('staged_path', image['path']))) != pin['sha256']:
            raise LabError('derived image digest differs from signed profile')
        inspect_qcow2_image(image.get('staged_path', image['path']), 32 * 1024**3)
        if pin['size'] > 16 * 1024**3:
            raise LabError('derived image exceeds maximum file size')
        return release
    except (KeyError, OSError, ImageError) as exc:
        raise LabError('derived image verification failed: ' + str(exc)) from exc


def inspect_qcow2_image(
    image_path: str | Path,
    max_virtual_size_bytes: int,
    *,
    runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Inspect image format and bound its guest-visible capacity before import."""
    if runner is None:
        runner = subprocess.run
    maximum = _positive_int(max_virtual_size_bytes, "image.max_virtual_size_bytes")
    try:
        result = runner(
            ["qemu-img", "info", "--output=json", str(image_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise LabError(f"qemu-img could not inspect the staged base image: {exc}") from exc
    if getattr(result, "returncode", 0) != 0:
        raise LabError("qemu-img could not inspect the staged base image")
    try:
        info = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise LabError("qemu-img returned invalid JSON for the staged base image") from exc
    if not isinstance(info, dict) or info.get("format") != "qcow2":
        raise LabError("staged base image must be qcow2")
    if info.get("backing-filename"):
        raise LabError("staged base image must not have an external backing file")
    virtual_size = info.get("virtual-size")
    if isinstance(virtual_size, bool) or not isinstance(virtual_size, int) or virtual_size <= 0:
        raise LabError("staged base image has an invalid virtual size")
    if virtual_size > maximum:
        raise LabError("staged base image virtual size exceeds the configured maximum")
    return info


def build_plan(
    config: dict[str, Any],
    inventory: dict[str, Any],
    host_routes: list[str],
    available_memory_mib: int,
    available_disk_bytes: int,
    *,
    image_verified: bool = False,
) -> dict[str, Any]:
    """Validate config against a read-only host snapshot and return a plan.

    This function has no host side effects. It intentionally refuses forwarding,
    host bridge addresses, DHCP, resource-name collisions, route overlap, and
    allocations that violate configured host reserves.
    """
    if not isinstance(config, dict):
        raise LabError("configuration must be a JSON object")

    network = config.get("network")
    storage = config.get("storage")
    image = config.get("image")
    nodes = config.get("nodes")
    if not isinstance(network, dict):
        raise LabError("network must be an object")
    if not isinstance(storage, dict):
        raise LabError("storage must be an object")
    if not isinstance(image, dict):
        raise LabError("image must be an object")
    if not isinstance(nodes, list) or not nodes:
        raise LabError("nodes must be a non-empty list")

    network_name = _require_name(network.get("name"), "network name")
    bridge_name = _require_name(network.get("bridge"), "bridge name")
    if len(bridge_name) > 15:
        raise LabError("bridge name exceeds Linux's 15-character interface limit")
    pool_name = _require_name(storage.get("pool"), "pool name")
    storage_path = storage.get("path")
    if not isinstance(storage_path, str) or not storage_path.startswith("/"):
        raise LabError("storage path must be absolute")
    if network.get("forward_mode") != "none" or network.get("dhcp") is not False:
        raise LabError("strict lab network must disable forwarding and DHCP")
    if network.get("host_address") is not None:
        raise LabError("strict lab network must not assign an IP address to the host bridge")

    cidr = network.get("cidr")
    if not isinstance(cidr, str):
        raise LabError("network.cidr must be a string")
    try:
        subnet = ipaddress.ip_network(cidr, strict=True)
    except (TypeError, ValueError) as exc:
        raise LabError(f"invalid lab CIDR: {exc}") from exc
    if subnet.version != 4:
        raise LabError("initial lab supports only an IPv4 subnet")
    observed_networks = [(route, "host route") for route in host_routes]
    observed_networks.extend((str(item), "existing libvirt network") for item in inventory.get("network_cidrs", []))
    for route_text, source in observed_networks:
        try:
            route = ipaddress.ip_network(route_text, strict=False)
        except ValueError as exc:
            raise LabError(f"invalid observed {source} {route_text!r}") from exc
        if route.version == subnet.version and route.prefixlen != 0 and subnet.overlaps(route):
            raise LabError(f"lab CIDR {subnet} overlaps {source} {route}")

    existing = {
        "network": _names(inventory, "networks"),
        "pool": _names(inventory, "pools"),
        "domain": _names(inventory, "domains"),
        "links": _names(inventory, "links"),
    }
    if bridge_name in existing["links"]:
        raise LabError(f"network bridge {bridge_name!r} already exists as a host link")
    for kind, name in (("network", network_name), ("pool", pool_name)):
        if name in existing[kind]:
            raise LabError(f"libvirt {kind} {name!r} already exists")
    target_path = Path(storage_path).resolve(strict=False)
    image_name = image.get("name")
    image_target = Path(str(image.get("path", ""))).resolve(strict=False)
    if (
        not isinstance(image_name, str)
        or Path(image_name).name != image_name
        or image_target.parent != target_path
        or image_target.name != image_name
    ):
        raise LabError("image path must be the configured image.name at the storage pool root")
    for path_text in inventory.get("pool_paths", []):
        existing_path = Path(str(path_text)).resolve(strict=False)
        if target_path == existing_path or target_path in existing_path.parents or existing_path in target_path.parents:
            raise LabError(f"storage path {target_path} overlaps existing pool path {existing_path}")

    node_names: list[str] = []
    host_ids: list[str] = []
    macs: list[str] = []
    addresses: list[str] = []
    normalized_nodes: list[dict[str, Any]] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise LabError(f"nodes[{index}] must be an object")
        name = _require_name(node.get("name"), f"nodes[{index}].name")
        if name in existing["domain"]:
            raise LabError(f"libvirt domain {name!r} already exists")
        host_id = node.get("host_id")
        if not isinstance(host_id, str) or not host_id.strip():
            raise LabError(f"nodes[{index}].host_id must be non-empty")
        try:
            parsed_host_id = uuid.UUID(host_id)
        except ValueError as exc:
            raise LabError(f"nodes[{index}].host_id must be a canonical UUIDv4") from exc
        if str(parsed_host_id) != host_id.lower() or parsed_host_id.version != 4:
            raise LabError(f"nodes[{index}].host_id must be a canonical UUIDv4")
        mac = node.get("mac")
        if not isinstance(mac, str) or not _MAC.fullmatch(mac):
            raise LabError(f"nodes[{index}].mac must be a six-octet MAC address")
        raw_address = node.get("address")
        if not isinstance(raw_address, str):
            raise LabError(f"nodes[{index}].address must be a string")
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise LabError(f"nodes[{index}].address is invalid") from exc
        if address.version != 4 or address not in subnet or address in (subnet.network_address, subnet.broadcast_address):
            raise LabError(f"nodes[{index}].address must be a usable address in {subnet}")
        role = node.get("role")
        if role not in {"server", "agent", "auto"}:
            raise LabError(f"nodes[{index}].role must be server, agent, or auto")
        if role == 'auto' and image.get('profile') != 'node':
            raise LabError('automatic role selection requires universal node image')
        vcpus = _positive_int(node.get("vcpus"), f"nodes[{index}].vcpus")
        memory_mib = _positive_int(node.get("memory_mib"), f"nodes[{index}].memory_mib")
        disk_gib = _positive_int(node.get("disk_gib"), f"nodes[{index}].disk_gib")
        node_names.append(name)
        host_ids.append(host_id)
        macs.append(mac.lower())
        addresses.append(str(address))
        normalized_nodes.append({
            "name": name,
            "host_id": host_id,
            "mac": mac.lower(),
            "address": str(address),
            "role": role,
            "vcpus": vcpus,
            "memory_mib": memory_mib,
            "disk_gib": disk_gib,
            **({"profile": image["profile"], "release_sha256": image["release_sha256"],
                "firewalld": "active" if image["profile"] == "os" else "disabled"} if image.get("kind") == "derived" else {}),
        })
        if image.get('kind') == 'derived':
            if image['profile'] == 'node' and role != 'auto':
                raise LabError('universal node image determines its role at boot; use auto')
            if image['profile'] not in ('os', 'node') and role != image['profile']:
                raise LabError('node role does not match derived image profile')
            if node.get('profile', image['profile']) != image['profile'] or node.get('release_sha256', image['release_sha256']) != image['release_sha256']:
                raise LabError('node profile/release differs from immutable deployment pin')
            if node.get('firewalld', normalized_nodes[-1]['firewalld']) != normalized_nodes[-1]['firewalld']:
                raise LabError('node cannot override image firewalld policy')

    for label, values in (("name", node_names), ("host_id", host_ids), ("MAC", macs), ("address", addresses)):
        if len(set(values)) != len(values):
            raise LabError(f"duplicate node {label}")

    totals = {
        "vcpus": sum(node["vcpus"] for node in normalized_nodes),
        "memory_mib": sum(node["memory_mib"] for node in normalized_nodes),
        "disk_gib": sum(node["disk_gib"] for node in normalized_nodes),
    }
    minimum_free_bytes = _positive_int(storage.get("minimum_free_bytes"), "storage.minimum_free_bytes")
    image_max_bytes = _positive_int(image.get("max_size_bytes"), "image.max_size_bytes")
    image_max_virtual_bytes = _positive_int(image.get("max_virtual_size_bytes"), "image.max_virtual_size_bytes")
    memory_reserve_mib = _positive_int(config.get("minimum_host_memory_reserve_mib", _MEMORY_RESERVE_MIB), "minimum_host_memory_reserve_mib")
    if totals["memory_mib"] + memory_reserve_mib > available_memory_mib:
        raise LabError("VM memory allocation would violate host memory reserve")
    requested_disk_bytes = totals["disk_gib"] * 1024**3
    max_base_storage_bytes = max(image_max_bytes, image_max_virtual_bytes)
    maximum_project_storage_bytes = requested_disk_bytes + max_base_storage_bytes
    projected_free_bytes = available_disk_bytes - maximum_project_storage_bytes
    if maximum_project_storage_bytes + minimum_free_bytes > available_disk_bytes:
        raise LabError("VM disks and image download would violate host storage reserve")

    blockers: list[str] = []
    if not isinstance(image.get("sha256"), str) or not _SHA256.fullmatch(image["sha256"]):
        blockers.append("base image SHA-256 is not pinned")
    if not image_verified:
        blockers.append("base image checksum signature has not been verified")
    image_path = Path(str(image.get("path", "")))
    staged_path = image.get("staged_path")
    image_source_path = Path(staged_path) if isinstance(staged_path, str) and Path(staged_path).is_file() else image_path
    if not image_source_path.is_file():
        blockers.append("base image has not been staged to the configured path")
    elif image_source_path.stat().st_size > image_max_bytes:
        blockers.append("base image exceeds the configured maximum size")
    public_key = config.get("ssh_public_key_file")
    if not isinstance(public_key, str) or not Path(public_key).is_file():
        blockers.append("a lab SSH public key file is not configured")

    return {
        "network": {
            "name": network_name,
            "bridge": bridge_name,
            "cidr": str(subnet),
            "forward_mode": "none",
            "host_address": None,
            "dhcp": False,
        },
        "storage": {"pool": pool_name, "path": storage_path},
        "image": {
            "name": image.get("name"),
            "path": image.get("path"),
            "staged_path": image.get("staged_path"),
        },
        "nodes": normalized_nodes,
        "node_names": node_names,
        "totals": totals,
        "storage_budget": {
            "available_bytes": available_disk_bytes,
            "max_project_bytes": maximum_project_storage_bytes,
            "projected_free_bytes": projected_free_bytes,
            "minimum_free_bytes": minimum_free_bytes,
        },
        "memory_budget": {
            "available_mib": available_memory_mib,
            "guest_mib": totals["memory_mib"],
            "minimum_host_reserve_mib": memory_reserve_mib,
        },
        "apply_blockers": blockers,
        "actions_if_approved": [
            "verify the pre-staged pinned Rocky GenericCloud image and qcow2 metadata",
            "define and start the isolated libvirt L2 network (no forwarding, host IP, or DHCP)",
            "define and start a new directory storage pool and upload the verified base image",
            "create one qcow2 overlay per node with a bounded virtual capacity",
            "provision the listed VMs with per-node cloud-init network and identity data",
        ],
    }


def render_cloud_init(
    node: dict[str, Any],
    cidr: str,
    ssh_public_key: str,
    template_dir: Path,
) -> dict[str, str]:
    """Render per-VM cloud-init files without writing secrets or host files."""
    hostname = node.get("name")
    if not isinstance(hostname, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", hostname):
        raise LabError("node hostname must be a lowercase DNS label")
    host_id = node.get("host_id")
    try:
        parsed_host_id = uuid.UUID(str(host_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise LabError("node host_id must be a UUID") from exc
    if str(parsed_host_id) != str(host_id).lower() or parsed_host_id.version != 4:
        raise LabError("node host_id must be a canonical UUIDv4")
    mac = node.get("mac")
    if not isinstance(mac, str) or not _MAC.fullmatch(mac):
        raise LabError("node MAC address is invalid")
    try:
        subnet = ipaddress.ip_network(cidr, strict=True)
        address = ipaddress.ip_address(node.get("address"))
    except (TypeError, ValueError) as exc:
        raise LabError("node address or lab CIDR is invalid") from exc
    if subnet.version != 4 or address.version != 4 or address not in subnet:
        raise LabError("node address must belong to the IPv4 lab subnet")
    if address in (subnet.network_address, subnet.broadcast_address):
        raise LabError("node address must be usable on the lab subnet")

    key_line = ssh_public_key.strip()
    key_parts = key_line.split()
    if (
        "\n" in key_line
        or "\r" in key_line
        or len(key_parts) < 2
        or key_parts[0] not in {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"}
    ):
        raise LabError("SSH public key must be one supported OpenSSH public key line")
    try:
        key_data = base64.b64decode(key_parts[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LabError("SSH public key has invalid base64 data") from exc
    if len(key_data) < 32:
        raise LabError("SSH public key data is too short")

    values = {
        "@@HOSTNAME@@": hostname,
        "@@HOST_ID@@": str(host_id),
        "@@HOST_ID_YAML@@": json.dumps(str(host_id)),
        "@@SSH_PUBLIC_KEY_YAML@@": json.dumps(ssh_public_key.strip()),
        "@@MAC_YAML@@": json.dumps(mac.lower()),
        "@@ADDRESS_YAML@@": json.dumps(f"{address}/{subnet.prefixlen}"),
        "@@PROFILE_YAML@@": json.dumps(node.get('profile', 'os')),
        "@@INSTANCE_YAML@@": json.dumps(json.dumps({"name": hostname, "host_id": host_id,
            "profile": node.get('profile', 'os'), "probe_targets": ['192.168.250.1', '1.1.1.1']})),
    }
    templates = {
        "user-data": "user-data.yaml.tmpl",
        "meta-data": "meta-data.yaml.tmpl",
        "network-config": "network-config.yaml.tmpl",
    }
    rendered: dict[str, str] = {}
    for name, filename in templates.items():
        content = (template_dir / filename).read_text()
        for placeholder, value in values.items():
            content = content.replace(placeholder, value)
        if "@@" in content:
            raise LabError(f"unresolved cloud-init placeholder in {filename}")
        rendered[name] = content
    return rendered


def _read_libvirt_names(command: str) -> set[str]:
    result = subprocess.run(
        ["virsh", "--connect", "qemu:///system", *command.split()],
        check=True,
        capture_output=True,
        text=True,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _virsh_xml(*args: str) -> ET.Element:
    result = subprocess.run(
        ["virsh", "--connect", "qemu:///system", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return ET.fromstring(result.stdout)


def _read_nwfilter_names() -> set[str]:
    result = subprocess.run(
        ["virsh", "--connect", "qemu:///system", "nwfilter-list"],
        check=True, capture_output=True, text=True,
    )
    names = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2:
            try:
                uuid.UUID(fields[0])
            except ValueError:
                continue
            names.add(fields[1])
    return names


def _read_network_cidrs(network_names: set[str]) -> list[str]:
    cidrs: list[str] = []
    for name in sorted(network_names):
        root = _virsh_xml("net-dumpxml", name)
        for ip_node in root.findall("ip"):
            address = ip_node.get("address")
            prefix = ip_node.get("prefix") or ip_node.get("netmask")
            if address and prefix:
                cidrs.append(str(ipaddress.ip_network(f"{address}/{prefix}", strict=False)))
    return cidrs


def _read_pool_paths(pool_names: set[str]) -> list[str]:
    paths: list[str] = []
    for name in sorted(pool_names):
        root = _virsh_xml("pool-dumpxml", name)
        path = root.findtext("target/path")
        if path:
            paths.append(path)
    return paths


def _read_host_links() -> set[str]:
    result = subprocess.run(["ip", "-j", "link", "show"], check=True, capture_output=True, text=True)
    links = json.loads(result.stdout)
    return {str(link["ifname"]) for link in links if link.get("ifname")}


def _read_host_routes() -> list[str]:
    result = subprocess.run(["ip", "-j", "route", "show", "table", "all"], check=True, capture_output=True, text=True)
    routes = json.loads(result.stdout)
    return [route["dst"] for route in routes if route.get("dst") and route["dst"] != "default"]


def _available_memory_mib() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) // 1024
    raise LabError("could not determine available host memory")


def _available_bytes(path: str) -> int:
    candidate = Path(path)
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    stats = os.statvfs(candidate)
    return stats.f_bavail * stats.f_frsize


def read_host_inventory() -> tuple[dict[str, Any], list[str]]:
    networks = _read_libvirt_names("net-list --all --name")
    pools = _read_libvirt_names("pool-list --all --name")
    inventory = {
        "domains": _read_libvirt_names("list --all --name"),
        "networks": networks,
        "pools": pools,
        "network_cidrs": _read_network_cidrs(networks),
        "pool_paths": _read_pool_paths(pools),
        "links": _read_host_links(),
        "nwfilters": _read_nwfilter_names(),
    }
    return inventory, _read_host_routes()


def apply_lab(
    config: dict[str, Any],
    *,
    confirmation: str,
    euid: int | None = None,
    runner: Callable[..., Any] | None = None,
) -> None:
    """Apply the exact lab only after an explicit name confirmation as root."""
    network = config.get("network")
    expected_name = network.get("name") if isinstance(network, dict) else None
    if not isinstance(expected_name, str) or confirmation != expected_name:
        raise LabError("exact network-name confirmation is required before apply")
    if euid is None:
        euid = os.geteuid()
    if euid != 0:
        raise LabError("lab apply must run as root to manage qemu:///system")
    if runner is None:
        runner = subprocess.run

    image = config.get("image")
    if not isinstance(image, dict):
        raise LabError("image configuration is required")
    verify_image_artifacts(image)
    staged_image = Path(str(image.get("staged_path", image.get("path", "")))).resolve(strict=False)
    image_info = inspect_qcow2_image(
        staged_image,
        _positive_int(image.get("max_virtual_size_bytes"), "image.max_virtual_size_bytes"),
        runner=runner,
    )
    inventory, routes = read_host_inventory()
    if "autonomous-rke2-ipv4-only" in inventory.get("nwfilters", set()):
        raise LabError("lab IPv4-only filter already exists; refusing to overwrite")
    storage = config.get("storage")
    storage_path = storage.get("path") if isinstance(storage, dict) else None
    if not isinstance(storage_path, str):
        raise LabError("storage.path must be configured")
    plan = build_plan(
        config,
        inventory,
        routes,
        _available_memory_mib(),
        _available_bytes(storage_path),
        image_verified=True,
    )
    if plan["apply_blockers"]:
        raise LabError("apply preflight blocked: " + "; ".join(plan["apply_blockers"]))

    requested_root = Path(storage_path).absolute()
    if any(candidate.is_symlink() for candidate in (requested_root, *requested_root.parents)):
        raise LabError(f"storage path contains a symlink; refusing target: {requested_root}")
    target_root = requested_root.resolve(strict=False)
    target_image = Path(str(image.get("path", ""))).resolve(strict=False)
    staged_image = Path(str(image.get("staged_path", ""))).resolve(strict=False)
    if target_root.exists() or target_root.is_symlink():
        raise LabError(f"storage target already exists; refusing to reuse: {target_root}")
    if target_image.exists() or target_image.is_symlink():
        raise LabError(f"image target already exists; refusing to overwrite: {target_image}")
    if target_root not in target_image.parents:
        raise LabError("final base image path must be inside the new storage pool")
    base_volume_name = image.get("name")
    if not isinstance(base_volume_name, str) or Path(base_volume_name).name != base_volume_name:
        raise LabError("image.name must be a basename for the libvirt base volume")
    if image.get('kind', 'upstream') != 'derived':
        raise LabError('deployment requires a signed derived-image release; upstream Rocky verification is retained for staging')

    network_xml = Path(__file__).with_name("network.xml")
    try:
        root = ET.parse(network_xml).getroot()
    except (OSError, ET.ParseError) as exc:
        raise LabError(f"could not parse isolated network XML: {exc}") from exc
    if (
        root.findtext("name") != plan["network"]["name"]
        or (root.find("bridge") is None or root.find("bridge").get("name") != plan["network"]["bridge"])
        or root.find("forward") is not None
        or root.find("ip") is not None
    ):
        raise LabError("checked-in network XML does not match the approved isolated network plan")

    public_key_path = Path(str(config["ssh_public_key_file"]))
    public_key = public_key_path.read_text()
    templates = Path(__file__).resolve().parents[1] / "cloud-init" / "rocky9"
    rendered_nodes = [
        (node, render_cloud_init(node, plan["network"]["cidr"], public_key, templates))
        for node in plan["nodes"]
    ]
    for executable in ("virsh", "virt-install", "genisoimage"):
        if shutil.which(executable) is None:
            raise LabError(f"required executable is unavailable: {executable}")
    firmware_code = _UEFI_CODE
    firmware_vars = _UEFI_VARS
    if not firmware_code.is_file() or not firmware_vars.is_file():
        raise LabError("required UEFI firmware is unavailable; no host packages were installed")

    actions: list[str] = []

    def run(command: list[str], action: str) -> Any:
        try:
            result = runner(command, check=True, capture_output=True, text=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            completed = ", ".join(actions) if actions else "none"
            raise LabError(
                f"apply interrupted at {action}: {getattr(exc, 'stderr', '') or exc}; completed actions: {completed}; "
                "inspect only the named lab resources before retrying"
            ) from exc
        if getattr(result, "returncode", 0) != 0:
            completed = ", ".join(actions) if actions else "none"
            raise LabError(
                f"apply interrupted at {action}; completed actions: {completed}; "
                "inspect only the named lab resources before retrying"
            )
        actions.append(action)
        return result

    run(
        ["virsh", "--connect", "qemu:///system", "nwfilter-define",
         str(Path(__file__).with_name("ipv4-only.xml"))],
        "define lab IPv4-only packet filter",
    )
    run(
        ["virsh", "--connect", "qemu:///system", "net-define", str(network_xml)],
        "define isolated network",
    )
    run(
        ["virsh", "--connect", "qemu:///system", "net-start", plan["network"]["name"]],
        "start isolated network",
    )
    try:
        # QEMU changes UID before opening disks; it must traverse the pool path.
        # Files remain protected by libvirt-managed ownership and permissions.
        target_root.mkdir(mode=0o711, parents=True, exist_ok=False)
    except OSError as exc:
        raise LabError(f"could not create new lab storage path {target_root}; inspect network state") from exc
    run(
        [
            "virsh",
            "--connect",
            "qemu:///system",
            "pool-define-as",
            plan["storage"]["pool"],
            "dir",
            "--target",
            str(target_root),
        ],
        "define new directory pool",
    )
    run(
        ["virsh", "--connect", "qemu:///system", "pool-start", plan["storage"]["pool"]],
        "start new directory pool",
    )
    base_volume_capacity = max(staged_image.stat().st_size, image_info["virtual-size"])
    run(
        [
            "virsh",
            "--connect",
            "qemu:///system",
            "vol-create-as",
            plan["storage"]["pool"],
            base_volume_name,
            str(base_volume_capacity),
            "--format",
            "raw",
        ],
        "create libvirt-managed base image volume",
    )
    run(
        [
            "virsh",
            "--connect",
            "qemu:///system",
            "vol-upload",
            base_volume_name,
            str(staged_image),
            "--pool",
            plan["storage"]["pool"],
            "--sparse",
        ],
        "upload verified base image into libvirt volume",
    )
    volume_path = run(
        [
            "virsh",
            "--connect",
            "qemu:///system",
            "vol-path",
            base_volume_name,
            "--pool",
            plan["storage"]["pool"],
        ],
        "resolve base image volume path",
    ).stdout.strip()
    if Path(volume_path).resolve(strict=False) != target_image:
        raise LabError("libvirt base image volume path differs from the configured target")

    with tempfile.TemporaryDirectory(prefix="rke2-cloud-init-") as seed_dir:
        seed_path = Path(seed_dir)
        for node, rendered in rendered_nodes:
            node_name = node["name"]
            volume_name = f"{node_name}.qcow2"
            run(
                [
                    "virsh",
                    "--connect",
                    "qemu:///system",
                    "vol-create-as",
                    plan["storage"]["pool"],
                    volume_name,
                    f"{node['disk_gib']}G",
                    "--format",
                    "qcow2",
                    "--backing-vol",
                    base_volume_name,
                    "--backing-vol-format",
                    "qcow2",
                ],
                f"create disk for {node_name}",
            )
            options: dict[str, str] = {}
            for item in ("user-data", "meta-data", "network-config"):
                path = seed_path / item
                path.write_text(rendered[item])
                path.chmod(0o600)
                options[item] = str(path)
            seed_iso = target_root / f"{node_name}-seed.iso"
            seed_iso.touch(mode=0o600, exist_ok=False)
            run(
                ["genisoimage", "-quiet", "-output", str(seed_iso), "-volid", "cidata",
                 "-joliet", "-rock", *options.values()],
                f"create NoCloud seed for {node_name}",
            )
            run(
                [
                    "virt-install",
                    "--connect",
                    "qemu:///system",
                    "--name",
                    node_name,
                    "--memory",
                    str(node["memory_mib"]),
                    "--vcpus",
                    str(node["vcpus"]),
                    "--disk",
                    f"vol={plan['storage']['pool']}/{volume_name},format=qcow2,bus=virtio",
                    "--disk",
                    f"path={seed_iso},device=cdrom,readonly=on",
                    "--network",
                    f"network={plan['network']['name']},model=virtio,mac={node['mac']},filterref.filter=autonomous-rke2-ipv4-only",
                    "--osinfo",
                    "rocky9",
                    "--import",
                    "--boot",
                    f"loader={firmware_code},loader.readonly=yes,loader.type=pflash,"
                    f"nvram.template={firmware_vars},nvram={target_root / (node_name + '_VARS.fd')}",
                    "--graphics",
                    "none",
                    "--channel",
                    "unix,target_type=virtio,name=org.qemu.guest_agent.0",
                    "--console",
                    "pty,target_type=serial",
                    "--noautoconsole",
                ],
                f"define and boot {node_name}",
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preflight or provision the Rocky RKE2 libvirt lab")
    parser.add_argument("--config", type=Path, default=Path("lab/libvirt/lab-config.example.json"))
    parser.add_argument("--apply", action="store_true", help="create the configured network, pool, and VMs")
    parser.add_argument("--confirm-lab", default="", help="must exactly match the configured libvirt network name")
    args = parser.parse_args(argv)
    try:
        config = json.loads(args.config.read_text())
        if args.apply:
            apply_lab(config, confirmation=args.confirm_lab)
            print("lab apply completed")
            return 0
        if args.confirm_lab:
            raise LabError("--confirm-lab is valid only with --apply")
        inventory, routes = read_host_inventory()
        path = config["storage"]["path"]
        image_verified = False
        image_verification_error = ""
        try:
            image_verified = verify_image_artifacts(config["image"])
        except (LabError, KeyError, TypeError) as exc:
            image_verification_error = str(exc)
        plan = build_plan(
            config,
            inventory,
            routes,
            _available_memory_mib(),
            _available_bytes(path),
            image_verified=image_verified,
        )
        if image_verification_error:
            plan["apply_blockers"].append(f"image verification: {image_verification_error}")
    except (OSError, json.JSONDecodeError, KeyError, subprocess.CalledProcessError, LabError) as exc:
        print(f"lab command failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
