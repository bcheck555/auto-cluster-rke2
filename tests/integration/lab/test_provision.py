from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import lab.libvirt.provision as provision
from lab.libvirt.provision import LabError, _available_bytes, build_plan, render_cloud_init


def sample_config() -> dict:
    return {
        "network": {
            "name": "autonomous-rke2-isolated",
            "bridge": "virbr-rke2",
            "cidr": "192.168.250.0/24",
            "forward_mode": "none",
            "host_address": None,
            "dhcp": False,
        },
        "storage": {
            "pool": "autonomous-rke2-lab",
            "path": "/var/lib/libvirt/images/autonomous-rke2-lab",
            "minimum_free_bytes": 300 * 1024**3,
        },
        "image": {
            "name": "rocky9.qcow2",
            "path": "/var/lib/libvirt/images/autonomous-rke2-lab/rocky9.qcow2",
            "staged_path": "lab/artifacts/rocky9.qcow2",
            "checksum_path": "lab/artifacts/rocky9.qcow2.CHECKSUM",
            "signature_path": "lab/artifacts/rocky9.qcow2.CHECKSUM.asc",
            "keyring_path": "lab/artifacts/rocky-release-keyring.gpg",
            "signing_fingerprint": "",
            "sha256": "",
            "max_size_bytes": 20 * 1024**3,
            "max_virtual_size_bytes": 20 * 1024**3,
        },
        "nodes": [
            {
                "name": f"rke2-r9-cp0{i}",
                "host_id": [
                    "2f4baedf-a8ad-4430-9126-b906e879f3b1",
                    "b0823732-a86c-4c37-a77f-334611ebc843",
                    "c55dbac3-eedc-4fc9-93d5-cd2ac3024496",
                ][i - 1],
                "mac": f"52:54:00:40:01:0{i}",
                "address": f"192.168.250.{10 + i}",
                "role": "server",
                "vcpus": 4,
                "memory_mib": 8192,
                "disk_gib": 60,
            }
            for i in range(1, 4)
        ],
    }


class CheckedInLabConfigTests(unittest.TestCase):
    def test_example_config_defines_three_unique_server_guests(self) -> None:
        root = Path(__file__).resolve().parents[3]
        config = json.loads((root / "lab/libvirt/lab-config.example.json").read_text())
        nodes = config["nodes"]
        self.assertEqual(len(nodes), 3)
        self.assertTrue(all(node["role"] == "server" for node in nodes))
        for field in ("name", "host_id", "mac", "address"):
            self.assertEqual(len({node[field] for node in nodes}), 3, field)
        self.assertEqual(config["network"]["forward_mode"], "none")
        self.assertIsNone(config["network"]["host_address"])
        self.assertFalse(config["network"]["dhcp"])

    def test_libvirt_network_xml_has_no_forward_host_ip_or_dhcp(self) -> None:
        root = Path(__file__).resolve().parents[3]
        network = ET.parse(root / "lab/libvirt/network.xml").getroot()
        self.assertEqual(network.findtext("name"), "autonomous-rke2-isolated")
        self.assertEqual(network.find("bridge").get("name"), "virbr-rke2")
        self.assertIsNone(network.find("forward"))
        self.assertIsNone(network.find("ip"))

    def test_cloud_init_templates_contain_no_join_secret_or_password(self) -> None:
        root = Path(__file__).resolve().parents[3]
        template_dir = root / "lab/cloud-init/rocky9"
        combined = "\n".join(path.read_text().lower() for path in template_dir.iterdir())
        self.assertNotIn("join-token", combined)
        self.assertNotIn("rke2-token", combined)
        self.assertNotIn("password:", combined)
        self.assertIn("renderer: networkmanager", combined)


class CloudInitRenderTests(unittest.TestCase):
    def test_renders_per_node_hostname_identity_and_isolated_static_network(self) -> None:
        node = {
            "name": "rke2-r9-cp01",
            "host_id": "c84a47bc-821c-4a79-87d4-2d092f05fce1",
            "mac": "52:54:00:40:01:01",
            "address": "192.168.250.11",
        }
        templates = Path(__file__).resolve().parents[3] / "lab" / "cloud-init" / "rocky9"
        rendered = render_cloud_init(
            node,
            "192.168.250.0/24",
            "ssh-ed25519 " + base64.b64encode(b"test-key-material" * 3).decode() + " lab-test",
            templates,
        )
        self.assertIn("hostname: rke2-r9-cp01", rendered["user-data"])
        self.assertIn(node["host_id"], rendered["user-data"])
        self.assertIn("ssh_deletekeys: true", rendered["user-data"])
        self.assertIn("instance-id: " + node["host_id"], rendered["meta-data"])
        self.assertIn(node["mac"], rendered["network-config"])
        self.assertIn("192.168.250.11/24", rendered["network-config"])
        self.assertIn("renderer: NetworkManager", rendered["network-config"])
        self.assertNotIn("gateway", rendered["network-config"].lower())
        self.assertNotIn("@@", "\n".join(rendered.values()))

    def test_accepts_one_trailing_newline_in_openssh_public_key_file(self) -> None:
        node = {
            "name": "rke2-r9-cp01",
            "host_id": "c84a47bc-821c-4a79-87d4-2d092f05fce1",
            "mac": "52:54:00:40:01:01",
            "address": "192.168.250.11",
        }
        templates = Path(__file__).resolve().parents[3] / "lab" / "cloud-init" / "rocky9"
        key = "ssh-ed25519 " + base64.b64encode(b"test-key-material" * 3).decode() + " lab-test\n"
        rendered = render_cloud_init(node, "192.168.250.0/24", key, templates)
        self.assertIn(key.strip(), rendered["user-data"])

    @unittest.skipUnless(shutil.which("cloud-init"), "cloud-init CLI not installed")
    def test_rendered_cloud_init_passes_cloud_init_schema(self) -> None:
        node = {
            "name": "rke2-r9-cp01",
            "host_id": "c84a47bc-821c-4a79-87d4-2d092f05fce1",
            "mac": "52:54:00:40:01:01",
            "address": "192.168.250.11",
        }
        root = Path(__file__).resolve().parents[3]
        template_dir = root / "lab/cloud-init/rocky9"
        key = "ssh-ed25519 " + base64.b64encode(b"test-key-material" * 3).decode() + " lab-test"
        rendered = render_cloud_init(node, "192.168.250.0/24", key, template_dir)
        with tempfile.TemporaryDirectory() as scratch:
            user_data = Path(scratch) / "user-data.yaml"
            network_config = Path(scratch) / "network-config.yaml"
            user_data.write_text(rendered["user-data"])
            network_config.write_text(rendered["network-config"])
            for path, schema_type in ((user_data, "cloud-config"), (network_config, "network-config")):
                result = subprocess.run(
                    ["cloud-init", "schema", "--config-file", str(path), "--schema-type", schema_type],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_multiline_or_unrecognized_ssh_public_key(self) -> None:
        node = {
            "name": "rke2-r9-cp01",
            "host_id": "c84a47bc-821c-4a79-87d4-2d092f05fce1",
            "mac": "52:54:00:40:01:01",
            "address": "192.168.250.11",
        }
        templates = Path(__file__).resolve().parents[3] / "lab" / "cloud-init" / "rocky9"
        with self.assertRaisesRegex(LabError, "public key"):
            render_cloud_init(node, "192.168.250.0/24", "ssh-ed25519 AAAA" + chr(10) + "malicious", templates)


class BuildPlanTests(unittest.TestCase):
    def test_produces_three_server_plan_on_non_forwarding_static_l2(self) -> None:
        plan = build_plan(
            sample_config(),
            inventory={"domains": set(), "networks": {"default"}, "pools": {"ad-hyperv-lab"}},
            host_routes=["192.168.1.0/24", "192.168.122.0/24", "172.20.0.0/16"],
            available_memory_mib=245 * 1024,
            available_disk_bytes=617 * 1024**3,
        )
        self.assertEqual(plan["totals"], {"vcpus": 12, "memory_mib": 24576, "disk_gib": 180})
        self.assertEqual(plan["network"]["forward_mode"], "none")
        self.assertIsNone(plan["network"]["host_address"])
        self.assertEqual(plan["node_names"], ["rke2-r9-cp01", "rke2-r9-cp02", "rke2-r9-cp03"])
        self.assertEqual(plan["image"]["staged_path"], "lab/artifacts/rocky9.qcow2")
        self.assertEqual(plan["storage_budget"]["projected_free_bytes"], 417 * 1024**3)
        self.assertEqual(plan["storage_budget"]["minimum_free_bytes"], 300 * 1024**3)
        self.assertEqual(plan["memory_budget"]["minimum_host_reserve_mib"], 32 * 1024)
        self.assertTrue(any("image" in item.lower() for item in plan["apply_blockers"]))

    def test_approved_action_list_does_not_claim_to_download_artifacts(self) -> None:
        plan = build_plan(sample_config(), {}, [], 245 * 1024, 617 * 1024**3)
        actions = plan["actions_if_approved"]
        self.assertFalse(any("download" in action.lower() for action in actions))
        self.assertTrue(any("staged" in action.lower() and "verify" in action.lower() for action in actions))
        self.assertTrue(any("upload" in action.lower() for action in actions))

    def test_rejects_base_image_target_outside_the_new_pool(self) -> None:
        config = sample_config()
        config["image"]["path"] = "/var/lib/libvirt/images/other.qcow2"
        with self.assertRaisesRegex(LabError, "image path"):
            build_plan(config, {}, [], 245 * 1024, 617 * 1024**3)

    def test_rejects_forwarding_or_host_address_on_isolated_network(self) -> None:
        for field, value in (("forward_mode", "nat"), ("host_address", "192.168.250.1")):
            with self.subTest(field=field):
                config = sample_config()
                config["network"][field] = value
                with self.assertRaises(LabError):
                    build_plan(config, {}, [], 245 * 1024, 617 * 1024**3)

    def test_rejects_overlap_with_existing_host_route(self) -> None:
        with self.assertRaisesRegex(LabError, "overlaps"):
            build_plan(sample_config(), {}, ["192.168.250.0/24"], 245 * 1024, 617 * 1024**3)

    def test_rejects_existing_libvirt_resource_name(self) -> None:
        inventory = {"domains": {"rke2-r9-cp02"}, "networks": set(), "pools": set()}
        with self.assertRaisesRegex(LabError, "already exists"):
            build_plan(sample_config(), inventory, [], 245 * 1024, 617 * 1024**3)

    def test_rejects_invalid_host_identity_uuid(self) -> None:
        config = sample_config()
        config["nodes"][0]["host_id"] = "not-a-uuid"
        with self.assertRaisesRegex(LabError, "UUIDv4"):
            build_plan(config, {}, [], 245 * 1024, 617 * 1024**3)

    def test_rejects_duplicate_node_identity_mac_or_address(self) -> None:
        for key in ("host_id", "mac", "address"):
            with self.subTest(key=key):
                config = sample_config()
                config["nodes"][1][key] = config["nodes"][0][key]
                with self.assertRaisesRegex(LabError, "duplicate"):
                    build_plan(config, {}, [], 245 * 1024, 617 * 1024**3)

    def test_reserves_capacity_for_image_download_and_vm_disks(self) -> None:
        with self.assertRaisesRegex(LabError, "storage reserve"):
            build_plan(sample_config(), {}, [], 245 * 1024, 499 * 1024**3)

    def test_reserves_whichever_image_limit_can_consume_more_storage(self) -> None:
        config = sample_config()
        config["image"]["max_size_bytes"] = 30 * 1024**3
        plan = build_plan(config, {}, [], 245 * 1024, 617 * 1024**3)
        self.assertEqual(plan["storage_budget"]["max_project_bytes"], 210 * 1024**3)
        self.assertEqual(plan["storage_budget"]["projected_free_bytes"], 407 * 1024**3)

    def test_respects_host_memory_and_storage_reserves(self) -> None:
        with self.assertRaisesRegex(LabError, "memory reserve"):
            build_plan(sample_config(), {}, [], 40 * 1024, 50 * 1024**3)
        with self.assertRaisesRegex(LabError, "storage reserve"):
            build_plan(sample_config(), {}, [], 245 * 1024, 400 * 1024**3)

    def test_available_bytes_reads_existing_parent_for_future_pool_path(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            missing_pool_path = Path(root) / "not-created" / "pool"
            self.assertGreater(_available_bytes(str(missing_pool_path)), 0)

    def test_rejects_overlap_with_existing_inactive_libvirt_network(self) -> None:
        inventory = {"network_cidrs": ["192.168.250.1/24"]}
        with self.assertRaisesRegex(LabError, "overlaps"):
            build_plan(sample_config(), inventory, [], 245 * 1024, 617 * 1024**3)

    def test_rejects_existing_bridge_link_name(self) -> None:
        inventory = {"links": {"virbr-rke2"}}
        with self.assertRaisesRegex(LabError, "bridge.*already exists"):
            build_plan(sample_config(), inventory, [], 245 * 1024, 617 * 1024**3)

    def test_rejects_storage_path_nested_in_existing_pool(self) -> None:
        inventory = {"pool_paths": ["/var/lib/libvirt/images"]}
        with self.assertRaisesRegex(LabError, "overlaps existing pool path"):
            build_plan(sample_config(), inventory, [], 245 * 1024, 617 * 1024**3)

    def test_does_not_mutate_input_configuration(self) -> None:
        config = sample_config()
        original = copy.deepcopy(config)
        build_plan(config, {}, [], 245 * 1024, 617 * 1024**3)
        self.assertEqual(config, original)

    def test_does_not_trust_user_set_signature_verified_flag(self) -> None:
        config = sample_config()
        config["image"]["signature_verified"] = True
        plan = build_plan(config, {}, [], 245 * 1024, 617 * 1024**3)
        self.assertIn(
            "base image checksum signature has not been verified",
            plan["apply_blockers"],
        )


class ImageVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.image_bytes = b"test qcow2 image payload"
        (self.root / "rocky.qcow2").write_bytes(self.image_bytes)
        (self.root / "rocky.qcow2.CHECKSUM").write_text(
            f"{hashlib.sha256(self.image_bytes).hexdigest()} *rocky.qcow2\n"
        )
        (self.root / "rocky.qcow2.CHECKSUM.asc").write_text("signature bytes")
        (self.root / "rocky-keyring.gpg").write_bytes(b"keyring")
        self.fingerprint = "21CB256AE16FC54C6E652949702D426D350D275D"
        self.image = {
            "name": "rocky.qcow2",
            "path": str(self.root / "rocky.qcow2"),
            "checksum_path": str(self.root / "rocky.qcow2.CHECKSUM"),
            "signature_path": str(self.root / "rocky.qcow2.CHECKSUM.asc"),
            "keyring_path": str(self.root / "rocky-keyring.gpg"),
            "signing_fingerprint": self.fingerprint,
            "sha256": hashlib.sha256(self.image_bytes).hexdigest(),
            "max_size_bytes": 1024,
        }

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_accepts_only_signed_checksum_from_pinned_key_and_matching_image(self) -> None:
        result = SimpleNamespace(
            returncode=0,
            stdout=f"[GNUPG:] VALIDSIG {self.fingerprint} 20261016 0 4 0 1 10 00\n",
            stderr="",
        )
        with patch.object(provision.subprocess, "run", return_value=result) as run:
            self.assertTrue(provision.verify_image_artifacts(self.image))
        args = run.call_args.args[0]
        self.assertEqual(args[:2], ["gpgv", "--status-fd=1"])
        self.assertIn(self.image["signature_path"], args)
        self.assertIn(self.image["checksum_path"], args)

    def test_verifies_staged_image_before_target_pool_exists(self) -> None:
        self.image["staged_path"] = self.image["path"]
        self.image["path"] = str(self.root / "pool-not-created" / "base" / "rocky.qcow2")
        result = SimpleNamespace(
            returncode=0,
            stdout=f"[GNUPG:] VALIDSIG {self.fingerprint} 20261016 0 4 0 1 10 00\n",
            stderr="",
        )
        with patch.object(provision.subprocess, "run", return_value=result) as run:
            self.assertTrue(provision.verify_image_artifacts(self.image))
        self.assertFalse(Path(self.image["path"]).exists())
        self.assertTrue(Path(self.image["staged_path"]).is_file())

    @unittest.skipUnless(shutil.which("gpg") and shutil.which("gpgv"), "GnuPG CLI unavailable")
    def test_verifies_a_real_detached_signature_with_gpgv(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            gpg_home = root / "gnupg"
            gpg_home.mkdir(mode=0o700)
            env = {**os.environ, "GNUPGHOME": str(gpg_home)}
            subprocess.run(
                ["gpg", "--batch", "--passphrase", "", "--quick-generate-key", "RKE2 Lab Test <lab@example.invalid>", "ed25519", "sign", "0"],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
            key_listing = subprocess.run(
                ["gpg", "--batch", "--with-colons", "--list-keys"],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
            fingerprint = next(line.split(":")[9] for line in key_listing.stdout.splitlines() if line.startswith("fpr:"))
            keyring_path = root / "public.gpg"
            key_export = subprocess.run(
                ["gpg", "--batch", "--export", fingerprint],
                check=True,
                capture_output=True,
                env=env,
            )
            keyring_path.write_bytes(key_export.stdout)
            image_path = root / "rocky.qcow2"
            image_path.write_bytes(b"signed image test")
            checksum_path = root / "rocky.qcow2.CHECKSUM"
            checksum_path.write_text(
                f"SHA256 (rocky.qcow2) = {hashlib.sha256(image_path.read_bytes()).hexdigest()}\n"
            )
            signature_path = root / "rocky.qcow2.CHECKSUM.asc"
            subprocess.run(
                ["gpg", "--batch", "--yes", "--armor", "--detach-sign", "--output", str(signature_path), str(checksum_path)],
                check=True,
                capture_output=True,
                env=env,
            )
            image = {
                "name": image_path.name,
                "path": str(image_path),
                "checksum_path": str(checksum_path),
                "signature_path": str(signature_path),
                "keyring_path": str(keyring_path),
                "signing_fingerprint": fingerprint,
                "sha256": hashlib.sha256(image_path.read_bytes()).hexdigest(),
                "max_size_bytes": 1024,
            }
            self.assertTrue(provision.verify_image_artifacts(image))

    def test_rejects_signed_checksum_from_an_unpinned_key(self) -> None:
        result = SimpleNamespace(
            returncode=0,
            stdout="[GNUPG:] VALIDSIG " + "A" * 40 + " 20261016 0 4 0 1 10 00\n",
            stderr="",
        )
        with patch.object(provision.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(LabError, "fingerprint"):
                provision.verify_image_artifacts(self.image)

    def test_rejects_image_when_local_hash_differs_from_signed_checksum(self) -> None:
        (self.root / "rocky.qcow2").write_bytes(b"tampered")
        result = SimpleNamespace(
            returncode=0,
            stdout=f"[GNUPG:] VALIDSIG {self.fingerprint} 20261016 0 4 0 1 10 00\n",
            stderr="",
        )
        with patch.object(provision.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(LabError, "SHA-256"):
                provision.verify_image_artifacts(self.image)


class ImageInspectionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("qemu-img"), "qemu-img CLI unavailable")
    def test_inspects_a_real_qcow2_image(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            image_path = Path(scratch) / "tiny.qcow2"
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", str(image_path), "2G"],
                check=True,
                capture_output=True,
            )
            info = provision.inspect_qcow2_image(image_path, 3 * 1024**3)
        self.assertEqual(info["format"], "qcow2")
        self.assertEqual(info["virtual-size"], 2 * 1024**3)

    def test_accepts_unbacked_qcow2_within_virtual_size_cap(self) -> None:
        result = SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"format": "qcow2", "virtual-size": 10 * 1024**3}),
            stderr="",
        )
        with patch.object(provision.subprocess, "run", return_value=result):
            info = provision.inspect_qcow2_image("/stage/rocky.qcow2", 20 * 1024**3)
        self.assertEqual(info["virtual-size"], 10 * 1024**3)

    def test_rejects_non_qcow2_image_format(self) -> None:
        result = SimpleNamespace(returncode=0, stdout='{"format":"raw","virtual-size":1024}', stderr="")
        with patch.object(provision.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(LabError, "qcow2"):
                provision.inspect_qcow2_image("/stage/rocky.qcow2", 20 * 1024**3)

    def test_rejects_image_with_external_backing_file(self) -> None:
        result = SimpleNamespace(
            returncode=0,
            stdout='{"format":"qcow2","virtual-size":1024,"backing-filename":"other.qcow2"}',
            stderr="",
        )
        with patch.object(provision.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(LabError, "backing file"):
                provision.inspect_qcow2_image("/stage/rocky.qcow2", 20 * 1024**3)

    def test_rejects_virtual_size_over_configured_limit(self) -> None:
        result = SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"format": "qcow2", "virtual-size": 21 * 1024**3}),
            stderr="",
        )
        with patch.object(provision.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(LabError, "virtual size"):
                provision.inspect_qcow2_image("/stage/rocky.qcow2", 20 * 1024**3)


class ApplyGuardTests(unittest.TestCase):
    def test_rejects_missing_exact_confirmation_before_host_discovery(self) -> None:
        with patch.object(provision, "read_host_inventory") as inventory_reader:
            with self.assertRaisesRegex(LabError, "confirmation"):
                provision.apply_lab(sample_config(), confirmation="wrong", euid=0)
        inventory_reader.assert_not_called()

    def test_rejects_non_root_apply_before_host_discovery(self) -> None:
        with patch.object(provision, "read_host_inventory") as inventory_reader:
            with self.assertRaisesRegex(LabError, "root"):
                provision.apply_lab(
                    sample_config(),
                    confirmation="autonomous-rke2-isolated",
                    euid=1000,
                )
        inventory_reader.assert_not_called()

    def test_stops_before_libvirt_when_image_verification_artifacts_are_missing(self) -> None:
        with patch.object(provision, "read_host_inventory") as inventory_reader:
            with patch.object(provision.subprocess, "run") as runner:
                with self.assertRaisesRegex(LabError, "image path does not exist"):
                    provision.apply_lab(
                        sample_config(),
                        confirmation="autonomous-rke2-isolated",
                        euid=0,
                    )
        inventory_reader.assert_not_called()
        runner.assert_not_called()
    def test_apply_resolves_default_runner_at_call_time(self) -> None:
        self.assertIsNone(inspect.signature(provision.apply_lab).parameters["runner"].default)

    def test_refuses_a_symlink_as_the_new_pool_path(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            config = sample_config()
            resolved_target = root / "future-pool"
            requested_path = root / "pool-link"
            requested_path.symlink_to(resolved_target, target_is_directory=True)
            config["storage"]["path"] = str(requested_path)
            config["image"]["path"] = str(resolved_target / "rocky9.qcow2")
            staged_image = root / "stage.qcow2"
            staged_image.write_bytes(b"staged")
            config["image"].update({"staged_path": str(staged_image), "sha256": "a" * 64})
            key_path = root / "lab.pub"
            key_path.write_text("ssh-ed25519 " + base64.b64encode(b"test-key-material" * 3).decode() + " lab-test\n")
            config["ssh_public_key_file"] = str(key_path)
            inventory = {"domains": set(), "networks": set(), "pools": set(), "links": set()}
            runner = Mock(
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps({"format": "qcow2", "virtual-size": 10 * 1024**3}),
                    stderr="",
                )
            )
            with (
                patch.object(provision, "verify_image_artifacts", return_value=True),
                patch.object(provision, "read_host_inventory", return_value=(inventory, [])),
                patch.object(provision, "_available_memory_mib", return_value=245 * 1024),
                patch.object(provision, "_available_bytes", return_value=617 * 1024**3),
            ):
                with self.assertRaisesRegex(LabError, "symlink"):
                    provision.apply_lab(
                        config,
                        confirmation="autonomous-rke2-isolated",
                        euid=0,
                        runner=runner,
                    )
            self.assertFalse(any("net-define" in call.args[0] for call in runner.call_args_list))


class ExistingFilterGuardTests(unittest.TestCase):
    def test_refuses_to_overwrite_an_existing_filter_before_any_mutation(self) -> None:
        runner = Mock(return_value=SimpleNamespace(
            returncode=0, stdout=json.dumps({"format": "qcow2", "virtual-size": 10 * 1024**3}), stderr=""))
        with (
            patch.object(provision, "verify_image_artifacts", return_value=True),
            patch.object(provision, "read_host_inventory", return_value=(
                {"nwfilters": {"autonomous-rke2-ipv4-only"}}, [])),
        ):
            with self.assertRaisesRegex(LabError, "filter already exists"):
                provision.apply_lab(sample_config(), confirmation="autonomous-rke2-isolated",
                                    euid=0, runner=runner)
        self.assertEqual(len(runner.call_args_list), 1)
        self.assertEqual(runner.call_args.args[0][:2], ["qemu-img", "info"])


class ApplyExecutionTests(unittest.TestCase):
    def test_cli_apply_requires_flag_and_passes_exact_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            config_path = Path(scratch) / "lab.json"
            config_path.write_text(json.dumps(sample_config()))
            with patch.object(provision, "apply_lab") as apply, patch("sys.stdout", new=io.StringIO()):
                result = provision.main(
                    [
                        "--config",
                        str(config_path),
                        "--apply",
                        "--confirm-lab",
                        "autonomous-rke2-isolated",
                    ]
                )
        self.assertEqual(result, 0)
        apply.assert_called_once_with(
            sample_config(),
            confirmation="autonomous-rke2-isolated",
        )

    @unittest.skipUnless(shutil.which("virt-install") and shutil.which("qemu-img") and shutil.which("genisoimage"), "libvirt CLI tools unavailable")
    def test_virt_install_accepts_uefi_seed_and_guest_agent_arguments_in_dry_run(self) -> None:
        node = {
            "name": "rke2-r9-cp01",
            "host_id": "c84a47bc-821c-4a79-87d4-2d092f05fce1",
            "mac": "52:54:00:40:01:01",
            "address": "192.168.250.11",
        }
        templates = Path(__file__).resolve().parents[3] / "lab" / "cloud-init" / "rocky9"
        key = "ssh-ed25519 " + base64.b64encode(b"test-key-material" * 3).decode() + " lab-test"
        rendered = render_cloud_init(node, "192.168.250.0/24", key, templates)
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            disk = root / "test.qcow2"
            subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk), "2G"], check=True, capture_output=True)
            cloud_paths = {}
            for name, content in rendered.items():
                path = root / name
                path.write_text(content)
                cloud_paths[name] = path
            seed = root / "seed.iso"
            subprocess.run(["genisoimage", "-quiet", "-output", str(seed), "-volid", "cidata",
                            "-joliet", "-rock", *map(str, cloud_paths.values())], check=True, capture_output=True)
            firmware_code = root / "CODE.fd"
            firmware_vars = root / "VARS.fd"
            firmware_code.touch()
            firmware_vars.touch()
            result = subprocess.run(
                [
                    "virt-install",
                    "--connect", "test:///default",
                    "--name", "rke2-cli-validation",
                    "--memory", "1024",
                    "--vcpus", "1",
                    "--disk", f"path={disk},format=qcow2,bus=virtio",
                    "--disk", f"path={seed},device=cdrom,readonly=on",
                    "--network", "network=default,model=virtio,filterref.filter=autonomous-rke2-ipv4-only",
                    "--osinfo", "rocky9",
                    "--import",
                    "--boot", f"loader={firmware_code},loader.readonly=yes,loader.type=pflash,nvram.template={firmware_vars},nvram={root / 'guest_VARS.fd'}",
                    "--graphics", "none",
                    "--channel", "unix,target_type=virtio,name=org.qemu.guest_agent.0",
                    "--console", "pty,target_type=serial",
                    "--noautoconsole",
                    "--dry-run",
                    "--print-xml",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("<domain", result.stdout)
        domain = ET.fromstring(result.stdout)
        self.assertEqual(domain.findtext("os/loader"), str(firmware_code))
        self.assertEqual(domain.find("os/nvram").get("template"), str(firmware_vars))
        self.assertIsNotNone(domain.find("devices/disk[@device='cdrom']/readonly"))
        self.assertEqual(domain.find("devices/channel/target").get("name"), "org.qemu.guest_agent.0")
        self.assertEqual(domain.find("devices/interface/filterref").get("filter"), "autonomous-rke2-ipv4-only")

    def test_provisions_only_configured_network_pool_and_three_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            config = sample_config()
            config["storage"]["path"] = str(root / "lab-pool")
            image_path = root / "lab-pool" / "rocky.qcow2"
            staged_image = root / "stage" / "rocky.qcow2"
            staged_image.parent.mkdir()
            with staged_image.open("wb") as staged_file:
                staged_file.truncate(11 * 1024**3)
            config["image"].update(
                {
                    "name": "rocky.qcow2",
                    "path": str(root / "lab-pool" / "rocky.qcow2"),
                    "staged_path": str(staged_image),
                    "sha256": "a" * 64,
                    "max_size_bytes": 12 * 1024**3,
                    "kind": "derived",
                    "profile": "server",
                    "release_sha256": "b" * 64,
                }
            )
            public_key_path = root / "lab.pub"
            public_key = "ssh-ed25519 " + base64.b64encode(b"test-key-material" * 3).decode() + " lab-test"
            public_key_path.write_text(public_key + "\n")
            config["ssh_public_key_file"] = str(public_key_path)
            guest_rpms = root / "rpms"
            (guest_rpms / "repodata").mkdir(parents=True)
            (guest_rpms / "repodata/repomd.xml").write_text("test repository")
            config["guest_rpm_repository"] = str(guest_rpms)
            inventory = {"domains": set(), "networks": set(), "pools": set(), "links": set()}
            def run_fake(command, **_kwargs):
                if command[0] == "qemu-img":
                    output = json.dumps({"format": "qcow2", "virtual-size": 10 * 1024**3})
                elif "vol-path" in command:
                    output = str(image_path)
                else:
                    output = ""
                return SimpleNamespace(returncode=0, stdout=output, stderr="")

            runner = Mock(side_effect=run_fake)
            with (
                patch.object(provision, "_UEFI_CODE", public_key_path),
                patch.object(provision, "_UEFI_VARS", public_key_path),
                patch.object(provision.shutil, "which", side_effect=lambda name: "/usr/bin/" + name),
                patch.object(provision, "read_host_inventory", return_value=(inventory, [])),
                patch.object(provision, "verify_image_artifacts", return_value=True),
                patch.object(provision, "_available_memory_mib", return_value=245 * 1024),
                patch.object(provision, "_available_bytes", return_value=617 * 1024**3),
                patch.dict(provision.os.environ, {"TMPDIR": scratch}),
            ):
                provision.apply_lab(
                    config,
                    confirmation="autonomous-rke2-isolated",
                    euid=0,
                    runner=runner,
                )

            commands = [call.args[0] for call in runner.call_args_list]
            self.assertEqual(sum(command[0] == "virt-install" for command in commands), 3)
            self.assertTrue(any(command[3:5] == ["net-define", str(Path(provision.__file__).with_name("network.xml"))] for command in commands))
            self.assertTrue(any(command[3:5] == ["pool-define-as", "autonomous-rke2-lab"] for command in commands))
            self.assertEqual(sum(command[3:4] == ["vol-create-as"] for command in commands), 4)
            base_volume = next(command for command in commands if command[3:5] == ["vol-create-as", "autonomous-rke2-lab"] and command[5] == "rocky.qcow2")
            self.assertEqual(base_volume[6], str(11 * 1024**3))
            self.assertEqual(sum(command[3:4] == ["vol-upload"] for command in commands), 1)
            self.assertFalse(image_path.exists())
            self.assertTrue(staged_image.is_file())
            self.assertEqual((root / "lab-pool").stat().st_mode & 0o777, 0o711)


if __name__ == "__main__":
    unittest.main()
