"""Universal image contracts; no hypervisor or network mutations."""
import json
import base64
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lab.packer import artifacts, guest, pipeline, runtime, stage


class UniversalImageTests(unittest.TestCase):
    def test_validation_never_overwrites_existing_filter_or_bridge(self):
        from lab.packer import validation_network
        for collision in ('filter', 'bridge'):
            with self.subTest(collision=collision), tempfile.TemporaryDirectory() as directory:
                calls = []
                def virsh(*args):
                    calls.append(args)
                    if args[0] == 'nwfilter-list' and collision == 'filter':
                        return 'uuid autonomous-rke2-image-123456789012'
                    return ''
                fake = SimpleNamespace(POOL=Path('/old-pool'), NETWORK='old-net', FILTER='old-filter',
                                       BRIDGE='old-bridge', OPERATOR_KEY=Path('/old-key.pub'), virsh=virsh,
                                       run=lambda args: json.dumps([{'ifname': 'br-img-12345678'}] if collision == 'bridge' else []))
                real_path = Path
                def path(value):
                    return real_path(directory) if value == '/var/lib/libvirt/images' else real_path(value)
                with patch.object(validation_network, 'Path', side_effect=path), \
                        patch.object(validation_network.os, 'geteuid', return_value=0), \
                        patch.object(validation_network.uuid, 'uuid4', return_value=SimpleNamespace(hex='12345678901234567890')), \
                        self.assertRaisesRegex(artifacts.ImageError, 'collision'):
                    with validation_network.isolated_validation(fake, directory):
                        self.fail('unexpected resource adoption')
                self.assertFalse(any(c[0].endswith(('define', 'undefine', 'destroy')) for c in calls))
                self.assertEqual(fake.NETWORK, 'old-net')

    def test_cached_formation_rechecks_stable_ids_roles_and_disk_binding(self):
        candidate = {'input_sha256': 'input', 'profiles': {'node': {'sha256': 'disk'}}}
        nodes = {}
        for i in range(4):
            identity = {'ClusterID': 'cluster', 'HostID': f'host-{i}',
                        'Role': 'server' if i < 3 else 'agent',
                        'Evidence': {'NodeUID': f'uid-{i}', 'EtcdClusterID': 'etcd',
                                     'EtcdMemberID': str(i), 'VotingServers': 3}}
            report = {'host_id': f'seed-{i}', 'smoke': {'formation': identity,
                       'nodes_ready': 4, 'cross_node_service': True, 'cross_node_pod': True}}
            nodes[f'image-test-formation-{i + 1}'] = {'boot': report, 'reboot': json.loads(json.dumps(report))}
        formation = {'passed': True, 'same_image_sha256': 'disk', 'nodes': nodes}
        with patch.object(runtime, 'validate_report') as validate:
            runtime.validate_cached_formation(candidate, formation, 'operator')
            self.assertEqual(validate.call_count, 8)
            nodes['image-test-formation-1']['reboot']['smoke']['formation']['Evidence']['NodeUID'] = 'replacement'
            with self.assertRaisesRegex(artifacts.ImageError, 'identities or roles'):
                runtime.validate_cached_formation(candidate, formation, 'operator')
            formation['same_image_sha256'] = 'other'
            with self.assertRaises(artifacts.ImageError):
                runtime.validate_cached_formation(candidate, formation, 'operator')

    def test_publication_requires_complete_scaling_evidence_for_exact_disk(self):
        candidate = {'capabilities': ['membership-reconciliation-v1'], 'profiles': {'node': {'sha256': 'a' * 64}}}
        evidence = {'passed': True, 'same_image_sha256': 'a' * 64,
                    'cases': [{'nodes': n, 'control_nodes': c} for n, c in
                              ((3, 3), (5, 5), (7, 7), (8, 7), (5, 3), (2, 3), (1, 3))],
                    'blocked_drain_preserved_vm': True, 'forced_drain_validated': True,
                    'source_inputs_preserved': True}
        pipeline.validate_scaling_evidence(candidate, {'scaling': evidence})
        for key in ('passed', 'same_image_sha256', 'cases', 'blocked_drain_preserved_vm',
                    'forced_drain_validated', 'source_inputs_preserved'):
            incomplete = {k: v for k, v in evidence.items() if k != key}
            with self.subTest(key=key), self.assertRaisesRegex(artifacts.ImageError, 'complete signed scaling'):
                pipeline.validate_scaling_evidence(candidate, {'scaling': incomplete})
        pipeline.validate_scaling_evidence({'capabilities': []}, {})

    def test_kernel_console_interleaving_does_not_corrupt_report_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'serial.log'
            report = {'boot_id': 'real-boot', 'operator_password': 'LK', 'payload': 'x' * 2000}
            encoded = base64.b64encode(json.dumps(report).encode())
            path.write_bytes(b'[ 150.000001] console prefix IMAGE_REPORT=' + encoded[:101] +
                             b'[ 150.000002] cni0 entered forwarding state\r\n' + encoded[101:] +
                             b'\r\n[ 151.000003] unrelated kernel message\r\n')
            self.assertEqual(runtime.reports({'serial': str(path)}), [report])

    def test_waiting_for_slow_boot_does_not_change_guest_password(self):
        from lab.packer import console
        spec = {'name': 'image-test-owned', 'diagnostic_path': '/unused', 'serial': '/unused'}
        report = {'boot_id': 'new-boot'}
        with patch.object(runtime, 'require_owner'), \
             patch.object(runtime, 'reports', side_effect=[[], [], [report]]), \
             patch.object(runtime.time, 'monotonic', side_effect=[0, 1, 151, 152]), \
             patch.object(runtime.time, 'sleep'), patch.object(console, 'diagnose') as diagnose:
            self.assertEqual(runtime.wait_report(spec), report)
            diagnose.assert_not_called()

    def test_validation_storage_fallback_reserves_full_ram_and_guest_growth(self):
        candidate = {'profiles': {'os': {'size': artifacts.GIB}, 'node': {'size': 2 * artifacts.GIB}}}
        with patch.object(runtime, 'preflight', side_effect=[artifacts.ImageError('insufficient disk after reserve'), {}]) as check:
            limit = runtime.validation_storage_budget(candidate)
        self.assertEqual(limit, 147 * artifacts.GIB)
        self.assertEqual(check.call_args_list[1].kwargs['extra_memory_mib'], 34816 + 147 * 1024)
        self.assertEqual(check.call_args_list[1].kwargs['extra_disk'], 128 * 1024**2)
        with patch.object(runtime, 'preflight', side_effect=artifacts.ImageError('insufficient RAM after reserve')) as check:
            with self.assertRaisesRegex(artifacts.ImageError, 'RAM'):
                runtime.validation_storage_budget(candidate)
            self.assertEqual(check.call_count, 1)

    def test_default_profiles_have_one_runtime_image(self):
        self.assertEqual(artifacts.PROFILES, ('os', 'node'))

    def test_staged_node_contains_binary_unit_and_public_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def build(args, **kwargs):
                self.assertEqual(args[:3], ['go', 'build', '-trimpath'])
                self.assertEqual(kwargs['env']['CGO_ENABLED'], '0')
                self.assertEqual(kwargs['env']['GOOS'], 'linux')
                Path(args[args.index('-o') + 1]).write_bytes(b'compiled-node')
            with patch.object(stage, 'run', side_effect=build):
                stage.stage_node(root)
            names = set(artifacts.inventory(root))
            self.assertIn('node/host-agent', names)
            self.assertIn('node/host-agent.service', names)
            self.assertEqual(json.loads((root / 'node/capabilities.json').read_text()),
                             {'capabilities': ['membership-reconciliation-v1']})
            self.assertIn('node/source/internal/formation/node.go', names)
            self.assertFalse(any('credentials/' in name or 'enrollment-secret' in name for name in names))
            unit = (root / 'node/host-agent.service').read_text()
            self.assertIn('ConditionPathExists=/etc/autonomous-rke2/enrollment-secret', unit)
            self.assertIn('/etc/autonomous-rke2/node.json', unit)

    def test_recipe_includes_only_public_reconciliation_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage.stage_recipe(root)
            names = set(artifacts.inventory(root))
            self.assertIn('recipe/lab/libvirt/scaling.py', names)
            self.assertIn('recipe/lab/libvirt/ipv4-only.xml', names)
            self.assertIn('recipe/lab/packer/validation_network.py', names)
            self.assertFalse(any('credentials/' in name or name.endswith('.env') for name in names))

    def test_seal_refuses_deployment_secret_and_initialized_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'etc/autonomous-rke2'
            config.mkdir(parents=True)
            (config / 'image.json').write_text(json.dumps({'profile': 'node'}))
            def command(args, **kwargs):
                return SimpleNamespace(stdout='masked' if 'is-enabled' in args else 'inactive')
            def mapped(value):
                return root / value.lstrip('/')
            with patch.object(guest, 'CONFIG', config), patch.object(guest, 'Path', side_effect=mapped), \
                 patch.object(guest, 'command', side_effect=command), patch.object(guest.os, 'geteuid', return_value=0), \
                 patch.object(guest, 'cluster_state_absent', return_value=True):
                guest.check_seal()
                for path in (config / 'enrollment-secret', root / 'var/lib/autonomous-rke2/identity'):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.touch()
                    with self.assertRaisesRegex(RuntimeError, 'state'):
                        guest.check_seal()
                    path.unlink()

    def test_four_clone_validation_supplies_no_role_or_server_endpoint(self):
        specs, extras = [], []
        def launch(spec, image, key, **kwargs):
            self.assertEqual(image, Path('/verified/node.qcow2'))
            specs.append(spec)
            extras.append(kwargs['extra_files'])
            self.assertEqual(kwargs['smoke'], {'formation_smoke': True})
        def report(spec, **kwargs):
            index = specs.index(spec)
            evidence = {'NodeUID': 'uid-' + str(index), 'EtcdClusterID': 'etcd' if index < 3 else '',
                        'EtcdMemberID': str(index) if index < 3 else '', 'VotingServers': 3 if index < 3 else 0}
            health = {'Role': 'server' if index < 3 else 'agent', 'ClusterID': 'cluster',
                      'HostID': 'host-' + str(index), 'Evidence': evidence}
            return {'smoke': {'formation': health, 'nodes_ready': 4, 'cross_node_service': True, 'cross_node_pod': True}}
        candidate = {'input_sha256': 'input', 'profiles': {'node': {'sha256': 'one-image'}}}
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime, 'launch', side_effect=launch), \
             patch.object(runtime, 'wait_report', side_effect=report), patch.object(runtime, 'validate_report'), \
             patch.object(runtime, 'reports', return_value=[]), patch.object(runtime, 'require_owner'), patch.object(runtime, 'virsh'):
            result = runtime.validate_formation(candidate, Path('/verified/node.qcow2'), Path(directory), 'public-key',
                                                [], Path(directory) / 'validation.json', b'public test runner')
        self.assertTrue(result['passed'])
        self.assertEqual(len(specs), 4)
        self.assertEqual(len({spec['interface'] for spec in specs}), 4)
        secrets = [next(file['content'] for file in files if file['path'].endswith('/enrollment-secret')) for files in extras]
        self.assertEqual(len(set(secrets)), 1)
        self.assertTrue(all(spec['profile'] == 'node' and 'runtime_role' not in spec for spec in specs))

    def test_raw_export_rejects_legacy_and_unpublished_images(self):
        for release in ({'kind': 'candidate', 'profiles': {'node': {}}}, {'kind': 'release', 'profiles': {'server': {}}}):
            with patch.object(pipeline, 'verify_manifest', return_value=release), patch.object(pipeline, 'run') as command:
                with self.assertRaisesRegex(artifacts.ImageError, 'published universal'):
                    pipeline.export(Path('/verified/release.json'), Path('/unused/output'))
                command.assert_not_called()

    def test_raw_export_compares_contents_and_signs_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / 'node.qcow2'
            image.write_bytes(b'verified-node')
            release = root / 'release.json'
            release.write_text('{}')
            (root / 'release.json.sig').write_bytes(b'signature')
            pin = {'file': image.name, 'sha256': artifacts.digest(image), 'size': image.stat().st_size}
            manifest = {'kind': 'release', 'profiles': {'node': pin},
                        'files': {image.name: {key: pin[key] for key in ('sha256', 'size')}}}
            def qemu(args):
                if args[1] == 'info':
                    return json.dumps({'format': 'raw' if str(args[-1]).endswith('.raw') else 'qcow2',
                                       'virtual-size': 32 * artifacts.GIB})
                if args[1] == 'convert':
                    Path(args[-1]).write_bytes(b'converted-node')
                return ''
            with patch.object(pipeline, 'verify_manifest', return_value=manifest), \
                 patch.object(pipeline, 'run', side_effect=qemu) as command, \
                 patch.object(pipeline, 'preflight'), patch.object(pipeline, 'sign') as sign:
                pipeline.export(release, root / 'raw')
                self.assertTrue(any(call.args[0][1] == 'compare' for call in command.call_args_list))
                sign.assert_called_once_with(root / 'raw/export.json')
            exported = json.loads((root / 'raw/export.json').read_text())
            self.assertEqual(exported['source_node_sha256'], pin['sha256'])
            self.assertIn('node.raw', exported['files'])


if __name__ == '__main__':
    unittest.main()
