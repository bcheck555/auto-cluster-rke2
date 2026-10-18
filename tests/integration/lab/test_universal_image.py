"""Universal image contracts; no hypervisor or network mutations."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lab.packer import artifacts, guest, pipeline, runtime, stage


class UniversalImageTests(unittest.TestCase):
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
            self.assertIn('node/source/internal/formation/node.go', names)
            self.assertFalse(any('credentials/' in name or 'enrollment-secret' in name for name in names))
            unit = (root / 'node/host-agent.service').read_text()
            self.assertIn('ConditionPathExists=/etc/autonomous-rke2/enrollment-secret', unit)
            self.assertIn('/etc/autonomous-rke2/node.json', unit)

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
