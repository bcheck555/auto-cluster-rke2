from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lab.libvirt import cluster_config as config
from lab.packer.artifacts import ImageError, ROOT


def document(cluster='dev', subnet='192.168.100.0/24'):
    return {'schema': 1, 'cluster': cluster, 'release': '../images/release.json',
            'hostname_prefix': cluster + '-node', 'nodes': 3,
            'network': {'name': cluster + '-private', 'subnet': subnet}}


@contextlib.contextmanager
def root_owner():
    original = os.fstat
    def owned(fd):
        info = original(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
    with patch.object(config.os, 'fstat', side_effect=owned):
        yield


class ClusterConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'dev.yaml'
        self.path.write_text(json.dumps(document()))
        self.env = self.path.with_suffix('.env')

    def test_load_paths_resources_and_paired_env_from_any_cwd(self):
        data = document()
        data['vm'] = {'vcpus': 6, 'memory_mib': 12288, 'disk_gib': 80}
        self.path.write_text(json.dumps(data))
        loaded = config.load_config(self.path)
        self.assertEqual(loaded.env_path, self.env)
        self.assertEqual(loaded.release, (self.directory / '../images/release.json').resolve())
        self.assertEqual(loaded.options['vm'], data['vm'])
        self.assertEqual(loaded.timeout, 1200)
        self.assertFalse(self.env.exists())

    def test_accepts_positive_counts_and_rejects_subnet_overflow(self):
        for count in (1, 2, 7, 100, 244):
            data = {**document(), 'nodes': count}
            self.path.write_text(json.dumps(data))
            with self.subTest(count=count):
                self.assertEqual(config.load_config(self.path).nodes, count)
        self.path.write_text(json.dumps({**document(), 'nodes': 245}))
        with self.assertRaisesRegex(ImageError, 'capacity is 244'):
            config.load_config(self.path)

    def test_committed_templates_load_and_have_no_live_secret(self):
        self.path.write_text((ROOT / 'clusters/cluster.yaml.example').read_text())
        loaded = config.load_config(self.path)
        self.assertEqual(loaded.cluster, 'dev')
        self.env.write_text((ROOT / 'clusters/cluster.env.example').read_text())
        self.env.chmod(0o600)
        with root_owner(), self.assertRaisesRegex(ImageError, '64 hexadecimal'):
            config.read_env(self.env)

    def test_rejects_unknown_fields_invalid_types_and_resource_limits(self):
        for mutation in ({'typo': 'x'}, {'nodes': True}, {'nodes': 0}, {'nodes': -1}, {'nodes': 1.5},
                         {'schema': True}, {'cluster': 12}, {'health_timeout': 0},
                         {'vm': {'vcpus': 1}}, {'vm': {'disk_gib': 31}},
                         {'network': {'subnet': None}}, {'network': {'subnet': '10.43.1.0/24'}}):
            with self.subTest(mutation=mutation):
                self.path.write_text(json.dumps({**document(), **mutation}))
                with self.assertRaises(ImageError):
                    config.load_config(self.path)

    def test_unsafe_yaml_aliases_duplicate_keys_and_python_tags_rejected(self):
        for text in ('schema: 1\nschema: 1\n', 'a: &value [1]\nb: *value\n',
                     '!!python/object/apply:os.system ["false"]', 'schema: ['):
            self.path.write_text(text)
            with self.subTest(text=text), self.assertRaises(ImageError):
                config.load_config(self.path)

    def test_other_configs_reserve_names_and_subnets_without_any_vms(self):
        peer = self.directory / 'qa.yml'
        for other in (document('dev', '192.168.101.0/24'), document('qa'),
                      {**document('qa', '192.168.101.0/24'), 'hostname_prefix': 'dev-node'},
                      {**document('qa', '192.168.101.0/24'),
                       'network': {'name': 'dev-private', 'subnet': '192.168.101.0/24'}},
                      {**document('qa', '192.168.101.0/24'),
                       'network': {'subnet': '192.168.101.0/24', 'reserved_cidrs': ['192.168.100.0/24']}}):
            peer.write_text(json.dumps(other))
            with self.subTest(other=other), self.assertRaisesRegex(ImageError, 'conflict|overlap'):
                config.load_config(self.path)
            # Destroy can load its target even if peer settings now conflict.
            self.assertEqual(config.load_config(self.path, check_siblings=False).cluster, 'dev')

    def test_distinct_configs_and_template_files_do_not_conflict(self):
        (self.directory / 'qa.yaml').write_text(json.dumps(document('qa', '192.168.101.0/24')))
        (self.directory / 'cluster.yaml.example').write_text('not: a real cluster')
        self.assertEqual(config.load_config(self.path).cluster, 'dev')

    def test_config_in_generated_storage_rejected(self):
        forbidden = Path('/var/lib/libvirt/images/autonomous-rke2-dev/dev.yaml')
        with patch.object(config, 'read_yaml', return_value=document()):
            with self.assertRaisesRegex(ImageError, 'outside generated'):
                config.load_config(forbidden)

    def test_literal_env_comments_quotes_and_root_permissions(self):
        self.env.write_text('# comment\nENROLLMENT_SECRET="' + 'AB' * 32 + '"\n')
        self.env.chmod(0o600)
        with root_owner():
            self.assertEqual(config.read_env(self.env), 'ab' * 32)
        self.env.chmod(0o644)
        with root_owner(), self.assertRaisesRegex(ImageError, '0600'):
            config.read_env(self.env)
        self.env.chmod(0o600)
        with patch.object(config.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100600, st_uid=1000)):
            with self.assertRaisesRegex(ImageError, 'root-owned'):
                config.read_env(self.env)

    def test_env_shell_expressions_duplicates_unknown_keys_and_errors_are_redacted(self):
        marker = self.directory / 'must-not-exist'
        payload = f'$(touch {marker})'
        for text in ('ENROLLMENT_SECRET=' + payload,
                     'ENROLLMENT_SECRET=' + 'a' * 64 + '\nENROLLMENT_SECRET=' + 'b' * 64,
                     'PASSWORD=private-value', 'export ENROLLMENT_SECRET=' + 'a' * 64,
                     '# no secret', 'ENROLLMENT_SECRET=private-value'):
            self.env.write_text(text)
            self.env.chmod(0o600)
            with root_owner(), self.assertRaises(ImageError) as raised:
                config.read_env(self.env)
            self.assertNotIn('private-value', str(raised.exception))
            self.assertNotIn(payload, str(raised.exception))
            self.assertFalse(marker.exists())

    def test_env_symlink_and_fifo_refused(self):
        target = self.directory / 'target'
        target.write_text('ENROLLMENT_SECRET=' + 'a' * 64)
        self.env.symlink_to(target)
        with self.assertRaises(OSError):
            config.read_env(self.env)
        self.env.unlink()
        os.mkfifo(self.env, 0o600)
        with root_owner(), self.assertRaisesRegex(ImageError, 'regular'):
            config.read_env(self.env)

    def test_init_creates_once_and_preserves_existing_input(self):
        with contextlib.redirect_stdout(io.StringIO()):
            config.init_env(self.env)
        content = self.env.read_bytes()
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o600)
        with root_owner():
            self.assertEqual(len(config.read_env(self.env)), 64)
        with self.assertRaises(FileExistsError):
            config.init_env(self.env)
        self.assertEqual(self.env.read_bytes(), content)

    def test_init_can_preserve_existing_deployment_key_for_migration(self):
        with contextlib.redirect_stdout(io.StringIO()):
            config.init_env(self.env, enrollment_secret='c' * 64)
        with root_owner():
            self.assertEqual(config.read_env(self.env), 'c' * 64)


if __name__ == '__main__':
    unittest.main()
