from __future__ import annotations

import base64
import copy
import json
import subprocess
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch, Mock
from types import SimpleNamespace

from lab.packer import artifacts, pipeline, runtime
from lab.packer import guest
from lab.libvirt import replace, provision


class GuestDefinitionTests(unittest.TestCase):
    def test_launch_uses_direct_definition_without_storage_pool_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            spec = runtime.make_spec('image-test-server', '192.168.250.241', 'server', directory)
            with patch.object(runtime, 'isolation'), patch.object(runtime, 'absent', return_value=True), \
                 patch.object(runtime, 'require_owner'), patch.object(runtime, 'prepare_seed'), \
                 patch.object(runtime.shutil, 'copyfile'), patch.object(runtime, 'run') as execute, \
                 patch.object(runtime, 'virsh') as virsh:
                runtime.launch(spec, directory / 'base.qcow2', 'operator-key')
            self.assertEqual([call.args[0] for call in virsh.call_args_list], ['define', 'start'])
            self.assertEqual(execute.call_args_list[0].args[0][0], 'qemu-img')
            self.assertEqual(execute.call_count, 1)
            xml = ET.parse(directory / (spec['name'] + '.xml')).getroot()
            self.assertEqual(xml.findtext('uuid'), spec['uuid'])
            self.assertEqual(xml.findtext('os/nvram'), spec['nvram'])
            self.assertEqual(xml.find("devices/disk[@device='disk']/source").get('file'), spec['disk'])
            self.assertEqual(xml.find('devices/interface/filterref').get('filter'), runtime.FILTER)
            self.assertIsNone(xml.find('devices/graphics'))
            self.assertIsNone(xml.find('devices/tpm'))


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.trust_patch = patch.object(artifacts, 'CREDENTIALS', self.root / 'trust')
        self.trust_patch.start()
        artifacts.init_signer()

    def tearDown(self):
        subprocess.run(['gpgconf', '--homedir', str(self.root / 'trust/gnupg'), '--kill', 'gpg-agent'], capture_output=True)
        self.trust_patch.stop()
        self.temporary.cleanup()

    def manifest(self):
        directory = self.root / 'bundle'
        directory.mkdir()
        (directory / 'payload').write_text('verified payload')
        path = directory / 'input.json'
        artifacts.write_json(path, {'schema': 1, 'kind': 'input', 'files': artifacts.inventory(directory)})
        artifacts.sign(path)
        return path

    def test_signature_hash_and_unlisted_payload_rejected(self):
        path = self.manifest()
        artifacts.verify_manifest(path)
        (path.parent / 'injected.rpm').write_text('unsigned')
        with self.assertRaisesRegex(artifacts.ImageError, 'unlisted'):
            artifacts.verify_manifest(path)
        (path.parent / 'injected.rpm').unlink()
        (path.parent / 'payload').write_text('corrupt payload')
        with self.assertRaisesRegex(artifacts.ImageError, 'mismatch'):
            artifacts.verify_manifest(path)

    def test_wrong_pinned_signer_rejected(self):
        path = self.manifest()
        _, key = artifacts.trust()
        with self.assertRaisesRegex(artifacts.ImageError, 'signer differs'):
            artifacts.verify_signature(path, key, 'A' * 40)

    def test_manifest_modification_rejected(self):
        path = self.manifest()
        path.write_text(path.read_text() + ' ')
        with self.assertRaises(artifacts.ImageError):
            artifacts.verify_manifest(path)

    def test_derived_release_binding_and_policy(self):
        directory = self.root / 'release'
        directory.mkdir()
        image = directory / 'server.qcow2'
        subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(image), '32G'], check=True, capture_output=True)
        pin = {'file': image.name, 'sha256': artifacts.digest(image), 'size': image.stat().st_size,
               'virtual_size': 32 * artifacts.GIB, 'firewalld': 'disabled'}
        path = directory / 'release.json'
        artifacts.write_json(path, {'schema': 1, 'kind': 'release', 'versions': artifacts.VERSIONS,
                                   'profiles': {'server': pin}, 'files': artifacts.inventory(directory)})
        artifacts.sign(path)
        fp, key = artifacts.trust()
        config = {'kind': 'derived', 'profile': 'server', 'path': str(image), 'release_manifest': str(path),
                  'release_sha256': artifacts.digest(path), 'keyring_path': str(key), 'signing_fingerprint': fp,
                  'sha256': pin['sha256']}
        self.assertTrue(provision.verify_image_artifacts(config))
        config['firewalld'] = 'active'
        with self.assertRaisesRegex(provision.LabError, 'override'):
            provision.verify_image_artifacts(config)
        config.pop('firewalld')
        config['release_sha256'] = '0' * 64
        with self.assertRaisesRegex(provision.LabError, 'digest'):
            provision.verify_image_artifacts(config)


class BundleTests(unittest.TestCase):
    def test_archive_traversal_and_links_rejected(self):
        for name, link in (('../escape', False), ('link', True)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / 'bad.tar'
                with tarfile.open(archive, 'w') as output:
                    member = tarfile.TarInfo(name)
                    if link:
                        member.type = tarfile.SYMTYPE
                        member.linkname = '/etc/passwd'
                    output.addfile(member)
                with patch.object(pipeline, 'STATE', root / 'state'):
                    with self.assertRaisesRegex(artifacts.ImageError, 'unsafe'):
                        pipeline.unpack_bundle(archive)
                self.assertFalse((root / 'escape').exists())


class ReserveTests(unittest.TestCase):
    def test_ram_reserve_counts_unallocated_running_lab_memory(self):
        xml = '<domain id="1"><currentMemory unit="KiB">8388608</currentMemory><devices/></domain>'
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(artifacts, 'ARTIFACTS', Path(temporary)), \
             patch.object(artifacts.shutil, 'disk_usage', return_value=SimpleNamespace(free=2000 * artifacts.GIB)), \
             patch.object(artifacts.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=xml)), \
             patch.object(artifacts, 'run', return_value='rss 1048576\n'):
            with patch.object(Path, 'read_text', return_value='MemAvailable: 36700160 kB\n'):
                with self.assertRaisesRegex(artifacts.ImageError, 'RAM'):
                    artifacts.preflight()
            with patch.object(Path, 'read_text', return_value='MemAvailable: 67108864 kB\n'):
                result = artifacts.preflight(extra_memory_mib=8192)
                self.assertEqual(result['remaining_lab_memory_mib'], 21 * 1024)


class ProfileTests(unittest.TestCase):
    def test_upstream_source_cannot_be_deployed_without_baked_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source.qcow2'
            source.write_bytes(b'source')
            config = {'network': {'name': runtime.NETWORK}, 'storage': {'path': str(root / 'pool')},
                      'image': {'name': 'base.qcow2', 'path': str(root / 'pool/base.qcow2'),
                                'staged_path': str(source), 'max_virtual_size_bytes': 32 * artifacts.GIB}}
            runner = Mock()
            with patch.object(provision, 'verify_image_artifacts', return_value=True), \
                 patch.object(provision, 'inspect_qcow2_image', return_value={'virtual-size': 32 * artifacts.GIB}), \
                 patch.object(provision, 'read_host_inventory', return_value=({}, [])), \
                 patch.object(provision, 'build_plan', return_value={'apply_blockers': []}), \
                 patch.object(provision, '_available_memory_mib', return_value=65536), \
                 patch.object(provision, '_available_bytes', return_value=1024 * artifacts.GIB):
                with self.assertRaisesRegex(provision.LabError, 'derived-image'):
                    provision.apply_lab(config, confirmation=runtime.NETWORK, euid=0, runner=runner)
            runner.assert_not_called()

    def test_service_route_is_scoped_to_disposable_smoke_metadata(self):
        for smoke in (None, {'smoke': True}):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                spec = runtime.make_spec('image-test-server', '192.168.250.241', 'server', root)
                Path(spec['seed']).touch()
                with patch.object(runtime, 'run'):
                    runtime.prepare_seed(spec, 'operator-key', smoke=smoke)
                network = json.loads((root / 'image-test-server-seed/network-config').read_text())
                routes = network['ethernets']['rke2lab0'].get('routes', [])
                self.assertEqual(routes, [{'to': '10.43.0.0/16', 'via': '0.0.0.0'}] if smoke else [])
                self.assertFalse(any(r.get('to') in ('default', '0.0.0.0/0') for r in routes))

    def test_libvirt_ipv6_filter_normalization(self):
        import xml.etree.ElementTree as ET
        for protocol in ('0x86dd', 'ipv6'):
            def virsh(*args):
                if args[0] == 'net-dumpxml':
                    return '<network><bridge name="virbr-rke2"/></network>'
                if args[0] == 'pool-dumpxml':
                    return '<pool><target><path>' + str(runtime.POOL) + '</path></target></pool>'
                return '<filter><rule action="drop" direction="inout"><mac protocolid="' + protocol + '"/></rule></filter>'
            with patch.object(runtime, 'virsh', side_effect=virsh), patch.object(runtime, 'run', return_value='[{"addr_info": []}]'):
                runtime.isolation()

    def test_empty_rpm_directories_are_allowed_but_cluster_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = root / 'server'
            (server / 'db/snapshots').mkdir(parents=True)
            containerd = root / 'containerd'
            (containerd / 'overlayfs/snapshots').mkdir(parents=True)
            def mapped(value):
                return server if value == '/var/lib/rancher/rke2/server' else containerd
            with patch.object(guest, 'Path', side_effect=mapped):
                self.assertTrue(guest.cluster_state_absent())
                (server / 'db/state').write_text('cluster state')
                self.assertFalse(guest.cluster_state_absent())
                (server / 'db/state').unlink()
                (server / 'tls').symlink_to(root, target_is_directory=True)
                self.assertFalse(guest.cluster_state_absent())

    def report(self, profile='server'):
        spec = {'name': 'image-test-server', 'host_id': 'host-id', 'profile': profile, 'address': '192.168.250.241'}
        report = {'errors': [], 'selinux': 'Enforcing', 'operator_password': 'LK', 'hostname': spec['name'],
            'host_id': spec['host_id'], 'identity_uid': 0, 'identity_mode': '0o600', 'authorized_keys': ['operator-key'],
            'machine_id': 'a' * 32, 'image': {'profile': profile, 'versions': artifacts.VERSIONS},
            'firewalld_active': 'active' if profile == 'os' else 'inactive',
            'firewalld_enabled': 'enabled' if profile == 'os' else 'disabled',
            'rke2_units': {role: {'enabled': 'masked', 'active': 'inactive'} for role in ('server', 'agent')},
            'cloud_init': {'status': 'done'}, 'addresses': [{'addr_info': [{'local': spec['address']}]}],
            'routes': [], 'pings': {'1.1.1.1': 1}, 'cluster_state_absent': True,
            'packages': {'firewalld': True, 'rke2-server': profile == 'server', 'rke2-agent': profile == 'agent',
                         'rke2-selinux': profile != 'os'}}
        return spec, report

    def test_profile_firewall_and_service_policy(self):
        for profile in ('os', 'server', 'agent'):
            spec, report = self.report(profile)
            runtime.validate_report(spec, report, 'operator-key')
            report['firewalld_enabled'] = 'masked'
            with self.assertRaisesRegex(artifacts.ImageError, 'firewalld'):
                runtime.validate_report(spec, report, 'operator-key')
        spec, report = self.report()
        report['rke2_units']['server']['enabled'] = 'enabled'
        with self.assertRaisesRegex(artifacts.ImageError, 'masked'):
            runtime.validate_report(spec, report, 'operator-key')

    def test_external_connectivity_rejected(self):
        spec, report = self.report()
        report['pings']['1.1.1.1'] = 0
        with self.assertRaisesRegex(artifacts.ImageError, 'external'):
            runtime.validate_report(spec, report, 'operator-key')

    def test_deployment_cloud_init_has_no_package_or_firewall_mutations(self):
        node = {'name': 'rke2-r9-cp01', 'host_id': '2f4baedf-a8ad-4430-9126-b906e879f3b1',
                'mac': '52:54:00:40:01:01', 'address': '192.168.250.11', 'profile': 'server'}
        key = 'ssh-ed25519 ' + base64.b64encode(b'x' * 40).decode()
        rendered = provision.render_cloud_init(node, '192.168.250.0/24', key,
            Path(provision.__file__).parents[1] / 'cloud-init/rocky9')['user-data']
        for forbidden in ('[dnf', '[rpm', '[mount', 'enable, --now, firewalld', 'packages:'):
            self.assertNotIn(forbidden, rendered)
        self.assertIn('lock_passwd: true', rendered)
        self.assertIn('autonomous-image-validation', rendered)
        self.assertIn('cloud-init.target.wants/autonomous-image-validation', rendered)
        self.assertNotIn('multi-user.target.wants/autonomous-image-validation', rendered)


class RecoveryTests(unittest.TestCase):
    def test_rollback_reserves_old_capacity_while_retaining_full_new_disks(self):
        import xml.etree.ElementTree as ET
        with tempfile.TemporaryDirectory() as temporary:
            old_disk = Path(temporary) / 'old.qcow2'
            old_disk.write_bytes(b'old data')
            old = {'name': 'rke2-r9-cp01', 'uuid': 'old', 'disk': str(old_disk), 'state': 'running'}
            new = {'uuid': 'new', 'disk': '/owned/new.qcow2'}
            xml = ET.fromstring('<domain id="1"><uuid>new</uuid><devices><disk device="disk"><source file="/owned/new.qcow2"/></disk></devices></domain>')
            with patch.object(runtime, 'absent', return_value=False), patch.object(runtime, 'current', return_value=xml), \
                 patch.object(runtime, 'virsh', return_value=f'Capacity: {60 * artifacts.GIB}\nAllocation: {60 * artifacts.GIB}\n'), \
                 patch.object(replace, 'preflight', side_effect=artifacts.ImageError('disk reserve')) as reserve:
                with self.assertRaisesRegex(artifacts.ImageError, 'reserve'):
                    replace.rollback_preflight({'nodes': [{'old': old, 'new': new}]})
            reserve.assert_called_once_with(extra_disk=60 * artifacts.GIB - old_disk.stat().st_blocks * 512,
                                            extra_memory_mib=0)

    def test_storage_inode_change_rejected_before_mutation(self):
        old = {'name': 'rke2-r9-cp01', 'uuid': 'same', 'disk': '/owned/disk', 'nvram': '/owned/nvram',
               'mac': 'mac', 'address': 'address', 'paths': ['/owned/disk'],
               'file_ids': {'/owned/disk': {'device': 1, 'inode': 2}}}
        changed = copy.deepcopy(old)
        changed['file_ids']['/owned/disk']['inode'] = 3
        with patch.object(replace, 'binding', return_value=changed):
            with self.assertRaisesRegex(artifacts.ImageError, 'ownership binding changed'):
                replace.check_binding(old)

    def journal(self, root):
        old = {'name': 'rke2-r9-cp01', 'uuid': 'old', 'nvram': str(root / 'old.fd'), 'state': 'running'}
        new = {'name': old['name'], 'uuid': 'new'}
        plan = root / 'plan.json'
        plan.write_text('{}')
        xml = root / (old['name'] + '.old.xml')
        xml.write_text('<domain/>')
        nvram = root / (old['name'] + '.old.vars.fd')
        nvram.write_bytes(b'old firmware')
        journal = root / 'journal.json'
        artifacts.write_json(journal, {'plan': str(plan), 'plan_sha256': artifacts.digest(plan), 'status': 'applying',
            'nodes': [{'name': old['name'], 'stage': 'created', 'old_xml_sha256': artifacts.digest(xml),
                       'old_nvram_sha256': artifacts.digest(nvram)}]})
        return journal, {'generation': str(root), 'nodes': [{'old': old, 'new': new}]}

    def test_rollback_stops_on_uuid_mismatch(self):
        import xml.etree.ElementTree as ET
        with tempfile.TemporaryDirectory() as temporary:
            path, doc = self.journal(Path(temporary))
            with patch.object(replace, 'load_plan', return_value=doc), patch.object(runtime, 'absent', return_value=False), \
                 patch.object(replace, 'rollback_preflight'), \
                 patch.object(runtime, 'current', return_value=ET.fromstring('<domain><uuid>foreign</uuid></domain>')), \
                 patch.object(runtime, 'discard') as discard:
                with self.assertRaisesRegex(artifacts.ImageError, 'ownership/UUID'):
                    replace.rollback_journal(path)
                discard.assert_not_called()

    def test_rollback_restores_previous_generation_and_keeps_files(self):
        import xml.etree.ElementTree as ET
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, doc = self.journal(root)
            with patch.object(replace, 'load_plan', return_value=doc), \
                 patch.object(replace, 'rollback_preflight'), \
                 patch.object(runtime, 'absent', side_effect=[False, True]), \
                 patch.object(runtime, 'current', return_value=ET.fromstring('<domain><uuid>new</uuid></domain>')), \
                 patch.object(runtime, 'discard') as discard, patch.object(replace, 'check_binding'), \
                 patch.object(runtime, 'virsh', return_value='shut off') as virsh:
                replace.rollback_journal(path)
            discard.assert_called_once_with(doc['nodes'][0]['new'])
            self.assertEqual((root / 'old.fd').read_bytes(), b'old firmware')
            self.assertEqual(json.loads(path.read_text())['status'], 'rolled-back')
            self.assertTrue((root / 'rke2-r9-cp01.old.xml').exists())
            self.assertIn(('start', 'old'), [c.args for c in virsh.call_args_list])

    def test_validation_failure_invokes_journal_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release_path = root / 'release.json'
            release_path.write_text('{}')
            image = root / 'server.qcow2'
            image.write_bytes(b'image')
            old_nvram = root / 'old.fd'
            old_nvram.write_bytes(b'firmware')
            old = {'name': 'rke2-r9-cp01', 'uuid': 'old', 'nvram': str(old_nvram), 'xml': '<domain/>', 'state': 'running'}
            new = {'name': old['name'], 'uuid': 'new'}
            plan_path = root / 'plan.json'
            plan_path.write_text('{}')
            doc = {'release': str(release_path), 'release_sha256': artifacts.digest(release_path),
                   'generation': str(root / 'generation'), 'nodes': [{'old': old, 'new': new}]}
            release = {'profiles': {'server': {'file': image.name, 'sha256': artifacts.digest(image)}}}
            key = root / 'operator.pub'
            key.write_text('operator-key')
            with patch.object(replace, 'load_plan', return_value=doc), \
                 patch.object(replace, 'capture_host', return_value={}), \
                 patch.object(replace, 'verify_manifest', return_value=release), patch.object(runtime, 'isolation'), \
                 patch.object(replace, 'preflight'), patch.object(replace, 'check_binding'), \
                 patch.object(runtime, 'stop'), patch.object(runtime, 'virsh', return_value=''), \
                 patch.object(runtime, 'OPERATOR_KEY', key), patch.object(runtime, 'launch'), \
                 patch.object(runtime, 'wait_report', return_value={}), \
                 patch.object(runtime, 'validate_report', side_effect=artifacts.ImageError('policy failed')), \
                 patch.object(replace, 'rollback_journal') as recover:
                with self.assertRaisesRegex(artifacts.ImageError, 'policy failed'):
                    replace.apply(plan_path)
            journal_path = root / 'generation/journal.json'
            recover.assert_called_once_with(journal_path)
            journal = json.loads(journal_path.read_text())
            self.assertEqual(journal['status'], 'recovering')
            self.assertEqual(journal['nodes'][0]['stage'], 'created')
            self.assertTrue((journal_path.parent / 'rke2-r9-cp01.old.vars.fd').exists())


if __name__ == '__main__':
    unittest.main()
