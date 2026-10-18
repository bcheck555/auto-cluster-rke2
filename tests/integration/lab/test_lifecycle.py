from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from lab.libvirt import lifecycle as life


class FakeHost:
    """Model libvirt state transitions; never invoke a real hypervisor."""

    def __init__(self):
        self.domains = {}
        self.running = set()
        self.pools = {}
        self.networks = {}
        self.active_pools = set()
        self.active_networks = set()
        self.filters = set()
        self.calls = []
        self.bridge = False
        self.ports = []
        self.fail_stop = None
        self.fail_undefine = None
        self.fail_settings = None

    def inventory(self):
        return {'domains': dict(self.domains), 'running': set(self.running),
                'pools': dict(self.pools), 'networks': dict(self.networks),
                'filters': set(self.filters)}

    def virsh(self, *args):
        args = tuple(map(str, args))
        self.calls.append(args)
        op = args[0]
        if op == 'list':
            return '\n'.join(self.domains if '--all' in args else self.running)
        if op == 'dumpxml':
            return ET.tostring(self.domains[args[1]], encoding='unicode')
        if op == 'nwfilter-list':
            return '\n'.join('11111111-1111-4111-8111-111111111111 ' + name for name in self.filters)
        if op == 'nwfilter-dumpxml':
            xml = ET.parse(life.ROOT / 'lab/libvirt/ipv4-only.xml').getroot()
            xml.set('name', args[1])
            return ET.tostring(xml, encoding='unicode')
        if op == 'nwfilter-define':
            self.filters.add(ET.parse(args[1]).getroot().get('name'))
        elif op == 'nwfilter-undefine':
            self.filters.remove(args[1])
        elif op == 'define':
            xml = ET.parse(args[1]).getroot()
            self.domains[xml.findtext('name')] = xml
        elif op == 'start':
            self.running.add(args[1])
        elif op == 'destroy':
            if self.fail_stop == args[1]:
                raise life.ImageError('injected stop failure')
            self.running.remove(args[1])
        elif op == 'undefine':
            if self.fail_undefine == args[1]:
                raise life.ImageError('injected undefine failure')
            del self.domains[args[1]]
        elif op.startswith('net-') or op.startswith('pool-'):
            kind, action = op.split('-', 1)
            entries, active = ((self.networks, self.active_networks) if kind == 'net'
                               else (self.pools, self.active_pools))
            if action == 'list':
                return '\n'.join(entries if '--all' in args else active)
            if action == 'dumpxml':
                return ET.tostring(entries[args[1]], encoding='unicode')
            if op == self.fail_settings:
                raise life.ImageError('injected settings failure')
            if action == 'define':
                xml = ET.parse(args[1]).getroot()
                entries[xml.findtext('name')] = xml
            elif action == 'define-as':
                xml = ET.Element('pool')
                ET.SubElement(ET.SubElement(xml, 'target'), 'path').text = args[-1]
                entries[args[1]] = xml
            elif action == 'start':
                active.add(args[1])
                if kind == 'net':
                    self.bridge = True
            elif action == 'destroy':
                active.remove(args[1])
                if kind == 'net':
                    self.bridge = False
            elif action == 'undefine':
                del entries[args[1]]
            elif action != 'autostart':
                raise AssertionError(args)
        else:
            raise AssertionError(args)
        return ''

    def command(self, args, **kwargs):
        args = list(map(str, args))
        if args[0] == 'ip':
            if 'delete' in args:
                self.bridge = False
                return ''
            if 'master' in args:
                return json.dumps(self.ports)
            if 'link' in args:
                bridges = {self.networks[name].find('bridge').get('name')
                           for name in self.active_networks}
                if self.bridge:
                    bridges.add(life.BRIDGE)
                return json.dumps([{'ifname': name} for name in bridges])
            return '[]'
        if args[:2] == ['qemu-img', 'convert']:
            Path(args[-1]).write_bytes(b'fresh standalone disk')
        elif args[:2] == ['qemu-img', 'resize']:
            pass
        elif args[:2] == ['qemu-img', 'info']:
            return json.dumps({'format': 'qcow2', 'virtual-size': 60 * life.GIB})
        elif args[0] == 'genisoimage':
            target = Path(args[args.index('-output') + 1])
            assert target.stat().st_mode & 0o777 == 0o600
            target.write_bytes(b'seed ISO')
        elif args[0] == 'ssh-keygen':
            if '-y' in args:
                return 'ssh-ed25519 fixture\n'
            target = Path(args[-1])
            target.write_text('private fixture')
            target.with_suffix('.pub').write_text('ssh-ed25519 fixture\n')
        elif args[0] == 'ssh':
            return 'server: https://127.0.0.1:6443\n' if 'sudo cat' in args[-1] else 'healthy\n'
        else:
            raise AssertionError(args)
        return ''


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pool = Path(self.temp.name) / 'pool'
        self.release = Path(self.temp.name) / 'release.json'
        self.release.write_text('{}')
        self.lab = life.Lab(self.pool)
        self.host = FakeHost()
        self.enter = contextlib.ExitStack()
        self.addCleanup(self.enter.close)
        self.enter.enter_context(patch.object(life, 'virsh', self.host.virsh))
        self.enter.enter_context(patch.object(life, 'command', self.host.command))
        self.enter.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def create(self, count=3):
        manifest = {'kind': 'release', 'profiles': {'node': {}}, 'files': {'node.qcow2': {}}}
        def firmware(source, target):
            Path(target).write_bytes(b'fresh NVRAM')
        with patch.object(life, 'verify_manifest', return_value=manifest), \
                patch.object(self.lab, 'check_capacity'), \
                patch.object(life.shutil, 'copyfile', side_effect=firmware):
            self.lab.create(self.release, count, 1, self.host.inventory())

    def test_create_four_nodes_sequentially_and_keep_seeds_private(self):
        original = self.lab.wait_healthy
        seen = []
        def healthy(spec, timeout):
            seen.append(spec['name'])
            self.assertEqual(self.host.running, set(life.NAMES[:len(seen)]))
            return original(spec, timeout)
        with patch.object(self.lab, 'wait_healthy', side_effect=healthy):
            self.create(4)
        state = json.loads(self.lab.state_path.read_text())
        self.assertTrue(state['complete'])
        self.assertEqual([node['name'] for node in state['nodes']],
                         ['rke2-node01', 'rke2-node02', 'rke2-node03', 'rke2-node04'])
        self.assertEqual(len({node['uuid'] for node in state['nodes']}), 4)
        self.assertEqual(len({node['mac'] for node in state['nodes']}), 4)
        self.assertEqual(len({node['instance_id'] for node in state['nodes']}), 4)
        for node in state['nodes']:
            seed = self.pool / (node['name'] + '-seed')
            data = json.loads((seed / 'user-data').read_text().split('\n', 1)[1])
            self.assertEqual(data['hostname'], node['name'])
            self.assertEqual(data['write_files'][0]['content'], state['secret'])
            self.assertEqual(data['runcmd'][-1][-1], 'autonomous-rke2-host-agent.service')
            self.assertNotIn('autonomous-image-validation', json.dumps(data))
            network = json.loads((seed / 'network-config').read_text())
            self.assertEqual(network['ethernets']['rke2lab0']['routes'][0]['to'], '10.43.0.0/16')
            self.assertEqual(Path(node['seed']).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.lab.state_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.pool / 'admin.yaml').stat().st_mode & 0o777, 0o600)
        self.assertIn('192.168.250.11', (self.pool / 'admin.yaml').read_text())

    def test_resume_after_second_node_failure_and_regain_quorum_before_waiting(self):
        def fail_second(spec, timeout):
            if spec['name'] == life.NAMES[1]:
                raise life.ImageError('join interrupted')
        with patch.object(self.lab, 'wait_healthy', side_effect=fail_second):
            with self.assertRaisesRegex(life.ImageError, 'join interrupted'):
                self.create()
        original_state = json.loads(self.lab.state_path.read_text())
        disk = self.pool / (life.NAMES[0] + '.qcow2')
        disk.write_bytes(b'initialized etcd data must survive')
        self.host.running.clear()  # Both previously booted voters now require restart.
        original_wait = self.lab.wait_healthy
        def resumed_health(spec, timeout):
            self.assertTrue(set(life.NAMES[:2]).issubset(self.host.running))
            return original_wait(spec, timeout)
        with patch.object(self.lab, 'wait_healthy', side_effect=resumed_health):
            self.create()
        resumed = json.loads(self.lab.state_path.read_text())
        self.assertEqual(original_state['secret'], resumed['secret'])
        self.assertEqual(original_state['nodes'][0]['uuid'], resumed['nodes'][0]['uuid'])
        self.assertEqual(disk.read_bytes(), b'initialized etcd data must survive')
        # The same resume behavior must work after a completed three-voter reboot.
        self.host.running.clear()
        def quorum(spec, timeout):
            self.assertEqual(self.host.running, set(life.NAMES[:3]))
        with patch.object(self.lab, 'wait_healthy', side_effect=quorum):
            self.create()

    def test_booted_missing_disk_is_never_silently_replaced(self):
        self.create()
        (self.pool / (life.NAMES[0] + '.qcow2')).unlink()
        with self.assertRaisesRegex(life.ImageError, 'missing disk/seed/NVRAM'):
            self.create()

    def test_partial_seed_generation_resumes_without_regenerating_identity(self):
        original = self.host.command
        failed = False
        def interrupted(args, **kwargs):
            nonlocal failed
            if str(args[0]) == 'genisoimage' and not failed:
                failed = True
                raise life.ImageError('interrupted seed generation')
            return original(args, **kwargs)
        with patch.object(life, 'command', side_effect=interrupted):
            with self.assertRaisesRegex(life.ImageError, 'interrupted seed generation'):
                self.create()
        state = json.loads(self.lab.state_path.read_text())
        self.assertFalse(any(node['boot_requested'] for node in state['nodes']))
        disk = self.pool / (life.NAMES[0] + '.qcow2')
        disk.write_bytes(b'keep prepared disk')
        self.create()
        resumed = json.loads(self.lab.state_path.read_text())
        self.assertEqual(state['secret'], resumed['secret'])
        self.assertEqual(state['nodes'][0]['uuid'], resumed['nodes'][0]['uuid'])
        self.assertEqual(disk.read_bytes(), b'keep prepared disk')

    def test_changed_vm_binding_cannot_resume(self):
        self.create()
        xml = self.host.domains[life.NAMES[0]]
        xml.find('devices/interface/mac').set('address', '52:54:00:00:00:00')
        with self.assertRaisesRegex(life.ImageError, 'binding changed'):
            self.create()

    def test_reject_release_or_count_change_and_unmanaged_leftovers(self):
        self.pool.mkdir()
        (self.pool / 'old-seed.iso').write_text('old')
        with self.assertRaisesRegex(life.ImageError, 'unmanaged'):
            self.create()
        self.lab.destroy(self.host.inventory())
        self.create()
        with self.assertRaisesRegex(life.ImageError, 'different release/node count'):
            self.create(4)
        self.release.write_text('{"changed":true}')
        with self.assertRaisesRegex(life.ImageError, 'different release/node count'):
            self.create()

    def test_signature_failure_precedes_all_mutations(self):
        with patch.object(life, 'verify_manifest', side_effect=life.ImageError('bad signature')):
            with self.assertRaisesRegex(life.ImageError, 'bad signature'):
                self.lab.create(self.release, 3, 1, self.host.inventory())
        self.assertFalse(self.pool.exists())
        self.assertFalse(self.host.calls)

    def test_destroy_full_lab_stop_all_before_undefine_and_repeat(self):
        self.create()
        (self.pool / 'old-generation').mkdir()
        (self.pool / 'old-generation' / 'old-secret').write_text('secret')
        self.host.domains['unrelated'] = ET.fromstring('<domain><name>unrelated</name></domain>')
        self.host.running.add('unrelated')
        self.host.calls.clear()
        self.lab.destroy(self.host.inventory())
        stop_indices = [i for i, call in enumerate(self.host.calls) if call[0] == 'destroy']
        undefine_indices = [i for i, call in enumerate(self.host.calls) if call[0] == 'undefine']
        self.assertLess(max(stop_indices), min(undefine_indices))
        self.assertEqual(self.host.running, {'unrelated'})
        self.assertEqual(set(self.host.domains), {'unrelated'})
        self.assertFalse(self.host.pools or self.host.networks or self.host.filters)
        self.assertFalse(self.pool.exists())
        self.lab.destroy(self.host.inventory())
        self.assertFalse(self.pool.exists())

    def test_destroy_orphaned_files_without_any_libvirt_definitions(self):
        self.pool.mkdir()
        (self.pool / 'orphan.qcow2').write_bytes(b'disk')
        self.host.bridge = True
        self.lab.destroy(self.host.inventory())
        self.assertFalse(self.pool.exists())
        self.assertFalse(self.host.bridge)

    def test_legacy_deployment_resumes_with_saved_names_and_capacity_then_destroys(self):
        with patch.object(life, 'NAMES', life.LEGACY_NAMES):
            self.create(4)
        state = json.loads(self.lab.state_path.read_text())
        self.host.running.clear()
        self.create(4)
        self.assertEqual(set(self.host.domains), set(life.LEGACY_NAMES))
        self.assertEqual(json.loads(self.lab.state_path.read_text())['nodes'], state['nodes'])
        self.assertEqual(self.lab.deployment_names(4), life.LEGACY_NAMES)
        # Resuming must count the existing legacy disks/VMs, rather than allocate
        # capacity for a second cluster under the new naming scheme.
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            if str(path) == '/proc/meminfo':
                return 'MemAvailable: 16777216 kB\n'
            return original_read(path, *args, **kwargs)
        with patch.object(life.shutil, 'disk_usage') as usage, \
                patch.object(Path, 'read_text', autospec=True, side_effect=read):
            usage.return_value.free = 9 * life.GIB
            self.lab.check_capacity(4, self.host.inventory())
        self.lab.destroy(self.host.inventory())
        self.assertFalse(self.host.domains)
        self.assertFalse(self.pool.exists())

    def test_unmanaged_legacy_vms_are_cleaned_but_not_adopted_by_create(self):
        self.pool.mkdir()
        for name in life.LEGACY_NAMES:
            spec = life.make_spec(name, '192.168.250.11', 'node', self.pool)
            self.host.domains[name] = ET.fromstring(life.domain_xml(spec))
            self.host.running.add(name)
            Path(spec['disk']).write_bytes(b'old lab disk')
        with self.assertRaisesRegex(life.ImageError, 'unmanaged'):
            self.create()
        self.lab.destroy(self.host.inventory())
        self.assertFalse(self.host.domains)
        self.assertFalse(self.pool.exists())

    def test_inactive_auxiliary_pool_inside_lab_is_also_removed(self):
        self.pool.mkdir()
        self.host.pools['old-virt-install-pool'] = ET.fromstring(
            f'<pool><target><path>{self.pool}/generation</path></target></pool>')
        self.lab.destroy(self.host.inventory())
        self.assertFalse(self.host.pools)

    def test_stop_or_undefine_failure_retains_disks_then_retry_succeeds(self):
        for failure in ('fail_stop', 'fail_undefine'):
            with self.subTest(failure=failure):
                self.create()
                setattr(self.host, failure, life.NAMES[1])
                with self.assertRaisesRegex(life.ImageError, 'disks retained'):
                    self.lab.destroy(self.host.inventory())
                self.assertTrue(self.pool.exists())
                setattr(self.host, failure, None)
                self.lab.destroy(self.host.inventory())
                self.assertFalse(self.pool.exists())

    def test_settings_failure_is_retryable_with_files_retained(self):
        self.create()
        self.host.fail_settings = 'net-destroy'
        with self.assertRaisesRegex(life.ImageError, 'files retained'):
            self.lab.destroy(self.host.inventory())
        self.assertTrue(self.pool.exists())
        self.assertFalse(self.host.domains)
        self.host.fail_settings = None
        self.lab.destroy(self.host.inventory())
        self.assertFalse(self.pool.exists())

    def test_foreign_vm_disk_or_network_binding_refuses_before_stop(self):
        self.create()
        for binding in (f"<disk device='disk'><source file='{self.pool}/shared.qcow2'/></disk>",
                        f"<interface><source network='{life.NETWORK}'/></interface>"):
            self.host.domains['foreign'] = ET.fromstring(f'<domain><devices>{binding}</devices></domain>')
            before = list(self.host.calls)
            with self.assertRaisesRegex(life.ImageError, 'unrelated VM foreign'):
                self.lab.destroy(self.host.inventory())
            self.assertEqual(before, self.host.calls)
        del self.host.domains['foreign']

    def test_same_named_vm_outside_pool_is_protected(self):
        self.host.domains[life.NAMES[0]] = ET.fromstring(
            "<domain><devices><disk device='disk'><source file='/other/vm.qcow2'/></disk></devices></domain>")
        with self.assertRaisesRegex(life.ImageError, 'outside lab directory'):
            self.lab.destroy(self.host.inventory())
        self.assertFalse(self.host.calls)

    def test_mount_or_symlink_pool_is_protected(self):
        self.pool.mkdir()
        with patch.object(life.os.path, 'ismount', return_value=True):
            with self.assertRaisesRegex(life.ImageError, 'mount inside'):
                self.lab.destroy(self.host.inventory())
        target = self.pool.parent / 'target'
        self.pool.rmdir()
        target.mkdir()
        self.pool.symlink_to(target)
        with self.assertRaisesRegex(life.ImageError, 'symlink'):
            self.lab.destroy(self.host.inventory())

    def test_plan_and_unconfirmed_destroy_never_mutate(self):
        with patch.object(life, 'Lab', return_value=self.lab), \
                patch.object(life.shutil, 'which', return_value='/fixture/tool'), \
                patch.object(life.os, 'geteuid', return_value=0):
            self.assertEqual(life.main('destroy', ['--plan']), 0)
            self.host.calls.clear()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(life.main('destroy', []), 1)
            self.assertFalse(self.host.calls)
            self.assertFalse(self.pool.exists())

    def test_multiple_clusters_custom_names_subnet_resume_and_scoped_destroy(self):
        dev_pool = self.pool.parent / 'dev'
        prod_pool = self.pool.parent / 'prod'
        self.lab = life.Lab(dev_pool, cluster='dev', hostname_prefix='compute-',
                            network='dev-private', subnet='172.22.8.0/23')
        self.create()
        dev_state = json.loads(self.lab.state_path.read_text())
        self.assertEqual([node['name'] for node in dev_state['nodes']],
                         ['compute-01', 'compute-02', 'compute-03'])
        first_seed = dev_pool / 'compute-01-seed' / 'network-config'
        network = json.loads(first_seed.read_text())['ethernets']['rke2lab0']
        self.assertEqual(network['addresses'], ['172.22.8.11/23'])
        domain = self.host.domains['compute-01']
        self.assertEqual(domain.find('devices/interface/source').get('network'), 'dev-private')
        self.assertEqual(domain.find('devices/interface/filterref').get('filter'),
                         'autonomous-rke2-dev-ipv4-only')
        self.lab = life.Lab(prod_pool, cluster='prod')
        self.create(4)
        prod_state = json.loads(self.lab.state_path.read_text())
        self.assertNotEqual(prod_state['configuration']['subnet'], dev_state['configuration']['subnet'])
        self.assertNotEqual(prod_state['secret'], dev_state['secret'])
        prod_names = {node['name'] for node in prod_state['nodes']}
        self.lab = life.Lab(dev_pool, cluster='dev')  # No custom flags needed on resume.
        self.create()
        self.assertEqual(self.lab.settings.hostname_prefix, 'compute-')
        self.assertEqual(self.lab.settings.network, 'dev-private')
        self.assertEqual(json.loads(self.lab.state_path.read_text())['nodes'], dev_state['nodes'])
        with patch.object(life, 'Lab', return_value=self.lab), \
                patch.object(life.os, 'geteuid', return_value=0), \
                patch.object(life.shutil, 'which', return_value='/fixture/tool'), \
                patch.object(life, 'operation_lock', side_effect=contextlib.nullcontext):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(life.main('destroy', ['--cluster', 'dev', '--confirm-cluster', 'prod']), 1)
            self.assertTrue(dev_pool.exists())
            self.assertTrue(prod_pool.exists())
            self.assertEqual(life.main('destroy', ['--cluster', 'dev', '--confirm-cluster', 'dev']), 0)
        self.assertFalse(dev_pool.exists())
        self.assertTrue(prod_pool.exists())
        self.assertEqual(set(self.host.domains), prod_names)
        self.assertEqual(set(self.host.networks), {'autonomous-rke2-prod'})
        self.assertEqual(set(self.host.pools), {'autonomous-rke2-prod'})
        self.assertEqual(self.host.filters, {'autonomous-rke2-prod-ipv4-only'})

    def test_custom_subnet_conflict_rejected_before_state_or_definitions(self):
        self.lab = life.Lab(self.pool, cluster='dev', subnet='10.43.8.0/24')
        with self.assertRaisesRegex(life.ImageError, 'Kubernetes pod/service'):
            self.create()
        self.assertFalse(self.pool.exists())
        self.assertFalse(self.host.calls)

    def test_second_cluster_cannot_reuse_hostname_prefix(self):
        self.lab = life.Lab(self.pool, cluster='dev', hostname_prefix='compute-')
        self.create()
        other = self.pool.parent / 'other'
        self.lab = life.Lab(other, cluster='prod', hostname_prefix='compute-')
        before = list(self.host.calls)
        with self.assertRaisesRegex(life.ImageError, 'outside lab directory'):
            self.create()
        self.assertEqual(before, self.host.calls)
        self.assertFalse(other.exists())

    def test_old_state_without_configuration_still_resumes(self):
        self.create()
        state = json.loads(self.lab.state_path.read_text())
        del state['configuration']
        for node in state['nodes']:
            del node['network']
            del node['filter']
        self.lab.save(state)
        self.lab = life.Lab(self.pool)
        self.create()
        self.assertEqual(set(self.host.domains), set(life.NAMES[:3]))


if __name__ == '__main__':
    unittest.main()
