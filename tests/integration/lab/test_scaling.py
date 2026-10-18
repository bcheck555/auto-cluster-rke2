"""Pure planning and crash-recovery tests; no real guest or cluster mutations."""
import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lab.libvirt.scaling import (Scaling, control_count, next_change, planned_changes,
                                 quorum_message, resize_peak, missing_retirements)
from lab.packer.artifacts import ImageError
from lab.libvirt import lifecycle as life


def node(index, role='server'):
    return {'index': index, 'role': role, 'name': f'test-node{index:02}', 'uuid': f'uuid-{index}',
            'address': f'192.168.99.{10 + index}', 'member_id': f'member-{index}',
            'node_name': f'kube-{index}', 'node_uid': f'uid-{index}', 'etcd_member_id': str(index)}


class PlannerTests(unittest.TestCase):
    def test_targets_and_warnings(self):
        for invalid in (True, 0, 1, 2, 4, 6, 8, '3'):
            with self.assertRaises(ImageError):
                control_count(invalid)
        for total, controls, warn, majority in ((1, 3, True, 1), (2, 3, True, 2),
                                               (3, 3, False, 2), (4, 5, True, 3),
                                               (5, 5, False, 3), (7, 7, False, 4)):
            text = quorum_message(total, controls)
            self.assertEqual(text.startswith('WARNING:'), warn)
            self.assertIn(f'quorum requires {majority}', text)

    def test_worker_first_highest_index_and_sparse_survivors(self):
        nodes = [node(1), node(4), node(7), node(3, 'agent'), node(9, 'agent')]
        changes, peak = planned_changes(nodes, 2, 3)
        self.assertEqual([c['victim']['index'] for c in changes], [9, 3, 7])
        self.assertEqual(peak, 5)
        self.assertEqual(nodes[1]['index'], 4)

    def test_grow_and_rebalance_at_constant_total(self):
        nodes = [node(i, 'server' if i <= 3 else 'agent') for i in range(1, 8)]
        changes, peak = planned_changes(nodes, 7, 5)
        self.assertEqual([c['role'] for c in changes], ['server', 'server'])
        self.assertEqual([c['victim']['index'] for c in changes], [7, 6])
        self.assertEqual(peak, 8)
        changes, peak = planned_changes([node(i) for i in range(1, 6)], 7, 3)
        self.assertEqual([c['role'] for c in changes], ['agent'] * 4)
        self.assertEqual(sum(c['victim'] is not None for c in changes), 2)
        self.assertEqual(peak, 7)

    def test_shrink_frees_excess_worker_before_control_role_replacement(self):
        nodes = [node(i, 'server' if i <= 3 else 'agent') for i in range(1, 6)]
        changes, peak = planned_changes(nodes, 4, 5)
        self.assertEqual(changes[0]['kind'], 'remove')
        self.assertEqual(changes[0]['victim']['index'], 5)
        self.assertEqual(changes[1]['role'], 'server')
        self.assertEqual(changes[1]['victim']['index'], 4)
        self.assertEqual(peak, 5)

    def test_noop_and_pending_step_peak(self):
        nodes = [node(i) for i in range(1, 4)]
        self.assertIsNone(next_change(nodes, 3, 3))
        state = {'nodes': nodes, 'resize': {'nodes': 2, 'controls': 3,
                                          'step': {'kind': 'remove', 'victim': nodes[-1]}}}
        self.assertEqual(resize_peak(state, 2, 3), 3)


class OwnershipAndObservationTests(unittest.TestCase):
    def test_missing_boot_artifacts_are_skipped_only_for_known_retirements(self):
        with tempfile.TemporaryDirectory() as directory:
            nodes = [node(i) for i in (1, 2, 3)]
            for spec in nodes:
                spec['boot_requested'] = True
                for key in ('disk', 'seed', 'nvram'):
                    path = Path(directory) / (spec['name'] + '-' + key)
                    path.touch()
                    spec[key] = str(path)
            Path(nodes[-1]['disk']).unlink()
            state = {'nodes': nodes}
            self.assertEqual(missing_retirements(state, 2, 3), {'uuid-3'})
            self.assertEqual(missing_retirements(state, 3, 3), set())
            state['resize'] = {'nodes': 3, 'controls': 3, 'step': None}
            self.assertEqual(missing_retirements(state, 1, 3), set())

    def test_sparse_saved_members_resume_and_legacy_count_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = life.Lab(pool=directory, cluster='scale', hostname_prefix='test-node', subnet='192.168.99.0/24')
            specs = [{**life.make_spec(f'test-node{i:02}', lab.settings.address(i - 1), 'node', Path(directory)),
                      'index': i, 'boot_requested': True, 'role': 'server',
                      'network': lab.settings.network, 'filter': lab.settings.filter} for i in (1, 4)]
            state = {'schema': 2, 'count': 2, 'nodes': specs, 'configuration': lab.settings.document(),
                     'release_sha256': 'hash', 'secret': 'a' * 64}
            lab.save(state)
            loaded = lab.load_or_initialize(Path('release'), 'hash', 3, {'domains': {}})
            self.assertEqual([s['index'] for s in loaded['nodes']], [1, 4])
            self.assertEqual(loaded['nodes'][1]['address'], '192.168.99.14')
            state['schema'] = 1
            lab.save(state)
            with self.assertRaisesRegex(ImageError, 'different release/node count'):
                lab.load_or_initialize(Path('release'), 'hash', 3, {'domains': {}})

    def test_live_identity_role_and_voter_drift_are_rejected(self):
        spec = node(1)
        member = {'ID': spec['member_id'], 'Address': spec['address'], 'NodeName': spec['node_name'],
                  'NodeUID': spec['node_uid'], 'EtcdMemberID': spec['etcd_member_id'], 'Role': 'server', 'Complete': True}
        status = {'catalog': {'ClusterID': 'cluster', 'Members': {member['ID']: member}},
                  'etcd': [{'ID': member['EtcdMemberID'], 'PeerURLs': ['https://' + member['Address'] + ':2380']}],
                  'nodes': [{'Metadata': {'Name': member['NodeName'], 'UID': member['NodeUID'],
                                          'Labels': {'autonomous-rke2.io/host-id': member['ID'][:32],
                                                     'autonomous-rke2.io/cluster-id': 'cluster',
                                                     'node-role.kubernetes.io/control-plane': 'true',
                                                     'node-role.kubernetes.io/etcd': 'true'}},
                             'Status': {'Addresses': [{'Type': 'InternalIP', 'Address': member['Address']}]}}]}
        scaler = Scaling()
        scaler.coordinator = lambda state, request: copy.deepcopy(status)
        self.assertEqual(scaler.observe_membership({'nodes': [dict(spec)]})['catalog']['ClusterID'], 'cluster')
        for change in ('uid', 'address', 'role', 'voter', 'unknown', 'learner', 'coordinated-uid', 'etcd-role'):
            changed = copy.deepcopy(status)
            if change == 'uid':
                changed['nodes'][0]['Metadata']['UID'] = 'other'
            elif change == 'address':
                changed['nodes'][0]['Status']['Addresses'][0]['Address'] = '192.168.99.99'
            elif change == 'role':
                changed['nodes'][0]['Metadata']['Labels'].pop('node-role.kubernetes.io/control-plane')
            elif change == 'voter':
                changed['etcd'][0]['PeerURLs'] = ['https://192.168.99.99:2380']
            elif change == 'learner':
                changed['etcd'].append({'ID': 'unknown', 'IsLearner': True, 'PeerURLs': ['https://192.168.99.99:2380']})
            elif change == 'coordinated-uid':
                changed['nodes'][0]['Metadata']['UID'] = 'other'
                changed['catalog']['Members'][member['ID']]['NodeUID'] = 'other'
            elif change == 'etcd-role':
                changed['nodes'][0]['Metadata']['Labels'].pop('node-role.kubernetes.io/etcd')
            else:
                changed['catalog']['Members']['unknown'] = {**member, 'Address': '192.168.99.99'}
            scaler.coordinator = lambda state, request: changed
            with self.subTest(change=change), self.assertRaises(ImageError):
                scaler.observe_membership({'nodes': [dict(spec)]})

    def test_peak_capacity_and_plan_are_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            scaler = FakeScaler(directory, {})
            specs = [node(i, 'server' if i <= 3 else 'agent') for i in range(1, 6)]
            for spec in specs:
                spec['disk'] = str(Path(directory) / (spec['name'] + '.qcow2'))
                Path(spec['disk']).touch()
            state = {'nodes': specs, 'count': 5, 'control_nodes': 3, 'secret': 'a' * 64}
            scaler.save(state)
            original = scaler.state_path.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                _, peak = scaler.describe_scaling(state, 5, 5)
            self.assertEqual(peak, 6)
            self.assertEqual(scaler.state_path.read_bytes(), original)
            inventory = {'running': {n['name'] for n in specs}}
            with patch('lab.libvirt.scaling.shutil.disk_usage', return_value=SimpleNamespace(free=39 * 1024**3)):
                with self.assertRaisesRegex(ImageError, 'disk'):
                    scaler.scaling_capacity(state, peak, inventory)

    def test_changed_vm_identity_is_never_fenced(self):
        import xml.etree.ElementTree as ET
        with tempfile.TemporaryDirectory() as directory:
            lab = life.Lab(pool=directory)
            spec = {**life.make_spec('test-node01', '192.168.99.11', 'node', Path(directory)),
                    'network': lab.settings.network, 'filter': lab.settings.filter}
            xml = ET.fromstring(life.domain_xml(spec))
            xml.find('uuid').text = 'different-owner'
            def virsh(*args):
                if args[0] == 'list':
                    return spec['name']
                if args[0] == 'dumpxml':
                    return ET.tostring(xml, encoding='unicode')
                self.fail('attempted mutation of unowned VM')
            with patch.object(life, 'virsh', side_effect=virsh), self.assertRaisesRegex(ImageError, 'ownership'):
                lab.fence_vm(spec)


class FakeScaler(Scaling):
    """Model remote CAS membership and retain real on-disk operation journals."""
    def __init__(self, pool, remote):
        self.pool, self.remote = Path(pool), remote
        self.state_path = self.pool / 'state.json'
        self.settings = SimpleNamespace(hostname_prefix='test-node', network='test-net', filter='test-filter',
                                        vm={'vcpus': 2, 'memory_mib': 4096, 'disk_gib': 32},
                                        address=lambda i: f'192.168.99.{11 + i}', validate_nodes=lambda n: None)
        self.fail_phase = None
        self.fail_after = None
        self.block_drain = False
        self.fail_quorum = False
        self.events = []

    def save(self, state):
        self.state_path.write_text(json.dumps(state))
        step = (state.get('resize') or {}).get('step') or {}
        if self.fail_phase is not None and self.fail_phase == step.get('phase'):
            self.fail_phase = None
            raise ImageError('injected crash after saved phase')

    def observe_membership(self, state):
        if self.fail_quorum:
            raise ImageError('quorum unavailable')
        for spec in state['nodes']:
            member = self.remote.get(spec['address'])
            if member:
                spec.update(member)
        return {'catalog': {}, 'etcd': [{'ID': n['member_id']} for n in self.remote.values() if n['role'] == 'server']}

    def coordinator(self, state, request, exclude=None):
        if self.fail_quorum:
            raise ImageError('quorum unavailable')
        self._coordinator = next(n for n in state['nodes'] if n['role'] == 'server' and n.get('member_id') != exclude)
        self.events.append(request['action'])
        if request['action'] == 'remove':
            for ip, n in list(self.remote.items()):
                if n['member_id'] == request['member_id']:
                    del self.remote[ip]
        if self.fail_after == request['action']:
            self.fail_after = None
            raise ImageError('injected crash after remote action')
        return self.observe_membership(state)

    def management(self, spec, request):
        self.events.append(request['action'])
        return {}

    def ssh(self, address, command, timeout=30):
        if ' cordon ' in command:
            self.events.append('cordon')
        if ' get pods ' in command or ' get persistentvolume' in command:
            return '{"items": []}'
        if ' drain ' in command:
            self.events.append('force-drain' if '--disable-eviction' in command else 'drain')
            if '--disable-eviction' in command:
                assert '--grace-period=0' in command
            if self.block_drain and '--disable-eviction' not in command:
                raise ImageError('PDB/emptyDir blocks drain')
        return ''

    def prepare_node(self, spec, state, image):
        self.events.append('prepare')

    def boot(self, spec, state):
        self.events.append('boot')
        spec['boot_requested'] = True
        spec.update(member_id='new-' + spec['uuid'], node_name='kube-' + spec['uuid'],
                    node_uid='uid-' + spec['uuid'], etcd_member_id=spec['uuid'])
        self.remote[spec['address']] = dict(spec)

    def wait_healthy(self, spec, timeout):
        self.events.append('healthy')

    def fence_vm(self, spec):
        self.events.append('fence')

    def vm_running(self, spec):
        return True

    def cleanup_node(self, spec):
        self.events.append('cleanup')


class RecoveryTests(unittest.TestCase):
    def test_forced_unreachable_control_requires_independent_remaining_majority(self):
        for count, permitted in ((3, True), (2, False)):
            with self.subTest(controls=count):
                scaler, state = self.run_case(count - 1, 3, initial=count)
                state['cluster_id'] = 'cluster'
                victim = state['nodes'][-1]
                original = scaler.ssh
                def ssh(address, command, timeout=30):
                    if command == life.HEALTH:
                        peer = scaler.remote[address]
                        return json.dumps({'ClusterID': 'cluster', 'Role': 'server',
                                           'HostID': peer['member_id'], 'Evidence': {
                                               'NodeUID': peer['node_uid'], 'EtcdMemberID': peer['etcd_member_id'],
                                               'EtcdClusterID': 'etcd'}})
                    return original(address, command, timeout)
                scaler.ssh = ssh
                def unreachable(spec, request):
                    if spec['uuid'] == victim['uuid']:
                        raise ImageError('guest unavailable')
                    return {}
                scaler.management = unreachable
                if permitted:
                    scaler.reconcile_scaling(state, count - 1, 3, 1, True, Path('image'))
                    self.assertEqual(state['count'], count - 1)
                else:
                    with self.assertRaisesRegex(ImageError, 'proven remaining current majority'):
                        scaler.reconcile_scaling(state, count - 1, 3, 1, True, Path('image'))
                    self.assertNotIn('fence', scaler.events)
                    self.assertNotIn('cleanup', scaler.events)

    def test_cordon_precedes_local_storage_check_and_block_preserves_vm(self):
        scaler, state = self.run_case(4, 3)
        def guard(coordinator, victim):
            self.assertIn('cordon', scaler.events)
            raise ImageError('local storage blocks retirement')
        scaler.protect_local_data = guard
        with self.assertRaisesRegex(ImageError, 'local storage'):
            scaler.reconcile_scaling(state, 4, 3, 1, False, Path('image'))
        self.assertNotIn('fence', scaler.events)
        self.assertNotIn('cleanup', scaler.events)

    def test_hostpath_and_local_pvc_are_protected_but_remote_pv_is_allowed(self):
        scaler, state = self.run_case(4, 3)
        victim, coordinator = state['nodes'][-1], state['nodes'][0]
        pod = {'metadata': {'name': 'app', 'namespace': 'apps'},
               'spec': {'volumes': [{'name': 'data', 'hostPath': {'path': '/data'}}]}}
        scaler.ssh = lambda address, command: json.dumps({'items': [pod]})
        with self.assertRaisesRegex(ImageError, 'hostPath'):
            scaler.protect_local_data(coordinator, victim)
        pod['spec']['volumes'] = [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'data'}}]
        pvc = {'metadata': {'name': 'data', 'namespace': 'apps'}, 'spec': {'volumeName': 'data-pv'}}
        pv = {'metadata': {'name': 'data-pv'}, 'spec': {'local': {'path': '/data'}}}
        def query(address, command):
            value = [pod] if 'get pods' in command else [pvc] if 'persistentvolumeclaims' in command else [pv]
            return json.dumps({'items': value})
        scaler.ssh = query
        with self.assertRaisesRegex(ImageError, 'node-local'):
            scaler.protect_local_data(coordinator, victim)
        pv['spec'] = {'nfs': {'server': 'storage', 'path': '/data'}}
        scaler.protect_local_data(coordinator, victim)
        pod['spec']['volumes'] = []
        pv['spec'] = {'local': {'path': '/retained-data'}}
        with self.assertRaisesRegex(ImageError, 'node-local'):
            scaler.protect_local_data(coordinator, victim)

    def run_case(self, total, controls, *, initial=5):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        nodes = [node(i, 'server' if i <= 3 else 'agent') for i in range(1, initial + 1)]
        state = {'nodes': nodes, 'count': initial, 'control_nodes': 3}
        remote = {n['address']: dict(n) for n in nodes}
        scaler = FakeScaler(directory.name, remote)
        return scaler, state

    def test_replacement_precedes_retirement_and_retries_are_noop(self):
        scaler, state = self.run_case(5, 5)
        original = {n['uuid'] for n in state['nodes'] if n['role'] == 'server'}
        scaler.reconcile_scaling(state, 5, 5, 1, False, Path('image'))
        self.assertEqual(sum(n['role'] == 'server' for n in state['nodes']), 5)
        self.assertTrue(original.issubset({n['uuid'] for n in state['nodes']}))
        self.assertLess(scaler.events.index('healthy'), scaler.events.index('drain'))
        events = len(scaler.events)
        scaler.reconcile_scaling(state, 5, 5, 1, False, Path('image'))
        self.assertEqual(len(scaler.events), events)

    def test_resume_each_retirement_phase(self):
        for phase in ('ready', 'draining', 'drained', 'fenced', 'removed', 'cleanup'):
            with self.subTest(phase=phase):
                scaler, state = self.run_case(4, 3)
                scaler.fail_phase = phase
                with self.assertRaises(ImageError):
                    scaler.reconcile_scaling(state, 4, 3, 1, False, Path('image'))
                state = json.loads(scaler.state_path.read_text())
                scaler.reconcile_scaling(state, 4, 3, 1, False, Path('image'))
                self.assertEqual(state['count'], 4)
                self.assertNotIn('uuid-5', {n['uuid'] for n in state['nodes']})

    def test_remote_remove_crash_and_changed_target(self):
        scaler, state = self.run_case(4, 3)
        scaler.fail_after = 'remove'
        with self.assertRaises(ImageError):
            scaler.reconcile_scaling(state, 4, 3, 1, False, Path('image'))
        state = json.loads(scaler.state_path.read_text())
        scaler.reconcile_scaling(state, 6, 3, 1, False, Path('image'))
        self.assertEqual(state['count'], 6)
        self.assertNotIn('uuid-5', {n['uuid'] for n in state['nodes']})

    def test_blocked_drain_force_and_missing_quorum(self):
        scaler, state = self.run_case(4, 3)
        scaler.block_drain = True
        with self.assertRaises(ImageError):
            scaler.reconcile_scaling(state, 4, 3, 1, False, Path('image'))
        self.assertNotIn('fence', scaler.events)
        scaler.fail_quorum = True
        with self.assertRaises(ImageError):
            scaler.reconcile_scaling(state, 4, 3, 1, True, Path('image'))
        self.assertNotIn('fence', scaler.events)
        scaler.fail_quorum = False
        scaler.reconcile_scaling(state, 4, 3, 1, True, Path('image'))
        self.assertIn('force-drain', scaler.events)

    def test_two_to_one_removes_live_vote_before_poweroff(self):
        scaler, state = self.run_case(1, 3, initial=2)
        scaler.reconcile_scaling(state, 1, 3, 1, False, Path('image'))
        self.assertLess(scaler.events.index('fence-local'), scaler.events.index('remove'))
        self.assertLess(scaler.events.index('remove'), scaler.events.index('fence'))
        self.assertEqual(state['count'], 1)


if __name__ == '__main__':
    unittest.main()
