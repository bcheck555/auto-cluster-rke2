from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lab.libvirt.lifecycle import Lab
from lab.libvirt.scaling import healing_transition, Scaling
from lab.packer import pipeline, runtime
from lab.packer.artifacts import ImageError, ROOT, digest, validation_sources


class HealingTests(unittest.TestCase):
    def test_coordinator_discovers_promoted_workers_and_checks_cluster_before_mutation(self):
        scaler = Scaling()
        state = {'cluster_id': 'owned', 'nodes': [
            {'name': 'old-control', 'role': 'server', 'member_id': 'old'},
            {'name': 'promoted-worker', 'role': 'agent', 'member_id': 'new'}]}
        calls = []
        def management(spec, request):
            calls.append((spec['name'], request['action']))
            if spec['name'] == 'old-control':
                raise ImageError('now a worker')
            return {'catalog': {'ClusterID': 'owned'}}
        scaler.management = management
        scaler.coordinator(state, {'action': 'begin'})
        self.assertEqual(calls[-2:], [('promoted-worker', 'status'), ('promoted-worker', 'begin')])
        calls.clear()
        def foreign(spec, request):
            calls.append(request['action'])
            return {'catalog': {'ClusterID': 'foreign'}}
        scaler.management = foreign
        with self.assertRaisesRegex(ImageError, 'another cluster'):
            scaler.coordinator(state, {'action': 'remove'})
        self.assertNotIn('remove', calls)

    def test_healing_cache_binds_validator_dependencies_and_disk(self):
        validator = ROOT / 'lab/packer/healing_acceptance.py'
        candidate = {'capabilities': ['control-self-healing-v1'], 'profiles': {'node': {'sha256': 'disk'}}}
        names = ('short_shutdown_preserved', 'worker_promoted', 'return_as_worker',
                 'repeated_failure', 'controller_failover', 'partition_reconnect',
                 'simultaneous_reboot', 'protected_drain', 'lost_quorum_blocked',
                 'stable_cluster_identity', 'exact_voters', 'workload_connectivity', 'source_inputs_preserved')
        evidence = {'passed': True, 'same_image_sha256': 'disk', **dict.fromkeys(names, True),
                    'validator_sha256': digest(validator), 'validator_inputs': validation_sources(validator)}
        self.assertTrue(runtime.cached_acceptance(candidate, evidence, 'self_healing', validator))
        evidence['validator_inputs']['lab/libvirt/scaling.py'] = 'changed'
        self.assertFalse(runtime.cached_acceptance(candidate, evidence, 'self_healing', validator))

    def test_pending_generation_cannot_trigger_a_second_replacement(self):
        spec = {'member_id': 'physical', 'generation': 0, 'node_uid': 'old-node',
                'etcd_member_id': 'old-voter', 'node_name': 'old', 'address': '192.168.100.11'}
        old = {'ID': 'physical', 'Generation': 0, 'NodeUID': 'old-node',
               'EtcdMemberID': 'old-voter', 'NodeName': 'old', 'Address': spec['address']}
        member = {**old, 'Generation': 1, 'Role': 'agent', 'Complete': False,
                  'NodeUID': '', 'EtcdMemberID': '', 'NodeName': 'new'}
        catalog = {'ClusterID': 'cluster', 'Members': {'physical': member},
                   'History': [{'Phase': 'completed', 'Failed': old}],
                   'Hosts': {'physical': {'Generation': 1, 'Role': 'agent'}}}
        scaler = Scaling()
        scaler.coordinator = lambda *args: {'catalog': catalog, 'nodes': [], 'etcd': []}
        state = {'nodes': [spec]}
        with self.assertRaisesRegex(ImageError, 'still enrolling'):
            scaler.observe_membership(state)
        self.assertEqual(spec['generation'], 0)
    def test_generation_adoption_requires_exact_history_and_current_assignment(self):
        spec = {'member_id': 'physical', 'generation': 0, 'node_uid': 'old-node',
                'etcd_member_id': 'old-voter', 'node_name': 'old', 'address': '192.168.100.11'}
        old = {'ID': 'physical', 'Generation': 0, 'NodeUID': 'old-node',
               'EtcdMemberID': 'old-voter', 'NodeName': 'old', 'Address': spec['address']}
        member = {**old, 'Generation': 1, 'Role': 'agent', 'NodeUID': 'new-node',
                  'EtcdMemberID': '', 'NodeName': 'new'}
        catalog = {'History': [{'Phase': 'completed', 'Failed': old}],
                   'Hosts': {'physical': {'Generation': 1, 'Role': 'agent'}}}
        self.assertTrue(healing_transition(spec, member, catalog))
        for field in ('NodeUID', 'EtcdMemberID', 'Address', 'NodeName'):
            altered = copy.deepcopy(catalog)
            altered['History'][0]['Failed'][field] = 'foreign'
            with self.assertRaises(ImageError):
                healing_transition(spec, member, altered)
        for field in ('Generation', 'Role'):
            altered = copy.deepcopy(catalog)
            altered['Hosts']['physical'][field] = 'foreign'
            with self.assertRaises(ImageError):
                healing_transition(spec, member, altered)
        cancelled = copy.deepcopy(catalog)
        cancelled['History'].insert(0, {'Phase': 'cancelled', 'Failed': old})
        self.assertTrue(healing_transition(spec, member, cancelled))
        self.assertFalse(healing_transition({**spec, 'generation': 1}, member, catalog))
        with self.assertRaises(ImageError):
            healing_transition({**spec, 'generation': 2}, member, catalog)

    def test_multiple_generations_require_contiguous_evidence(self):
        old = {'ID': 'physical', 'Generation': 0, 'NodeUID': 'first',
               'EtcdMemberID': 'voter', 'NodeName': 'first', 'Address': '192.168.100.11'}
        worker = {**old, 'Generation': 1, 'Role': 'agent', 'NodeUID': 'second',
                  'EtcdMemberID': '', 'NodeName': 'second'}
        control = {**worker, 'Generation': 2, 'Role': 'server', 'NodeUID': 'third',
                   'EtcdMemberID': 'new-voter', 'NodeName': 'third'}
        spec = {'member_id': old['ID'], 'node_uid': old['NodeUID'],
                'etcd_member_id': old['EtcdMemberID'], 'node_name': old['NodeName'], 'address': old['Address']}
        catalog = {'History': [{'Phase': 'completed', 'Failed': old},
                               {'Phase': 'completed', 'Candidate': worker}],
                   'Hosts': {'physical': {'Generation': 2, 'Role': 'server'}}}
        self.assertTrue(healing_transition(spec, control, catalog))
        catalog['History'].pop(0)
        with self.assertRaises(ImageError):
            healing_transition(spec, control, catalog)

    def test_old_image_rejected_before_scaling_or_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Lab(pool=Path(directory), subnet='192.168.100.0/24')
            lab.self_healing = {'enabled': True, 'failure_timeout': '5m'}
            manifest = {'kind': 'release', 'profiles': {'node': {}}, 'files': {'node.qcow2': {}},
                        'capabilities': ['membership-reconciliation-v1']}
            with patch.object(lab, 'check_ownership'), patch.object(lab, 'check_networks'), \
                    patch('lab.libvirt.lifecycle.verify_manifest', return_value=manifest), \
                    patch.object(lab, 'create_scaling') as create:
                with self.assertRaisesRegex(ImageError, 'control-self-healing-v1'):
                    lab.create(Path('release.json'), 4, 60, {})
                create.assert_not_called()

    def test_publication_requires_all_healing_scenarios_for_exact_disk(self):
        candidate = {'capabilities': ['control-self-healing-v1'], 'profiles': {'node': {'sha256': 'disk'}}}
        names = ('short_shutdown_preserved', 'worker_promoted', 'return_as_worker',
                 'repeated_failure', 'controller_failover', 'partition_reconnect',
                 'simultaneous_reboot', 'protected_drain', 'lost_quorum_blocked',
                 'stable_cluster_identity', 'exact_voters', 'workload_connectivity',
                 'source_inputs_preserved')
        evidence = {'passed': True, 'same_image_sha256': 'disk', **dict.fromkeys(names, True)}
        pipeline.validate_healing_evidence(candidate, {'self_healing': evidence})
        for name in (*names, 'passed', 'same_image_sha256'):
            broken = {k: v for k, v in evidence.items() if k != name}
            with self.subTest(name=name), self.assertRaises(ImageError):
                pipeline.validate_healing_evidence(candidate, {'self_healing': broken})
        pipeline.validate_healing_evidence({'capabilities': []}, {})
