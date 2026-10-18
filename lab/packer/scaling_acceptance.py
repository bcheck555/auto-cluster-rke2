"""Disposable, owned libvirt acceptance for the signed scaling capability."""
from __future__ import annotations

import base64
import json
import shlex
import uuid
import secrets

from lab.libvirt.lifecycle import Lab, KUBECTL, virsh, write_private
from lab.packer.artifacts import ROOT, ImageError, digest, write_json


def validate_scaling(candidate_path, candidate, output):
    cluster = 'accept-scale-' + uuid.uuid4().hex[:10]
    lab = Lab(cluster=cluster, hostname_prefix=cluster + '-node')
    inventory = lab.inventory()
    lab.check_ownership(inventory)
    lab.node_count = 8
    lab.check_networks(inventory)
    lab.options['subnet'] = str(lab.settings.subnet)
    inputs = output.parent / ('_inputs-' + cluster)
    inputs.mkdir(mode=0o700)
    public, private = inputs / 'cluster.yaml', inputs / 'cluster.env'
    write_json(public, {'schema': 1, 'cluster': cluster, 'nodes': 3,
                        'hostname_prefix': lab.settings.hostname_prefix,
                        'network': {'subnet': str(lab.settings.subnet)},
                        'release': str(candidate_path)})
    secret = secrets.token_hex(32)
    write_private(private, 'ENROLLMENT_SECRET=' + secret + '\n')
    source_hashes = {str(p): digest(p) for p in (public, private)}
    lab.input_files = (public, private)
    lab.enrollment_secret = secret
    results = {'passed': False, 'same_image_sha256': candidate['profiles']['node']['sha256'],
               'validator_sha256': digest(__file__), 'cases': []}
    original_cluster = None
    previous = {}
    source = base64.b64encode((ROOT / 'lab/packer/guest.py').read_bytes()).decode()

    def snapshot(total, controls):
        nonlocal original_cluster, previous
        state = json.loads(lab.state_path.read_text())
        status = lab.observe_membership(state)
        members = status['catalog']['Members']
        if len(members) != total or sum(m['Role'] == 'server' for m in members.values()) != min(total, controls):
            raise ImageError('scaling acceptance: incorrect total/role counts')
        if original_cluster is None:
            original_cluster = state['cluster_id']
        if state['cluster_id'] != original_cluster:
            raise ImageError('scaling changed cluster identity')
        for member_id in set(previous) & set(members):
            for field in ('NodeUID', 'EtcdMemberID', 'Role', 'Address'):
                if previous[member_id][field] != members[member_id][field]:
                    raise ImageError('scaling changed a surviving identity')
        if set(status['catalog'].get('Retired') or {}) & set(members):
            raise ImageError('retired member returned')
        first = next(n for n in state['nodes'] if n['role'] == 'server')
        client = next((n for n in reversed(state['nodes']) if n['role'] == 'agent'), state['nodes'][-1])
        code = ("import base64,json; ns={'__name__':'scaling_probe'};"
                f"exec(compile(base64.b64decode({source!r}),'<guest-probe>','exec'),ns);"
                f"print(json.dumps(ns['workload_checks']({{}},{{'validation_image':'docker.io/library/busybox:1.37.0'}},{total},{first['node_name']!r},{client['node_name']!r})))")
        probe = json.loads(lab.ssh(first['address'], 'sudo python3 -c ' + shlex.quote(code), timeout=1800))
        lab.ssh(first['address'], KUBECTL + ' delete namespace image-validation --wait=true --timeout=120s', timeout=150)
        results['cases'].append({'nodes': total, 'control_nodes': controls,
                                 'members': members, 'workloads': probe, 'cross_node': total > 1})
        previous = members
        if {str(p): digest(p) for p in (public, private)} != source_hashes:
            raise ImageError('reconciliation modified source inputs')
        write_json(output.parent / 'scaling-progress.json', results)

    try:
        for total, controls in ((3, 3), (5, 5), (7, 7), (8, 7), (7, 7),
                                (5, 5), (5, 3), (5, 5), (3, 3), (2, 3), (1, 3), (3, 3)):
            print(f'Scaling acceptance: {total} nodes, control target {controls}', flush=True)
            lab.control_nodes = controls
            inventory = lab.inventory()
            lab.node_count = total
            lab.check_ownership(inventory)
            lab.node_count = total
            lab.check_networks(inventory)
            lab.create_scaling(candidate_path, candidate, total, 1200, inventory)
            snapshot(total, controls)
        # A real PDB must block deletion until an explicit workload override.
        lab.control_nodes = 3
        lab.create_scaling(candidate_path, candidate, 4, 1200, lab.inventory())
        state = json.loads(lab.state_path.read_text())
        worker = next(n for n in state['nodes'] if n['role'] == 'agent')
        first = next(n for n in state['nodes'] if n['role'] == 'server')
        resources = {'apiVersion': 'v1', 'kind': 'List', 'items': [
            {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'scaling-blocker'}},
            {'apiVersion': 'apps/v1', 'kind': 'Deployment',
             'metadata': {'name': 'protected', 'namespace': 'scaling-blocker'},
             'spec': {'replicas': 1, 'selector': {'matchLabels': {'app': 'protected'}},
                      'template': {'metadata': {'labels': {'app': 'protected'}},
                                   'spec': {'nodeName': worker['node_name'], 'containers': [
                                       {'name': 'sleep', 'image': 'docker.io/library/busybox:1.37.0',
                                        'imagePullPolicy': 'Never', 'command': ['sleep', '3600']}]}}}},
            {'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget',
             'metadata': {'name': 'protected', 'namespace': 'scaling-blocker'},
             'spec': {'minAvailable': 1, 'selector': {'matchLabels': {'app': 'protected'}}}}]}
        lab.ssh(first['address'], "printf '%s' " + shlex.quote(json.dumps(resources)) + ' | ' + KUBECTL + ' apply -f -')
        lab.ssh(first['address'], KUBECTL + ' -n scaling-blocker rollout status deployment/protected --timeout=120s', timeout=150)
        try:
            lab.create_scaling(candidate_path, candidate, 3, 15, lab.inventory())
        except ImageError:
            state = json.loads(lab.state_path.read_text())
            if ((state.get('resize') or {}).get('step', {}).get('phase') != 'draining'
                    or worker['name'] not in virsh('list', '--name').split()):
                raise ImageError('blocked drain did not preserve the selected VM')
        else:
            raise ImageError('PDB failed to block ordinary scale-down')
        results['blocked_drain_preserved_vm'] = True
        lab.force_remove = True
        lab.create_scaling(candidate_path, candidate, 3, 1200, lab.inventory())
        lab.force_remove = False
        lab.ssh(first['address'], KUBECTL + ' -n scaling-blocker delete deployment/protected')
        lab.ssh(first['address'], KUBECTL + ' -n scaling-blocker delete pod --all --force --grace-period=0')
        lab.ssh(first['address'], KUBECTL + ' delete namespace scaling-blocker --wait=true --timeout=120s', timeout=150)
        results['forced_drain_validated'] = True
        snapshot(3, 3)
        results['source_inputs_preserved'] = True
        results['passed'] = True
        return results
    finally:
        if lab.state_path.exists():
            lab.destroy(lab.inventory())
        if {str(p): digest(p) for p in (public, private)} != source_hashes:
            raise ImageError('teardown modified source inputs')
        if lab.settings.network in virsh('net-list', '--all', '--name').split():
            raise ImageError('scaling acceptance leaked its owned network')
