"""Destructive failure injection confined to a fresh, ownership-checked lab."""
from __future__ import annotations

import base64
import json
import secrets
import shlex
import socket
import time
import uuid

from lab.libvirt.lifecycle import Lab, KUBECTL, HEALTH, virsh, write_private
from lab.packer.artifacts import ROOT, ImageError, digest, write_json, validation_sources


def validate_healing(candidate_path, candidate, output):
    cluster = 'accept-heal-' + uuid.uuid4().hex[:10]
    lab = Lab(cluster=cluster, hostname_prefix=cluster + '-node')
    inventory = lab.inventory()
    lab.check_ownership(inventory)
    lab.node_count = 5
    lab.check_networks(inventory)
    lab.options['subnet'] = str(lab.settings.subnet)
    inputs = output.parent / ('_inputs-' + cluster)
    inputs.mkdir(mode=0o700)
    public, private = inputs / 'cluster.yaml', inputs / 'cluster.env'
    write_json(public, {'schema': 1, 'cluster': cluster, 'nodes': 5, 'control_nodes': 3,
                        'hostname_prefix': lab.settings.hostname_prefix,
                        'network': {'subnet': str(lab.settings.subnet)},
                        'release': str(candidate_path),
                        'self_healing': {'enabled': True, 'failure_timeout': '3m'}})
    secret = secrets.token_hex(32)
    write_private(private, 'ENROLLMENT_SECRET=' + secret + '\n')
    inputs_before = {str(p): digest(p) for p in (public, private)}
    lab.input_files, lab.enrollment_secret = (public, private), secret
    lab.self_healing = {'enabled': True, 'failure_timeout': '3m'}
    result = {'passed': False, 'same_image_sha256': candidate['profiles']['node']['sha256'],
              'validator_sha256': digest(__file__), 'validator_inputs': validation_sources(__file__), 'operations': []}
    state = None
    cluster_id = None
    physical_before = {}
    sentinel = '/var/lib/rancher/rke2/storage/' + cluster + '-sentinel'

    def status():
        return lab.coordinator(state, {'action': 'status'})

    def wait(predicate, label, timeout=900):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                observed = status()
                if predicate(observed):
                    return observed
                operation = observed['catalog'].get('Healing') or {}
                phase = (operation.get('ID'), operation.get('Phase'))
                if phase != last:
                    print(f'Healing acceptance {label}: {phase}', flush=True)
                    last = phase
            except ImageError:
                pass
            time.sleep(5)
        raise ImageError('self-healing acceptance timed out: ' + label)

    def off(spec):
        if not lab.owned_vm(spec):
            raise ImageError('acceptance VM ownership missing')
        virsh('destroy', spec['name'])

    def on(spec):
        if not lab.owned_vm(spec):
            raise ImageError('acceptance VM ownership missing')
        if spec['name'] not in virsh('list', '--name').split():
            virsh('start', spec['name'])

    def verify():
        nonlocal state
        observed = wait(lambda s: not s['catalog'].get('Healing')
                        and len(s['catalog']['Members']) == 5
                        and all(m['Complete'] for m in s['catalog']['Members'].values()), 'all members returned')
        if observed['catalog']['ClusterID'] != cluster_id:
            raise ImageError('healing changed cluster identity')
        members = observed['catalog']['Members']
        node_uids = {n['Metadata']['UID'] for n in observed['nodes']}
        for member_id, member in members.items():
            for field in ('NodeName', 'Address', 'PublicKey', 'PodCIDR', 'PodCIDRs'):
                if member[field] != physical_before[member_id][field]:
                    raise ImageError('healing changed physical identity or node networking: ' + field)
        controls = [m for m in members.values() if m['Role'] == 'server']
        voters = {m['ID'] for m in observed['etcd'] if not m.get('IsLearner')}
        if len(controls) != 3 or voters != {m['EtcdMemberID'] for m in controls} or len(observed['etcd']) != 3:
            raise ImageError('healing voter membership differs')
        for operation in observed['catalog'].get('History') or []:
            if operation['Phase'] != 'completed':
                continue
            if operation['Failed']['EtcdMemberID'] in voters:
                raise ImageError('retired voter returned')
            if any(operation[field]['NodeUID'] in node_uids for field in ('Failed', 'Candidate')):
                raise ImageError('retired Node UID returned')
            if operation['Evidence'].get('workload_connectivity') != 'verified':
                raise ImageError('healing finished without connectivity evidence')
        state = json.loads(lab.state_path.read_text())
        lab.observe_membership(state)
        lab.save(state)
        for spec in state['nodes']:
            lab.wait_healthy(spec, 300)
            health = json.loads(lab.ssh(spec['address'], HEALTH))
            if health['HostID'] != spec['member_id'] or health['Generation'] != spec.get('generation', 0):
                raise ImageError('physical identity or generation changed unexpectedly')
            actual = lab.ssh(spec['address'], 'sudo cat ' + shlex.quote(sentinel)).strip()
            if actual != spec['member_id']:
                raise ImageError(f'local-data sentinel differs on {spec["name"]}: '
                                 f'expected {spec["member_id"]!r}, found {actual!r}')
        result['stable_cluster_identity'] = result['exact_voters'] = True
        result['operations'] = observed['catalog'].get('History') or []
        write_json(output.parent / 'healing-progress.json', result)
        return observed

    def cycle(victim, *, partition=False, failover=False):
        before = status()
        history_count = len(before['catalog'].get('History') or [])
        old = before['catalog']['Members'][victim['member_id']]
        if partition:
            if not lab.owned_vm(victim):
                raise ImageError('partition target ownership changed')
            virsh('domif-setlink', victim['name'], victim['mac'], 'down')
        else:
            off(victim)
        stopped_controller = None
        if failover:
            observed = wait(lambda s: bool(s['catalog'].get('Healing')), 'operation recorded')
            alive = sorted(m['ID'] for m in observed['catalog']['Members'].values()
                           if m['Role'] == 'server' and m['ID'] != old['ID'] and not m.get('Retiring'))
            stopped_controller = next(n for n in state['nodes'] if n['member_id'] == alive[0])
            lab.ssh(stopped_controller['address'], 'sudo systemctl stop autonomous-rke2-host-agent.service', timeout=90)
        observed = wait(lambda s: len(s['catalog'].get('History') or []) > history_count
                        and not s['catalog'].get('Healing'), 'replacement completed')
        operation = observed['catalog']['History'][-1]
        if operation['Phase'] != 'completed' or operation['Failed']['ID'] != old['ID']:
            raise ImageError('wrong failed control replaced')
        replacement = observed['catalog']['Members'][operation['Candidate']['ID']]
        if replacement['Generation'] != operation['Candidate'].get('Generation', 0) + 1 or replacement['Role'] != 'server':
            raise ImageError('worker promotion did not create a fresh control incarnation')
        if stopped_controller:
            lab.ssh(stopped_controller['address'], 'sudo systemctl start autonomous-rke2-host-agent.service', timeout=90)
            result['controller_failover'] = True
        if partition:
            virsh('domif-setlink', victim['name'], victim['mac'], 'up')
        else:
            on(victim)
        observed = wait(lambda s: (s['catalog']['Members'].get(old['ID']) or {}).get('Complete', False), 'old control returned')
        returned = observed['catalog']['Members'][old['ID']]
        if returned['Role'] != 'agent' or returned['Generation'] != old.get('Generation', 0) + 1:
            raise ImageError('replaced control resumed old role')
        # A worker must not expose the native control API after returning.
        try:
            with socket.create_connection((victim['address'], 6443), timeout=2):
                raise ImageError('returning worker exposed a control endpoint')
        except OSError:
            pass
        result['worker_promoted'] = result['return_as_worker'] = True
        verify()

    try:
        lab.create_scaling(candidate_path, candidate, 5, 1200, inventory)
        state = json.loads(lab.state_path.read_text())
        cluster_id = state['cluster_id']
        initial = status()
        physical_before = initial['catalog']['Members']
        for spec in state['nodes']:
            # A read-back can succeed from page cache while an immediate VM
            # power cut loses unsynced data. Persist fixture data and metadata
            # before exercising abrupt shutdown or role-state preservation.
            code = ("import os; from pathlib import Path; p=Path(" + repr(sentinel) + ");"
                    "p.parent.mkdir(parents=True,exist_ok=True);f=p.open('w');"
                    "f.write(" + repr(spec['member_id']) + ");f.flush();os.fsync(f.fileno());f.close();"
                    "d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d);"
                    "d=os.open(p.parent.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)")
            lab.ssh(spec['address'], 'sudo python3 -c ' + shlex.quote(code))
            actual = lab.ssh(spec['address'], 'sudo cat ' + shlex.quote(sentinel)).strip()
            if actual != spec['member_id']:
                raise ImageError(f'local-data fixture failed on {spec["name"]}: '
                                 f'expected {spec["member_id"]!r}, found {actual!r}')
        controls = sorted((n for n in state['nodes'] if n['role'] == 'server'), key=lambda n: n['index'])
        victim = controls[-1]
        old = initial['catalog']['Members'][victim['member_id']]
        off(victim)
        time.sleep(15)
        on(victim)
        wait(lambda s: (s['catalog']['Members'].get(old['ID']) or {}).get('NodeUID') == old['NodeUID']
             and any(n['Metadata']['UID'] == old['NodeUID'] and any(c['Type'] == 'Ready' and c['Status'] == 'True'
                     for c in n['Status']['Conditions']) for n in s['nodes']), 'short shutdown recovered', 300)
        lab.wait_healthy(victim, 300)
        if status()['catalog'].get('History'):
            raise ImageError('short shutdown caused replacement')
        result['short_shutdown_preserved'] = True
        lab.coordinator(state, {'action': 'policy', 'nodes': 5,
                                'self_healing': {'enabled': True, 'failure_timeout': '1m'}})
        # Protect both spare workers with real disruption budgets. The failed
        # voter must remain enrolled until one candidate can drain safely.
        first = controls[0]
        workers = sorted((n for n in state['nodes'] if n['role'] == 'agent'), key=lambda n: n['index'])
        items = [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'healing-blocker'}}]
        for i, worker in enumerate(workers):
            name = 'protected-' + str(i)
            items.extend([
                {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': name, 'namespace': 'healing-blocker'},
                 'spec': {'replicas': 1, 'selector': {'matchLabels': {'app': name}},
                          'template': {'metadata': {'labels': {'app': name}}, 'spec': {'nodeName': worker['node_name'],
                                       'containers': [{'name': 'sleep', 'image': 'docker.io/library/busybox:1.37.0',
                                                       'imagePullPolicy': 'Never', 'command': ['sleep', '3600']}]}}}},
                {'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget', 'metadata': {'name': name, 'namespace': 'healing-blocker'},
                 'spec': {'minAvailable': 1, 'selector': {'matchLabels': {'app': name}}}}])
        lab.ssh(first['address'], "printf '%s' " + shlex.quote(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items})) + ' | ' + KUBECTL + ' apply -f -')
        for i in range(2):
            lab.ssh(first['address'], KUBECTL + f' -n healing-blocker rollout status deployment/protected-{i} --timeout=120s', timeout=150)
        off(victim)
        observed = wait(lambda s: (s['catalog'].get('Healing') or {}).get('Phase') == 'blocked', 'protected drains blocked')
        if old['ID'] not in observed['catalog']['Members'] or old['EtcdMemberID'] not in {v['ID'] for v in observed['etcd']}:
            raise ImageError('blocked drain retired failed member prematurely')
        result['protected_drain'] = True
        lab.ssh(first['address'], KUBECTL + ' delete namespace healing-blocker --wait=true --timeout=120s', timeout=150)
        wait(lambda s: not s['catalog'].get('Healing') and bool(s['catalog'].get('History')), 'drain unblocked and worker promoted')
        on(victim)
        verify()
        result['worker_promoted'] = result['return_as_worker'] = True
        second = next(n for n in state['nodes'] if n['member_id'] == controls[1]['member_id'])
        cycle(second, failover=True)
        result['repeated_failure'] = True
        third = max((n for n in state['nodes'] if n['role'] == 'server'), key=lambda n: n['index'])
        cycle(third, partition=True)
        result['partition_reconnect'] = True
        current_controls = [n for n in state['nodes'] if n['role'] == 'server']
        count = len(status()['catalog'].get('History') or [])
        for spec in current_controls[:2]:
            off(spec)
        time.sleep(110)
        # No quorum means status itself must fail; recovery cannot fabricate a
        # successful operation while the datastore is unavailable.
        try:
            status()
        except ImageError:
            result['lost_quorum_blocked'] = True
        else:
            raise ImageError('writable majority reported with two of three controls down')
        for spec in current_controls[:2]:
            on(spec)
        verify()
        if len(status()['catalog'].get('History') or []) != count:
            raise ImageError('lost-quorum interval produced a replacement')
        before = {m['ID']: (m['Generation'], m['NodeUID'], m['EtcdMemberID'])
                  for m in status()['catalog']['Members'].values()}
        for spec in state['nodes']:
            if not lab.owned_vm(spec):
                raise ImageError('reboot target ownership changed')
            virsh('reboot', spec['name'])
        time.sleep(30)
        verify()
        after = {m['ID']: (m['Generation'], m['NodeUID'], m['EtcdMemberID'])
                 for m in status()['catalog']['Members'].values()}
        if before != after:
            raise ImageError('simultaneous reboot changed role identities')
        result['simultaneous_reboot'] = True
        source = base64.b64encode((ROOT / 'lab/packer/guest.py').read_bytes()).decode()
        first = next(n for n in state['nodes'] if n['role'] == 'server')
        client = next(n for n in state['nodes'] if n['role'] == 'agent')
        code = ("import base64,json; ns={'__name__':'healing_probe'};"
                f"exec(compile(base64.b64decode({source!r}),'<guest-probe>','exec'),ns);"
                f"print(json.dumps(ns['workload_checks']({{}},{{'validation_image':'docker.io/library/busybox:1.37.0'}},5,{first['node_name']!r},{client['node_name']!r})))")
        result['workloads'] = json.loads(lab.ssh(first['address'], 'sudo python3 -c ' + shlex.quote(code), timeout=1800))
        result['workload_connectivity'] = True
        result['passed'] = True
    finally:
        lab.destroy(lab.inventory())
        result['source_inputs_preserved'] = all(p.exists() and digest(p) == inputs_before[str(p)] for p in (public, private))
        result['passed'] = result['passed'] and result['source_inputs_preserved']
        write_json(output.parent / 'healing-progress.json', result)
    if not result['passed']:
        raise ImageError('self-healing acceptance failed')
    return result
