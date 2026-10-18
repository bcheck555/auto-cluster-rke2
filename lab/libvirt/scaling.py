"""Journaled reconciliation for signed membership-reconciliation-v1 images.

Only the local libvirt owner deletes disks. Node-local management uses cluster
CAS and never accepts lifecycle requests on the public enrollment listener.
"""
from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from lab.packer.artifacts import GIB, ImageError, digest

CAPABILITY = 'membership-reconciliation-v1'
MANAGE = 'sudo /usr/local/libexec/autonomous-rke2/host-agent -manage'


def control_count(value):
    if type(value) is not int or value not in (3, 5, 7):
        raise ImageError('control_nodes must be 3, 5, or 7')
    return value


def quorum_message(nodes, controls):
    actual = min(nodes, control_count(controls))
    majority = actual // 2 + 1
    tolerance = actual - majority
    warning = actual < controls or actual % 2 == 0 or tolerance == 0
    return (('WARNING: ' if warning else '') +
            f'{actual} control nodes (target {controls}); quorum requires {majority}; '
            f'tolerates {tolerance} server failure(s). Changes are allowed while quorum exists.')


def next_change(nodes, total, controls):
    """Pure deterministic planner; replacements add before removing a counterpart."""
    desired = {'server': min(total, controls), 'agent': max(0, total - controls)}
    by_role = {role: sorted((n for n in nodes if n['role'] == role),
                            key=lambda n: n['index'], reverse=True)
               for role in desired}
    if len(nodes) > total:
        for role in ('agent', 'server'):
            if len(by_role[role]) > desired[role]:
                return {'kind': 'remove', 'victim': by_role[role][0]}
    for role in ('server', 'agent'):
        if len(by_role[role]) < desired[role]:
            opposite = 'agent' if role == 'server' else 'server'
            victim = by_role[opposite][0] if len(by_role[opposite]) > desired[opposite] else None
            return {'kind': 'add', 'role': role, 'victim': victim}
    for role in ('agent', 'server'):
        if len(by_role[role]) > desired[role]:
            return {'kind': 'remove', 'victim': by_role[role][0]}
    return None


def planned_changes(nodes, total, controls):
    simulated = [dict(n) for n in nodes]
    changes, peak = [], len(nodes)
    while change := next_change(simulated, total, controls):
        changes.append(change)
        if change['kind'] == 'add':
            used = {n['index'] for n in simulated}
            index = next(i for i in range(1, 1026) if i not in used)
            simulated.append({'index': index, 'role': change['role']})
            peak = max(peak, len(simulated))
        if change['victim'] is not None:
            simulated = [n for n in simulated if n['index'] != change['victim']['index']]
    return changes, peak


def resize_peak(state, total, controls):
    """Include a journaled partial step without allocating a second replacement."""
    simulated = [dict(n) for n in state['nodes']]
    peak = len(simulated)
    operation = state.get('resize')
    if operation:
        step = operation.get('step') or {}
        victim = step.get('victim')
        if victim:
            simulated = [n for n in simulated if n['index'] != victim['index']]
        changes, old_peak = planned_changes(simulated, operation['nodes'], operation['controls'])
        peak = max(peak, old_peak)
        # The recorded operation finishes before any newly edited desired state.
        _, latest_peak = planned_changes(
            [{'index': i + 1, 'role': 'server' if i < min(operation['nodes'], operation['controls']) else 'agent'}
             for i in range(operation['nodes'])], total, controls)
        return max(peak, latest_peak)
    return planned_changes(simulated, total, controls)[1]


def missing_retirements(state, total, controls):
    target = state.get('resize') or {'nodes': total, 'controls': controls}
    changes, _ = planned_changes(state['nodes'], target['nodes'], target['controls'])
    victims = {c['victim'].get('uuid') for c in changes if c['victim'] is not None}
    recorded = (target.get('step') or {}).get('victim') or {}
    victims.add(recorded.get('uuid'))
    return {n['uuid'] for n in state['nodes'] if n['uuid'] in victims and n.get('boot_requested')
            and not all(Path(n[key]).is_file() for key in ('disk', 'seed', 'nvram'))}


def affinity_matches(terms, victim):
    labels = victim.get('node_labels', {'kubernetes.io/hostname': victim['node_name']})
    def matches(expression, values):
        key, operator = expression.get('key'), expression.get('operator')
        choices = expression.get('values', [])
        value = values.get(key)
        if operator == 'In':
            return value in choices
        if operator == 'NotIn':
            return value not in choices
        if operator == 'Exists':
            return key in values
        if operator == 'DoesNotExist':
            return key not in values
        if operator in ('Gt', 'Lt'):
            try:
                return int(value) > int(choices[0]) if operator == 'Gt' else int(value) < int(choices[0])
            except (TypeError, ValueError, IndexError):
                return True  # Unknown storage placement is not permission to delete.
        return True
    return any((term.get('matchExpressions') or term.get('matchFields'))
               and all(matches(e, labels) for e in term.get('matchExpressions', []))
               and all(matches(e, {'metadata.name': victim['node_name']}) for e in term.get('matchFields', []))
               for term in terms)


class Scaling:
    def management(self, spec, request):
        # shlex.quote protects JSON from remote-shell evaluation; contains no keys.
        remote = "printf '%s' " + shlex.quote(json.dumps(request)) + ' | ' + MANAGE
        return json.loads(self.ssh(spec['address'], remote, timeout=75))

    def coordinator(self, state, request, *, exclude=None):
        errors = []
        for spec in state['nodes']:
            if spec.get('role') != 'server' or spec.get('member_id') == exclude:
                continue
            try:
                result = self.management(spec, request)
                self._coordinator = spec
                return result
            except (ImageError, ValueError, OSError, subprocess.SubprocessError) as exc:
                errors.append(str(exc))
        raise ImageError('no writable control node/quorum available: ' + '; '.join(errors)[-1200:])

    def observe_membership(self, state):
        status = self.coordinator(state, {'action': 'status'})
        catalog = status['catalog']
        cluster = catalog['ClusterID']
        if state.get('cluster_id', cluster) != cluster:
            raise ImageError('live cluster identity differs from saved ownership')
        members = catalog['Members']
        known = {s['address']: s for s in state['nodes']}
        if len(known) != len(state['nodes']):
            raise ImageError('duplicate saved node address')
        nodes = {n['Metadata']['Name']: n for n in status['nodes']}
        expected_voters = set()
        step = (state.get('resize') or {}).get('step') or {}
        victim = step.get('victim') or {}
        removed_id = victim.get('member_id') if step.get('phase') in ('fenced', 'removed', 'cleanup') else None
        for member_id, member in members.items():
            spec = known.get(member['Address'])
            if spec is None or spec.get('member_id', member_id) != member_id:
                raise ImageError('unowned or changed member in cluster catalog')
            if spec.get('member_id') and any(
                    key in spec and spec[key] != member[field]
                    for key, field in (('node_name', 'NodeName'), ('node_uid', 'NodeUID'),
                                       ('etcd_member_id', 'EtcdMemberID'), ('role', 'Role'))):
                raise ImageError('saved node/etcd identity or role changed; refusing reconciliation')
            if not member['Complete']:
                if step.get('kind') != 'add' or step['spec']['address'] != member['Address']:
                    raise ImageError('unrelated pending admission; resume its owner')
                continue
            node = nodes.get(member['NodeName'])
            if member_id != removed_id:
                if node is None or node['Metadata']['UID'] != member['NodeUID']:
                    raise ImageError('Kubernetes node UID differs from catalog')
                labels = node['Metadata']['Labels'] or {}
                addresses = node['Status']['Addresses']
                if (labels.get('autonomous-rke2.io/host-id') != member_id[:32]
                        or labels.get('autonomous-rke2.io/cluster-id') != cluster
                        or not any(a['Type'] == 'InternalIP' and a['Address'] == member['Address'] for a in addresses)
                        or ('node-role.kubernetes.io/control-plane' in labels) != (member['Role'] == 'server')
                        or ('node-role.kubernetes.io/etcd' in labels) != (member['Role'] == 'server')):
                    raise ImageError('live node address/role/identity differs from catalog')
                if member['Role'] == 'server':
                    expected_voters.add(member['EtcdMemberID'])
                    matches = [v for v in status['etcd'] if v['ID'] == member['EtcdMemberID']]
                    if (len(matches) != 1 or matches[0].get('IsLearner', False)
                            or matches[0]['PeerURLs'] != ['https://' + member['Address'] + ':2380']):
                        raise ImageError('etcd identity/peer address differs from catalog')
            spec.update(member_id=member_id, role=member['Role'], node_name=member['NodeName'],
                        node_uid=member['NodeUID'], etcd_member_id=member['EtcdMemberID'])
            if member_id != removed_id:
                spec['node_labels'] = node['Metadata']['Labels'] or {}
        active_voters = {m['ID'] for m in status['etcd'] if not m.get('IsLearner', False)}
        # An in-flight join can already be a voter before its catalog completion.
        pending_addresses = {m['Address'] for m in members.values() if not m['Complete'] and m['Role'] == 'server'}
        for voter in status['etcd']:
            pending = any(url == 'https://' + ip + ':2380' for ip in pending_addresses for url in voter['PeerURLs'])
            if voter.get('IsLearner', False) and not pending:
                raise ImageError('unowned etcd learner; refusing reconciliation')
            if pending:
                active_voters.discard(voter['ID'])
        if removed_id and victim.get('etcd_member_id') in active_voters:
            active_voters.remove(victim['etcd_member_id'])
        if active_voters != expected_voters:
            raise ImageError('etcd voters differ from owned completed catalog members')
        expected_nodes = {m['NodeName'] for m in members.values()}
        if set(nodes) - expected_nodes:
            raise ImageError('unowned Kubernetes node; refusing reconciliation')
        for spec in state['nodes']:
            if (spec.get('member_id') and spec['member_id'] not in members
                    and spec.get('member_id') != removed_id):
                raise ImageError('saved member is absent from the live catalog')
        state['cluster_id'] = cluster
        return status

    def wait_membership(self, state, timeout):
        deadline = time.monotonic() + timeout
        while True:
            try:
                return self.observe_membership(state)
            except ImageError as exc:
                if 'no writable control node/quorum available' not in str(exc) or time.monotonic() >= deadline:
                    raise
                time.sleep(min(5, max(0, deadline - time.monotonic())))

    def describe_scaling(self, state, total, controls):
        self.observe_membership(state)
        target = state.get('resize') or {'nodes': total, 'controls': controls}
        changes, _ = planned_changes(state['nodes'], target['nodes'], target['controls'])
        peak = resize_peak(state, total, controls)
        print(quorum_message(target['nodes'], target['controls']))
        if state.get('resize'):
            print(f'Resume operation {target["id"]} before reconciling latest config.')
        for change in changes:
            victim = change['victim']
            if change['kind'] == 'add':
                print(f'Add {change["role"]}' + (f'; then retire {victim["name"]}' if victim else ''))
            else:
                print(f'Retire {victim["name"]} ({victim["role"]})')
        print(f'Peak {peak} VMs; {self.settings.vm["memory_mib"]} MiB RAM and '
              f'{self.settings.vm["disk_gib"]} GiB disk per additional VM, plus host reserves.')
        return changes, peak

    def scaling_capacity(self, state, peak, inventory):
        self.settings.validate_nodes(peak)
        # Also validate the highest occupied index: sparse survivors keep IPs.
        highest = max((n['index'] for n in state['nodes']), default=1)
        self.settings.validate_nodes(max(peak, highest))
        extra = max(0, peak - len(state['nodes']))
        step = (state.get('resize') or {}).get('step') or {}
        victim = step.get('victim') or {}
        retiring = victim.get('uuid') if step.get('fencing') or step.get('phase') in ('fenced', 'removed', 'cleanup') else None
        retained = [n for n in state['nodes'] if n['uuid'] != retiring
                    and n['uuid'] not in getattr(self, '_missing_retiring', set())]
        disks = extra + sum(not Path(n['disk']).exists() for n in retained)
        starting = extra + sum(n['name'] not in inventory['running'] for n in retained)
        parent = self.pool if self.pool.exists() else self.pool.parent
        if disks and shutil.disk_usage(parent).free < (disks * self.settings.vm['disk_gib'] + 8) * GIB:
            raise ImageError('insufficient disk for resize/replacement peak plus 8 GiB host reserve')
        available = next(int(x.split()[1]) * 1024 for x in Path('/proc/meminfo').read_text().splitlines()
                         if x.startswith('MemAvailable:'))
        if starting and available < (starting * self.settings.vm['memory_mib'] + 8192) * 1024**2:
            raise ImageError('insufficient RAM for resize/replacement peak plus 8 GiB host reserve')

    def owned_vm(self, spec):
        from lab.libvirt.lifecycle import virsh
        import xml.etree.ElementTree as ET
        if spec['name'] not in virsh('list', '--all', '--name').split():
            return False
        xml = ET.fromstring(virsh('dumpxml', spec['name']))
        if (xml.findtext('uuid') != spec['uuid']
                or [d.get('file') for d in xml.findall("devices/disk[@device='disk']/source")] != [spec['disk']]
                or xml.findtext('os/nvram') != spec['nvram']
                or [n.get('address') for n in xml.findall('devices/interface/mac')] != [spec['mac']]
                or [n.get('network') for n in xml.findall('devices/interface/source')] != [spec['network']]
                or [n.get('filter') for n in xml.findall('devices/interface/filterref')] != [spec['filter']]):
            raise ImageError('VM ownership changed during resize; refusing')
        return True

    def fence_vm(self, spec):
        from lab.libvirt.lifecycle import virsh
        if self.owned_vm(spec) and spec['name'] in virsh('list', '--name').split():
            virsh('destroy', spec['name'])
        if spec['name'] in virsh('list', '--name').split():
            raise ImageError('VM failed to stop; membership preserved')

    def vm_running(self, spec):
        from lab.libvirt.lifecycle import virsh
        return self.owned_vm(spec) and spec['name'] in virsh('list', '--name').split()

    def cleanup_node(self, spec):
        from lab.libvirt.lifecycle import virsh, command
        self.fence_vm(spec)
        if self.owned_vm(spec):
            virsh('undefine', spec['name'], '--keep-nvram')
        for suffix in ('.qcow2', '.vars.fd', '.iso', '.serial.log', '.xml'):
            path = self.pool / (spec['name'] + suffix)
            if path.is_symlink() or not self.inside(path):
                raise ImageError('unexpected node artifact path; refusing')
            path.unlink(missing_ok=True)
        seed = self.pool / (spec['name'] + '-seed')
        if seed.is_symlink():
            raise ImageError('unexpected seed symlink; refusing')
        if seed.exists():
            shutil.rmtree(seed)
        if (self.pool / 'known_hosts').exists():
            command(['ssh-keygen', '-R', spec['address'], '-f', self.pool / 'known_hosts'])

    def protect_local_data(self, coordinator, victim):
        from lab.libvirt.lifecycle import KUBECTL
        def items(command):
            return json.loads(self.ssh(coordinator['address'], KUBECTL + command))['items']
        pods = items(' get pods --all-namespaces --field-selector ' +
                     shlex.quote('spec.nodeName=' + victim['node_name']) + ' -o json')
        claims = set()
        for pod in pods:
            metadata = pod['metadata']
            # Mirror pods hold native control-plane state; daemonsets include
            # CNI host paths. Application PV consumers are checked separately.
            if (metadata.get('namespace') == 'kube-system'
                    and ('kubernetes.io/config.mirror' in metadata.get('annotations', {})
                         or any(o.get('kind') == 'DaemonSet' for o in metadata.get('ownerReferences', [])))):
                continue
            for volume in pod['spec'].get('volumes', []):
                if 'hostPath' in volume:
                    raise ImageError('node-local hostPath data blocks retirement; migrate it or explicitly use --force-remove')
                if 'persistentVolumeClaim' in volume:
                    claims.add((metadata['namespace'], volume['persistentVolumeClaim']['claimName']))
        pvs = {p['metadata']['name']: p for p in items(' get persistentvolumes -o json')}
        for pv in pvs.values():
            spec = pv['spec']
            terms = spec.get('nodeAffinity', {}).get('required', {}).get('nodeSelectorTerms', [])
            host_bound = any(e.get('key') == 'kubernetes.io/hostname' for term in terms
                             for e in term.get('matchExpressions', [])) or any(
                                 e.get('key') == 'metadata.name' for term in terms for e in term.get('matchFields', []))
            # Protect retained/unmounted local PVs too, not only running pods.
            if (('local' in spec or 'hostPath' in spec or host_bound)
                    and (not terms or affinity_matches(terms, victim))):
                raise ImageError('node-local or hostname-bound PV blocks retirement; migrate data or use --force-remove')

        if not claims:
            return
        pvcs = {(p['metadata']['namespace'], p['metadata']['name']): p for p in
                items(' get persistentvolumeclaims --all-namespaces -o json')}
        for claim in claims:
            pvc = pvcs.get(claim)
            if pvc is None or not pvc['spec'].get('volumeName'):
                raise ImageError('unresolved PVC blocks retirement; resolve storage before removing the node')
            pv = pvs.get(pvc['spec']['volumeName'])
            if pv is None:
                raise ImageError('bound PV is missing; refusing node retirement')
            spec = pv['spec']
            terms = spec.get('nodeAffinity', {}).get('required', {}).get('nodeSelectorTerms', [])
            host_bound = any(e.get('key') == 'kubernetes.io/hostname'
                             for term in terms for e in term.get('matchExpressions', []))
            if 'local' in spec or 'hostPath' in spec or host_bound:
                raise ImageError('node-local or hostname-bound PV blocks retirement; migrate data or use --force-remove')

    def prove_remaining_majority(self, state, victim, timeout):
        from lab.libvirt.lifecycle import HEALTH
        status = self.coordinator(state, {'action': 'status'}, exclude=victim['member_id'])
        voters = sum(not m.get('IsLearner', False) for m in status['etcd'])
        required = voters // 2 + 1
        healthy = set()
        clusters = set()
        for other in state['nodes']:
            if other['role'] != 'server' or other.get('member_id') == victim['member_id']:
                continue
            try:
                health = json.loads(self.ssh(other['address'], HEALTH, timeout=min(timeout, 30)))
                if (health['ClusterID'] == state['cluster_id'] and health['Role'] == 'server'
                        and health['HostID'] == other['member_id']
                        and health['Evidence']['NodeUID'] == other['node_uid']
                        and health['Evidence']['EtcdMemberID'] == other['etcd_member_id']):
                    healthy.add(health['HostID'])
                    clusters.add(health['Evidence']['EtcdClusterID'])
            except (ImageError, ValueError, KeyError, OSError, subprocess.SubprocessError):
                continue
        if len(healthy) < required or len(clusters) != 1 or not next(iter(clusters), ''):
            raise ImageError('cannot fence control VM without a proven remaining current majority; restore guest access/quorum')

    def retire_step(self, state, step, timeout, force):
        from lab.libvirt.lifecycle import KUBECTL
        victim = step['victim']
        print(f'Retiring {victim["name"]} ({victim["role"]}), phase {step["phase"]}', flush=True)
        request = {'operation': state['resize']['id'], 'member_id': victim['member_id']}
        if step['phase'] == 'ready':
            self.coordinator(state, {**request, 'action': 'retire'}, exclude=victim['member_id'])
            step['phase'] = 'draining'
            self.save(state)
        if step['phase'] == 'draining':
            self.coordinator(state, {'action': 'status'}, exclude=victim['member_id'])
            coordinator = self._coordinator
            name = shlex.quote(victim['node_name'])
            # Freeze ordinary scheduling before inspecting local storage; drain
            # will repeat this idempotently. Otherwise a new hostPath consumer
            # could land between the storage check and drain's own cordon.
            self.ssh(coordinator['address'], KUBECTL + f' cordon {name}')
            if not force:
                self.protect_local_data(coordinator, victim)
            # Do not implicitly delete emptyDir data or unmanaged pods.
            flags = ' --disable-eviction --force --delete-emptydir-data --grace-period=0' if force else ''
            self.ssh(coordinator['address'], KUBECTL + f' drain {name} --ignore-daemonsets'
                     f' --timeout={timeout}s' + flags, timeout=timeout + 30)
            step['phase'] = 'drained'
            self.save(state)
        if step['phase'] == 'drained':
            was_fencing = step.get('fencing', False)
            step['fencing'] = True
            step['live_remove'] = victim['role'] == 'server'
            self.save(state)
            if was_fencing and not self.vm_running(victim):
                step['live_remove'] = False  # Resume an already completed power-off.
            elif step['live_remove']:
                # Preserve the current vote until committed removal. This is
                # essential for 2->1 and avoids losing quorum in degraded clusters.
                try:
                    self.management(victim, {'action': 'fence-local', 'member_id': victim['member_id']})
                    self.ssh(victim['address'], 'sudo systemctl disable autonomous-rke2-host-agent.service && '
                             'sudo systemctl mask rke2-server.service rke2-agent.service && '
                             'sudo systemctl stop autonomous-rke2-host-agent.service')
                except (ImageError, OSError, subprocess.SubprocessError):
                    if not force:
                        raise
                    # An unreachable guest can be powered off only if independent
                    # health checks prove the old majority survives its loss.
                    self.prove_remaining_majority(state, victim, timeout)
                    step['live_remove'] = False
                    self.save(state)
                    self.fence_vm(victim)
            else:
                try:
                    self.management(victim, {'action': 'fence-local', 'member_id': victim['member_id']})
                except (ImageError, OSError, subprocess.SubprocessError):
                    if not force:
                        raise
                self.fence_vm(victim)
            step['phase'] = 'fenced'
            self.save(state)
        if step['phase'] == 'fenced':
            # Recheck the fence on retries before any remote destructive action.
            if not step.get('live_remove'):
                self.fence_vm(victim)
            deadline = time.monotonic() + timeout
            while True:
                try:
                    self.coordinator(state, {**request, 'action': 'remove'}, exclude=victim['member_id'])
                    break
                except ImageError as exc:
                    # Removal can commit immediately before a leader election or
                    # Node finalization. The same ID is safe to retry; conflicts
                    # and ownership errors never enter this retry path.
                    if 'formation waiting' not in str(exc) or time.monotonic() >= deadline:
                        raise
                    time.sleep(min(3, max(0, deadline - time.monotonic())))
            step['phase'] = 'removed'
            self.save(state)
        if step['phase'] == 'removed':
            self.fence_vm(victim)
            self.observe_membership(state)
            step['phase'] = 'cleanup'
            self.save(state)
        if step['phase'] == 'cleanup':
            self.cleanup_node(victim)
            state['nodes'] = [n for n in state['nodes'] if n['uuid'] != victim['uuid']]
            state['count'] = len(state['nodes'])
            state['resize']['step'] = None
            self.save(state)

    def reconcile_scaling(self, state, total, controls, timeout, force, image):
        from lab.libvirt.lifecycle import make_spec
        while True:
            if not state.get('resize'):
                status = self.observe_membership(state)
                live_target = status['catalog'].get('ControlNodes') or state.get('control_nodes', 3)
                if next_change(state['nodes'], total, controls) is None and live_target == controls:
                    if state.get('control_nodes') != controls:
                        state['control_nodes'] = controls
                        self.save(state)
                    return
                state['resize'] = {'id': uuid.uuid4().hex, 'nodes': total,
                                   'controls': controls, 'step': None}
                state['complete'] = False
                self.save(state)
            operation = state['resize']
            self.coordinator(state, {'action': 'begin', 'operation': operation['id'],
                                    'nodes': operation['nodes'], 'control_nodes': operation['controls']})
            if operation['step'] is None:
                self.observe_membership(state)
                change = next_change(state['nodes'], operation['nodes'], operation['controls'])
                if change is None:
                    self.coordinator(state, {'action': 'finish', 'operation': operation['id']})
                    state['control_nodes'] = operation['controls']
                    state['resize'] = None
                    self.save(state)
                    continue
                step = {**change, 'phase': 'ready'}
                if change['kind'] == 'add':
                    used = {n['index'] for n in state['nodes']}
                    index = next(i for i in range(1, 1026) if i not in used)
                    self.settings.validate_nodes(index)
                    spec = {**make_spec(f'{self.settings.hostname_prefix}{index:02}',
                                       self.settings.address(index - 1), 'node', self.pool),
                            'network': self.settings.network, 'filter': self.settings.filter,
                            **self.settings.vm, 'index': index, 'role': change['role'], 'boot_requested': False}
                    step['spec'] = spec
                    state['nodes'].append(spec)
                    state['count'] = len(state['nodes'])
                operation['step'] = step
                self.save(state)
            step = operation['step']
            if step['kind'] == 'add' and step['phase'] == 'ready':
                spec = next(n for n in state['nodes'] if n['uuid'] == step['spec']['uuid'])
                self.coordinator(state, {'action': 'admit', 'operation': operation['id'], 'address': spec['address']})
                self.prepare_node(spec, state, image)
                self.boot(spec, state)
                self.wait_healthy(spec, timeout)
                self.observe_membership(state)
                if spec['role'] != step['role']:
                    raise ImageError('admission assigned an unexpected role')
                self.coordinator(state, {'action': 'admitted', 'operation': operation['id'], 'address': spec['address']})
                if step['victim'] is None:
                    operation['step'] = None
                else:
                    step['phase'] = 'ready'
                    step['kind'] = 'remove'
                self.save(state)
            elif step['kind'] == 'remove':
                self.retire_step(state, step, timeout, force)

    def create_scaling(self, release, manifest, count, timeout, inventory):
        from lab.libvirt.lifecycle import command, KUBECTL, write_private
        controls = control_count(self.control_nodes)
        print(quorum_message(count, controls))
        fresh = not self.state_path.exists()
        old = json.loads(self.state_path.read_text()) if not fresh else None
        state = self.load_or_initialize(release, digest(release), old['count'] if old else 1, inventory)
        state['schema'] = 2
        state['capabilities'] = [CAPABILITY]
        for i, spec in enumerate(state['nodes']):
            spec.setdefault('index', i + 1)
        self.save(state)
        planning_state = {**state, 'nodes': [{**n, 'role': n.get('role', 'server' if n['index'] <= 3 else 'agent')}
                                            for n in state['nodes']]}
        self._missing_retiring = missing_retirements(planning_state, count, controls)
        peak = resize_peak(planning_state, count, controls)
        self.scaling_capacity(state, peak, inventory)
        self.ensure_settings(inventory)
        key = self.pool / 'operator'
        if not key.exists():
            if any(n['boot_requested'] for n in state['nodes']):
                raise ImageError('missing operator key; restore it before resuming')
            key.with_suffix('.pub').unlink(missing_ok=True)
            command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
        if not key.with_suffix('.pub').exists():
            write_private(key.with_suffix('.pub'), command(['ssh-keygen', '-y', '-f', key]))
        step = (state.get('resize') or {}).get('step') or {}
        victim = step.get('victim') or {}
        for spec in state['nodes']:
            if spec['uuid'] in self._missing_retiring:
                print(f'{spec["name"]}: missing boot artifacts; retirement only, no disk reconstruction', flush=True)
                continue
            # Never restart a node selected for retirement, including crash windows.
            if (spec.get('member_id') == victim.get('member_id') and victim
                    and (step.get('phase') in ('fenced', 'removed', 'cleanup') or step.get('fencing'))):
                continue
            if spec['boot_requested']:
                self.prepare_node(spec, state, release.parent / 'node.qcow2')
                self.boot(spec, state)
        if not any(n['boot_requested'] for n in state['nodes']):
            first = state['nodes'][0]
            self.prepare_node(first, state, release.parent / 'node.qcow2')
            self.boot(first, state)
        # Discover public identities once; management thereafter observes live
        # membership rather than assuming VM hostnames equal Kubernetes names.
        for spec in state['nodes']:
            if not spec.get('role') and spec['boot_requested']:
                self.wait_healthy(spec, timeout)
                health = json.loads(self.ssh(spec['address'], 'sudo /usr/local/libexec/autonomous-rke2/host-agent -health'))
                spec.update(role=health['Role'], member_id=health['HostID'])
        self.wait_membership(state, timeout)
        self.save(state)
        self.reconcile_scaling(state, count, controls, timeout, self.force_remove, release.parent / 'node.qcow2')
        for spec in state['nodes']:
            self.wait_healthy(spec, timeout)
        self.observe_membership(state)
        address = next(n['address'] for n in state['nodes'] if n['role'] == 'server')
        print(self.ssh(address, KUBECTL + ' get nodes -o wide'), end='')
        config = self.ssh(address, 'sudo cat /etc/rancher/rke2/rke2.yaml')
        write_private(self.pool / 'admin.yaml', config.replace('127.0.0.1', address))
        state['complete'] = True
        self.save(state)
        print(f'Cluster ready. Kubeconfig: {self.pool}/admin.yaml')
