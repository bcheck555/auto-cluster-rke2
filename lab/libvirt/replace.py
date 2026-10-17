"""Generation-bound, journaled Phase 1 image replacement and explicit rollback."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lab.packer.artifacts import CREDENTIALS, GIB, ImageError, digest, operation_lock, preflight, sign, trust, verify_manifest, verify_signature, write_json
from lab.packer import runtime as vm
from lab.libvirt.provision import verify_derived_image
from lab.libvirt.snapshot import capture as capture_host

NODES = {'rke2-r9-cp01': ('192.168.250.11', '52:54:00:40:01:01'),
         'rke2-r9-cp02': ('192.168.250.12', '52:54:00:40:01:02'),
         'rke2-r9-cp03': ('192.168.250.13', '52:54:00:40:01:03')}


def protected_state(snapshot):
    result = {}
    for kind in ('domains', 'networks', 'pools', 'nwfilters'):
        result[kind] = {}
        for name, source in snapshot.get(kind, {}).items():
            if kind == 'domains' and name in NODES:
                continue
            xml = ET.fromstring(source)
            if kind == 'pools':
                # Shared filesystem free-space counters change when owned lab files are created.
                for tag in ('capacity', 'allocation', 'available'):
                    for node in xml.findall(tag):
                        xml.remove(node)
            result[kind][name] = ET.tostring(xml, encoding='unicode')
    return result


def file_ids(paths):
    result = {}
    for path in paths:
        target = Path(path)
        if target.is_symlink() or vm.POOL not in target.resolve().parents:
            raise ImageError('storage ownership path changed')
        info = target.stat()
        result[path] = {'device': info.st_dev, 'inode': info.st_ino}
    return result


def binding(name):
    xml = vm.current(name)
    disks = [n.get('file') for n in xml.findall("devices/disk[@device='disk']/source")]
    nvram = xml.findtext('os/nvram')
    interfaces = xml.findall('devices/interface')
    if len(disks) != 1 or len(interfaces) != 1 or not nvram:
        raise ImageError('unexpected domain disk/network/firmware layout: ' + name)
    nic = interfaces[0]
    mac = nic.find('mac').get('address')
    if mac != NODES[name][1] or nic.find('source').get('network') != vm.NETWORK or nic.find('filterref').get('filter') != vm.FILTER:
        raise ImageError('domain MAC/network/filter differs: ' + name)
    paths = [*disks, nvram, *[n.get('file') for n in xml.findall("devices/disk[@device='cdrom']/source")]]
    if any(vm.POOL not in Path(p).resolve().parents for p in paths):
        raise ImageError('domain storage outside owned pool')
    if int(xml.findtext('vcpu')) != 4 or int(xml.findtext('memory')) != 8192 * 1024:
        raise ImageError('domain resources differ from approved replacement')
    capacity = int(vm.virsh('domblkinfo', name, disks[0]).split('Capacity:')[1].split()[0])
    if capacity != 60 * GIB:
        raise ImageError('domain disk capacity differs')
    state = vm.virsh('domstate', name).strip()
    if state == 'running' and NODES[name][0] not in vm.virsh('domifaddr', name, '--source', 'agent'):
        raise ImageError('running domain address differs from replacement binding')
    return {'name': name, 'uuid': xml.findtext('uuid'), 'disk': disks[0], 'nvram': nvram,
            'mac': mac, 'address': NODES[name][0], 'paths': paths,
            'file_ids': file_ids(paths),
            'state': state, 'xml': ET.tostring(xml, encoding='unicode')}


def check_binding(expected):
    actual = binding(expected['name'])
    for key in ('uuid', 'disk', 'nvram', 'mac', 'address', 'paths', 'file_ids'):
        if actual[key] != expected[key]:
            raise ImageError('replacement ownership binding changed: ' + expected['name'] + ' ' + key)


def plan(release_path, output):
    if output.exists():
        raise ImageError('replacement plan already exists')
    release = verify_manifest(release_path)
    if release.get('kind') != 'release' or release['profiles']['server']['firewalld'] != 'disabled':
        raise ImageError('replacement requires tested signed server release')
    fp, keyring = trust()
    pin = release['profiles']['server']
    verify_derived_image({'profile': 'server', 'release_manifest': str(release_path),
                         'release_sha256': digest(release_path), 'keyring_path': str(keyring),
                         'signing_fingerprint': fp, 'sha256': pin['sha256'],
                         'path': str(release_path.parent / pin['file'])})
    vm.isolation()
    preflight(extra_disk=60 * GIB, extra_memory_mib=8192)
    generation = vm.POOL / ('replacement-' + uuid.uuid4().hex[:16])
    records = []
    for name, (address, mac) in NODES.items():
        old = binding(name)
        new = vm.make_spec(name, address, 'server', generation, mac=mac)
        new['disk_gib'] = 60
        new['release_sha256'] = digest(release_path)
        new['image_sha256'] = release['profiles']['server']['sha256']
        new['input_sha256'] = release['input_sha256']
        records.append({'old': old, 'new': new})
    document = {'schema': 1, 'kind': 'replacement-plan', 'release': str(release_path.resolve()),
                'release_sha256': digest(release_path), 'generation': str(generation), 'nodes': records}
    write_json(output, document)
    sign(output)
    print('signed replacement plan: ' + str(output))


def load_plan(path):
    fp, key = trust()
    verify_signature(path, key, fp)
    doc = json.loads(path.read_text())
    if doc.get('kind') != 'replacement-plan' or set(n['old']['name'] for n in doc['nodes']) != set(NODES):
        raise ImageError('invalid replacement plan')
    return doc


def rollback_preflight(doc):
    """Reserve the old guests' future writes when keeping the new generation."""
    extra_disk = 0
    extra_memory = 0
    for record in doc['nodes']:
        old, new = record['old'], record['new']
        info = Path(old['disk']).stat()
        old_remaining = max(0, 60 * GIB - info.st_blocks * 512)
        if vm.absent(old['name']):
            extra_disk += old_remaining
            if old['state'] == 'running':
                extra_memory += 8192
            continue
        xml = vm.current(old['name'])
        if xml.findtext('uuid') not in (old['uuid'], new['uuid']):
            raise ImageError('rollback stopped: domain ownership/UUID mismatch')
        disk = xml.find("devices/disk[@device='disk']/source").get('file')
        if disk not in (old['disk'], new['disk']):
            raise ImageError('rollback stopped: domain disk ownership mismatch')
        text = vm.virsh('domblkinfo', old['name'], disk)
        stats = {line.split(':')[0]: int(line.split(':')[1]) for line in text.splitlines() if ':' in line}
        current_remaining = max(0, stats['Capacity'] - stats['Allocation'])
        extra_disk += max(0, old_remaining - current_remaining)
        if old['state'] == 'running' and xml.get('id') is None:
            extra_memory += 8192
    preflight(extra_disk=extra_disk, extra_memory_mib=extra_memory)


def rollback_journal(path):
    journal = json.loads(path.read_text())
    plan_path = Path(journal['plan'])
    if digest(plan_path) != journal['plan_sha256']:
        raise ImageError('journal plan digest mismatch')
    doc = load_plan(plan_path)
    if str(path.parent) != doc['generation']:
        raise ImageError('journal generation mismatch')
    rollback_preflight(doc)
    by_name = {n['old']['name']: n for n in doc['nodes']}
    for entry in reversed(journal['nodes']):
        if entry['stage'] in ('untouched', 'restored'):
            continue
        record = by_name[entry['name']]
        old, new = record['old'], record['new']
        if old.get('file_ids') and file_ids(old['paths']) != old['file_ids']:
            raise ImageError('rollback stopped: preserved storage ownership changed')
        if not vm.absent(entry['name']):
            observed_uuid = vm.current(entry['name']).findtext('uuid')
            if observed_uuid == new['uuid']:
                vm.discard(new)
            elif observed_uuid == old['uuid']:
                check_binding(old)
            else:
                raise ImageError('rollback stopped: domain ownership/UUID mismatch')
        xml_path = path.parent / (entry['name'] + '.old.xml')
        nvram_copy = path.parent / (entry['name'] + '.old.vars.fd')
        if digest(xml_path) != entry['old_xml_sha256'] or digest(nvram_copy) != entry['old_nvram_sha256']:
            raise ImageError('rollback snapshot corrupted')
        if vm.absent(entry['name']):
            # Old disks and seeds were never modified; restore snapshot of old firmware state.
            shutil.copyfile(nvram_copy, old['nvram'])
            vm.virsh('define', str(xml_path))
        check_binding(old)
        if old['state'] == 'running' and vm.virsh('domstate', entry['name']).strip() == 'shut off':
            vm.virsh('start', old['uuid'])
        entry['stage'] = 'restored'
        write_json(path, journal)
    journal['status'] = 'rolled-back'
    write_json(path, journal)
    print('rollback complete; both generations retained: ' + str(path))


def apply(plan_path):
    doc = load_plan(plan_path)
    release_path = Path(doc['release'])
    if digest(release_path) != doc['release_sha256']:
        raise ImageError('release differs from replacement plan')
    release = verify_manifest(release_path)
    vm.isolation()
    preflight(extra_disk=60 * GIB, extra_memory_mib=8192)
    for record in doc['nodes']:
        check_binding(record['old'])
    directory = Path(doc['generation'])
    directory.mkdir(mode=0o711, exist_ok=False)
    journal_path = directory / 'journal.json'
    journal = {'schema': 1, 'plan': str(plan_path.resolve()), 'plan_sha256': digest(plan_path), 'status': 'applying',
               'nodes': [{'name': n['old']['name'], 'stage': 'untouched'} for n in doc['nodes']]}
    write_json(journal_path, journal)
    # Snapshot complete resource definitions without changing unrelated resources.
    before = capture_host()
    write_json(directory / 'host-before.json', {**before, 'owned_resource_definitions': {
        'domains': vm.virsh('list', '--all'), 'networks': vm.virsh('net-list', '--all'),
        'pools': vm.virsh('pool-list', '--all'), 'network_xml': vm.virsh('net-dumpxml', vm.NETWORK),
        'pool_xml': vm.virsh('pool-dumpxml', 'autonomous-rke2-lab'),
        'filter_xml': vm.virsh('nwfilter-dumpxml', vm.FILTER)}})
    pin = release['profiles']['server']
    base = directory / 'server-base.qcow2'
    shutil.copyfile(release_path.parent / pin['file'], base)
    os.chmod(base, 0o444)
    if digest(base) != pin['sha256']:
        raise ImageError('copied release image digest mismatch')
    key = vm.OPERATOR_KEY.read_text().strip()
    identities = {field: set() for field in ('host_id', 'machine_id', 'ssh_fingerprint')}
    try:
        for record, entry in zip(doc['nodes'], journal['nodes']):
            old, new = record['old'], record['new']
            check_binding(old)
            xml_path = directory / (old['name'] + '.old.xml')
            xml_path.write_text(old['xml'])
            os.chmod(xml_path, 0o600)
            nvram_copy = directory / (old['name'] + '.old.vars.fd')
            shutil.copyfile(old['nvram'], nvram_copy)
            entry.update({'old_xml_sha256': digest(xml_path), 'old_nvram_sha256': digest(nvram_copy)})
            # Journal before destructive transition; old NVRAM copied after confirmed power-off.
            entry['stage'] = 'stopping'
            write_json(journal_path, journal)
            vm.stop(old)
            shutil.copyfile(old['nvram'], directory / (old['name'] + '.old.vars.fd'))
            entry.update({'old_xml_sha256': digest(xml_path),
                          'old_nvram_sha256': digest(directory / (old['name'] + '.old.vars.fd')), 'stage': 'stopped'})
            write_json(journal_path, journal)
            check_binding(old)
            vm.virsh('undefine', old['uuid'], '--keep-nvram', '--keep-tpm')
            if old['uuid'] in vm.virsh('list', '--uuid').split():
                raise ImageError('old domain became active during replacement; refusing MAC/address reuse')
            entry['stage'] = 'undefined'
            write_json(journal_path, journal)
            vm.launch(new, base, key)
            entry['stage'] = 'created'
            write_json(journal_path, journal)
            report = vm.wait_report(new, timeout=300)
            vm.validate_report(new, report, key)
            second = vm.reboot_report(new, key)
            if any(report[f] != second[f] for f in ('host_id', 'machine_id', 'ssh_fingerprint')):
                raise ImageError('replacement identity changed across reboot')
            for field, seen in identities.items():
                if report[field] in seen:
                    raise ImageError('replacement guest identity duplicated: ' + field)
                seen.add(report[field])
            write_json(directory / (new['name'] + '.validation.json'), {'boot': report, 'reboot': second})
            entry['stage'] = 'validated'
            write_json(journal_path, journal)
        after = capture_host()
        write_json(directory / 'host-after.json', after)
        if protected_state(before) != protected_state(after):
            raise ImageError('protected host resource definitions changed during replacement')
        write_json(directory / 'host-differences.json', {
            'protected_definitions_unchanged': True, 'replaced_domains': list(NODES),
            'before_links': [x['ifname'] for x in before.get('links', [])],
            'after_links': [x['ifname'] for x in after.get('links', [])],
            'network_pool_filter_reused': True})
    except Exception:
        journal['status'] = 'recovering'
        write_json(journal_path, journal)
        rollback_journal(journal_path)
        raise
    journal['status'] = 'complete'
    write_json(journal_path, journal)
    fp, keyring = trust()
    write_json(directory / 'effective-nodes.json', {'release_sha256': doc['release_sha256'],
               'image_sha256': pin['sha256'], 'ssh_public_key_file': str(vm.OPERATOR_KEY),
               'network': {'name': vm.NETWORK, 'cidr': '192.168.250.0/24'},
               'image': {'kind': 'derived', 'profile': 'server', 'release_manifest': str(release_path),
                         'release_sha256': doc['release_sha256'], 'keyring_path': str(keyring),
                         'signing_fingerprint': fp, 'sha256': pin['sha256'], 'path': str(base)},
               'nodes': [{**n['new'], 'role': 'server', 'vcpus': 4, 'memory_mib': 8192,
                          'firewalld': 'disabled'} for n in doc['nodes']]})
    print('replacement complete; rollback journal: ' + str(journal_path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('plan', 'apply', 'rollback'))
    parser.add_argument('--release', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--journal', type=Path)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ImageError('replacement operations require root')
        with operation_lock():
            if args.operation == 'plan':
                if not args.release or not args.output:
                    raise ImageError('plan requires --release and --output')
                plan(args.release.resolve(), args.output.resolve())
            elif args.operation == 'apply':
                if not args.plan:
                    raise ImageError('apply requires --plan')
                apply(args.plan.resolve())
            else:
                if not args.journal:
                    raise ImageError('rollback requires --journal')
                rollback_journal(args.journal.resolve())
    except (ImageError, OSError, ValueError, KeyError) as exc:
        print('replacement failed: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
