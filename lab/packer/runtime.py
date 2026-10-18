"""Owned disposable libvirt guests and signed, offline boot/cluster validation."""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from .artifacts import GIB, ROOT, VERSIONS, ImageError, digest, preflight, run, sign, verify_manifest, write_json

POOL = Path('/var/lib/libvirt/images/autonomous-rke2-lab')
NETWORK = 'autonomous-rke2-isolated'
FILTER = 'autonomous-rke2-ipv4-only'
OPERATOR_KEY = ROOT / 'lab/credentials/lab.pub'


def virsh(*args):
    return run(['virsh', '-c', 'qemu:///system', *args])


def isolation():
    network = ET.fromstring(virsh('net-dumpxml', NETWORK))
    if network.find('forward') is not None or network.findall('ip') or network.find('bridge').get('name') != 'virbr-rke2':
        raise ImageError('lab network isolation differs from approved configuration')
    pool = ET.fromstring(virsh('pool-dumpxml', 'autonomous-rke2-lab'))
    if pool.findtext('target/path') != str(POOL):
        raise ImageError('lab pool ownership differs')
    filt = ET.fromstring(virsh('nwfilter-dumpxml', FILTER))
    drops = [r for r in filt.findall('rule') if r.get('action') == 'drop' and r.get('direction') == 'inout'
             and any(m.get('protocolid') in ('0x86dd', 'ipv6') for m in r.findall('mac'))]
    if not drops:
        raise ImageError('required IPv6 isolation filter missing')
    bridge = json.loads(run(['ip', '-j', 'address', 'show', 'virbr-rke2']))
    if any(a.get('scope') != 'link' for d in bridge for a in d.get('addr_info', [])):
        raise ImageError('isolated bridge has a host address')


def current(name):
    return ET.fromstring(virsh('dumpxml', name))


def require_owner(spec):
    xml = current(spec['name'])
    if xml.findtext('uuid') != spec['uuid']:
        raise ImageError('domain ownership/UUID mismatch: ' + spec['name'])
    disks = [x.get('file') for x in xml.findall("devices/disk[@device='disk']/source")]
    if 'disk' in spec and disks != [spec['disk']]:
        raise ImageError('domain disk ownership mismatch: ' + spec['name'])
    if 'nvram' in spec and xml.findtext('os/nvram') != spec['nvram']:
        raise ImageError('domain firmware ownership mismatch: ' + spec['name'])
    macs = [x.get('address') for x in xml.findall('devices/interface/mac')]
    if 'mac' in spec and macs != [spec['mac']]:
        raise ImageError('domain MAC ownership mismatch: ' + spec['name'])


def absent(name):
    return name not in virsh('list', '--all', '--name').split()


def stop(spec):
    require_owner(spec)
    if virsh('domstate', spec['uuid']).strip() != 'shut off':
        virsh('destroy', spec['uuid'])
    if virsh('domstate', spec['uuid']).strip() != 'shut off':
        raise ImageError('old domain did not stop')


def discard(spec):
    require_owner(spec)
    has_tpm = current(spec['name']).find('devices/tpm') is not None
    stop(spec)
    virsh('undefine', spec['uuid'], '--keep-nvram', *(['--tpm'] if has_tpm else []))


def make_spec(name, address, profile, directory, *, mac=None, host_id=None, domain_uuid=None):
    ident = uuid.uuid4()
    return {'name': name, 'address': address, 'profile': profile, 'uuid': domain_uuid or str(uuid.uuid4()),
            'host_id': host_id or str(uuid.uuid4()), 'mac': mac or '52:54:00:' + ':'.join(f'{x:02x}' for x in ident.bytes[:3]),
            'disk_gib': 32, 'directory': str(directory), 'disk': str(directory / (name + '.qcow2')),
            'nvram': str(directory / (name + '.vars.fd')), 'seed': str(directory / (name + '.iso')),
            'serial': str(directory / (name + '.serial.log')), 'instance_id': str(uuid.uuid4())}


def prepare_seed(spec, operator_key, extra_files=None, smoke=None):
    directory = Path(spec['directory']) / (spec['name'] + '-seed')
    directory.mkdir(mode=0o700)
    instance = {key: spec[key] for key in ('name', 'host_id', 'profile', 'address')}
    instance['probe_targets'] = ['192.168.250.1', '1.1.1.1']
    if smoke:
        instance.update(smoke)
    def file(path, content, permissions='0600'):
        return {'path': path, 'content': content, 'permissions': permissions, 'owner': 'root:root'}
    userdata = {'hostname': spec['name'], 'preserve_hostname': False, 'disable_root': True, 'ssh_pwauth': False,
        'ssh_deletekeys': True, 'users': [{'name': 'rke2lab', 'shell': '/bin/bash', 'lock_passwd': True,
            'sudo': ['ALL=(ALL) NOPASSWD: ALL'], 'ssh_authorized_keys': [operator_key.strip()]}],
        'package_update': False, 'package_upgrade': False,
        'write_files': [file('/var/lib/autonomous-rke2/host-id', spec['host_id'] + '\n'),
            file('/etc/autonomous-rke2/instance.json', json.dumps(instance)), *(extra_files or [])],
        'runcmd': [['systemctl', 'enable', '--now', 'qemu-guest-agent'],
            ['mkdir', '-p', '/etc/systemd/system/cloud-init.target.wants'],
            ['ln', '-sf', '/etc/systemd/system/autonomous-image-validation.service',
             '/etc/systemd/system/cloud-init.target.wants/autonomous-image-validation.service'],
            ['systemctl', 'start', '--no-block', 'autonomous-image-validation.service']]}
    interface = spec.get('interface', 'rke2lab0')
    network = {'version': 2, 'ethernets': {interface: {'match': {'macaddress': spec['mac']}, 'set-name': interface,
               'dhcp4': False, 'dhcp6': False, 'accept-ra': False, 'addresses': [spec['address'] + '/24']}}}
    if smoke and not smoke.get('formation_smoke'):
        # OUTPUT DNAT still requires an initial route lookup. This on-link route
        # reaches only the service CIDR and survives reboot without a default route.
        network['ethernets'][interface]['routes'] = [{'to': '10.43.0.0/16', 'via': '0.0.0.0'}]
    if smoke:
        userdata['runcmd'].insert(0, ['systemctl', 'daemon-reload'])
    (directory / 'user-data').write_text('#cloud-config\n' + json.dumps(userdata))
    write_json(directory / 'meta-data', {'instance-id': spec['instance_id'], 'local-hostname': spec['name']})
    write_json(directory / 'network-config', network)
    run(['genisoimage', '-quiet', '-output', spec['seed'], '-volid', 'cidata', '-joliet', '-rock',
         directory / 'user-data', directory / 'meta-data', directory / 'network-config'])
    os.chmod(spec['seed'], 0o600)


def domain_xml(spec):
    """Define file-backed guests directly; virt-install auto-creates directory pools."""
    root = ET.Element('domain', type='kvm')
    def element(parent, tag, text=None, **attributes):
        node = ET.SubElement(parent, tag, attributes)
        node.text = text
        return node
    element(root, 'name', spec['name'])
    element(root, 'uuid', spec['uuid'])
    element(root, 'memory', '8388608', unit='KiB')
    element(root, 'currentMemory', '8388608', unit='KiB')
    element(root, 'vcpu', '4', placement='static')
    system = element(root, 'os')
    element(system, 'type', 'hvm', arch='x86_64', machine='q35')
    element(system, 'loader', '/usr/share/OVMF/OVMF_CODE_4M.fd', readonly='yes', type='pflash')
    element(system, 'nvram', spec['nvram'])
    element(system, 'boot', dev='hd')
    features = element(root, 'features')
    element(features, 'acpi')
    element(features, 'apic')
    element(root, 'cpu', mode='host-passthrough', check='none', migratable='off')
    element(root, 'clock', offset='utc')
    for tag, value in (('on_poweroff', 'destroy'), ('on_reboot', 'restart'), ('on_crash', 'destroy')):
        element(root, tag, value)
    devices = element(root, 'devices')
    element(devices, 'emulator', shutil.which('qemu-system-x86_64'))
    for role, key, target, bus, fmt in (('disk', 'disk', 'vda', 'virtio', 'qcow2'),
                                       ('cdrom', 'seed', 'sda', 'sata', 'raw')):
        disk = element(devices, 'disk', type='file', device=role)
        element(disk, 'driver', name='qemu', type=fmt)
        element(disk, 'source', file=spec[key])
        element(disk, 'target', dev=target, bus=bus)
        if role == 'cdrom':
            element(disk, 'readonly')
    nic = element(devices, 'interface', type='network')
    element(nic, 'mac', address=spec['mac'])
    element(nic, 'source', network=spec.get('network', NETWORK))
    element(nic, 'model', type='virtio')
    element(nic, 'filterref', filter=spec.get('filter', FILTER))
    channel = element(devices, 'channel', type='unix')
    element(channel, 'target', type='virtio', name='org.qemu.guest_agent.0')
    serial = element(devices, 'serial', type='pty')
    element(serial, 'log', file=spec['serial'], append='on')
    element(serial, 'target', type='isa-serial', port='0')
    console = element(devices, 'console', type='pty')
    element(console, 'target', type='serial', port='0')
    return ET.tostring(root, encoding='unicode')


def launch(spec, image, operator_key, *, extra_files=None, smoke=None):
    isolation()
    if not absent(spec['name']):
        raise ImageError('domain already exists: ' + spec['name'])
    directory = Path(spec['directory'])
    directory.mkdir(parents=True, mode=0o711, exist_ok=True)
    os.chmod(directory, 0o711)
    write_json(directory / (spec['name'] + '-spec.json'), spec)
    if any(Path(spec[key]).exists() for key in ('disk', 'nvram', 'seed', 'serial')):
        raise ImageError('generation artifact already exists')
    run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image), spec['disk'], str(spec['disk_gib']) + 'G'])
    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', spec['nvram'])
    prepare_seed(spec, operator_key, extra_files, smoke)
    definition = directory / (spec['name'] + '.xml')
    definition.write_text(domain_xml(spec))
    os.chmod(definition, 0o600)
    virsh('define', str(definition))
    require_owner(spec)
    virsh('start', spec['uuid'])
    require_owner(spec)


def reports(spec):
    path = Path(spec['serial'])
    if not path.exists():
        return []
    result = []
    for match in re.finditer(rb'IMAGE_REPORT=([A-Za-z0-9+/=]+)', path.read_bytes()):
        try:
            result.append(json.loads(base64.b64decode(match[1])))
        except (ValueError, UnicodeDecodeError):
            continue
    return result


def wait_report(spec, after=0, timeout=1800):
    deadline = time.monotonic() + timeout
    diagnosed = False
    while time.monotonic() < deadline:
        require_owner(spec)
        found = reports(spec)
        if len(found) > after:
            report = found[-1]
            if not spec.get('last_boot_id') or report.get('boot_id') != spec['last_boot_id']:
                spec['last_boot_id'] = report.get('boot_id')
                return report
        if not diagnosed and time.monotonic() > deadline - timeout + 150 and spec.get('diagnostic_path'):
            diagnosed = True
            from .console import diagnose
            try:
                diagnostic = diagnose(spec)
                write_json(spec['diagnostic_path'], diagnostic)
                print('saved private smoke diagnostic: ' + spec['diagnostic_path'], flush=True)
                report = diagnostic.get('boot_report')
                if (report and report.get('boot_id') == diagnostic['boot_id'] and
                        report.get('boot_id') != spec.get('last_boot_id')):
                    spec['last_boot_id'] = report['boot_id']
                    return report
            except Exception as exc:
                write_json(spec['diagnostic_path'], {'diagnostic_error': type(exc).__name__})
        time.sleep(3)
    raise ImageError('guest validation timed out: ' + spec['name'] + '; inspect ' + spec['serial'])


def validate_report(spec, report, operator_key, *, smoke=False):
    if report['errors'] or report['selinux'] != 'Enforcing' or report['operator_password'] not in ('LK', 'L'):
        raise ImageError('guest SELinux/password/runtime validation failed: ' + spec['name'])
    if report['hostname'] != spec['name'] or report['host_id'] != spec['host_id']:
        raise ImageError('guest identity differs from deployment')
    if report['identity_uid'] != 0 or report['identity_mode'] != '0o600':
        raise ImageError('host identity ownership/mode differs')
    if operator_key.strip() not in report['authorized_keys'] or not re.fullmatch('[a-f0-9]{32}', report['machine_id']):
        raise ImageError('guest key or machine identity invalid')
    profile = spec['profile']
    if report['image']['profile'] != profile or report['image']['versions'] != VERSIONS:
        raise ImageError('image profile/version differs')
    if spec.get('input_sha256') and report['image'].get('input_sha256') != spec['input_sha256']:
        raise ImageError('image input digest differs from immutable deployment pin')
    expected = ('active', 'enabled') if profile == 'os' else ('inactive', 'disabled')
    if (report['firewalld_active'], report['firewalld_enabled']) != expected:
        raise ImageError('firewalld violates immutable profile policy')
    if not smoke and any(x['enabled'] != 'masked' or x['active'] == 'active' for x in report['rke2_units'].values()):
        raise ImageError('unjoined RKE2 units must remain masked and stopped')
    if report['cloud_init'].get('status') != 'done':
        raise ImageError('cloud-init did not complete successfully')
    packages = report.get('packages', {})
    if not packages.get('firewalld') or (profile == 'os' and any(packages.get(p) for p in ('rke2-server', 'rke2-agent'))):
        raise ImageError('installed packages differ from image profile')
    required_roles = ('server', 'agent') if profile == 'node' else (profile,)
    if profile != 'os' and (any(not packages.get('rke2-' + role) for role in required_roles) or not packages.get('rke2-selinux')):
        raise ImageError('RKE2 role or SELinux package missing')
    if profile in ('server', 'agent') and packages.get('rke2-' + ('agent' if profile == 'server' else 'server')):
        raise ImageError('image has an incompatible installed role')
    if not smoke and report.get('cluster_state_absent') is not True:
        raise ImageError('unjoined guest contains cluster state')
    addresses = [a['local'] for d in report['addresses'] for a in d.get('addr_info', [])]
    if spec['address'] not in addresses or any(r.get('dst') == 'default' for r in report['routes']):
        raise ImageError('guest network differs or has external default route')
    if any(code == 0 for code in report['pings'].values()):
        raise ImageError('guest can reach host/external probe')
    if smoke and not report.get('smoke'):
        raise ImageError('smoke results missing')


def reboot_report(spec, operator_key, *, smoke=False):
    count = len(reports(spec))
    require_owner(spec)
    virsh('reboot', spec['uuid'])
    report = wait_report(spec, after=count, timeout=1800 if smoke else 300)
    validate_report(spec, report, operator_key, smoke=smoke)
    return report


def check_test_collisions():
    targets = {'192.168.250.' + str(i) for i in range(241, 245)}
    for name in virsh('list', '--all', '--name').split():
        xml = current(name)
        if name.startswith('image-test-'):
            raise ImageError('previous test domain retained; inspect ownership before cleanup')
        # Static lab allocations are not libvirt DHCP leases; inspect known addresses and neighbor cache.
        if any(t in ET.tostring(xml, encoding='unicode') for t in targets):
            raise ImageError('temporary address already allocated')
    neighbors = json.loads(run(['ip', '-j', 'neigh', 'show', 'dev', 'virbr-rke2']))
    if any(n.get('dst') in targets for n in neighbors):
        raise ImageError('temporary address appears in bridge neighbor cache')
    for name in virsh('list', '--name').split():
        raw = virsh('domifaddr', name, '--source', 'agent')
        if any(t in raw for t in targets):
            raise ImageError('temporary address already used by running guest')


def validate_formation(candidate, image, directory, operator_key, owned, output, runner):
    """All guests clone one image; only the common site secret is supplied."""
    secret = secrets.token_hex(32)
    extra = [{'path': '/etc/autonomous-rke2/enrollment-secret', 'content': secret,
              'permissions': '0600', 'owner': 'root:root'},
             {'path': '/etc/autonomous-rke2/test-runner.py', 'content': base64.b64encode(runner).decode(),
              'encoding': 'b64', 'permissions': '0600', 'owner': 'root:root'},
             {'path': '/etc/systemd/system/autonomous-image-validation.service.d/test-runner.conf',
              'owner': 'root:root', 'permissions': '0644',
              'content': '[Service]\nExecStart=\nExecStart=/usr/bin/python3 /etc/autonomous-rke2/test-runner.py report\n'}]
    result = {'same_image_sha256': candidate['profiles']['node']['sha256'], 'nodes': {}}
    specs = []
    cluster = None
    identities = set()
    for index in range(4):
        spec = make_spec('image-test-formation-' + str(index + 1), '192.168.250.' + str(241 + index), 'node', directory)
        spec['interface'] = 'rke2test' + str(index)
        spec['input_sha256'] = candidate['input_sha256']
        spec['diagnostic_path'] = str(output.parent / (spec['name'] + '-diagnostic.json'))
        owned.append(spec)
        specs.append(spec)
        launch(spec, image, operator_key, extra_files=extra, smoke={'formation_smoke': True})
        report = wait_report(spec)
        validate_report(spec, report, operator_key, smoke=True)
        health = report['smoke']['formation']
        expected_role = 'server' if index < 3 else 'agent'
        if health['Role'] != expected_role or health['HostID'] in identities:
            raise ImageError('automatic role or unique identity validation failed')
        identities.add(health['HostID'])
        if cluster is None:
            cluster = health['ClusterID']
        if health['ClusterID'] != cluster:
            raise ImageError('clones formed different clusters')
        result['nodes'][spec['name']] = {'boot': report}
        print('self-forming clone healthy: ' + str(index + 1), flush=True)
    # Reboot every member together: journals must restart known roles, never
    # create a fresh cluster while discovery/services are coming back online.
    counts = {spec['name']: len(reports(spec)) for spec in specs}
    for spec in specs:
        require_owner(spec)
        virsh('reboot', spec['uuid'])
    for spec in specs:
        report = wait_report(spec, after=counts[spec['name']])
        validate_report(spec, report, operator_key, smoke=True)
        before = result['nodes'][spec['name']]['boot']['smoke']['formation']
        after = report['smoke']['formation']
        for field in ('ClusterID', 'HostID', 'Role'):
            if before[field] != after[field]:
                raise ImageError('formation assignment changed across reboot')
        for field in ('NodeUID', 'EtcdClusterID', 'EtcdMemberID'):
            if before['Evidence'][field] != after['Evidence'][field]:
                raise ImageError('cluster/node/etcd identity changed across reboot')
        if after['Role'] == 'server' and after['Evidence']['VotingServers'] != 3:
            raise ImageError('three-server voting membership missing')
        result['nodes'][spec['name']]['reboot'] = report
    first = result['nodes'][specs[0]['name']]['reboot']['smoke']
    if first.get('nodes_ready') != 4 or not first.get('cross_node_service') or not first.get('cross_node_pod'):
        raise ImageError('universal cluster networking validation incomplete')
    result['passed'] = True
    return result


def validation_storage_budget(candidate):
    """Reserve full guest growth on disk, or bounded tmpfs when RAM permits.

    The fallback preserves both host reserves; it never discounts existing lab
    commitments or removes an older generation to make room.
    """
    copies = sum(pin['size'] for pin in candidate['profiles'].values())
    try:
        preflight(extra_disk=129 * GIB + copies, extra_memory_mib=34816)
        return None
    except ImageError as error:
        if not str(error).startswith('insufficient disk'):
            raise
    # Four 32-GiB disks, qcow2 metadata/growth slack, and copied immutable bases.
    memory_bytes = 144 * GIB + copies
    preflight(extra_disk=128 * 1024**2,
              extra_memory_mib=34816 + (memory_bytes + 1024**2 - 1) // 1024**2)
    return memory_bytes


def test_candidate(candidate_path, output):
    if os.geteuid() != 0:
        raise ImageError('libvirt validation requires root')
    candidate = verify_manifest(candidate_path)
    if candidate.get('kind') != 'candidate' or candidate.get('offline_build') is not True:
        raise ImageError('validation requires signed offline candidate')
    if output.exists():
        raise ImageError('validation output already exists')
    isolation()
    check_test_collisions()
    memory_storage = validation_storage_budget(candidate)
    directory = POOL / ('image-test-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o711)
    operator_key = OPERATOR_KEY.read_text().strip()
    owned = []
    results = {'schema': 1, 'candidate_sha256': digest(candidate_path), 'passed': False, 'profiles': {}, 'smoke': {}}
    results['storage'] = {'kind': 'tmpfs' if memory_storage else 'disk', 'byte_limit': memory_storage}
    results['validator_sha256'] = digest(Path(__file__))
    runner = (ROOT / 'lab/packer/guest.py').read_bytes()
    import hashlib
    results['test_runner_sha256'] = hashlib.sha256(runner).hexdigest()
    checkpoint = output.parent / 'validation-progress.json'
    if checkpoint.exists():
        from .artifacts import trust, verify_signature
        fingerprint, keyring = trust()
        verify_signature(checkpoint, keyring, fingerprint)
        previous = json.loads(checkpoint.read_text())
        if previous.get('candidate_sha256') != digest(candidate_path):
            raise ImageError('validation checkpoint belongs to a different candidate')
        results['profiles'] = previous.get('profiles', {})
    def save_progress():
        write_json(checkpoint, results)
        sign(checkpoint)
        os.chmod(checkpoint, 0o644)
    memory_mounted = False
    try:
        if memory_storage:
            run(['mount', '-t', 'tmpfs', '-o', f'size={memory_storage},mode=0711,nodev,nosuid',
                 'autonomous-image-validation', directory])
            memory_mounted = True
        # Bases copied inside traversable libvirt pool. Source candidates never become writable disks.
        bases = {}
        for profile, pin in candidate['profiles'].items():
            path = directory / (profile + '-base.qcow2')
            shutil.copyfile(candidate_path.parent / pin['file'], path)
            if digest(path) != pin['sha256']:
                raise ImageError('copied test base differs from candidate')
            os.chmod(path, 0o444)
            bases[profile] = path
        identities = {'machine_id': set(), 'ssh_fingerprint': set(), 'host_id': set()}
        for index, profile in enumerate(('os', 'node')):
            print('validating offline boot/reboot: ' + profile, flush=True)
            spec = make_spec('image-test-' + profile, '192.168.250.' + str(241 + index), profile, directory)
            spec['input_sha256'] = candidate['input_sha256']
            if profile in results['profiles']:
                previous = results['profiles'][profile]
                spec['host_id'] = previous['boot']['host_id']
                for report in previous.values():
                    validate_report(spec, report, operator_key)
                for field in identities:
                    if previous['boot'][field] in identities[field] or previous['boot'][field] != previous['reboot'][field]:
                        raise ImageError('checkpoint guest identities differ or duplicate')
                    identities[field].add(previous['boot'][field])
                print('reused signed boot/reboot evidence: ' + profile, flush=True)
                continue
            owned.append(spec)
            launch(spec, bases[profile], operator_key)
            first = wait_report(spec, timeout=300)
            validate_report(spec, first, operator_key)
            import hashlib
            expected_rpms = json.loads((candidate_path.parent / (profile + '-inventory.json')).read_text())['rpms']
            if first['rpm_inventory_sha256'] != hashlib.sha256(json.dumps(expected_rpms).encode()).hexdigest():
                raise ImageError('installed RPM inventory differs from signed candidate inventory')
            second = reboot_report(spec, operator_key)
            for field in identities:
                if first[field] in identities[field] or first[field] != second[field]:
                    raise ImageError('guest identities duplicated or changed after reboot')
                identities[field].add(first[field])
            results['profiles'][profile] = {'boot': first, 'reboot': second}
            save_progress()
            discard(spec)
            owned.remove(spec)
        results['formation'] = validate_formation(candidate, bases['node'], directory, operator_key, owned, output, runner)
        isolation()
        results['passed'] = True
    except Exception:
        results['failed_reports'] = {}
        for spec in owned:
            found = reports(spec)
            if found:
                results['failed_reports'][spec['name']] = found[-1]
            if spec.get('diagnostic_path') and not absent(spec['name']):
                from .console import diagnose
                try:
                    write_json(spec['diagnostic_path'], diagnose(spec))
                except Exception as exc:
                    write_json(spec['diagnostic_path'], {'diagnostic_error': type(exc).__name__})
        save_progress()
        raise
    finally:
        # Ownership failures deliberately stop recovery; never remove another generation's domain or files.
        for spec in reversed(owned):
            if not absent(spec['name']):
                discard(spec)
        if memory_mounted:
            run(['umount', directory])
        shutil.rmtree(directory)
    write_json(output, results)
    sign(output)
    os.chmod(output, 0o644)
    print('signed validation: ' + str(output), flush=True)
