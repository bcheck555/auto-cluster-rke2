"""Resumable universal-image lab creation and bounded, repeatable teardown."""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from lab.packer.artifacts import (
    GIB, ROOT, ImageError, digest, operation_lock, verify_manifest,
)
from lab.packer.runtime import FILTER, NETWORK, domain_xml, make_spec
from lab.libvirt.settings import Settings
from lab.libvirt.cluster_config import init_env, load_config, read_env
from lab.libvirt.scaling import Scaling, CAPABILITY, control_count, quorum_message

BRIDGE = 'virbr-rke2'
# Historical four-node list for legacy callers; provisioning uses node_names(count).
NAMES = tuple(f'rke2-node{i:02}' for i in range(1, 5))
LEGACY_NAMES = ('rke2-r9-cp01', 'rke2-r9-cp02', 'rke2-r9-cp03', 'rke2-r9-worker01')
DEFAULT_RELEASE = ROOT / 'lab/artifacts/packer/release-scaling-20261018/release.json'
HEALTH = 'sudo /usr/local/libexec/autonomous-rke2/host-agent -health'
KUBECTL = 'sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml'


def command(args, *, timeout=120):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ImageError(f"{args[0]} {args[1]} failed: {(result.stderr or result.stdout).strip()[-2000:]}")
    return result.stdout


def virsh(*args):
    # Ignore caller's default connection; never operate on a remote hypervisor.
    return command(['virsh', '-c', 'qemu:///system', *args])


def write_private(path, content):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        os.chmod(temporary, 0o600)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Lab(Scaling):
    def __init__(self, pool=None, *, cluster='lab', hostname_prefix=None, network=None,
                 subnet=None, reserved_cidrs=None, vm=None, enrollment_secret=None, input_files=()):
        self.options = dict(cluster=cluster, hostname_prefix=hostname_prefix, network=network,
                            subnet=subnet, reserved_cidrs=reserved_cidrs, vm=vm)
        self.settings = Settings(**self.options)
        self.pool = Path(pool) if pool is not None else self.settings.pool
        self.state_path = self.pool / 'universal-lab.json'
        self.enrollment_secret = enrollment_secret
        self.input_files = tuple(Path(path).resolve() for path in input_files)
        self.node_count = 3
        self._owned_names = ()
        self.control_nodes = 3
        self.force_remove = False

    def node_names(self, count):
        return tuple(f'{self.settings.hostname_prefix}{i:02}' for i in range(1, count + 1))

    @property
    def names(self):
        return self.node_names(self.node_count)

    @property
    def legacy_names(self):
        return LEGACY_NAMES if self.settings.cluster == 'lab' else ()

    @property
    def owned_names(self):
        return self._owned_names

    def owns_name(self, name):
        if name in self.legacy_names:
            return True
        prefix = self.settings.hostname_prefix
        suffix = name[len(prefix):] if name.startswith(prefix) else ''
        return bool(suffix.isascii() and suffix.isdigit() and int(suffix) > 0
                    and name == f'{prefix}{int(suffix):02}')

    def inventory(self):
        domains = {name: ET.fromstring(virsh('dumpxml', name))
                   for name in virsh('list', '--all', '--name').split()}
        pools = {name: ET.fromstring(virsh('pool-dumpxml', name))
                 for name in virsh('pool-list', '--all', '--name').split()}
        networks = {name: ET.fromstring(virsh('net-dumpxml', name))
                    for name in virsh('net-list', '--all', '--name').split()}
        filters = {line.split()[1] for line in virsh('nwfilter-list').splitlines()
                   if re.match(r'^\s*[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\s+\S+', line)}
        return {'domains': domains, 'pools': pools, 'networks': networks, 'filters': filters,
                'running': set(virsh('list', '--name').split())}

    def inside(self, path):
        return bool(path) and Path(path).resolve().is_relative_to(self.pool.resolve())

    def check_ownership(self, inventory):
        if self.pool.is_symlink() or self.pool.resolve() != self.pool.absolute():
            raise ImageError('lab disk directory or a parent is a symlink; refusing')
        if self.pool.exists():
            for directory, children, files in os.walk(self.pool, followlinks=False):
                if os.path.ismount(directory) or any(
                    os.path.ismount(Path(directory) / child) for child in children
                ):
                    raise ImageError('mount inside lab disk directory; unmount it before retrying')
                if any(Path(name).suffix in ('.yaml', '.yml', '.env')
                       and Path(directory) / name != self.pool / 'admin.yaml' for name in files):
                    raise ImageError('YAML/.env input found inside generated lab directory; move it outside before cleanup')
        saved = json.loads(self.state_path.read_text()) if self.state_path.exists() else None
        if saved is not None and not isinstance(saved, dict):
            raise ImageError('invalid saved deployment state; refusing')
        for path in (*self.input_files, *((saved or {}).get('input_files', []))):
            if self.inside(path):
                raise ImageError('cluster config/.env is inside generated lab directory; move it outside before cleanup')
        self.settings = Settings(**self.options, saved=saved)
        if saved:
            self.settings.validate_nodes(saved['count'])
            self.node_count = saved['count']
        self._owned_names = tuple(name for name in inventory['domains'] if self.owns_name(name))
        for name, xml in inventory['domains'].items():
            paths = [node.get('file') for node in xml.findall('.//disk//source')]
            paths += [xml.findtext('os/nvram')]
            uses_disks = any(self.inside(path) for path in paths)
            uses_network = any(
                node.get('network') == self.settings.network or node.get('bridge') == self.settings.bridge
                for node in xml.findall('devices/interface/source'))
            uses_filter = any(node.get('filter') == self.settings.filter
                              for node in xml.findall('devices/interface/filterref'))
            if name not in self.owned_names and (uses_disks or uses_network or uses_filter):
                raise ImageError(f'unrelated VM {name} uses lab resources; refusing')
            if name in self.owned_names:
                disks = xml.findall("devices/disk[@device='disk']/source")
                if not disks or any(not self.inside(node.get('file')) for node in disks):
                    raise ImageError(f'{name} has a disk outside lab directory; refusing')
                nvram = xml.findtext('os/nvram')
                if nvram and not self.inside(nvram):
                    raise ImageError(f'{name} has NVRAM outside lab directory; refusing')
        for name, xml in inventory['pools'].items():
            if name == self.settings.pool_name and Path(xml.findtext('target/path', '/')).resolve() != self.pool:
                raise ImageError('named lab pool points outside lab directory; refusing')
        for name, xml in inventory['networks'].items():
            bridge = xml.find('bridge')
            if name == self.settings.network:
                if bridge is None or bridge.get('name') != self.settings.bridge or xml.find('forward') is not None:
                    raise ImageError('named lab network has unexpected bridge/forwarding; refusing')
            elif bridge is not None and bridge.get('name') == self.settings.bridge:
                raise ImageError(f'unrelated network {name} uses lab bridge; refusing')

    def plan(self, inventory):
        print('Connection: qemu:///system')
        print('Cluster: ' + self.settings.cluster)
        first, last = self.node_names(1)[0], f'{self.settings.hostname_prefix}{self.node_count:02}'
        print(f'Hostnames: {first}' + (f' through {last}' if self.node_count > 1 else ''))
        if self.state_path.exists() and json.loads(self.state_path.read_text()).get('schema') == 2:
            print('Surviving node indices remain unchanged; allocations may be sparse.')
        print('VMs: ' + (', '.join(name for name in self.owned_names if name in inventory['domains']) or '(none)'))
        print(f'Disk/settings directory: {self.pool} (exists: {self.pool.exists()})')
        print('Pools: ' + (', '.join(name for name, xml in inventory['pools'].items()
                                  if self.inside(xml.findtext('target/path'))) or '(none)'))
        print(f'Network: {self.settings.network} (defined: {self.settings.network in inventory["networks"]})')
        print(f'Filter: {self.settings.filter}; bridge: {self.settings.bridge}; subnet: {self.settings.subnet or "auto"}')

    def destroy(self, inventory):
        self.check_ownership(inventory)
        self.plan(inventory)
        errors = []

        def attempt(label, operation):
            try:
                operation()
            except (ImageError, OSError, subprocess.SubprocessError) as exc:
                errors.append(f'{label}: {exc}')

        # Never remove disks until every member is stopped and undefined.
        for name in self.owned_names:
            if name in inventory['running']:
                attempt(name, lambda name=name: virsh('destroy', name))
        if errors:
            raise ImageError('Stop failed; disks retained. Retry destroy.\n' + '\n'.join(errors))
        remaining = set(virsh('list', '--all', '--name').split())
        for name in self.owned_names:
            if name in remaining:
                flags = ['--managed-save', '--snapshots-metadata', '--checkpoints-metadata']
                xml = inventory['domains'][name]
                if xml.find('os/nvram') is not None:
                    flags.append('--nvram')
                if xml.find('devices/tpm') is not None:
                    flags.append('--tpm')
                attempt(name, lambda name=name, flags=flags: virsh('undefine', name, *flags))
        if errors:
            raise ImageError('Undefine failed; disks retained. Retry destroy.\n' + '\n'.join(errors))
        refreshed = self.inventory()
        self.check_ownership(refreshed)
        if any(name in refreshed['domains'] for name in self.owned_names):
            raise ImageError('a lab VM still exists; files retained; retry destroy')

        def remove_definition(kind, name):
            if name in virsh(kind + '-list', '--name').split():
                virsh(kind + '-destroy', name)
            if name in virsh(kind + '-list', '--all', '--name').split():
                virsh(kind + '-undefine', name)

        if self.settings.network in inventory['networks']:
            attempt(self.settings.network, lambda: remove_definition('net', self.settings.network))
        for name, xml in inventory['pools'].items():
            if self.inside(xml.findtext('target/path')):
                attempt(name, lambda name=name: remove_definition('pool', name))
        if self.settings.filter in inventory['filters']:
            attempt(self.settings.filter, lambda: virsh('nwfilter-undefine', self.settings.filter))
        if errors:
            raise ImageError('Settings cleanup incomplete; files retained. Retry destroy.\n' + '\n'.join(errors))
        # An interrupted previous cleanup can leave a bridge without a network definition.
        links = json.loads(command(['ip', '-j', 'link', 'show']))
        if any(link['ifname'] == self.settings.bridge for link in links):
            ports = json.loads(command(['ip', '-j', 'link', 'show', 'master', self.settings.bridge]))
            if ports:
                raise ImageError('lab bridge still has ports; files retained; inspect before retrying')
            command(['ip', 'link', 'delete', 'dev', self.settings.bridge, 'type', 'bridge'])
        if self.pool.exists():
            shutil.rmtree(self.pool)
        print('Lab destroyed, including disks, NVRAM, seeds, keys, kubeconfig and settings.')

    def save(self, state):
        write_private(self.state_path, json.dumps(state, indent=2) + '\n')

    def deployment_names(self, count):
        if not self.state_path.exists():
            return self.node_names(count)
        state = json.loads(self.state_path.read_text())
        if state.get('count') != count and state.get('schema') != 2:
            raise ImageError('existing image cannot resize: rebuild once with a scaling-capable release; different release/node count')
        names = tuple(node['name'] for node in state['nodes'])
        if state.get('schema') == 2:
            if (len(names) != state['count'] or len(set(names)) != len(names)
                    or any(not self.owns_name(name) for name in names)):
                raise ImageError('invalid saved node list; refusing')
            return names
        if len(names) != count or names not in (self.node_names(count), self.legacy_names[:count]):
            raise ImageError('invalid saved node list; refusing')
        return names

    def load_or_initialize(self, release, release_hash, count, inventory):
        self.settings.validate_nodes(count)
        self.node_count = count
        if self.state_path.exists():
            state = json.loads(self.state_path.read_text())
            if (state.get('schema') not in (1, 2) or state.get('release_sha256') != release_hash
                    or (state.get('schema') == 1 and state.get('count') != count)):
                raise ImageError('existing deployment uses a different release/node count; destroy it first')
            if self.enrollment_secret is not None and not hmac.compare_digest(state['secret'], self.enrollment_secret):
                raise ImageError('ENROLLMENT_SECRET differs from saved deployment; restore it or recreate the cluster')
            self.deployment_names(count)
            for index, spec in enumerate(state['nodes']):
                if state.get('schema') == 2:
                    if type(spec['index']) is not int:
                        raise ImageError('invalid saved sparse node index')
                    index = spec['index'] - 1
                    if (type(index) is not int or index < 0
                            or spec['name'] != f'{self.settings.hostname_prefix}{index + 1:02}'):
                        raise ImageError('invalid saved sparse node index')
                for key, suffix in (('disk', '.qcow2'), ('nvram', '.vars.fd'),
                                    ('seed', '.iso'), ('serial', '.serial.log')):
                    if Path(spec[key]) != self.pool / (spec['name'] + suffix):
                        raise ImageError('invalid saved node path; refusing')
                if (spec['address'] != self.settings.address(index)
                        or spec.get('network', self.settings.network) != self.settings.network
                        or spec.get('filter', self.settings.filter) != self.settings.filter):
                    raise ImageError('saved node network settings differ; refusing')
            print('Resuming existing deployment; retaining disks, identities and enrollment secret.')
        else:
            if any(name in inventory['domains'] for name in self.owned_names) or (
                self.pool.exists() and any(self.pool.iterdir())
            ):
                raise ImageError('old/partial unmanaged lab remains; run destroy.py first')
            import secrets
            self.pool.mkdir(parents=True, mode=0o711, exist_ok=True)
            os.chmod(self.pool, 0o711)
            names = self.node_names(count)
            state = {'schema': 1, 'release': str(release), 'release_sha256': release_hash,
                     'configuration': self.settings.document(),
                     'count': count, 'secret': self.enrollment_secret or secrets.token_hex(32), 'nodes': [
                         {**make_spec(names[i], self.settings.address(i), 'node', self.pool),
                          'network': self.settings.network, 'filter': self.settings.filter,
                          **self.settings.vm, 'boot_requested': False} for i in range(count)]}
            self.save(state)
        if self.input_files:
            state['input_files'] = list(map(str, self.input_files))
            self.save(state)
        for name, xml in inventory['domains'].items():
            if name in self.owned_names:
                spec = next((node for node in state['nodes'] if node['name'] == name), None)
                if not spec or xml.findtext('uuid') != spec['uuid']:
                    raise ImageError(f'{name} is not from saved deployment; refusing')
                disks = xml.findall("devices/disk[@device='disk']/source")
                mac = xml.find('devices/interface/mac')
                source = xml.find('devices/interface/source')
                if (len(disks) != 1 or disks[0].get('file') != spec['disk']
                        or xml.findtext('os/nvram') != spec['nvram']
                        or mac is None or mac.get('address') != spec['mac']
                        or source is None or source.get('network') != self.settings.network):
                    raise ImageError(f'{name} disk/NVRAM/NIC binding changed; refusing')
        return state

    def check_capacity(self, count, inventory):
        if self.state_path.exists():
            names = self.deployment_names(count)
            new_disks = sum(not (self.pool / (name + '.qcow2')).exists() for name in names)
            starting = sum(name not in inventory['running'] for name in names)
        else:
            new_disks = starting = count
        parent = self.pool if self.pool.exists() else self.pool.parent
        disk_gib = self.settings.vm['disk_gib']
        memory_mib = self.settings.vm['memory_mib']
        if shutil.disk_usage(parent).free < (disk_gib * new_disks + 8) * GIB:
            raise ImageError(f'insufficient disk space: reserve {disk_gib} GiB per new disk plus 8 GiB')
        available = next(int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                         if line.startswith('MemAvailable:'))
        if available < (memory_mib * starting + 8192) * 1024**2:
            raise ImageError(f'insufficient available RAM: {memory_mib} MiB per stopped/new VM plus 8 GiB host reserve')

    def check_networks(self, inventory):
        if not self.settings.resuming:
            for kind, name in (('networks', self.settings.network), ('pools', self.settings.pool_name),
                               ('filters', self.settings.filter)):
                if name in inventory[kind]:
                    raise ImageError(f'{kind}: {name} already exists without this deployment state; '
                                     'choose another cluster/network or destroy the old lab first')
            links = json.loads(command(['ip', '-j', 'link', 'show']))
            if any(link['ifname'] == self.settings.bridge for link in links):
                raise ImageError('target bridge already exists without deployment state; refusing')
        self.settings.select_subnet(
            inventory, json.loads(command(['ip', '-j', '-4', 'address', 'show'])),
            json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])), count=self.node_count)
        print(f'Network {self.settings.network}: {self.settings.subnet}; host {self.settings.gateway}', flush=True)

    def ensure_settings(self, inventory):
        network_path = self.pool / 'network.xml'
        write_private(network_path, self.settings.network_xml())
        if self.settings.network not in inventory['networks']:
            virsh('net-define', network_path)
        else:
            xml = inventory['networks'][self.settings.network]
            addresses = [node.get('address') for node in xml.findall('ip')]
            masks = [node.get('netmask') for node in xml.findall('ip')]
            if addresses != [self.settings.gateway] or masks != [str(self.settings.subnet.netmask)]:
                raise ImageError('existing network lacks expected host management address; destroy lab first')
        if self.settings.network not in virsh('net-list', '--name').split():
            virsh('net-start', self.settings.network)
        virsh('net-autostart', self.settings.network)
        if self.settings.pool_name not in inventory['pools']:
            virsh('pool-define-as', self.settings.pool_name, 'dir', '--target', self.pool)
        if self.settings.pool_name not in virsh('pool-list', '--name').split():
            virsh('pool-start', self.settings.pool_name)
        virsh('pool-autostart', self.settings.pool_name)
        if self.settings.filter not in inventory['filters']:
            filter_xml = ET.parse(ROOT / 'lab/libvirt/ipv4-only.xml').getroot()
            filter_xml.set('name', self.settings.filter)
            filter_path = self.pool / 'filter.xml'
            write_private(filter_path, ET.tostring(filter_xml, encoding='unicode'))
            virsh('nwfilter-define', filter_path)
        else:
            filt = ET.fromstring(virsh('nwfilter-dumpxml', self.settings.filter))
            rules = filt.findall('rule')
            if len(rules) != 1 or rules[0].get('action') != 'drop' or rules[0].get('direction') != 'inout' or not any(
                node.get('protocolid') in ('0x86dd', 'ipv6') for node in rules[0].findall('mac')
            ):
                raise ImageError('existing lab filter differs from IPv6-only drop policy; destroy lab first')

    def prepare_node(self, spec, state, image):
        name = spec['name']
        disk = Path(spec['disk'])
        seed_iso = Path(spec['seed'])
        nvram = Path(spec['nvram'])
        # Never repair missing boot artifacts by replacing an initialized node's disk.
        if spec['boot_requested'] and not all(path.is_file() for path in (disk, seed_iso, nvram)):
            raise ImageError(f'{name}: booted node has missing disk/seed/NVRAM; restore files or destroy lab')
        if not disk.exists():
            temporary = disk.with_suffix('.qcow2.tmp')
            command(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'qcow2', image, temporary], timeout=1800)
            command(['qemu-img', 'resize', temporary, str(spec['disk_gib']) + 'G'])
            os.chmod(temporary, 0o600)
            temporary.replace(disk)
        # Read metadata while an existing VM holds its normal writer lock.
        # --force-share is read-only here; resize/convert never touch this disk.
        info = json.loads(command(['qemu-img', 'info', '--force-share', '--output=json', disk]))
        if info.get('format') != 'qcow2' or info.get('backing-filename') or info.get('virtual-size') != spec['disk_gib'] * GIB:
            raise ImageError(f'{name}: expected standalone {spec["disk_gib"]} GiB QCOW2 disk; refusing to modify it')
        if not nvram.exists():
            temporary = nvram.with_suffix('.fd.tmp')
            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', temporary)
            os.chmod(temporary, 0o600)
            temporary.replace(nvram)
        if not seed_iso.exists():
            seed = self.pool / (name + '-seed')
            seed.mkdir(mode=0o700, exist_ok=True)
            key = (self.pool / 'operator.pub').read_text().strip()
            userdata = {
                'hostname': name, 'preserve_hostname': False, 'ssh_deletekeys': True,
                'disable_root': True, 'ssh_pwauth': False,
                'package_update': False, 'package_upgrade': False,
                'users': [{'name': 'rke2lab', 'shell': '/bin/bash', 'lock_passwd': True,
                           'sudo': ['ALL=(ALL) NOPASSWD: ALL'], 'ssh_authorized_keys': [key]}],
                'write_files': [{'path': '/etc/autonomous-rke2/enrollment-secret',
                                 'owner': 'root:root', 'permissions': '0600', 'content': state['secret']},
                                {'path': '/var/lib/autonomous-rke2/host-id',
                                 'owner': 'root:root', 'permissions': '0600', 'content': spec['host_id'] + '\n'}],
                'runcmd': [['systemctl', 'enable', '--now', 'qemu-guest-agent'],
                          ['systemctl', 'restart', '--no-block', 'autonomous-rke2-host-agent.service']]}
            network = {'version': 2, 'ethernets': {'rke2lab0': {
                'match': {'macaddress': spec['mac']}, 'set-name': 'rke2lab0',
                'dhcp4': False, 'dhcp6': False, 'accept-ra': False,
                'addresses': [spec['address'] + f'/{self.settings.subnet.prefixlen}'],
                'routes': [{'to': '10.43.0.0/16', 'via': '0.0.0.0'}]}}}
            write_private(seed / 'user-data', '#cloud-config\n' + json.dumps(userdata))
            write_private(seed / 'meta-data', json.dumps({
                'instance-id': spec['instance_id'], 'local-hostname': name}))
            write_private(seed / 'network-config', json.dumps(network))
            temporary = seed_iso.with_suffix('.iso.tmp')
            temporary.touch(mode=0o600, exist_ok=True)
            os.chmod(temporary, 0o600)
            command(['genisoimage', '-quiet', '-output', temporary, '-volid', 'cidata', '-joliet', '-rock',
                     *(seed / item for item in ('user-data', 'meta-data', 'network-config'))])
            os.chmod(temporary, 0o600)
            temporary.replace(seed_iso)
        xml_path = self.pool / (name + '.xml')
        write_private(xml_path, domain_xml(spec))
        if name not in virsh('list', '--all', '--name').split():
            virsh('define', xml_path)

    def ssh(self, address, remote, *, timeout=30):
        return command(['ssh', '-i', self.pool / 'operator', '-o', 'IdentitiesOnly=yes',
                        '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                        '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
                        '-o', 'StrictHostKeyChecking=accept-new',
                        '-o', f'UserKnownHostsFile={self.pool / "known_hosts"}',
                        f'rke2lab@{address}', remote], timeout=timeout)

    def wait_healthy(self, spec, timeout):
        print(f'Waiting for {spec["name"]} ({spec["address"]}) health...', flush=True)
        deadline = time.monotonic() + timeout
        last_error = ''
        while time.monotonic() < deadline:
            try:
                self.ssh(spec['address'], HEALTH)
                print(f'{spec["name"]}: healthy', flush=True)
                return
            except (ImageError, subprocess.SubprocessError) as exc:
                last_error = str(exc)
                time.sleep(min(10, max(0, deadline - time.monotonic())))
        raise ImageError(f'{spec["name"]}: timed out waiting for health. {last_error}\n'
                         f'Rerun create to resume, or inspect with:\n'
                         f'sudo ssh -i {self.pool}/operator -o UserKnownHostsFile={self.pool}/known_hosts '
                         f'rke2lab@{spec["address"]} '
                         '"sudo journalctl -u autonomous-rke2-host-agent.service -n 100 --no-pager"')

    def boot(self, spec, state):
        if state.get('schema') == 2 and not self.owned_vm(spec):
            raise ImageError('prepared VM definition is missing; refusing boot')
        if not spec['boot_requested']:
            spec['boot_requested'] = True
            self.save(state)  # Record intent before boot, including crash windows.
        if spec['name'] not in virsh('list', '--name').split():
            print('Starting ' + spec['name'], flush=True)
            virsh('start', spec['name'])

    def create(self, release, count, timeout, inventory):
        self.node_count = count
        self.check_ownership(inventory)
        self.settings.validate_nodes(count)
        self.node_count = count
        print('Verifying signed universal release...', flush=True)
        manifest = verify_manifest(release)
        if manifest.get('kind') != 'release' or 'node' not in manifest.get('profiles', {}) or 'node.qcow2' not in manifest['files']:
            raise ImageError('a signed universal node release is required')
        self.check_networks(inventory)
        if CAPABILITY in manifest.get('capabilities', []):
            return self.create_scaling(release, manifest, count, timeout, inventory)
        if self.control_nodes != 3:
            raise ImageError('control_nodes requires a scaling-capable image; rebuild once with the new release')
        self.check_capacity(count, inventory)
        state = self.load_or_initialize(release, digest(release), count, inventory)
        self.ensure_settings(inventory)
        key = self.pool / 'operator'
        if not key.exists():
            if any(node['boot_requested'] for node in state['nodes']):
                raise ImageError('operator key is missing for booted nodes; restore it or destroy lab')
            # A prior interrupted keygen may have left only a public key.
            key.with_suffix('.pub').unlink(missing_ok=True)
            command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
        if not key.with_suffix('.pub').exists():
            write_private(key.with_suffix('.pub'), command(['ssh-keygen', '-y', '-f', key]))
        for spec in state['nodes']:
            print('Preparing ' + spec['name'], flush=True)
            self.prepare_node(spec, state, Path(release).parent / 'node.qcow2')
        # On resume/reboot all previously booted voters may be needed for quorum.
        previous = [node for node in state['nodes'] if node['boot_requested']]
        for spec in previous:
            self.boot(spec, state)
        for spec in previous:
            self.wait_healthy(spec, timeout)
        for spec in state['nodes']:
            if not spec['boot_requested']:
                self.boot(spec, state)
                self.wait_healthy(spec, timeout)
        address = state['nodes'][0]['address']
        self.ssh(address, KUBECTL + ' wait --for=condition=Ready node --all --timeout=300s', timeout=320)
        print(self.ssh(address, KUBECTL + ' get nodes -o wide'), end='')
        print(self.ssh(address, KUBECTL + ' get pods -A'), end='')
        config = self.ssh(address, 'sudo cat /etc/rancher/rke2/rke2.yaml')
        write_private(self.pool / 'admin.yaml', config.replace('127.0.0.1', address))
        state['complete'] = True
        self.save(state)
        print(f'Cluster ready. Kubeconfig: {self.pool}/admin.yaml')


def main(operation, argv=None):
    parser = argparse.ArgumentParser(description=(
        'Create/resume the universal-image lab on local qemu:///system.' if operation == 'create'
        else 'Permanently delete the local lab, including disks and settings. Safe to retry.'))
    parser.add_argument('--plan', action='store_true', help='inspect ownership and print targets without changes')
    parser.add_argument('--config', type=Path, help='cluster YAML; reads the paired <basename>.env on create')
    parser.add_argument('--cluster', help='cluster identity; scopes disks and all libvirt resources (default: lab)')
    parser.add_argument('--hostname-prefix', help='base hostname, e.g. dev-node produces dev-node01; saved on first create')
    parser.add_argument('--network', help='name of the isolated libvirt network to create; saved on first create')
    parser.add_argument('--subnet', help='private IPv4 node subnet; otherwise choose an unused subnet sized for the node count')
    parser.add_argument('--reserved-cidr', action='append', help='additional Kubernetes/VPN/network range to avoid; repeatable')
    if operation == 'create':
        parser.add_argument('--release', type=Path, help='signed release.json')
        parser.add_argument('--nodes', type=int, help='desired positive total node count (default: 3)')
        parser.add_argument('--control-nodes', type=int, choices=(3, 5, 7), help='desired control target (default: 3)')
        parser.add_argument('--force-remove', action='store_true', help='override drain workload protections; never bypass ownership/quorum')
        parser.add_argument('--timeout', type=int, help='health wait seconds per node (default: 1200)')
        parser.add_argument('--init-secrets', action='store_true', help='create missing paired .env only; never overwrite it or create VMs')
    else:
        parser.add_argument('--confirm-cluster', help='must match --cluster for actual deletion')
        parser.add_argument('--confirm-lab', help='legacy confirmation: must match the selected storage pool name')
    args = parser.parse_args(argv)
    try:
        config = None
        if args.config:
            overrides = (args.cluster, args.hostname_prefix, args.network, args.subnet, args.reserved_cidr)
            if operation == 'create':
                overrides += (args.release, args.nodes, args.control_nodes)
            if any(value is not None for value in overrides):
                raise ImageError('--config cannot be combined with deployment overrides; edit the YAML instead')
            config = load_config(args.config, check_siblings=operation == 'create')
            options = config.options
            args.cluster = config.cluster
            if operation == 'create':
                args.release, args.nodes = config.release, config.nodes
                args.control_nodes = config.control_nodes
                args.timeout = args.timeout if args.timeout is not None else config.timeout
        else:
            args.cluster = args.cluster or 'lab'
            options = dict(cluster=args.cluster, hostname_prefix=args.hostname_prefix,
                           network=args.network, subnet=args.subnet, reserved_cidrs=args.reserved_cidr)
            if operation == 'create':
                args.release = args.release or DEFAULT_RELEASE
                args.nodes = args.nodes if args.nodes is not None else 3
                args.control_nodes = args.control_nodes if args.control_nodes is not None else 3
                args.timeout = args.timeout if args.timeout is not None else 1200
        lab = Lab(**options, input_files=(config.path, config.env_path) if config else ())
        if operation == 'create':
            lab.control_nodes = control_count(args.control_nodes)
            lab.force_remove = args.force_remove
            lab.settings.validate_nodes(args.nodes)
            lab.node_count = args.nodes
        if config and operation == 'destroy' and lab.state_path.exists():
            # YAML may describe the desired replacement. Clean up the saved deployment.
            lab.options = dict(cluster=args.cluster)
        if not args.plan and os.geteuid() != 0:
            raise ImageError('run this script using sudo python3; no interactive root shell is needed')
        if (operation == 'destroy' and not args.plan
                and args.confirm_cluster != args.cluster and args.confirm_lab != lab.settings.pool_name):
            raise ImageError(f'deletion requires --confirm-cluster {args.cluster}')
        if operation == 'create' and args.timeout <= 0:
            raise ImageError('--timeout must be positive')
        if operation == 'create' and args.init_secrets:
            if config is None or args.plan:
                raise ImageError('--init-secrets requires --config and cannot be combined with --plan')
            existing_secret = None
            if lab.state_path.exists():
                saved = json.loads(lab.state_path.read_text())
                Settings(**lab.options, saved=saved)
                existing_secret = saved['secret']
            init_env(config.env_path, enrollment_secret=existing_secret)
            return 0
        if config and operation == 'create' and not args.plan:
            lab.enrollment_secret = read_env(config.env_path)
        required = ['virsh', 'ip']
        if operation == 'create' and not args.plan:
            required += ['qemu-img', 'qemu-system-x86_64', 'genisoimage', 'ssh', 'ssh-keygen', 'gpgv']
            for firmware in ('OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd'):
                if not (Path('/usr/share/OVMF') / firmware).is_file():
                    raise ImageError('missing UEFI firmware: ' + firmware)
        for tool in required:
            if not shutil.which(tool):
                raise ImageError('required command missing: ' + tool)
        if args.plan:
            if config:
                print(f'Config: {config.path}; private inputs: {config.env_path}')
            inventory = lab.inventory()
            lab.check_ownership(inventory)
            if operation == 'create':
                if lab.state_path.exists():
                    lab.deployment_names(args.nodes)
                    saved = json.loads(lab.state_path.read_text())
                    if saved.get('schema') == 2:
                        if digest(args.release.resolve()) != saved['release_sha256']:
                            raise ImageError('release differs; recreate the cluster')
                        lab.describe_scaling(saved, args.nodes, args.control_nodes)
                    elif args.control_nodes != 3:
                        raise ImageError('control_nodes requires a scaling-capable image; rebuild once')
                print(quorum_message(args.nodes, args.control_nodes))
                lab.node_count = args.nodes
                lab.check_networks(inventory)
            lab.plan(inventory)
            if operation == 'create':
                print(f'Create/resume: {args.nodes} nodes using {args.release.resolve()}')
            return 0
        with operation_lock():
            inventory = lab.inventory()
            if operation == 'create':
                lab.create(args.release.resolve(), args.nodes, args.timeout, inventory)
            else:
                lab.destroy(inventory)
        return 0
    except (ImageError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, ET.ParseError) as exc:
        print(f'{operation}: {exc}', file=sys.stderr)
        print('No shell settings were changed. Resolve the error, then rerun this script.', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f'\n{operation}: interrupted; rerun to continue.', file=sys.stderr)
        return 130
