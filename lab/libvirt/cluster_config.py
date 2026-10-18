"""Versioned YAML settings and literal, private per-cluster .env inputs."""
from __future__ import annotations

import ipaddress
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from lab.libvirt.settings import Settings
from lab.packer.artifacts import ImageError


@dataclass(frozen=True)
class ClusterConfig:
    path: Path
    options: dict
    release: Path
    nodes: int
    timeout: int
    control_nodes: int = 3

    @property
    def env_path(self):
        return self.path.with_suffix('.env')

    @property
    def cluster(self):
        return self.options['cluster']


def integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ImageError(f'{name} must be an integer between {minimum} and {maximum}')
    return value


def mapping(value, name, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise ImageError(f'{name}: expected mapping with supported keys: {", ".join(allowed)}')
    return value


def read_yaml(path):
    try:
        import yaml
    except ImportError:
        raise ImageError('YAML configs require PyYAML (the yaml module) in this Python interpreter') from None

    class StrictLoader(yaml.SafeLoader):
        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise ImageError('YAML aliases are unsupported in cluster configs')
            return super().compose_node(parent, index)

    def unique_mapping(loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if not isinstance(key, str) or key in result:
                raise ImageError('cluster config contains duplicate or non-string mapping keys')
            result[key] = loader.construct_object(value_node)
        return result

    StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
    if path.stat().st_size > 65536:
        raise ImageError('cluster config exceeds 64 KiB')
    try:
        return yaml.load(path.read_text(encoding='utf-8'), Loader=StrictLoader)
    except yaml.YAMLError as exc:
        mark = getattr(exc, 'problem_mark', None)
        location = f' at line {mark.line + 1}' if mark else ''
        raise ImageError(f'{path.name}: invalid YAML{location}') from None


def load_config(path, *, check_siblings=True):
    path = Path(path).resolve()
    if path.suffix not in ('.yaml', '.yml'):
        raise ImageError('cluster config filename must end in .yaml or .yml')
    data = mapping(read_yaml(path), path.name,
                   ('schema', 'cluster', 'hostname_prefix', 'release', 'nodes', 'control_nodes',
                    'health_timeout', 'network', 'vm'),
                   ('schema', 'cluster', 'release', 'nodes', 'network'))
    if type(data['schema']) is not int or data['schema'] != 1:
        raise ImageError('cluster config requires schema: 1')
    network = mapping(data['network'], 'network', ('name', 'subnet', 'reserved_cidrs'), ('subnet',))
    if not isinstance(network['subnet'], str):
        raise ImageError('network.subnet must be an explicit private IPv4 CIDR')
    reserved = network.get('reserved_cidrs', [])
    if not isinstance(reserved, list) or any(not isinstance(value, str) for value in reserved):
        raise ImageError('network.reserved_cidrs must be a list of CIDR strings')
    vm = mapping(data.get('vm', {}), 'vm', ('vcpus', 'memory_mib', 'disk_gib'))
    resources = {'vcpus': integer(vm.get('vcpus', 4), 'vm.vcpus', 2, 256),
                 'memory_mib': integer(vm.get('memory_mib', 8192), 'vm.memory_mib', 4096, 1048576),
                 'disk_gib': integer(vm.get('disk_gib', 60), 'vm.disk_gib', 32, 4096)}
    options = dict(cluster=data['cluster'], hostname_prefix=data.get('hostname_prefix'),
                   network=network.get('name'), subnet=network['subnet'],
                   reserved_cidrs=reserved, vm=resources)
    settings = Settings(**options)
    settings.select_subnet({'networks': {}}, [], [], count=data['nodes'])
    timeout = integer(data.get('health_timeout', 1200), 'health_timeout', 1, 86400)
    control_nodes = data.get('control_nodes', 3)
    if type(control_nodes) is not int or control_nodes not in (3, 5, 7):
        raise ImageError('control_nodes must be 3, 5, or 7')
    if not isinstance(data['release'], str) or not data['release'].strip():
        raise ImageError('release must be a nonempty manifest path')
    release = (path.parent / data['release']).resolve()
    config = ClusterConfig(path, options, release, data['nodes'], timeout, control_nodes)
    for source in (config.path, config.env_path):
        if any(parent.parent == Path('/var/lib/libvirt/images')
               and parent.name.startswith('autonomous-rke2-') for parent in source.parents):
            raise ImageError('cluster YAML/.env must be outside generated lab disk directories')
    if check_siblings:
        for other_path in sorted(set(path.parent.glob('*.yaml')) | set(path.parent.glob('*.yml'))):
            if other_path.resolve() == path:
                continue
            other = load_config(other_path, check_siblings=False)
            peer = Settings(**other.options)
            for label, first, second in (
                ('cluster identity', settings.cluster, peer.cluster),
                ('hostname prefix', settings.hostname_prefix, peer.hostname_prefix),
                ('libvirt network', settings.network, peer.network),
                ('bridge', settings.bridge, peer.bridge),
            ):
                if first == second:
                    raise ImageError(f'{path.name} conflicts with {other_path.name}: duplicate {label}')
            if settings.subnet.overlaps(peer.subnet):
                raise ImageError(f'{path.name} node subnet overlaps reservation in {other_path.name}')
            for first, second in ((settings, peer), (peer, settings)):
                if any(first.subnet.overlaps(ipaddress.ip_network(value))
                       for value in second.reserved_cidrs if ipaddress.ip_network(value).version == 4):
                    raise ImageError(f'{path.name} conflicts with reserved CIDRs in {other_path.name}')
    return config


def read_env(path):
    """No shell, expansion, inherited environment, or secret-bearing error messages."""
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise ImageError(f'{path}: missing secrets file; run create.py --config CONFIG --init-secrets') from None
    with os.fdopen(fd, 'r', encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ImageError(f'{path}: secrets file must be regular, root-owned, and mode 0600')
        content = stream.read(16385)
    if len(content) > 16384:
        raise ImageError(f'{path}: secrets file exceeds 16 KiB')
    values = {}
    for number, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if not separator or key != 'ENROLLMENT_SECRET' or key in values:
            raise ImageError(f'{path}: unsupported or duplicate assignment at line {number}')
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        if not re.fullmatch(r'[0-9a-fA-F]{64}', value):
            raise ImageError(f'{path}: ENROLLMENT_SECRET must contain exactly 64 hexadecimal characters')
        values[key] = value
    if set(values) != {'ENROLLMENT_SECRET'}:
        raise ImageError(f'{path}: missing ENROLLMENT_SECRET')
    return values['ENROLLMENT_SECRET'].lower()


def init_env(path, *, enrollment_secret=None):
    """Explicit initialization only. Never overwrite or remove an existing input."""
    path = Path(path)
    if enrollment_secret is not None and not re.fullmatch(r'[0-9a-fA-F]{64}', enrollment_secret):
        raise ImageError('saved ENROLLMENT_SECRET has invalid format; refusing initialization')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write('# Private cluster input. Scripts never overwrite or delete this file.\n'
                     'ENROLLMENT_SECRET=' + (enrollment_secret or secrets.token_hex(32)) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    print(f'Created {path} (root-owned, mode 0600). No lab resources were changed.')
