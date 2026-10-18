"""Cluster-scoped libvirt names and IPv4 subnet conflict checks."""
from __future__ import annotations

import hashlib
import ipaddress
import itertools
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from lab.packer.artifacts import ImageError

DEFAULT_SUBNET = '192.168.250.0/24'
KUBERNETES_CIDRS = ('10.42.0.0/16', '10.43.0.0/16')
DEFAULT_VM = {'vcpus': 4, 'memory_mib': 8192, 'disk_gib': 60}
# Existing signed node runtime guard in internal/formation/{ledger,kubernetes}.go.
MAX_IMAGE_NODES = 1024


def ipv4_subnet(value):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ImageError(f'invalid subnet {value}: {exc}') from None
    private = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
    if network.version != 4 or not any(network.subnet_of(ipaddress.ip_network(cidr)) for cidr in private):
        raise ImageError('node subnet must be an RFC1918 IPv4 subnet')
    if network.num_addresses < 16:
        raise ImageError('node subnet must provide at least 16 addresses (/28 or larger)')
    return network


class Settings:
    def __init__(self, cluster='lab', *, hostname_prefix=None, network=None, subnet=None,
                 reserved_cidrs=None, vm=None, saved=None):
        if not isinstance(cluster, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,30}[a-z0-9]|[a-z]', cluster):
            raise ImageError('--cluster must be a lowercase DNS label, at most 32 characters')
        self.cluster = cluster
        if saved is not None and not isinstance(saved, dict):
            raise ImageError('invalid saved deployment state; refusing')
        previous = saved.get('configuration') if saved else None
        if previous is not None and (
            not isinstance(previous, dict)
            or any(not isinstance(previous.get(key), str)
                   for key in ('cluster', 'hostname_prefix', 'network', 'subnet'))
            or not isinstance(previous.get('reserved_cidrs'), list)
        ):
            raise ImageError('invalid saved cluster configuration; refusing')
        if saved and previous is None:
            if cluster != 'lab':
                raise ImageError('legacy deployment state belongs to the default lab')
            previous = {'cluster': 'lab', 'hostname_prefix': 'rke2-node',
                        'network': 'autonomous-rke2-isolated', 'subnet': DEFAULT_SUBNET,
                        'reserved_cidrs': []}
        if previous and previous.get('cluster') != cluster:
            raise ImageError('saved cluster identity differs; refusing')
        defaults = {'hostname_prefix': 'rke2-node' if cluster == 'lab' else f'rke2-{cluster}-node',
                    'network': 'autonomous-rke2-isolated' if cluster == 'lab' else f'autonomous-rke2-{cluster}',
                    'subnet': None, 'reserved_cidrs': [], 'vm': dict(DEFAULT_VM)}
        requested = {'hostname_prefix': hostname_prefix, 'network': network,
                     'subnet': str(ipv4_subnet(subnet)) if subnet is not None else None,
                     'reserved_cidrs': list(reserved_cidrs) if reserved_cidrs is not None else None,
                     'vm': vm}
        for key, value in requested.items():
            if previous and value is not None and value != previous.get(key, defaults[key]):
                raise ImageError(f'saved {key} differs; use the original options or destroy this cluster first')
            setattr(self, key, value if value is not None else (previous or defaults).get(key, defaults[key]))
        if not isinstance(self.hostname_prefix, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,60}', self.hostname_prefix):
            raise ImageError('--hostname-prefix must be a lowercase DNS prefix, at most 61 characters')
        if not isinstance(self.network, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}', self.network):
            raise ImageError('--network must be a libvirt network name, at most 63 characters')
        self.subnet = ipv4_subnet(self.subnet) if self.subnet is not None else None
        if not isinstance(self.vm, dict) or set(self.vm) != set(DEFAULT_VM):
            raise ImageError('vm requires vcpus, memory_mib and disk_gib')
        for key, lower, upper in (('vcpus', 2, 256), ('memory_mib', 4096, 1048576), ('disk_gib', 32, 4096)):
            if type(self.vm[key]) is not int or not lower <= self.vm[key] <= upper:
                raise ImageError(f'vm.{key} must be an integer between {lower} and {upper}')
        for value in self.reserved_cidrs:
            try:
                ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise ImageError(f'invalid --reserved-cidr {value}: {exc}') from None
        self.resuming = bool(saved)

    @property
    def pool_name(self):
        return f'autonomous-rke2-{self.cluster}'

    @property
    def pool(self):
        return Path('/var/lib/libvirt/images') / self.pool_name

    @property
    def bridge(self):
        return 'virbr-rke2' if self.cluster == 'lab' else 'br-rke2-' + hashlib.sha256(self.cluster.encode()).hexdigest()[:6]

    @property
    def filter(self):
        return 'autonomous-rke2-ipv4-only' if self.cluster == 'lab' else self.pool_name + '-ipv4-only'

    @property
    def gateway(self):
        return str(self.subnet.network_address + 1)

    def address(self, index):
        if type(index) is not int or index < 0 or index >= self.subnet.num_addresses - 12:
            raise ImageError('node address would exceed usable subnet addresses')
        return str(self.subnet.network_address + 11 + index)

    def validate_nodes(self, count):
        if type(count) is not int or count < 1:
            raise ImageError('nodes must be a positive integer')
        if count > MAX_IMAGE_NODES:
            raise ImageError(f'this image supports at most {MAX_IMAGE_NODES} members in its cluster catalog')
        if len(self.hostname_prefix) + max(2, len(str(count))) > 63:
            raise ImageError('hostname prefix plus node index exceeds 63 characters; shorten the prefix')
        if self.subnet is not None and count > self.subnet.num_addresses - 12:
            raise ImageError(f'{count} nodes do not fit {self.subnet}; capacity is {self.subnet.num_addresses - 12} '
                             'with node addresses starting at subnet +11')

    def document(self):
        if self.subnet is None:
            raise ImageError('select and validate the node subnet before saving deployment settings')
        return {'cluster': self.cluster, 'hostname_prefix': self.hostname_prefix,
                'network': self.network, 'subnet': str(self.subnet),
                'reserved_cidrs': self.reserved_cidrs, 'vm': self.vm}

    def network_xml(self):
        root = ET.Element('network')
        ET.SubElement(root, 'name').text = self.network
        ET.SubElement(root, 'bridge', name=self.bridge, stp='on', delay='0')
        ET.SubElement(root, 'dns', enable='no')
        ET.SubElement(root, 'ip', address=self.gateway, netmask=str(self.subnet.netmask))
        return ET.tostring(root, encoding='unicode')

    def select_subnet(self, inventory, addresses, routes, *, count=1):
        self.validate_nodes(count)
        reserved = []
        def add(value, source):
            try:
                subnet = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ImageError(f'cannot inspect {source}: {exc}') from None
            if subnet.version == 4 and subnet.prefixlen:
                reserved.append((subnet, source))
        for value in KUBERNETES_CIDRS:
            add(value, 'image Kubernetes pod/service range')
        for value in self.reserved_cidrs:
            add(value, '--reserved-cidr')
        for name, xml in inventory['networks'].items():
            if name == self.network and self.resuming:
                continue
            for node in xml.findall('ip'):
                if node.get('family') != 'ipv6' and ':' not in node.get('address', ''):
                    mask = node.get('netmask') or node.get('prefix')
                    if not node.get('address') or mask is None:
                        raise ImageError(f'cannot determine subnet of libvirt network {name}')
                    add(f'{node.get("address")}/{mask}', f'libvirt network {name}')
            for node in xml.findall('route'):
                if node.get('family') != 'ipv6' and ':' not in node.get('address', ''):
                    mask = node.get('netmask') or node.get('prefix')
                    if not node.get('address') or mask is None:
                        raise ImageError(f'cannot determine route subnet of libvirt network {name}')
                    add(f'{node.get("address")}/{mask}', f'libvirt network {name} route')
        for link in addresses:
            if link['ifname'] == self.bridge and self.resuming:
                continue
            for address in link.get('addr_info', []):
                if address.get('family') == 'inet':
                    add(f"{address['local']}/{address['prefixlen']}", f'host interface {link["ifname"]}')
        for route in routes:
            if route.get('dev') == self.bridge and self.resuming:
                continue
            if route.get('dst') and route['dst'] != 'default':
                add(route['dst'], f'host route via {route.get("dev", route.get("gateway", "unknown"))}')

        def conflict(subnet):
            return next(((network, source) for network, source in reserved if subnet.overlaps(network)), None)

        if self.subnet is not None:
            overlap = conflict(self.subnet)
            if overlap:
                raise ImageError(f'subnet {self.subnet} overlaps {overlap[0]} ({overlap[1]})')
            return
        prefix = 32 - max(8, (count + 11).bit_length())
        blocks = [ipaddress.ip_network(cidr) for cidr in
                  ('172.16.0.0/12', '192.168.0.0/16', '10.0.0.0/8')]
        preferred = ([ipaddress.ip_network(DEFAULT_SUBNET).supernet(new_prefix=prefix)]
                     if 16 <= prefix <= 24 else [])
        candidates = itertools.chain(preferred, *(block.subnets(new_prefix=prefix)
                                                 for block in blocks if prefix >= block.prefixlen))
        self.subnet = next((network for network in candidates if not conflict(network)), None)
        if self.subnet is None:
            raise ImageError('no unused private subnet found for this node count; supply a non-conflicting --subnet')
