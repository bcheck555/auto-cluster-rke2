"""Private validation resources; never depend on or reconfigure a user's lab."""
from contextlib import contextmanager
import os
import json
from pathlib import Path
import shutil
import uuid
import xml.etree.ElementTree as ET

from .artifacts import ROOT, ImageError


@contextmanager
def isolated_validation(runtime, operator_directory):
    if os.geteuid() != 0:
        raise ImageError('libvirt validation requires root')
    name = 'autonomous-rke2-image-' + uuid.uuid4().hex[:12]
    pool = Path('/var/lib/libvirt/images') / name
    bridge = 'br-img-' + uuid.uuid4().hex[:8]
    previous = runtime.POOL, runtime.NETWORK, runtime.FILTER, runtime.BRIDGE, runtime.OPERATOR_KEY
    created = []
    pool.mkdir(mode=0o711)
    try:
        filters = {line.split()[-1] for line in runtime.virsh('nwfilter-list').splitlines() if line.split()}
        links = json.loads(runtime.run(['ip', '-j', 'link', 'show']))
        if (name in runtime.virsh('net-list', '--all', '--name').split()
                or name in runtime.virsh('pool-list', '--all', '--name').split()
                or name in filters or any(link['ifname'] == bridge for link in links)):
            raise ImageError('temporary validation resource collision')
        network = ET.Element('network')
        ET.SubElement(network, 'name').text = name
        ET.SubElement(network, 'bridge', name=bridge, stp='on', delay='0')
        ET.SubElement(network, 'dns', enable='no')
        path = pool / 'network.xml'
        path.write_text(ET.tostring(network, encoding='unicode'))
        runtime.virsh('net-define', path)
        created.append('network')
        runtime.virsh('net-start', name)
        runtime.virsh('pool-define-as', name, 'dir', '--target', pool)
        created.append('pool')
        runtime.virsh('pool-start', name)
        filt = ET.parse(ROOT / 'lab/libvirt/ipv4-only.xml').getroot()
        filt.set('name', name)
        path = pool / 'filter.xml'
        path.write_text(ET.tostring(filt, encoding='unicode'))
        runtime.virsh('nwfilter-define', path)
        created.append('filter')
        runtime.POOL, runtime.NETWORK, runtime.FILTER, runtime.BRIDGE = pool, name, name, bridge
        if not runtime.OPERATOR_KEY.is_file():
            key = Path(operator_directory) / 'validation-operator'
            if not key.with_suffix('.pub').exists():
                if key.exists():
                    public = runtime.run(['ssh-keygen', '-y', '-f', key])
                    key.with_suffix('.pub').write_text(public)
                else:
                    runtime.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
            runtime.OPERATOR_KEY = key.with_suffix('.pub')
        yield
    finally:
        # Do not unlink storage if unexpected guests or failed ownership checks
        # left a consumer. Leave only our own resources for manual inspection.
        consumers = []
        for domain in runtime.virsh('list', '--all', '--name').split():
            xml = ET.fromstring(runtime.virsh('dumpxml', domain))
            paths = [n.get('file') for n in xml.findall('devices/disk/source')]
            paths.append(xml.findtext('os/nvram'))
            if (any(n.get('network') == name for n in xml.findall('devices/interface/source'))
                    or any(p and Path(p).resolve().is_relative_to(pool.resolve()) for p in paths)):
                consumers.append(domain)
        runtime.POOL, runtime.NETWORK, runtime.FILTER, runtime.BRIDGE, runtime.OPERATOR_KEY = previous
        if consumers:
            raise ImageError('validation consumers remain; storage preserved: ' + ', '.join(consumers))
        if 'filter' in created:
            runtime.virsh('nwfilter-undefine', name)
        if 'pool' in created:
            if name in runtime.virsh('pool-list', '--name').split():
                runtime.virsh('pool-destroy', name)
            runtime.virsh('pool-undefine', name)
        if 'network' in created:
            if name in runtime.virsh('net-list', '--name').split():
                runtime.virsh('net-destroy', name)
            runtime.virsh('net-undefine', name)
        shutil.rmtree(pool)
