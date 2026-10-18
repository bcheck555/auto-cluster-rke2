"""Owned test-guest diagnostics over serial; temporary password always re-locked."""
import base64
import hashlib
import json
import secrets
import shlex
import time
import zlib


def diagnose(spec, test_service_route=False):
    from .runtime import require_owner, virsh
    import pexpect
    require_owner(spec)
    if not spec['name'].startswith('image-test-'):
        raise ValueError('diagnostics restricted to owned disposable guests')
    def password(value, crypted):
        require_owner(spec)
        virsh('qemu-agent-command', spec['uuid'], json.dumps({'execute': 'guest-set-user-password', 'arguments': {
            'username': 'rke2lab', 'password': base64.b64encode(value.encode()).decode(), 'crypted': crypted}}))
    child = None
    try:
        temporary = secrets.token_urlsafe(32)
        password(temporary, False)
        child = pexpect.spawn('virsh', ['-c', 'qemu:///system', 'console', spec['uuid'], '--safe'], encoding='utf-8', timeout=40)
        child.expect('Escape character')
        child.send('\r')
        selected = child.expect(['login: ', r'\$ '])
        if selected == 0:
            child.send(spec.get('operator', 'rke2lab') + '\r')
            child.expect('Password:')
            child.send(temporary + '\r')
            child.expect(r'\$ ')
        password('!', True)
        source = '''import json,subprocess,base64,pathlib,time,zlib,tempfile,os
def run(args):
 try:
  p=subprocess.run(args,capture_output=True,text=True,timeout=20);return p.stdout[-24000:]+p.stderr[-2000:]
 except subprocess.TimeoutExpired:return 'diagnostic command timed out'
data={'units':run(['systemctl','show','rke2-server','rke2-agent','autonomous-rke2-host-agent','autonomous-image-validation','-p','ActiveState','-p','SubState','-p','Result']),
 'journal':run(['journalctl','-b','--no-pager','-n','120','-u','rke2-server','-u','rke2-agent','-u','autonomous-rke2-host-agent','-u','autonomous-image-validation']),
 'error':pathlib.Path('/var/tmp/image-validation-error.txt').read_text() if pathlib.Path('/var/tmp/image-validation-error.txt').exists() else '',
 'network':run(['ip','-j','route','show','table','all']),
 'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
data['prerequisites']={
 'os':run(['cat','/usr/lib/os-release']),
 'selinux':run(['getenforce']),
 'rpms':run(['rpm','-q','rke2-server','rke2-agent','rke2-selinux']),
 'version':run(['/usr/bin/rke2','--version']),
 'firewall':run(['systemctl','show','firewalld','-p','ActiveState','-p','UnitFileState']),
 'network_manager':run(['cat','/etc/NetworkManager/conf.d/rke2-flannel.conf']),
 'unit_files':run(['systemctl','is-enabled','rke2-server','rke2-agent'])}
data['agent_journal']=run(['journalctl','-b','--no-pager','-n','30','-u','autonomous-rke2-host-agent'])
data['formation_journals']={str(p):p.read_text() for p in pathlib.Path('/var/lib/autonomous-rke2/formation').glob('operation-*.json') if p.is_file() and p.stat().st_size<65536}
data['runtime_files']={}
for name in ('/usr/lib/os-release','/etc/rancher/rke2/config.yaml','/etc/rancher/rke2/registries.yaml',
             '/opt/autonomous-rke2/offline/coredns-config.yaml',
             '/var/lib/rancher/rke2/server/manifests/rke2-flannel-config.yaml'):
 p=pathlib.Path(name)
 try:
  st=p.lstat();data['runtime_files'][name]={'mode':oct(st.st_mode),'uid':st.st_uid,'links':st.st_nlink,'size':st.st_size}
 except FileNotFoundError:data['runtime_files'][name]=None
data['environment_lines']={}
for name in ('/etc/default/rke2-server','/etc/sysconfig/rke2-server'):
 p=pathlib.Path(name)
 if p.is_file():data['environment_lines'][name]=[line.split('=',1)[0] for line in p.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#') and line.strip() not in ('HOME=/root','RKE2_SELINUX=true','RKE2_SELINUX="true"')]
data['runtime_enablement']=[str(p) for root in ('/etc/systemd/system','/run/systemd/system') for pattern in ('*.wants/rke2-*.service','*.requires/rke2-*.service') for p in pathlib.Path(root).glob(pattern)]
report=pathlib.Path('/var/tmp/image-boot-report.json')
if report.exists():data['boot_report']=json.loads(report.read_text())
data['processes']=run(['ps','-eo','pid,etime,args'])
containerlog=pathlib.Path('/var/lib/rancher/rke2/agent/containerd/containerd.log')
if containerlog.exists():data['containerd_log']=run(['tail','-n','60',str(containerlog)])
etcdlogs=list(pathlib.Path('/var/log/pods').glob('kube-system_etcd-*/*/*.log'))
if etcdlogs:data['etcd_log']=run(['tail','-n','40',str(max(etcdlogs,key=lambda p:p.stat().st_mtime))])
flannellogs=list(pathlib.Path('/var/log/pods').glob('kube-system_kube-flannel-ds-*/*/*.log'))
if flannellogs:data['flannel_local_log']=run(['tail','-n','25',str(max(flannellogs,key=lambda p:p.stat().st_mtime))])
kubectl=pathlib.Path('/var/lib/rancher/rke2/bin/kubectl')
if kubectl.exists() and pathlib.Path('/etc/rancher/rke2/rke2.yaml').exists():
 args=[str(kubectl),'--kubeconfig=/etc/rancher/rke2/rke2.yaml','--request-timeout=5s']
 data['nodes']=run(args+['get','nodes','-o','wide'])
 data['pods']=run(args+['get','pods','-A','-o','wide'])
 data['events']=run(args+['get','events','-A','--sort-by=.metadata.creationTimestamp'])[-12000:]
 data['flannel']=run(args+['-n','kube-system','logs','-l','app=flannel','--all-containers=true','--tail=25'])
 try:
  service=json.loads(run(args+['-n','image-validation','get','service','http','-o','json']))
  pod=json.loads(run(args+['-n','image-validation','get','pod','http','-o','json']))
  data['http_service_ip']=service['spec']['clusterIP']
  data['http_pod_ip']=pod['status']['podIP']
  for kind,address in [('service',data['http_service_ip']),('pod',data['http_pod_ip'])]:
   probe="printf 'GET / HTTP/1.0\\r\\n\\r\\n' | timeout 12 nc -w 5 "+address+' 8080'
   data['http_'+kind+'_probe']=run(args+['-n','image-validation','exec','client','--','sh','-c',probe])
  data['dns_http']=run(args+['-n','image-validation','exec','client','--','nslookup','-type=A','http.image-validation.svc.cluster.local.'])
 except Exception as exc:data['probe_error']=type(exc).__name__
text=json.dumps(data)
for name in ('/etc/autonomous-rke2/test-token','/etc/autonomous-rke2/enrollment-secret',
             '/var/lib/autonomous-rke2/credentials/rke2-token','/var/lib/autonomous-rke2/credentials/agent-token',
             '/var/lib/rancher/rke2/server/token','/var/lib/rancher/rke2/server/agent-token'):
 token=pathlib.Path(name)
 if token.is_file() and token.stat().st_size<=4096:
  value=token.read_text().strip()
  for secret in (value,value.rsplit(':',1)[-1]):
   if len(secret)>=32:text=text.replace(secret,'[REDACTED]')
payload=zlib.compress(text.encode())
fd,name=tempfile.mkstemp(prefix='autonomous-image-diagnostic-',dir='/var/tmp')
with os.fdopen(fd,'wb') as output:output.write(payload)
print('IMAGE_DIAGNOSTIC_FILE='+name+':'+str(len(payload)),flush=True)
'''
        if test_service_route:
            repair = '''import json,pathlib,subprocess,time
root=pathlib.Path('/etc/autonomous-rke2')
instance=json.loads((root/'instance.json').read_text())
grant=json.loads((root/'test-grant.json').read_text())
assert instance.get('smoke') and grant['purpose']=='offline-image-smoke' and time.time()<grant['expires']
assert instance['host_id'] in grant['hosts']
subprocess.run(['ip','route','replace','10.43.0.0/16','dev','rke2lab0'],check=True)
kubectl=pathlib.Path('/var/lib/rancher/rke2/bin/kubectl')
if kubectl.exists() and pathlib.Path('/etc/rancher/rke2/rke2.yaml').exists():
 subprocess.run([str(kubectl),'--kubeconfig=/etc/rancher/rke2/rke2.yaml','-n','kube-system','delete','pod','-l','app=flannel','--wait=false'],check=True)
'''
            source = repair + source
        encoded = base64.b64encode(source.encode()).decode()
        expression = 'import base64;exec(base64.b64decode(' + repr(encoded) + '))'
        child.send('sudo -n python3 -c ' + shlex.quote(expression) + '\r')
        child.expect(r'[\r\n]+IMAGE_DIAGNOSTIC_FILE=(/var/tmp/autonomous-image-diagnostic-[A-Za-z0-9_]+):([0-9]+)[\r\n]', timeout=100)
        name, size = child.match.group(1), int(child.match.group(2))
        if not 0 < size <= 1 << 20:
            raise ValueError('diagnostic exceeds transfer limit')
        # Kernel messages can interrupt serial output. Small chunks carry
        # independent checksums; retry only missing/corrupt chunks.
        count = (size + 511) // 512
        chunks = {}
        for _ in range(3):
            missing = [index for index in range(count) if index not in chunks]
            transfer = ('import pathlib,base64,hashlib;data=pathlib.Path(' + repr(name) + ').read_bytes();'
                        + '\nfor index in ' + repr(missing) + ':\n chunk=data[index*512:(index+1)*512];'
                        + 'print("IMAGE_DIAGNOSTIC_CHUNK="+str(index)+":"+base64.b64encode(chunk).decode()+":"+hashlib.sha256(chunk).hexdigest(),flush=True)'
                        + '\nprint("IMAGE_DIAGNOSTIC_END",flush=True)')
            expression = 'import base64;exec(base64.b64decode(' + repr(base64.b64encode(transfer.encode()).decode()) + '))'
            child.send('sudo -n python3 -c ' + shlex.quote(expression) + '\r')
            while True:
                matched = child.expect([r'IMAGE_DIAGNOSTIC_CHUNK=([0-9]+):([A-Za-z0-9+/=]+):([0-9a-f]{64})[\r\n]',
                                        r'IMAGE_DIAGNOSTIC_END[\r\n]'], timeout=20)
                if matched == 1:
                    break
                index = int(child.match.group(1))
                chunk = base64.b64decode(child.match.group(2))
                if index in missing and len(chunk) <= 512 and hashlib.sha256(chunk).hexdigest() == child.match.group(3):
                    chunks[index] = chunk
            if len(chunks) == count:
                break
        if len(chunks) != count:
            raise ValueError('diagnostic serial transfer incomplete')
        payload = b''.join(chunks[index] for index in range(count))
        if len(payload) != size:
            raise ValueError('diagnostic serial size differs')
        child.send('sudo -n rm -f -- ' + shlex.quote(name) + '\r')
        text = zlib.decompressobj().decompress(payload, (1 << 20) + 1)
        if len(text) > 1 << 20:
            raise ValueError('diagnostic expansion exceeds limit')
        return json.loads(text)
    finally:
        try:
            password('!', True)
        finally:
            if child:
                try:
                    child.send('exit\r')
                    child.expect('login:', timeout=10)
                except pexpect.ExceptionPexpect:
                    pass
                finally:
                    child.close(force=True)


if __name__ == '__main__':
    import argparse
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from lab.packer.artifacts import write_json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--test-service-route', action='store_true')
    args = parser.parse_args()
    from lab.packer.console import diagnose as owned_diagnose
    write_json(args.output, owned_diagnose(json.loads(args.spec.read_text()), args.test_service_route))
