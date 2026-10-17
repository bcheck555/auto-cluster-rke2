"""Owned test-guest diagnostics over serial; temporary password always re-locked."""
import base64
import json
import secrets
import shlex
import time


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
        source = '''import json,subprocess,base64,pathlib,time
def run(args):
 try:
  p=subprocess.run(args,capture_output=True,text=True,timeout=20);return p.stdout[-24000:]+p.stderr[-2000:]
 except subprocess.TimeoutExpired:return 'diagnostic command timed out'
data={'units':run(['systemctl','show','rke2-server','rke2-agent','autonomous-image-validation','-p','ActiveState','-p','SubState','-p','Result']),
 'journal':run(['journalctl','-b','--no-pager','-n','120','-u','rke2-server','-u','rke2-agent','-u','autonomous-image-validation']),
 'error':pathlib.Path('/var/tmp/image-validation-error.txt').read_text() if pathlib.Path('/var/tmp/image-validation-error.txt').exists() else '',
 'network':run(['ip','-j','route','show','table','all']),
 'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
report=pathlib.Path('/var/tmp/image-boot-report.json')
if report.exists():data['boot_report']=json.loads(report.read_text())
data['processes']=run(['ps','-eo','pid,etime,args'])
containerlog=pathlib.Path('/var/lib/rancher/rke2/agent/containerd/containerd.log')
if containerlog.exists():data['containerd_log']=run(['tail','-n','60',str(containerlog)])
etcdlogs=list(pathlib.Path('/var/log/pods').glob('kube-system_etcd-*/*/*.log'))
if etcdlogs:data['etcd_log']=run(['tail','-n','40',str(max(etcdlogs,key=lambda p:p.stat().st_mtime))])
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
token=pathlib.Path('/etc/autonomous-rke2/test-token')
if token.exists():text=text.replace(token.read_text().strip(),'[REDACTED]')
print('IMAGE_DIAGNOSTIC='+base64.b64encode(text.encode()).decode())
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
        child.expect(r'[\r\n]+IMAGE_DIAGNOSTIC=([A-Za-z0-9+/=]+)[\r\n]', timeout=100)
        return json.loads(base64.b64decode(child.match.group(1)))
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
