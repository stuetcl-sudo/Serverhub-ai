"""Actual network namespaces, HTTPS gateway and Caddy; disposable Ubuntu only."""
import json
import os
from pathlib import Path
import pwd
import shutil
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

if os.geteuid()!=0 or os.environ.get('SERVERHUB_DISPOSABLE_TEST')!='fresh-ubuntu-ci' or os.environ.get('GITHUB_ACTIONS')!='true':
    raise SystemExit('Disposable Ubuntu CI confirmation required')
if not Path('/etc/serverhub/native-ci-node.json').exists():
    raise SystemExit('Guarded native installation suite must run first')


def run(argv, **kw):
    return subprocess.run(argv,check=True,text=True,capture_output=True,timeout=180,**kw).stdout.strip()


root=Path('/var/lib/serverhub-hardening-ci')
root.mkdir(mode=0o755)
worker=pwd.getpwnam('serverhub-ai')
workspace=root/'workspace'
workspace.mkdir(mode=0o700)
os.chown(workspace,worker.pw_uid,worker.pw_gid)
run(['runuser','-u','serverhub-ai','--','git','init',str(workspace)])
seen=[]
class Sentinel(BaseHTTPRequestHandler):
    def do_GET(self):
        seen.append(self.path)
        self.send_response(200)
        self.end_headers()
    def log_message(self,*args):
        pass
sentinel=ThreadingHTTPServer(('127.0.0.1',0),Sentinel)
threading.Thread(target=sentinel.serve_forever,daemon=True).start()
python='/opt/serverhub/current/venv/bin/python'
probe="""import json,socket,urllib.request
assert [name for _,name in socket.if_nameindex()]==['lo']
for host in ['127.0.0.1','192.168.68.135','169.254.169.254']:
    try:
        socket.create_connection((host,SENTINEL_PORT),timeout=.3)
    except OSError:
        pass
    else:
        raise AssertionError('Host/LAN direct TCP escaped the private namespace')
print('Direct loopback/LAN/metadata access denied')
""".replace('SENTINEL_PORT',str(sentinel.server_port))
# Default namespace and the explicit dependency proxy both deny direct host/LAN.
for network in (False,True):
    payload={'name':'security-fixture','repository':str(workspace),'tests':[{'argv':['/usr/bin/true']}],
             'allow_dependency_network':True}
    command={'argv':['/usr/bin/python3','-c',probe],'network':network,'timeout':20}
    code='from pathlib import Path;from serverhub.development.config import Project,Command;from serverhub.development.sandbox import SandboxRunner;'+\
        'p=Project.model_validate('+repr(payload)+');r=SandboxRunner(p).run(Path('+repr(str(workspace))+'),Command.model_validate('+repr(command)+'));print(r.output);assert r.returncode==0,r'
    output=run(['runuser','-u','serverhub-ai','--',python,'-c',code])
    assert 'Direct loopback/LAN/metadata access denied' in output
# Real package-index HTTPS works; private destinations through the proxy fail.
probe2="""import urllib.request,urllib.error
with urllib.request.urlopen('https://pypi.org/pypi/pip/json',timeout=30) as response:
    assert response.status==200
try:
    urllib.request.urlopen('https://127.0.0.1:443/',timeout=3)
except (OSError,urllib.error.URLError):
    pass
else:
    raise AssertionError('Proxy allowed a private destination')
print('Public HTTPS verified; private proxy destination denied')
"""
command={'argv':['/usr/bin/python3','-c',probe2],'network':True,'timeout':45}
code='from pathlib import Path;from serverhub.development.config import Project,Command;from serverhub.development.sandbox import SandboxRunner;'+\
    'p=Project.model_validate('+repr(payload)+');r=SandboxRunner(p).run(Path('+repr(str(workspace))+'),Command.model_validate('+repr(command)+'));print(r.output);assert r.returncode==0,r'
output=run(['runuser','-u','serverhub-ai','--',python,'-c',code])
assert 'Public HTTPS verified' in output and not seen
sentinel.shutdown()
print('DEPENDENCY_NETWORK_EVIDENCE='+json.dumps({'private_namespace':True,'direct_loopback_lan_metadata':'denied',
    'public_https':'verified actual pypi.org','private_proxy_destination':'denied','host_sentinel_requests':len(seen),'firewall_changes':False}),flush=True)

# Explicit disposable API setting, not a production Caddy or Control edit.
api_env=Path('/etc/serverhub/api.env')
original=api_env.read_bytes()
api_env.write_bytes(original+b'\nSERVERHUB_TRUSTED_PROXY_CIDRS=\'["127.0.0.1/32"]\'\n')
run(['systemctl','restart','serverhub-ai-api'])
ca=Path('/etc/serverhub/tls/cert.pem')
shutil.copyfile(ca,root/'ca.pem')
(root/'ca.pem').chmod(0o644)
(root/'Caddyfile').write_text('''http://127.0.0.1:19081 {
    reverse_proxy https://127.0.0.1:9080 {
        header_up Host 127.0.0.1:9080
        transport http {
            tls_trust_pool file /fixtures/ca.pem
        }
    }
}
''')
(root/'Caddyfile').chmod(0o644)
try:
    run(['docker','run','-d','--name','shub-hardening-caddy','--network','host','--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges:true','--tmpfs','/data','--tmpfs','/config',
        '-v',str(root)+':/fixtures:ro','caddy:2.11.7','caddy','run','--config','/fixtures/Caddyfile','--adapter','caddyfile'])
    for _ in range(40):
        try:
            if httpx.get('http://127.0.0.1:19081/health',trust_env=False).status_code==200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(.5)
    else:
        raise AssertionError('Disposable Caddy proxy did not become healthy')
    origin={'Origin':'https://127.0.0.1:9080'}
    with httpx.Client(base_url='http://127.0.0.1:19081',transport=httpx.HTTPTransport(local_address='127.0.0.2'),trust_env=False) as attacker:
        for _ in range(5):
            assert attacker.post('/api/auth/login',headers=origin,json={'username':'ciowner','password':'incorrect-fixture'}).status_code==401
        response=attacker.post('/api/auth/login',headers={**origin,'X-Forwarded-For':'203.0.113.7'},json={'username':'ciowner','password':'incorrect-fixture'})
        assert response.status_code==429 and 'Retry-After' in response.headers
    with httpx.Client(base_url='http://127.0.0.1:19081',transport=httpx.HTTPTransport(local_address='127.0.0.3'),trust_env=False) as owner:
        response=owner.post('/api/auth/login',headers=origin,json={'username':'ciowner','password':'isolated-native-owner-password-42'})
        assert response.status_code==200,response.status_code
        token=response.json()['token']
        assert owner.get('/api/projects',headers={'Authorization':'Bearer '+token}).status_code==200
        assert owner.get('/.well-known/oauth-authorization-server').status_code==200
        index=owner.get('/')
        assert index.status_code==200 and '<html' in index.text
    print('CADDY_LOGIN_EVIDENCE='+json.dumps({'caddy':'2.11.7 disposable fixture','upstream_tls_verified':True,
        'spoofed_forwarding_does_not_bypass_limit':True,'other_client_can_login':True,'oauth_discovery_and_frontend':'passed',
        'production_proxy_changed':False}),flush=True)
finally:
    subprocess.run(['docker','rm','-f','shub-hardening-caddy'],check=False,capture_output=True)
    api_env.write_bytes(original)
    run(['systemctl','restart','serverhub-ai-api'])
