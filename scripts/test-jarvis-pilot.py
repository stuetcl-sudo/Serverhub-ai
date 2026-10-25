"""Real public Jarvis source + qwen + native broker staging, disposable Ubuntu only.

The version regression is deliberately injected into a LOCAL fork. This is an
autonomous repair acceptance test, not a claim that upstream Jarvis is broken.
"""
import json
import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlsplit
import os
from pathlib import Path
import pwd
import shutil
import ssl
import subprocess
import time

import httpx
import yaml

if os.geteuid()!=0 or os.environ.get('SERVERHUB_DISPOSABLE_TEST')!='fresh-ubuntu-ci' or not os.environ.get('GITHUB_ACTIONS'):
    raise SystemExit('Disposable Ubuntu CI confirmation required')
if not Path('/etc/serverhub/native-ci-node.json').exists():
    raise SystemExit('Guarded native installation suite must run first')

def run(argv, **kw):
    try:
        return subprocess.run(argv,check=True,text=True,capture_output=True,**kw).stdout.strip()
    except subprocess.CalledProcessError as error:
        print('JARVIS_FIXTURE_FAILURE='+json.dumps({'executable':argv[0],'stderr':error.stderr[-6000:]}),flush=True)
        raise

os.umask(0o077)
root=Path('/var/lib/serverhub-jarvis-pilot')
root.mkdir(mode=0o755)
root.chmod(0o755)
source=root/'source'
run(['git','clone','https://github.com/stuetcl-sudo/Jarvis-os.git',str(source)])
upstream='0c0ab744cb4159b0d36c00cf52defe3d4caab02b'
run(['git','-C',str(source),'checkout','-b','serverhub-acceptance',upstream])
original=(source/'app/version.py').read_text()
assert '0.23.0' in original
(source/'app/version.py').write_text(original.replace('0.23.0','0.0.0-ci-broken'))
run(['git','-C',str(source),'-c','user.name=Disposable acceptance','-c','user.email=ci@example.invalid','commit','-am','Inject controlled local version regression'])
fixture_commit=run(['git','-C',str(source),'rev-parse','HEAD'])
worker=pwd.getpwnam('serverhub-ai')
for path in [source,*source.rglob('*')]:
    os.chown(path,worker.pw_uid,worker.pw_gid)

checks=root/'checks'
checks.mkdir(mode=0o755)
checks.chmod(0o755)
(checks/'check.py').write_text("from pathlib import Path\nimport ast,sys\nbase=Path(sys.argv[1]) if len(sys.argv)>1 else Path('/workspace')\nmodule=ast.parse((base/'app/version.py').read_text())\nassert any(isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VERSION' for t in n.targets) and ast.literal_eval(n.value)=='0.23.0' for n in module.body)\nprint('Independent version acceptance passed')\n")
with (checks/'check.py').open('a') as check:
    check.write("import os,resource\nif str(base)=='/workspace':\n    assert not any(Path(p).exists() for p in ['/etc/serverhub','/opt/serverhub-control','/run/docker.sock','/var/run/docker.sock','/home/dennis'])\n    assert not any(k.startswith('SERVERHUB_') or k in ('GITHUB_TOKEN','SSH_AUTH_SOCK') for k in os.environ)\n    assert resource.getrlimit(resource.RLIMIT_AS)[0] <= 2048*1024*1024\n    assert resource.getrlimit(resource.RLIMIT_NPROC)[0] <= 128\n    print('Independent sandbox secret/mount/resource boundaries passed')\n")
(checks/'check.py').chmod(0o644)
python='/opt/serverhub/current/venv/bin/python'
# /usr/bin Python remains inside the minimal sandbox. Dependencies and package
# entry points are installed into the isolated workspace, never the host Python.
run(['apt-get','update'])
run(['apt-get','install','-y','python3-pip','bubblewrap'])
project={'name':'jarvis','repository':str(source),'base_ref':'serverhub-acceptance',
    'allow_dependency_network':True,'max_memory_mb':2048,'max_processes':128,
    'dependencies':[{'argv':['/usr/bin/python3','-m','pip','install','--break-system-packages','--no-compile','--upgrade','--force-reinstall','--target','runtime','-r','requirements.txt','pytest==8.3.5'],'network':True,'timeout':600}],
    'build':[{'argv':['/usr/bin/python3','-m','compileall','-q','app']}],
    'tests':[{'argv':['/usr/bin/env','PYTHONPATH=runtime','DB_PATH=/tmp/jarvis-test.db','SAFE_MODE=true','DRY_RUN=true','WORKER_ENABLED=false','/usr/bin/python3','-m','pytest','-q','tests/test_dashboard_routes.py'],'timeout':180}],
    'checks_path':str(checks),'independent_checks':[{'argv':['/usr/bin/python3','/checks/check.py']}],
    'artifact_paths':['app','runtime','requirements.txt'],'max_artifact_bytes':512*1024**2}
projects=Path('/etc/serverhub/projects.yaml')
projects.write_text(yaml.safe_dump({'projects':[project]}))
projects.chmod(0o644)
plan={'argv':['/usr/bin/python3','-m','uvicorn','app.main_auth:app','--host','127.0.0.1','--port','28098'],
      'port':28098,'health_path':'/api/health','health_contains':'0.23.0','memory_mb':1024,
      'acceptance_script':{'path':str(checks/'check.py'),'sha256':__import__('hashlib').sha256((checks/'check.py').read_bytes()).hexdigest()},
      'environment':{'SAFE_MODE':'true','DRY_RUN':'true','WORKER_ENABLED':'false'}}
plans=root/'staging.yaml'
plans.write_text(yaml.safe_dump({'staging_projects':{'jarvis':plan}}))
plans.chmod(0o600)
run([python,'-m','serverhub.node.enroll','--plans',str(plans),'--apply'])

# Actual local model daemon, no fake HTTP provider and no public listener.
run(['docker','run','-d','--name','serverhub-jarvis-ollama','--memory','5g','--cpus','4',
     '-p','127.0.0.1:11434:11434','ollama/ollama:0.40.9'])
for _ in range(60):
    try:
        tags=httpx.get('http://127.0.0.1:11434/api/tags',trust_env=False).json()
        break
    except httpx.HTTPError:
        time.sleep(1)
else:
    raise AssertionError('Real Ollama daemon unavailable')
run(['docker','exec','serverhub-jarvis-ollama','ollama','pull','qwen2.5:3b'],timeout=900)
tags=httpx.get('http://127.0.0.1:11434/api/tags',trust_env=False).json()

ca='/etc/serverhub/tls/cert.pem'
public_ca=Path('/etc/serverhub/native-public-ca.pem')
shutil.copyfile(ca,public_ca)
public_ca.chmod(0o644)
node_path=Path('/etc/serverhub/native-ci-node.json')
node=json.loads(node_path.read_text())
node.update(controller_url='https://127.0.0.1:9080',ca_bundle=str(public_ca))
node_path.write_text(json.dumps(node))
client=httpx.Client(base_url='https://127.0.0.1:9080',verify=ssl.create_default_context(cafile=ca),trust_env=False,timeout=360)
login=client.post('/api/auth/login',json={'username':'ciowner','password':'isolated-native-owner-password-42'})
login.raise_for_status()
headers={'Authorization':'Bearer '+login.json()['token'],'Origin':'https://127.0.0.1:9080'}
host=client.get('/api/hosts',headers=headers).json()[0]['id']
provider={'kind':'ollama','base_url':'http://127.0.0.1:11434','model':'qwen2.5:3b','context_limit':8192,
          'max_output_tokens':512,'timeout_seconds':300,'max_retries':1}
saved=client.put('/api/settings/models/development',headers=headers,json=provider)
saved.raise_for_status()
grant=client.post('/api/policies/profiles',headers=headers,json={'profile':'development','subject_id':login.json()['user']['id'],
    'project':'jarvis','hours':1,'allow_dependency_network':True})
grant.raise_for_status()

recovery_evidence={}

def await_job(identity, timeout=1800, restart_after_patch=False):
    deadline=time.monotonic()+timeout
    last_report=0
    while time.monotonic()<deadline:
        run(['runuser','-u','serverhub-ai-node','--',python,'-c',
             'import json;from serverhub.node.agent import NodeAgent;NodeAgent(json.load(open("/etc/serverhub/native-ci-node.json"))).run_once()'],cwd='/')
        job=client.get('/api/jobs/'+identity,headers=headers).json()
        developer=job.get('checkpoint',{}).get('developer') or {}
        if restart_after_patch and not recovery_evidence and developer.get('patch_count',0)>0 and not developer.get('ready'):
            before_pid=run(['systemctl','show','serverhub-ai-worker','--property=MainPID','--value'])
            run(['systemctl','restart','serverhub-ai-worker'])
            after_pid=run(['systemctl','show','serverhub-ai-worker','--property=MainPID','--value'])
            assert before_pid!=after_pid and int(after_pid)>0
            recovery_evidence.update(restarted_after_source_commit=True,pid_changed=True)
            print('JARVIS_WORKER_INTERRUPTION='+json.dumps(recovery_evidence),flush=True)
        if time.monotonic()-last_report>20:
            print('JARVIS_PROGRESS='+json.dumps({'job_id':identity,'state':job['state'],'progress':job.get('progress'),'used_units':job.get('tokens_used'),'step':(job.get('checkpoint',{}).get('developer') or {}).get('step')}),flush=True)
            last_report=time.monotonic()
        if job['state'] in {'succeeded','partial','failed','cancelled','paused','waiting_approval'}:
            return job
        time.sleep(1)
    raise AssertionError('Jarvis acceptance job exceeded integration deadline')

# A separate no-patch run uses upstream main, with no host or staging permission.
# Register and consent to a distinct AI OS OAuth client; never reuse Control tokens.
registered=client.post('/api/mcp/clients',headers=headers,json={'name':'Disposable Jarvis MCP acceptance',
    'redirect_uris':['https://client.example.invalid/callback']})
registered.raise_for_status()
verifier=secrets.token_urlsafe(48)
parameters={'client_id':registered.json()['client_id'],'redirect_uri':'https://client.example.invalid/callback',
    'response_type':'code','scope':'serverhub:read serverhub:jobs serverhub:policies',
    'code_challenge':base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode(),
    'code_challenge_method':'S256','state':'isolated-ci','resource':'https://127.0.0.1:9080/mcp'}
consent=client.get('/oauth/authorize',params=parameters,headers=headers)
consent.raise_for_status()
nonce=re.search(r'name="consent_nonce" value="([^"]+)"',consent.text).group(1)
consent=client.post('/oauth/authorize',headers=headers,data={'consent_nonce':nonce,'decision':'approve'},follow_redirects=False)
assert consent.status_code==303
code=parse_qs(urlsplit(consent.headers['location']).query)['code'][0]
access=client.post('/oauth/token',headers={'Origin':'https://127.0.0.1:9080'},data={'grant_type':'authorization_code',
    'client_id':parameters['client_id'],'redirect_uri':parameters['redirect_uri'],'code':code,
    'code_verifier':verifier,'resource':parameters['resource']})
access.raise_for_status()
mcp_headers={'Authorization':'Bearer '+access.json()['access_token'],'MCP-Protocol-Version':'2025-11-25'}
def mcp_call(name, arguments):
    response=client.post('/mcp',headers=mcp_headers,json={'jsonrpc':'2.0','id':1,'method':'tools/call',
        'params':{'name':name,'arguments':arguments}})
    response.raise_for_status()
    result=response.json()['result']
    assert not result.get('isError'),result
    return json.loads(result['content'][0]['text'])

main_project={**project,'repository':'https://github.com/stuetcl-sudo/Jarvis-os.git','base_ref':'main'}
projects.write_text(yaml.safe_dump({'projects':[main_project]}))
projects.chmod(0o644)
assert mcp_call('list_projects',{})[0]['execution_location']=='controller'
no_patch=mcp_call('create_development_job',{'project':'jarvis','idempotency_key':'jarvis-upstream-main-no-patch'})
no_patch=await_job(no_patch['id'])
assert no_patch['state']=='succeeded' and no_patch['result']['verified'],no_patch
assert no_patch['host_id'] is None and no_patch['result']['production_deployed'] is False
assert no_patch['result']['candidate']['commit']==upstream
assert no_patch['result']['source_patch']==''
logs=mcp_call('job_logs',{'job_id':no_patch['id']})
artifact=mcp_call('development_artifacts',{'job_id':no_patch['id']})
assert artifact['verified'] and artifact['manifest']['sha256'] and logs
print('JARVIS_MAIN_NO_PATCH='+json.dumps({'state':no_patch['state'],'verified':True,'upstream_commit':upstream,
    'host':None,'transport':'OAuth S256 MCP','commands':[{k:v for k,v in c.items() if k in ('phase','returncode','output')} for c in no_patch['result']['commands']]}),flush=True)
# The model repair runs on a local fork of that exact public main commit. Its
# separate staging grant cannot authorize production or a different project.
projects.write_text(yaml.safe_dump({'projects':[project]}))
projects.chmod(0o644)
staging_grant=mcp_call('grant_development_profile',{'subject_id':login.json()['user']['id'],
    'project':'jarvis','hours':1,'allow_dependency_network':True,'allow_staging':True,'host_id':host})
assert any(p['environment']=='staging' and p['host_id']==host for p in staging_grant['policies'])

response=client.post('/api/jobs',headers=headers,json={'kind':'development_autonomous','project':'jarvis','host_id':host,
    'token_budget':100000,'time_limit':1800,'max_attempts':2,'spec':{'project':'jarvis','stage':True,'max_steps':16,
    'prompt':'Repair the controlled local version regression. Record a plan, read app/version.py, and change ONLY VERSION to the expected release 0.23.0 using set_python_constant with name VERSION and value 0.23.0. Then run_checks and finish. Preserve the application and tests; the independent acceptance check verifies the exact version. Do not change requirements or other files.'}})
response.raise_for_status()
job=await_job(response.json()['id'],restart_after_patch=True)
events=client.get('/api/jobs/'+job['id']+'/events',headers=headers).json()
print('JARVIS_JOB_EVIDENCE='+json.dumps({'state':job['state'],'error':job.get('error'),'result':job['result'],
    'tokens_used':job['tokens_used'],'events':events[-12:],'upstream_commit':upstream,'injected_local_regression':True,
    'worker_recovery':recovery_evidence,'attempts':job['attempts'],'model_digests':tags}),flush=True)
assert job['state']=='succeeded' and job['result']['verified'],job
claims = [event for event in events if event.get('message') == 'Job claimed']
shutdowns = [event for event in events if event.get('data', {}).get('class') == 'worker_shutdown']
# Graceful resume is an execution entry, not a failed attempt. Prove actual
# restart/reclaim independently, while preserving the failure-attempt ceiling.
assert recovery_evidence.get('pid_changed') and len(claims) >= 2 and shutdowns, events
assert 1 <= job['attempts'] < len(claims), job
assert job['result']['staging']['verified'] and job['result']['production_deployed'] is False
assert (source/'app/version.py').read_text()!=original
assert run(['git','-c','safe.directory='+str(source),'-C',str(source),'rev-parse','HEAD'])==fixture_commit
work=Path('/var/lib/serverhub-ai-worker/development/workspaces/jarvis')/job['id']
import ast
assert ast.literal_eval(next(node.value for node in ast.parse((work/'app/version.py').read_text()).body if isinstance(node,ast.Assign) and any(isinstance(name,ast.Name) and name.id=='VERSION' for name in node.targets)))=='0.23.0'
previous=json.loads(Path('/var/lib/serverhub-broker/operations/stage-jarvis.state').read_text())
assert run(['systemctl','is-active',previous['unit']])=='active'

# A deliberately failing next health contract must restore the existing release.
plan['health_contains']='THIS-ACCEPTANCE-MUST-FAIL'
plans.write_text(yaml.safe_dump({'staging_projects':{'jarvis':plan}}))
run([python,'-m','serverhub.node.enroll','--plans',str(plans),'--apply'])
response=client.post('/api/jobs',headers=headers,json={'kind':'operation','project':'jarvis','host_id':host,
    'token_budget':0,'cost_budget':0,'time_limit':300,'spec':{'operation':'development.deploy',
    'arguments':{'target':'jarvis','artifact_id':job['id']}}})
response.raise_for_status()
failed=await_job(response.json()['id'],timeout=360)
assert failed['state']=='failed',failed
assert json.loads(Path('/var/lib/serverhub-broker/operations/stage-jarvis.state').read_text())['unit']==previous['unit']
assert run(['systemctl','is-active',previous['unit']])=='active'
from serverhub.ops.operation_watchdog import stage_health
assert stage_health(previous,timeout=20)
print('JARVIS_STAGING_ROLLBACK_EVIDENCE='+json.dumps({'failed_candidate_state':failed['state'],
    'previous_http_verified':True,'private_network':True,'production_deployed':False}),flush=True)
client.close()
