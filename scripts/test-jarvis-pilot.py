"""Real public Jarvis source + qwen + native broker staging, disposable Ubuntu only.

The version regression is deliberately injected into a LOCAL fork. This is an
autonomous repair acceptance test, not a claim that upstream Jarvis is broken.
"""
import json
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
(checks/'check.py').write_text("from pathlib import Path\nimport ast\nmodule=ast.parse(Path('/workspace/app/version.py').read_text())\nassert any(isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VERSION' for t in n.targets) and ast.literal_eval(n.value)=='0.23.0' for n in module.body)\nprint('Independent version acceptance passed')\n")
(checks/'check.py').chmod(0o644)
python='/opt/serverhub/current/venv/bin/python'
# /usr/bin Python remains inside the minimal sandbox. Dependencies and package
# entry points are installed into the isolated workspace, never the host Python.
run(['apt-get','update'])
run(['apt-get','install','-y','python3-pip','bubblewrap'])
project={'name':'jarvis','repository':str(source),'base_ref':'serverhub-acceptance',
    'allow_dependency_network':True,'max_memory_mb':2048,'max_processes':128,
    'dependencies':[{'argv':['/usr/bin/python3','-m','pip','install','--break-system-packages','--no-compile','--target','runtime','-r','requirements.txt','pytest==8.3.5'],'network':True,'timeout':600}],
    'build':[{'argv':['/usr/bin/python3','-m','compileall','-q','app']}],
    'tests':[{'argv':['/usr/bin/env','PYTHONPATH=runtime','DB_PATH=/tmp/jarvis-test.db','SAFE_MODE=true','DRY_RUN=true','WORKER_ENABLED=false','/usr/bin/python3','-m','pytest','-q','tests/test_dashboard_routes.py'],'timeout':180}],
    'checks_path':str(checks),'independent_checks':[{'argv':['/usr/bin/python3','/checks/check.py']}],
    'artifact_paths':['app','runtime','requirements.txt'],'max_artifact_bytes':512*1024**2}
projects=Path('/etc/serverhub/projects.yaml')
projects.write_text(yaml.safe_dump({'projects':[project]}))
projects.chmod(0o644)
plan={'argv':['/usr/bin/python3','-m','uvicorn','app.main_auth:app','--host','127.0.0.1','--port','28098'],
      'port':28098,'health_path':'/','health_contains':'Jarvis','memory_mb':1024,
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
    'host_id':host,'project':'jarvis','hours':1,'allow_dependency_network':True})
grant.raise_for_status()

def await_job(identity, timeout=1800):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        run(['runuser','-u','serverhub-node','--',python,'-c',
             'import json;from serverhub.node.agent import NodeAgent;NodeAgent(json.load(open("/etc/serverhub/native-ci-node.json"))).run_once()'],cwd='/')
        job=client.get('/api/jobs/'+identity,headers=headers).json()
        if job['state'] in {'succeeded','partial','failed','cancelled','paused','waiting_approval'}:
            return job
        time.sleep(1)
    raise AssertionError('Jarvis acceptance job exceeded integration deadline')

response=client.post('/api/jobs',headers=headers,json={'kind':'development_autonomous','project':'jarvis','host_id':host,
    'token_budget':100000,'time_limit':1800,'max_attempts':2,'spec':{'project':'jarvis','stage':True,'max_steps':16,
    'prompt':'Repair the controlled local version regression. Record a plan, read app/version.py, and change ONLY VERSION to the expected release 0.23.0 using edit_file. Then run_checks and finish. Preserve the application and tests; the independent acceptance check verifies the exact version. Do not change requirements or other files.'}})
response.raise_for_status()
job=await_job(response.json()['id'])
events=client.get('/api/jobs/'+job['id']+'/events',headers=headers).json()
print('JARVIS_JOB_EVIDENCE='+json.dumps({'state':job['state'],'error':job.get('error'),'result':job['result'],
    'tokens_used':job['tokens_used'],'events':events[-12:],'upstream_commit':upstream,'injected_local_regression':True,
    'model_digests':tags}),flush=True)
assert job['state']=='succeeded' and job['result']['verified'],job
assert job['result']['staging']['verified'] and job['result']['production_deployed'] is False
assert (source/'app/version.py').read_text()!=original
assert run(['git','-c','safe.directory='+str(source),'-C',str(source),'rev-parse','HEAD'])==fixture_commit
work=Path('/var/lib/serverhub-worker/development/workspaces/jarvis')/job['id']
assert (work/'app/version.py').read_text()==original
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
