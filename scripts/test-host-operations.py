"""Actual privileged integration suite; fresh disposable Ubuntu CI only.

Creates its own named database/container/Compose fixtures and package. Never run
on production or an existing independent installation.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import time

import httpx
import yaml

if (os.geteuid()!=0 or os.environ.get('SERVERHUB_DISPOSABLE_TEST')!='fresh-ubuntu-ci' or not os.environ.get('GITHUB_ACTIONS')):
    raise SystemExit('Disposable Ubuntu CI confirmation required')
if not Path('/etc/serverhub/native-ci-node.json').exists():
    raise SystemExit('Run only after the guarded native installation suite')

os.umask(0o077)
root=Path('/var/lib/serverhub-operation-fixtures')
root.mkdir(mode=0o700)
output={}

def run(argv, **kwargs):
    try:
        return subprocess.run(argv,check=True,text=True,capture_output=True,**kwargs).stdout.strip()
    except subprocess.CalledProcessError as error:
        print('DISPOSABLE_FIXTURE_FAILURE='+json.dumps({'executable':argv[0],'stderr':error.stderr[-4000:]}),flush=True)
        raise


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# Real distro package manager operations on a deliberately dependency-free fixture.
for version in ('1','2','3'):
    package=root/('package-'+version)
    (package/'DEBIAN').mkdir(parents=True)
    (package/'DEBIAN/control').write_text(f'Package: shub-disposable-fixture\nVersion: {version}.0\nArchitecture: all\nMaintainer: CI fixture <ci@example.invalid>\nDescription: Disposable ServerHub acceptance fixture\n')
    target=package/'usr/share/shub-disposable-fixture'
    target.mkdir(parents=True)
    (target/'version').write_text(version)
    for item in [package,*package.rglob('*')]:
        item.chmod(0o755 if item.is_dir() else 0o644)
    run(['dpkg-deb','--build',str(package),str(root/f'package-{version}.deb')])
run(['dpkg','--install',str(root/'package-1.deb')])
Path('/etc/shub-disposable.conf').write_text('healthy\n')
(root/'healthy.conf').write_text('healthy\n')
(root/'broken.conf').write_text('broken\n')
Path('/etc/systemd/system/shub-disposable.service').write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/grep -qx healthy /etc/shub-disposable.conf\n')
run(['systemctl','daemon-reload'])
run(['systemctl','start','shub-disposable'])

# Actual isolated Docker database, bind mount, named volume and Compose metadata.
run(['docker','pull','postgres:16-alpine'])
run(['docker','volume','create','shub-ci-postgres'])
bind=root/'bind'
bind.mkdir()
bind.chmod(0o755)
(bind/'evidence').write_text('persistent bind content\n')
(bind/'evidence').chmod(0o644)
(root/'compose.database.yaml').write_text('services:\n  database:\n    image: postgres:16-alpine\n')
container=run(['docker','run','-d','--name','shub-ci-database','--network','none',
    '--label',f'com.docker.compose.project.config_files={root / "compose.database.yaml"}',
    '-e','POSTGRES_PASSWORD=isolated-ci-only','-v','shub-ci-postgres:/var/lib/postgresql/data',
    '-v',f'{bind}:/fixture:ro','--health-cmd','pg_isready -U postgres','--health-interval','1s',
    '--health-timeout','3s','--health-retries','60','postgres:16-alpine'])
for _ in range(60):
    if run(['docker','inspect','--format','{{.State.Health.Status}}',container])=='healthy':
        break
    time.sleep(1)
else:
    raise AssertionError('Disposable database did not start')
run(['docker','exec',container,'psql','-U','postgres','-c',"CREATE TABLE acceptance(value text); INSERT INTO acceptance VALUES ('verified database row');"])
# Actual pinned stateless Compose lifecycle. Fixtures have no host socket/data.
compose_images=[]
for tag in ('busybox:1.36.1','busybox:1.37.0'):
    run(['docker','pull',tag])
    compose_images.append(json.loads(run(['docker','image','inspect',tag]))[0]['RepoDigests'][0])
for name,image,bad in (('compose-old.yaml',compose_images[0],False),('compose-new.yaml',compose_images[1],False),('compose-bad.yaml',compose_images[1],True)):
    (root/name).write_text(yaml.safe_dump({'services':{'app':{'image':image,'read_only':True,'user':'65534:65534',
        'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'command':['sh','-c','while true; do sleep 1; done'],
        'healthcheck':{'test':['CMD','false' if bad else 'true'],'interval':'1s','timeout':'2s','retries':2},
        'mem_limit':'128m','pids_limit':32,'networks':['isolated']}},'networks':{'isolated':{'internal':True}}}))
run(['docker','compose','--project-name','shub-ci-update','--env-file','/dev/null','-f',str(root/'compose-old.yaml'),'up','-d','--wait'])
destination=root/'backups'
destination.mkdir(mode=0o700)

def artifact(name):return {'path':str(root/name),'sha256':sha(root/name)}
plans={
    'package_plans':{
        'fixture-upgrade':{'stateless':True,'debs':[artifact('package-2.deb')],'previous_debs':[artifact('package-1.deb')],
            'verify_file':{'path':'/usr/share/shub-disposable-fixture/version','sha256':hashlib.sha256(b'2').hexdigest()}},
        'fixture-bad':{'stateless':True,'debs':[artifact('package-3.deb')],'previous_debs':[artifact('package-2.deb')],
            'verify_file':{'path':'/usr/share/shub-disposable-fixture/version','sha256':hashlib.sha256(b'never').hexdigest()}}},
    'configuration_plans':{
        'fixture-config':{'path':'/etc/shub-disposable.conf','candidate':artifact('healthy.conf'),'service':'shub-disposable.service'},
        'fixture-config-bad':{'path':'/etc/shub-disposable.conf','candidate':artifact('broken.conf'),'service':'shub-disposable.service'}},
    'compose_updates':{
        'fixture-compose':{'stateless':True,'project':'shub-ci-update',
            'previous':{'path':str(root),'compose_file':'compose-old.yaml','sha256':sha(root/'compose-old.yaml')},
            'candidate':{'path':str(root),'compose_file':'compose-new.yaml','sha256':sha(root/'compose-new.yaml')}},
        'fixture-compose-bad':{'stateless':True,'project':'shub-ci-update',
            'previous':{'path':str(root),'compose_file':'compose-new.yaml','sha256':sha(root/'compose-new.yaml')},
            'candidate':{'path':str(root),'compose_file':'compose-bad.yaml','sha256':sha(root/'compose-bad.yaml')}}},
    'docker_backup_plans':{'fixture-backup':{'containers':['shub-ci-database'],'destination':str(destination),
        'key_file':'/etc/serverhub/docker-backup.key','allow_system_disk':True,'include_images':True,'allow_isolated_restore':True,
        'allowed_bind_roots':[str(root)]}}
}
plans_path=root/'plans.yaml'
plans_path.write_text(yaml.safe_dump(plans))
python='/opt/serverhub/current/venv/bin/python'
run([python,'-m','serverhub.node.enroll','--plans',str(plans_path),'--apply'])

# Use the actual HTTPS API, expiring grant, worker DB identity, node identity and root broker.
ca=Path('/etc/serverhub/tls/cert.pem')
public_ca=Path('/etc/serverhub/native-public-ca.pem')
shutil.copyfile(ca,public_ca)
public_ca.chmod(0o644)
node_path=Path('/etc/serverhub/native-ci-node.json')
node=yaml.safe_load(node_path.read_text())
node.update(controller_url='https://127.0.0.1:9080',ca_bundle=str(public_ca))
node_path.write_text(json.dumps(node))
client=httpx.Client(base_url='https://127.0.0.1:9080',verify=ssl.create_default_context(cafile=str(ca)),trust_env=False,timeout=30)
login=client.post('/api/auth/login',json={'username':'ciowner','password':'isolated-native-owner-password-42'})
login.raise_for_status()
headers={'Authorization':'Bearer '+login.json()['token'],'Origin':'https://127.0.0.1:9080'}
host=client.get('/api/hosts',headers=headers).json()[0]['id']
policy=client.post('/api/policies/profiles',headers=headers,json={'profile':'maintenance','subject_id':login.json()['user']['id'],
    'host_id':host,'hours':1,'package_targets':['fixture-upgrade','fixture-bad'],
    'configuration_targets':['fixture-config','fixture-config-bad'],'compose_targets':['fixture-compose','fixture-compose-bad'],'backup_targets':['fixture-backup']})
policy.raise_for_status()


def job(operation,arguments,expected='succeeded'):
    response=client.post('/api/jobs',headers=headers,json={'kind':'operation','host_id':host,
        'spec':{'operation':operation,'arguments':arguments},'time_limit':1800,'token_budget':0,'cost_budget':0})
    response.raise_for_status()
    identity=response.json()['id']
    for _ in range(60):
        run(['runuser','-u','serverhub-node','--',python,'-c',
             'import json;from serverhub.node.agent import NodeAgent;NodeAgent(json.load(open("/etc/serverhub/native-ci-node.json"))).run_once()'],cwd='/')
        result=client.get('/api/jobs/'+identity,headers=headers).json()
        if result['state'] in {'succeeded','partial','failed','waiting_approval'}:
            break
        time.sleep(.5)
    assert result['state']==expected,result
    return result['result']


try:
    job('package.apply',{'target':'fixture-upgrade'})
    assert Path('/usr/share/shub-disposable-fixture/version').read_text()=='2'
    job('package.apply',{'target':'fixture-bad'},'failed')
    assert Path('/usr/share/shub-disposable-fixture/version').read_text()=='2'
    output['package_upgrade_and_verified_failure_rollback']='passed'
    job('configuration.apply',{'target':'fixture-config'})
    job('configuration.apply',{'target':'fixture-config-bad'},'failed')
    assert Path('/etc/shub-disposable.conf').read_text()=='healthy\n'
    assert run(['systemctl','is-active','shub-disposable'])=='active'
    output['configuration_rollback']='passed'
    job('docker.compose.update',{'target':'fixture-compose'})
    job('docker.compose.update',{'target':'fixture-compose-bad'},'failed')
    compose_id=run(['docker','compose','--project-name','shub-ci-update','-f',str(root/'compose-new.yaml'),'ps','-q']).strip()
    assert run(['docker','inspect','--format','{{.State.Health.Status}}',compose_id])=='healthy'
    assert json.loads(run(['docker','inspect',compose_id]))[0]['Config']['Image']==compose_images[1]
    output['stateless_compose_update_and_health_failure_rollback']='passed'
    backup=job('docker.backup.create',{'target':'fixture-backup'})
    assert backup['consistency']=='offline_clean_shutdown' and backup['verified']
    assert run(['docker','inspect','--format','{{.State.Running}}',container])=='true'
    job('docker.backup.verify',{'target':'fixture-backup','backup_id':backup['id']})
    restored=job('docker.restore.apply',{'target':'fixture-backup','backup_id':backup['id']})
    actual=run(['docker','exec',restored['containers'][0],'psql','-U','postgres','-Atc','SELECT value FROM acceptance'])
    assert actual=='verified database row'
    assert run(['docker','exec',restored['containers'][0],'cat','/fixture/evidence'])=='persistent bind content'
    assert backup['id'] in job('docker.backup.list',{'target':'fixture-backup'})['backups'][0]['id']
    output['database_consistent_encrypted_backup_and_isolated_restore']='passed'
    output['image_exports_and_compose_metadata']='included and authenticated'
    # Simulate an abandoned offline operation; only the independent root timer
    # may recover it. No API/worker process performs this inverse.
    import uuid
    identity=uuid.uuid4().hex
    journal=Path('/var/lib/serverhub-broker/operations')/(identity+'.json')
    run(['docker','stop',container])
    journal.write_text(json.dumps({'id':identity,'kind':'docker_start','containers':[container],
        'state':'armed','deadline':time.time()-1}))
    journal.chmod(0o600)
    for _ in range(50):
        if json.loads(journal.read_text())['state']=='reverted':
            break
        time.sleep(1)
    assert json.loads(journal.read_text())['state']=='reverted'
    assert run(['docker','inspect','--format','{{.State.Running}}',container])=='true'
    output['independent_watchdog_abandoned_offline_operation']='passed'
    output['source_data_overwritten']=False
    print('HOST_OPERATIONS_EVIDENCE='+json.dumps(output),flush=True)
finally:
    # Fixture resources belong only to this guarded disposable runner.
    run(['docker','rm','-f','shub-ci-database'])
    run(['dpkg','--remove','shub-disposable-fixture'])
    client.close()
