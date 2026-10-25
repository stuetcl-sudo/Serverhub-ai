"""Development controller/MCP regression tests: no production or provider access."""
from datetime import timedelta

import pytest

from test_control_plane import control as control, enroll_node
from serverhub.auth import Principal, create_session
from serverhub.database import SessionLocal, utcnow
from serverhub.development.config import Command, DevelopmentError, Project, load_projects
from serverhub.models import Job, Policy, User
from serverhub.oauth_models import OAuthClient
from serverhub.policy import PermissionDenied, authorize


@pytest.fixture
def registered(monkeypatch):
    project = Project(name='jarvis-os', repository='https://github.com/stuetcl-sudo/Jarvis-os.git',
                      tests=[Command(argv=['/usr/bin/true'])])
    monkeypatch.setattr('serverhub.development.config.load_projects', lambda: {project.name: project})
    return project


def mcp_token(owner_id, scopes):
    with SessionLocal() as db:
        client = OAuthClient(name='isolated MCP test', redirect_uris=['https://example.invalid/callback'], created_by=owner_id)
        db.add(client)
        db.flush()
        token = create_session(db, db.get(User, owner_id), audience='mcp', label='oauth:' + client.id, scopes=scopes)
        db.commit()
    return {'Authorization': 'Bearer ' + token}


def call(client, headers, name, arguments=None):
    response = client.post('/mcp', headers=headers, json={'jsonrpc':'2.0', 'id':1,
        'method':'tools/call', 'params':{'name':name, 'arguments':arguments or {}}})
    assert response.status_code == 200, response.text
    return response.json()


def test_empty_and_invalid_project_configuration(tmp_path):
    config = tmp_path / 'projects.yaml'
    for text in ('projects: []', 'projects: {}'):
        config.write_text(text)
        assert load_projects(config, enforce_permissions=False) == {}
    for text in ('projects: {secret: confidential}', 'projects: [{repository: secret-password}]', 'projects: ['):
        config.write_text(text)
        with pytest.raises(DevelopmentError) as error:
            load_projects(config, enforce_permissions=False)
        assert 'secret-password' not in str(error.value)


def test_project_profile_is_hostless_expiring_and_excludes_staging(control, registered):
    client, headers, identity = control
    response = client.post('/api/policies/profiles', headers=headers, json={
        'profile':'development', 'subject_id':identity, 'project':registered.name, 'hours':1})
    assert response.status_code == 201, response.text
    policies = response.json()['policies']
    assert all(p['host_id'] is None and p['environment'] == 'development' for p in policies)
    assert not any('development.deploy' in p['operations'] for p in policies)
    with SessionLocal() as db:
        user = db.get(User, identity)
        actor = Principal(id=user.id, username=user.username, role=user.role)
        for operation in ('development.workspace', 'development.patch', 'development.artifact', 'development.test'):
            authorize(db, actor, operation, project=registered.name)
        for operation, project in (('development.stage',registered.name), ('development.patch','other-project'),
                                   ('development.release',registered.name), ('systemd.restart',registered.name)):
            with pytest.raises(PermissionDenied):
                authorize(db, actor, operation, project=project)
        grant = db.get(Policy, policies[0]['id'])
        grant.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
        with pytest.raises(PermissionDenied):
            authorize(db, actor, 'development.workspace', project=registered.name)
    bad = client.post('/api/policies/profiles', headers=headers, json={
        'profile':'development', 'subject_id':identity, 'project':registered.name, 'services':['ssh']})
    assert bad.status_code == 422


def test_mcp_project_job_lifecycle_and_scopes(control, registered):
    client, headers, identity = control
    mcp = mcp_token(identity, ['serverhub:read','serverhub:jobs','serverhub:policies'])
    readonly = mcp_token(identity, ['serverhub:read'])
    assert client.post('/mcp', headers=headers, json={'jsonrpc':'2.0','id':1,'method':'tools/list'}).status_code == 401
    assert client.get('/api/projects', headers=mcp).status_code == 401
    listed = call(client,mcp,'list_projects')['result']
    assert not listed.get('isError')
    import json
    descriptor = json.loads(listed['content'][0]['text'])[0]
    assert descriptor['execution_location'] == 'controller' and descriptor['isolation'] == 'bubblewrap'
    denied = client.post('/mcp', headers=readonly, json={'jsonrpc':'2.0','id':1,'method':'tools/call',
        'params':{'name':'create_development_job','arguments':{'project':registered.name}}})
    assert denied.status_code == 403
    grant = call(client,mcp,'grant_development_profile',{'subject_id':identity,'project':registered.name,'hours':1})
    assert not grant.get('result',{}).get('isError'), grant
    response = client.post('/api/jobs',headers=headers,json={'kind':'development','spec':{'project':registered.name},
        'idempotency_key':'development-test'})
    assert response.status_code == 202, response.text
    job_id = response.json()['id']
    assert response.json()['project'] == registered.name and response.json()['host_id'] is None
    for tool in ('job_logs','development_artifacts'):
        result = call(client,mcp,tool,{'job_id':job_id})
        assert not result.get('result',{}).get('isError'), result
    result = call(client,mcp,'cancel_job',{'job_id':job_id})
    assert not result.get('result',{}).get('isError'), result
    with SessionLocal() as db:
        assert db.get(Job,job_id).state == 'cancelled'
    assert call(client,mcp,'create_development_job',{'project':registered.name,'command':'sudo anything'}).get('result',{}).get('isError')


def test_infrastructure_host_selection_is_explicit_when_ambiguous(control):
    client, headers, _ = control
    assert client.post('/api/chat',headers=headers,json={'prompt':'Inspect health'}).status_code == 422
    first,_ = enroll_node(client,headers)
    response = client.post('/api/chat',headers=headers,json={'prompt':'Inspect health'})
    assert response.status_code == 202 and response.json()['host_id'] == first['host_id']
    enroll_node(client,headers,'second')
    response = client.post('/api/chat',headers=headers,json={'prompt':'Inspect health'})
    assert response.status_code == 422 and 'host' in response.text.lower()


def test_project_errors_are_actionable_and_do_not_echo_yaml(control, monkeypatch):
    client, headers, _ = control
    def broken():
        raise DevelopmentError('secret-password from parser')
    monkeypatch.setattr('serverhub.development.config.load_projects', broken)
    response = client.get('/api/projects', headers=headers)
    assert response.status_code == 503
    assert response.json()['detail']['code'] == 'projects_configuration_invalid'
    assert 'secret-password' not in response.text
    diagnostics = client.get('/api/diagnostics',headers=headers)
    assert diagnostics.status_code == 200
    assert next(c for c in diagnostics.json()['checks'] if c['id']=='projects')['status'] == 'error'
    assert 'secret-password' not in diagnostics.text


def test_resume_rechecks_original_subject_and_revocation(control, registered):
    client, headers, identity = control
    response = client.post('/api/jobs', headers=headers, json={'kind':'development', 'project':registered.name,
        'spec':{'project':registered.name}})
    assert response.status_code == 202
    job_id = response.json()['id']
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        job.state = 'waiting_approval'
        job.result = {'denial':{'operation':'development.patch','environment':'development','arguments':{}}}
        db.commit()
    assert client.post('/api/jobs/' + job_id + '/resume', headers=headers).status_code == 403
    response = client.post('/api/policies/profiles', headers=headers, json={'profile':'development',
        'subject_id':identity,'project':registered.name,'hours':1})
    assert response.status_code == 201
    assert client.post('/api/jobs/' + job_id + '/resume', headers=headers).status_code == 200
    with SessionLocal() as db:
        job = db.get(Job,job_id)
        job.state = 'waiting_approval'
        db.commit()
    for grant in response.json()['policies']:
        assert client.patch('/api/policies/' + grant['id'], headers=headers,json={'enabled':False}).status_code == 200
    assert client.post('/api/jobs/' + job_id + '/resume', headers=headers).status_code == 403
    with SessionLocal() as db:
        assert db.get(Job,job_id).state == 'waiting_approval'


def test_no_patch_pipeline_survives_artifact_approval_without_repeating_tests(control, monkeypatch, tmp_path):
    from test_development_workspaces import repository
    from serverhub.development import workflow
    from serverhub.development.sandbox import CommandResult
    from serverhub.jobs import Worker
    client, headers, identity = control
    source = repository(tmp_path / 'source')
    project = Project(name='jarvis-os', repository=str(source), tests=[Command(argv=['/usr/bin/true'])])
    monkeypatch.setenv('SERVERHUB_STATE_DIR', str(tmp_path / 'worker-state'))
    from serverhub.settings import get_settings
    get_settings.cache_clear()
    monkeypatch.setattr('serverhub.development.config.load_projects', lambda: {project.name:project})
    monkeypatch.setattr(workflow, 'load_projects', lambda: {project.name:project})
    runs = []
    class RunnerFixture:
        def __init__(self, project):
            pass
        def preflight(self, workspace):
            return {'available':True}
        def run(self, workspace, command, heartbeat=None):
            runs.append(command.argv)
            return CommandResult(command.argv, 0, 'fixture check passed')
    monkeypatch.setattr(workflow, 'SandboxRunner', RunnerFixture)
    with SessionLocal() as db:
        db.add(Policy(name='incomplete legacy development profile',subject_id=identity,project=project.name,
            environment='development',operations=['development.workspace','development.test'],constraints={},
            expires_at=utcnow()+timedelta(hours=1),created_by=identity))
        db.commit()
    response = client.post('/api/jobs',headers=headers,json={'kind':'development','project':project.name,
        'spec':{'project':project.name}})
    assert response.status_code == 202
    job_id = response.json()['id']
    assert Worker(isolated=False).run_once()
    blocked = client.get('/api/jobs/' + job_id,headers=headers).json()
    assert blocked['state'] == 'waiting_approval'
    assert blocked['result']['denial']['operation'] == 'development.artifact'
    assert blocked['checkpoint']['development']['completed'] == ['tests:0']
    assert client.post('/api/policies/profiles',headers=headers,json={'profile':'development','subject_id':identity,
        'project':project.name,'hours':1}).status_code == 201
    assert client.post('/api/jobs/' + job_id + '/resume',headers=headers).status_code == 200
    assert Worker(isolated=False).run_once()
    result = client.get('/api/jobs/' + job_id,headers=headers).json()
    assert result['state'] == 'succeeded' and result['result']['verified'], result
    assert len(runs) == 1
    assert result['result']['source_patch'] == ''
    assert (source / 'app.py').read_text() == "print('old')\n"


def test_publication_requires_separate_live_project_grant_and_audits(control, registered, monkeypatch):
    client, headers, identity = control
    contract = registered.model_copy(update={'publication_token_env':'SERVERHUB_GITHUB_JARVIS','publication_paths':['app']})
    monkeypatch.setattr('serverhub.development.config.load_projects',lambda:{contract.name:contract})
    response = client.post('/api/jobs', headers=headers, json={'kind':'development','project':contract.name,
        'spec':{'project':contract.name}})
    job_id = response.json()['id']
    with SessionLocal() as db:
        job = db.get(Job,job_id)
        job.state,job.result = 'succeeded',{'verified':True}
        db.commit()
    assert client.post('/api/projects/jobs/' + job_id + '/publish',headers=headers).status_code == 403
    grant = client.post('/api/policies/profiles', headers=headers,json={'profile':'development','project':contract.name,
        'subject_id':identity,'hours':1,'allow_publication':True})
    assert grant.status_code == 201,grant.text
    published=[]
    def publish(project, job):
        published.append(job.id)
        return {'pull_request':'https://github.com/example/Jarvis-os/pull/1','draft':True,'merged':False}
    monkeypatch.setattr('serverhub.development.publication.publish_candidate',publish)
    for _ in range(2):
        assert client.post('/api/projects/jobs/' + job_id + '/publish',headers=headers).status_code == 200
    assert published == [job_id]
    for policy in grant.json()['policies']:
        client.patch('/api/policies/' + policy['id'],headers=headers,json={'enabled':False})
    assert client.post('/api/projects/jobs/' + job_id + '/publish',headers=headers).status_code == 403


def test_unverified_plain_development_never_reports_success(control, registered, monkeypatch):
    from serverhub.jobs import HANDLERS, Worker
    client, headers, _ = control
    monkeypatch.setitem(HANDLERS, 'development', lambda ctx,spec: {'verified':False,'tests_passed':True,'staging':{'verified':False}})
    submitted = client.post('/api/jobs',headers=headers,json={'kind':'development','project':registered.name,
        'spec':{'project':registered.name}})
    assert submitted.status_code == 202
    assert Worker(isolated=False).run_once()
    result = client.get('/api/jobs/' + submitted.json()['id'],headers=headers).json()
    assert result['state'] == 'partial'


def test_mcp_budget_ceiling_and_role_enforced(control, registered):
    import json
    from serverhub.models import ModelRoute, User
    client, headers, identity = control
    token = mcp_token(identity, ['serverhub:read', 'serverhub:jobs', 'serverhub:policies'])
    with SessionLocal() as db:
        db.add(ModelRoute(name='development', enabled=True, updated_by=identity, config={
            'kind':'ollama','model':'fixture','base_url':'http://localhost:11434',
            'ordinary_job_token_limit':30000,'ordinary_job_cost_limit':1,
            'max_job_token_budget':50000,'max_job_cost_budget':5}))
        db.commit()
    rejected = call(client, token, 'create_development_job', {'project':registered.name,
        'prompt':'Inspect source','token_budget':50001})
    assert rejected['result']['isError']
    accepted = call(client, token, 'create_development_job', {'project':registered.name,
        'prompt':'Inspect source','token_budget':40000})
    assert not accepted['result'].get('isError'), accepted
    identity_job = json.loads(accepted['result']['content'][0]['text'])['id']
    assert call(client, token, 'update_job_budget', {'job_id':identity_job,'token_budget':50001,'cost_budget':1})['result']['isError']
    # Existing OAuth tokens resolve the current role; owner status isn't cached.
    with SessionLocal() as db:
        db.get(User, identity).role = 'administrator'
        db.commit()
    assert call(client, token, 'update_job_budget', {'job_id':identity_job,'token_budget':40000,'cost_budget':1})['result']['isError']
