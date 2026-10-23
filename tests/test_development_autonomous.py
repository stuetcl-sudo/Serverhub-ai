"""Model fixtures test durable development semantics; native isolation is tested separately."""
from datetime import timedelta
import pytest

from test_core import core_env as core_env, owner as owner
from test_development_workspaces import repository
from serverhub.ai.providers import Completion, ProviderConfig, ToolCall
from serverhub.database import SessionLocal, utcnow
from serverhub.development import autonomous
from serverhub.development.config import Command, Project
from serverhub.development.sandbox import CommandResult
from serverhub.jobs import HANDLERS, Worker, submit_job
from serverhub.models import Job, Policy


@pytest.mark.parametrize('scenario',['repair','stall'])
def test_model_repairs_after_failed_check_and_exports_only_verified_source(core_env,owner,monkeypatch,tmp_path,scenario):
    source=repository(tmp_path/'source')
    project=Project(name='example',repository=str(source),tests=[Command(argv=['/usr/bin/true'])])
    monkeypatch.setattr(autonomous,'load_projects',lambda:{'example':project})
    config=ProviderConfig(kind='ollama',base_url='http://127.0.0.1',model='fixture',context_limit=16384,max_output_tokens=512)
    monkeypatch.setattr(autonomous,'load_routes',lambda:{'default':config})
    class IsolatedRunnerFixture:
        def __init__(self,project): pass
        def preflight(self,workspace): return {'available':True}
        def run(self,workspace,command,heartbeat=None):
            if heartbeat: heartbeat()
            correct=(workspace/'app.py').read_text()=="print('new')\n"
            return CommandResult(command.argv,0 if correct else 1,'passed' if correct else 'expected new application version')
    monkeypatch.setattr(autonomous,'SandboxRunner',IsolatedRunnerFixture)
    responses=iter([
        Completion('',tool_calls=[ToolCall('plan','plan',{'steps':['Inspect','Repair failed version check','Verify']}),
                                  ToolCall('read','read_file',{'path':'app.py'}),ToolCall('initial','run_checks',{})]),
        Completion('',tool_calls=[ToolCall('edit','edit_file',{'path':'app.py','old':"print('old')",'new':"print('new')"})]),
        Completion('',tool_calls=[ToolCall('checks','run_checks',{})]),
        Completion('',tool_calls=[ToolCall('finish','finish',{})])])
    if scenario=='stall':
        responses=iter([Completion('',tool_calls=[ToolCall('read','read_file',{'path':'app.py'})]),
            *[Completion('',tool_calls=[ToolCall('bad-'+str(index),'edit_file',{'path':'app.py','old':'no matching content','new':'new'})]) for index in range(3)]])
    class ProviderFixture:
        def __init__(self,config): self.config=config
        def complete(self,messages,tools,budget,before_request=None):
            budget.preflight(self.config,messages,tools=tools)
            if before_request: before_request()
            result=next(responses)
            result.input_tokens,result.output_tokens=11,7
            budget.charge(result)
            return result
    monkeypatch.setattr(autonomous,'ChatProvider',ProviderFixture)
    HANDLERS['development_autonomous']=autonomous.autonomous_development
    with SessionLocal() as db:
        db.add(Policy(name='scoped development',subject_id='owner',host_id='node1',project='example',environment='any',
            operations=['development.workspace','development.read','development.patch','development.test','development.stage'],
            constraints={},expires_at=utcnow()+timedelta(hours=1),created_by='owner'))
        db.commit()
        job=submit_job(db,owner,'development_autonomous',{'project':'example','prompt':'Repair the failing application version'},
                       project='example',host_id='node1',token_budget=50000)
        identity=job.id
        db.commit()
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job=db.get(Job,identity)
        if scenario=='stall':
            assert job.state=='partial',job.error
            assert not job.result['verified'] and 'Three rounds' in job.result['reason']
            assert job.tokens_used==72
            assert (source/'app.py').read_text()=="print('old')\n"
            return
        assert job.state=='succeeded',job.error
        assert job.result['verified'] and job.result['tests_passed']
        assert job.tokens_used==72 and job.checkpoint['developer']['ready']
        assert job.checkpoint['developer']['completed_calls']['initial']['verified'] is False
        assert [record['returncode'] for record in job.result['commands']]==[1,0]
        assert job.result['candidate']['sha256']
    assert (source/'app.py').read_text()=="print('old')\n"



def test_failed_parent_cannot_leave_an_unattended_orphan_executing(core_env,owner):
    HANDLERS['orphan-fixture']=lambda ctx,spec: {'unexpected_execution':True}
    with SessionLocal() as db:
        parent=submit_job(db,owner,'orphan-fixture',{})
        child=submit_job(db,owner,'orphan-fixture',{},parent_id=parent.id)
        parent.state='failed'
        identity=child.id
        db.commit()
    assert not Worker(isolated=False).run_once()
    with SessionLocal() as db:
        child=db.get(Job,identity)
        assert child.state=='cancelled' and child.failure_class=='parent_stopped'
        assert not child.result

def test_development_catalog_tracks_inspection_and_verification():
    def names(state):
        return {item['function']['name'] for item in autonomous.available_development_tools(state)}
    assert names({})=={'plan','read_file','list_files'}
    inspected=names({'read_hashes':{'app.py':'digest'}})
    assert 'set_python_constant' in inspected and 'run_checks' in inspected
    assert 'finish' not in inspected
    assert 'finish' in names({'read_hashes':{'app.py':'digest'},'checked_commit':'commit'})
