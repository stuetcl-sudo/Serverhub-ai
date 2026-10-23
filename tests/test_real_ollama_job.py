"""Opt-in real model + real HTTP + durable job lifecycle. No fake provider."""
import json
import os

import pytest
from sqlalchemy import select

from test_core import core_env as core_env, client as client, bearer
from serverhub.ai import orchestrator
from serverhub.ai.providers import ProviderConfig
from serverhub.database import SessionLocal
from serverhub.jobs import Worker
from serverhub.models import InventorySample, Job, JobEvent


@pytest.mark.skipif(not os.environ.get('SERVERHUB_REAL_OLLAMA_URL'), reason='Real Ollama URL not configured')
def test_qwen_read_only_job_with_real_tool_calls_and_accounting(client, monkeypatch):
    cfg = ProviderConfig(kind='ollama', model='qwen2.5:3b', base_url=os.environ['SERVERHUB_REAL_OLLAMA_URL'],
                         context_limit=8192, timeout_seconds=300, max_retries=1, max_output_tokens=512)
    monkeypatch.setattr(orchestrator, 'load_routes', lambda: {'default': cfg})
    with SessionLocal() as db:
        headers = bearer(db)
        db.add(InventorySample(host_id='node1', metrics={}))
        db.commit()
    response = client.post('/api/jobs', headers=headers, json={'kind':'autonomous','host_id':'node1',
        'token_budget':100000,'time_limit':1200, 'spec': {'max_steps':8,
        'prompt':'Read the existing host inventory using inventory__read. Then call task__verify with checks [{"kind":"inventory.fresh"}]. After both tools succeed, finish with a short report. Do not refresh inventory or delegate; the test host is already fresh.'}})
    assert response.status_code == 201, response.text
    identity = response.json()['id']
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        events = db.scalars(select(JobEvent).where(JobEvent.job_id == identity)).all()
        measured = [event.data for event in events if event.message == 'Model request accounting']
        evidence = {'model':cfg.model,'job_state':job.state,'attempts':job.attempts,
                    'used_units':job.tokens_used,'verified':job.result.get('verified'),
                    'operations':[item['operation'] for item in job.result.get('evidence',[])],
                    'accounting':measured,'error':job.error}
        print('REAL_OLLAMA_EVIDENCE=' + json.dumps(evidence))
        assert job.state == 'succeeded', evidence
        assert job.result['verified'] and job.tokens_used > 0
        assert measured and all(entry['usage_verified'] for entry in measured)
        assert 'inventory.read' in evidence['operations'] and 'task.verify' in evidence['operations']
