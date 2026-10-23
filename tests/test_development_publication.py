"""GitHub HTTP contract tests; no external repository/token or production access."""
from datetime import datetime
from types import SimpleNamespace
import hashlib
import json

import httpx
import pytest

from serverhub.development.config import Command, DevelopmentError, Project
from serverhub.development.publication import publish_candidate


@pytest.fixture
def candidate(monkeypatch):
    monkeypatch.setenv('SERVERHUB_GITHUB_JARVIS', 'fixture-only-not-a-real-token')
    config = Project(name='jarvis',repository='https://github.com/example/Jarvis-os.git',
        tests=[Command(argv=['/usr/bin/true'])],publication_token_env='SERVERHUB_GITHUB_JARVIS',publication_paths=['app'])
    content = "print('repaired')\n"
    job = SimpleNamespace(id='test-job',state='succeeded',finished_at=datetime(2026,10,24),result={
        'verified':True,'base_commit':'a'*40,'candidate':{'sha256':'b'*64},
        'source_changes':[{'path':'app/version.py','content':content,'sha256':hashlib.sha256(content.encode()).hexdigest()}]})
    return config,job


@pytest.mark.parametrize("existing", [False, True])
def test_verified_candidate_only_creates_new_branch_and_draft_pr(candidate, existing):
    config,job = candidate
    calls = []
    def handler(request):
        calls.append((request.method,request.url.path,json.loads(request.content) if request.content else None))
        path = request.url.path
        if request.method=='GET' and path.endswith('/git/ref/heads/main'):
            return httpx.Response(200,json={'object':{'sha':'a'*40}})
        if path.endswith('/git/commits/'+'a'*40):
            return httpx.Response(200,json={'tree':{'sha':'parent-tree'}})
        if path.endswith('/git/trees'):
            return httpx.Response(201,json={'sha':'new-tree'})
        if path.endswith('/git/commits'):
            return httpx.Response(201,json={'sha':'c'*40})
        if path.endswith('/git/ref/heads/serverhub/test-job'):
            return httpx.Response(200,json={'object':{'sha':'c'*40}}) if existing else httpx.Response(404)
        if path.endswith('/git/refs'):
            return httpx.Response(201,json={'ref':'refs/heads/serverhub/test-job'})
        if path.endswith('/pulls'):
            return httpx.Response(200 if request.method=='GET' else 201,json=([{'html_url':'https://github.com/example/Jarvis-os/pull/1'}] if existing else []) if request.method=='GET' else
                {'html_url':'https://github.com/example/Jarvis-os/pull/1'})
        raise AssertionError(str(request.url))
    result = publish_candidate(config,job,transport=httpx.MockTransport(handler))
    assert result['draft'] and not result['merged']
    assert not any(method in {'PATCH','PUT','DELETE'} for method,_,_ in calls)
    tree = next(payload for method,path,payload in calls if path.endswith('/git/trees'))
    assert tree['tree'][0]['content'] == job.result['source_changes'][0]['content']
    if existing:
        assert not any(method=='POST' and path.endswith(('/pulls','/git/refs')) for method,path,_ in calls)
    else:
        assert calls[-1][2]['draft'] is True


@pytest.mark.parametrize('defect',['outside','workflow','unverified','redacted','missing-token','base-moved','foreign-ref'])
def test_publication_fails_closed_without_mutating_existing_refs(candidate,monkeypatch,defect):
    config,job = candidate
    if defect=='outside':
        job.result['source_changes'][0]['path']='private/secret.py'
    if defect=='workflow':
        job.result['source_changes'][0]['path']='.github/workflows/steal.yaml'
    if defect=='unverified':
        job.result['verified']=False
    if defect=='redacted':
        job.result['source_changes'][0]['content']='redacted'
    if defect=='missing-token':
        monkeypatch.delenv('SERVERHUB_GITHUB_JARVIS')
    mutations=[]
    def handler(request):
        if request.method=='GET' and request.url.path.endswith('/git/ref/heads/main'):
            return httpx.Response(200,json={'object':{'sha':('d' if defect=='base-moved' else 'a')*40}})
        if request.url.path.endswith('/git/commits/'+'a'*40):
            return httpx.Response(200,json={'tree':{'sha':'parent'}})
        if request.method=='POST' and request.url.path.endswith(('/git/trees','/git/commits')):
            return httpx.Response(201,json={'sha':'c'*40})
        if request.url.path.endswith('/git/ref/heads/serverhub/test-job'):
            return httpx.Response(200,json={'object':{'sha':'foreign'}})
        mutations.append(request.method)
        raise AssertionError('Unexpected write')
    with pytest.raises(DevelopmentError):
        publish_candidate(config,job,transport=httpx.MockTransport(handler))
    assert not mutations
