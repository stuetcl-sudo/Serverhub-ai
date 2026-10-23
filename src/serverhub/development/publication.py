"""API-only draft PR publication. Credentials never enter the build sandbox.

Only a verified candidate, root-registered repository/path prefixes and an
expiring development.publish grant can create a new branch and draft PR.
Existing refs are never updated, merged, deleted or force-pushed.
"""
from __future__ import annotations

import os
import hashlib
import re
from urllib.parse import urlsplit

import httpx

from .config import DevelopmentError


def publish_candidate(project, job, *, transport=None):
    token = os.environ.get(project.publication_token_env or '', '')
    remote = urlsplit(project.repository)
    match = re.fullmatch(r'/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?', remote.path)
    if not project.publication_paths or not token or remote.hostname != 'github.com' or not match:
        raise DevelopmentError('Publication requires a root-registered GitHub HTTPS repository, allowed paths and an API-only credential')
    result = job.result or {}
    changes = result.get('source_changes')
    base = result.get('base_commit')
    if job.state != 'succeeded' or result.get('verified') is not True or not re.fullmatch(r'[a-f0-9]{40,64}', base or ''):
        raise DevelopmentError('Only a successfully verified candidate with an exact base commit can be published')
    if not isinstance(changes, list) or not changes or len(changes) > 100 or len(str(changes).encode()) > 600000:
        raise DevelopmentError('Candidate contains no bounded publishable text changes')
    entries = []
    seen = set()
    for item in changes:
        path = item.get('path', '')
        if not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', path) or any(p in {'..','.git','.github','.env'} for p in path.split('/')) or path.startswith('/'):
            raise DevelopmentError('Candidate publication path is unsafe')
        if path in seen or not any(path == prefix or path.startswith(prefix.rstrip('/') + '/') for prefix in project.publication_paths):
            raise DevelopmentError('Candidate publication exceeds root-registered source paths')
        seen.add(path)
        content = item.get('content')
        if content is not None and (not isinstance(content,str) or '\0' in content or len(content.encode()) > 200000):
            raise DevelopmentError('Only bounded UTF-8 text files may be published')
        if item.get('sha256') != (hashlib.sha256(content.encode()).hexdigest() if content is not None else None):
            raise DevelopmentError('Candidate text was changed or redacted after verification; publication refused')
        mode = item.get('mode', '100644')
        if mode not in {'100644','100755'}:
            raise DevelopmentError('Candidate publication mode must be a regular source file')
        entries.append({'path':path,'mode':mode,'type':'blob',**({'sha':None} if content is None else {'content':content})})
    repo = '/repos/' + match[1] + '/' + match[2]
    branch = 'serverhub/' + job.id
    if not re.fullmatch(r'serverhub/[a-zA-Z0-9_-]{1,80}', branch):
        raise DevelopmentError('Invalid candidate branch identity')
    with httpx.Client(base_url='https://api.github.com', headers={'Authorization':'Bearer ' + token,
            'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},
            timeout=30, trust_env=False, follow_redirects=False, transport=transport) as client:
        def request(method, path, **kwargs):
            response = client.request(method, repo + path, **kwargs)
            if response.status_code >= 300:
                # Do not log remote bodies, URLs with credentials, headers or tokens.
                raise DevelopmentError(f'GitHub publication rejected HTTP {response.status_code}; check the API-only repository credential and branch state')
            return response.json()
        # Bind the candidate to the current upstream base; never silently rebase
        # verified changes onto a new, untested version.
        current = request('GET', '/git/ref/heads/' + project.base_ref)
        if current['object']['sha'] != base:
            raise DevelopmentError('Upstream base changed; run a new verified job before publication')
        parent = request('GET', '/git/commits/' + base)
        tree = request('POST', '/git/trees', json={'base_tree':parent['tree']['sha'],'tree':entries})
        identity = {'name':'ServerHub AI OS', 'email':'serverhub-ai@users.noreply.github.com',
                    'date':job.finished_at.isoformat() + ('Z' if job.finished_at.tzinfo is None else '')}
        commit = request('POST', '/git/commits', json={'author':identity,'committer':identity,'message':'ServerHub verified candidate ' + job.id,
            'tree':tree['sha'],'parents':[base]})
        ref = client.get(repo + '/git/ref/heads/' + branch)
        if ref.status_code == 404:
            request('POST', '/git/refs', json={'ref':'refs/heads/' + branch,'sha':commit['sha']})
        elif ref.status_code != 200 or ref.json()['object']['sha'] != commit['sha']:
            raise DevelopmentError('Candidate branch already exists with different content; no existing ref was changed')
        existing = request('GET', '/pulls', params={'head':match[1] + ':' + branch,'base':project.base_ref,'state':'open'})
        pr = existing[0] if existing else request('POST', '/pulls', json={'title':'ServerHub candidate ' + job.id,
            'head':branch,'base':project.base_ref,'draft':True,
            'body':'Verified isolated development job `' + job.id + '`. Candidate SHA-256: `' +
                str((result.get('candidate') or {}).get('sha256','')) + '`. Review required. No production deployment or merge was performed.'})
        if not re.fullmatch(r'https://github\.com/' + re.escape(match[1] + '/' + match[2]) + r'/pull/[0-9]+', pr.get('html_url','')):
            raise DevelopmentError('GitHub returned an unexpected PR URL; inspect candidate branch before retrying')
        return {'repository':match[1] + '/' + match[2],'branch':branch,'commit':commit['sha'],
            'pull_request':pr['html_url'],'draft':True,'merged':False}
