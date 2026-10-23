"""Installed-system verifier: real HTTP request shapes, no changes by default."""
import json

import httpx
import pytest

from serverhub.ops.verify_install import controller_url, read_token, verify
from serverhub.ops import verify_install


@pytest.mark.parametrize('url', ['http://192.168.122.10:9080', 'https://owner:secret@example.test',
                                 'https://example.test/api', 'https://example.test?token=secret',
                                 'https://example.test:bad', 'file:///etc/passwd'])
def test_reject_unsafe_controller_origins(url):
    with pytest.raises(ValueError):
        controller_url(url)


def test_private_token_file_and_no_symlink(tmp_path):
    token = tmp_path / 'token'
    token.write_text('private-token\n')
    token.chmod(0o600)
    assert read_token(token) == 'private-token'
    token.chmod(0o644)
    with pytest.raises(ValueError):
        read_token(token)
    token.chmod(0o600)
    link = tmp_path / 'link'
    link.symlink_to(token)
    with pytest.raises(OSError):
        read_token(link)
    directory = tmp_path / 'directory'
    directory.mkdir()
    with pytest.raises(ValueError):
        read_token(directory)


def fixture_transport(requests, *, anonymous_status=401, model_ready=True, job_state='succeeded',
                      gaps=None, diagnostic='ok', host='node1'):
    def handle(request):
        path = request.url.path
        requests.append((request.method, path, request.headers.get('Authorization'),
                         json.loads(request.content) if request.content else None))
        if path == '/health':
            return httpx.Response(200, json={'status': 'ok'})
        if path == '/':
            return httpx.Response(200, text='<script src="/assets/app.js"></script>',
                                  headers={'content-type': 'text/html'})
        if path == '/assets/app.js':
            return httpx.Response(200, text='console.log("built")', headers={'content-type': 'text/javascript'})
        if path == '/api/hosts':
            assert not request.headers.get('Authorization') and not request.headers.get('cookie')
            return httpx.Response(anonymous_status, json={'detail': 'never print this private body'})
        assert request.headers['Authorization'] == 'Bearer private-token'
        if path == '/api/auth/me':
            return httpx.Response(200, json={'role': 'owner'})
        if path == '/api/diagnostics':
            return httpx.Response(200, json={'checks': [
                {'id': name, 'status': diagnostic if name == 'worker' else 'ok',
                 'evidence': {'password': 'private-evidence'}}
                for name in ['database', 'worker', 'models', 'frontend']]})
        if path == '/api/settings/models':
            return httpx.Response(200, json={'routes': {'default': {'kind': 'ollama', 'api_key_env': 'PRIVATE_KEY_NAME'}}})
        if path == '/api/settings/models/test':
            return httpx.Response(200, json={'ready': model_ready, 'tool_calling': model_ready})
        if path == '/api/jobs':
            assert requests[-1][3]['spec'] == {'operation': 'inventory.refresh', 'arguments': {}}
            assert requests[-1][3]['token_budget'] == requests[-1][3]['cost_budget'] == 0
            return httpx.Response(202, json={'id': 'receipt'})
        if path == '/api/jobs/receipt':
            return httpx.Response(200, json={'state': job_state, 'host_id': host,
                                            'result': {'inventory': {'os': {'kernel': 'fixture'}, 'errors': gaps or []}}})
        raise AssertionError('Unexpected request: ' + path)
    return httpx.MockTransport(handle)


def test_default_verification_only_reads_and_never_prints_private_responses():
    requests = []
    with httpx.Client(base_url='http://127.0.0.1:9080', transport=fixture_transport(requests)) as client:
        client.cookies.set('session', 'must-not-authenticate-public-check')
        result = verify(client, 'private-token')
    assert result['state'] == 'passed'
    assert all(method == 'GET' for method, *_ in requests)
    assert 'private-token' not in json.dumps(result)
    assert 'private-evidence' not in json.dumps(result)


def test_explicit_probe_and_fixed_durable_job():
    requests = []
    with httpx.Client(base_url='https://controller.test', transport=fixture_transport(requests)) as client:
        result = verify(client, 'private-token', host_id='node1', model_route='default')
    assert result['state'] == 'passed'
    assert [path for method, path, *_ in requests if method == 'POST'] == ['/api/settings/models/test', '/api/jobs']


@pytest.mark.parametrize('options,expected', [({'anonymous_status': 200}, 'failed'),
    ({'model_ready': False}, 'failed'), ({'job_state': 'waiting_approval'}, 'failed'),
    ({'gaps': [{'collector': 'broker'}]}, 'partial'), ({'diagnostic': 'warning'}, 'partial'),
    ({'diagnostic': 'error'}, 'failed'), ({'host': 'different-host'}, 'failed')])
def test_failure_and_collection_gaps_are_never_green(options, expected):
    requests = []
    with httpx.Client(base_url='https://controller.test', transport=fixture_transport(requests, **options)) as client:
        result = verify(client, 'private-token', host_id='node1', model_route='default')
    assert result['state'] == expected
    assert 'never print this private body' not in json.dumps(result)


def test_timeout_keeps_durable_job_receipt():
    requests = []
    seconds = [0]
    def sleep(amount):
        seconds[0] += amount
    with httpx.Client(base_url='https://controller.test', transport=fixture_transport(requests, job_state='queued')) as client:
        result = verify(client, 'private-token', host_id='node1', timeout=2, clock=lambda: seconds[0], sleep=sleep)
    job = next(check for check in result['checks'] if check['id'] == 'persistent_inventory_job')
    assert result['state'] == 'failed' and job['job_id'] == 'receipt'
    assert len([item for item in requests if item[1] == '/api/jobs']) == 1
    assert not any(path.endswith('/cancel') for _, path, *_ in requests)


@pytest.mark.parametrize('logout_status,expected', [(200, 0), (503, 1)])
def test_password_login_revokes_only_the_created_session(monkeypatch, capsys, logout_status, expected):
    requests = []
    base = fixture_transport(requests)
    def handler(request):
        if request.url.path == '/api/auth/login':
            assert json.loads(request.content)['password'] == 'never-print-password'
            return httpx.Response(200, json={'token': 'private-token'})
        if request.url.path == '/api/auth/logout':
            assert request.headers['Authorization'] == 'Bearer private-token'
            return httpx.Response(logout_status, json={'private': 'never-print-password'})
        return base.handle_request(request)
    original = httpx.Client
    monkeypatch.setattr(verify_install.httpx, 'Client', lambda **kw: original(**kw, transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(verify_install.getpass, 'getpass', lambda prompt: 'never-print-password')
    assert verify_install.main(['--url', 'https://controller.test', '--username', 'owner']) == expected
    output = capsys.readouterr().out
    assert 'private-token' not in output and 'never-print-password' not in output
    assert json.loads(output)['state'] == ('passed' if expected == 0 else 'failed')


def test_missing_core_diagnostics_are_not_accepted():
    requests = []
    base = fixture_transport(requests)
    def handler(request):
        if request.url.path == '/api/diagnostics':
            return httpx.Response(200, json={'checks': [{'id': 'models', 'status': 'ok'}]})
        return base.handle_request(request)
    with httpx.Client(base_url='https://controller.test', transport=httpx.MockTransport(handler)) as client:
        assert verify(client, 'private-token')['state'] == 'failed'
