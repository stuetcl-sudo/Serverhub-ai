from fastapi.testclient import TestClient
from test_control_plane import control as control
from serverhub.auth import verify_password
from serverhub.database import SessionLocal
from serverhub.login_security import client_address
from serverhub.models import User
from serverhub.settings import get_settings
from starlette.requests import Request


def request(peer, forwarded):
    return Request({'type':'http','client':(peer,1234),'headers':[(b'x-forwarded-for',forwarded.encode())]})


def test_forwarded_ip_requires_explicit_proxy_and_right_to_left_validation(monkeypatch):
    monkeypatch.setenv('SERVERHUB_TRUSTED_PROXY_CIDRS','["127.0.0.1/32"]')
    get_settings.cache_clear()
    assert client_address(request('198.51.100.20','1.2.3.4')) == '198.51.100.20'
    assert client_address(request('127.0.0.1','1.2.3.4, 198.51.100.20')) == '198.51.100.20'
    assert client_address(request('127.0.0.1','not-an-address')) == '127.0.0.1'
    get_settings.cache_clear()


def test_attacker_cannot_lock_account_from_other_ip_or_spoof_headers(control):
    client, _, identity = control
    from serverhub.main import create_app
    body={'username':'owner','password':'incorrect-fixture'}
    with TestClient(create_app(),client=('198.51.100.5',1000)) as attacker:
        for _ in range(5):
            assert attacker.post('/api/auth/login',json=body).status_code == 401
        for _ in range(15):
            response=attacker.post('/api/auth/login',json=body,headers={'X-Forwarded-For':'203.0.113.99'})
            assert response.status_code == 429 and 'Retry-After' in response.headers
    with TestClient(create_app(),client=('198.51.100.6',1000)) as owner:
        response=owner.post('/api/auth/login',json={'username':'owner','password':'strong-test-password-42'})
        assert response.status_code == 200
        assert owner.get('/.well-known/oauth-authorization-server').status_code == 200
        assert owner.get('/api/auth/me').status_code == 200
    with SessionLocal() as db:
        user=db.get(User,identity)
        assert user.locked_until is None and verify_password('strong-test-password-42',user.password_hash)


def test_ip_limit_persists_across_app_instances_and_usernames(control,monkeypatch):
    from serverhub.main import create_app
    monkeypatch.setenv('SERVERHUB_LOGIN_IP_LIMIT','2')
    get_settings.cache_clear()
    for name in ('not-an-account-1','not-an-account-2'):
        with TestClient(create_app(),client=('198.51.100.8',1000)) as client:
            assert client.post('/api/auth/login',json={'username':name,'password':'wrong'}).status_code == 401
    with TestClient(create_app(),client=('198.51.100.8',1000)) as client:
        assert client.post('/api/auth/login',json={'username':'third','password':'wrong'}).status_code == 429


def test_password_failures_refresh_cached_admission_counter(control):
    from serverhub.login_security import admit, failure
    from serverhub.models import SystemState
    peer = request('198.51.100.11','')
    with SessionLocal() as first, SessionLocal() as second:
        key = admit(first,peer,'owner')
        assert admit(second,peer,'owner') == key
        # Keep strong references: SQLAlchemy's identity map uses weak references.
        stale_first = first.get(SystemState,key)
        stale_second = second.get(SystemState,key)
        assert stale_first.value['count'] == stale_second.value['count'] == 0
        failure(first,key)
        failure(second,key)
    with SessionLocal() as db:
        assert db.get(SystemState,key).value['count'] == 2
