"""Cross-process admission race regression against a confirmed disposable DB."""
from concurrent.futures import ProcessPoolExecutor
import multiprocessing

from test_core_postgres import pg_env as pg_env


def admit_once(number):
    from fastapi import HTTPException
    from starlette.requests import Request
    from serverhub.database import SessionLocal, get_engine
    from serverhub.login_security import admit
    get_engine().dispose(close=False)
    request=Request({'type':'http','client':('198.51.100.10',1234),'headers':[]})
    with SessionLocal() as db:
        try:
            admit(db,request,'caller-'+str(number))
            return 'admitted'
        except HTTPException as error:
            return error.status_code


def test_postgres_login_admission_survives_multi_process_race(pg_env,monkeypatch):
    from serverhub.settings import get_settings
    monkeypatch.setenv('SERVERHUB_LOGIN_IP_LIMIT','2')
    get_settings.cache_clear()
    with ProcessPoolExecutor(max_workers=4,mp_context=multiprocessing.get_context('fork')) as pool:
        results=list(pool.map(admit_once,range(12)))
    assert results.count('admitted')==2,results
    assert results.count(429)==10,results


def test_postgres_password_failure_refreshes_admission_session(pg_env):
    from starlette.requests import Request
    from serverhub.database import SessionLocal
    from serverhub.login_security import admit, failure
    from serverhub.models import SystemState
    request = Request({'type':'http','client':('198.51.100.12',1234),'headers':[]})
    with SessionLocal() as first, SessionLocal() as second:
        key = admit(first,request,'pgowner')
        assert admit(second,request,'pgowner') == key
        cached_first = first.get(SystemState,key)
        cached_second = second.get(SystemState,key)
        assert cached_first.value['count'] == cached_second.value['count'] == 0
        failure(first,key)
        failure(second,key)
    with SessionLocal() as db:
        assert db.get(SystemState,key).value['count'] == 2
