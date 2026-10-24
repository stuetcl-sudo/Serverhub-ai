"""Regression coverage for the supplied review, against the current registry."""
import pytest
from datetime import timedelta
from test_core import core_env as core_env, owner as owner
from serverhub.auth import Principal
from serverhub.database import SessionLocal, utcnow
from serverhub.integrations.registry import OPERATIONS
from serverhub.models import Policy
from serverhub.policy import ADULT_OPS, READ_OPERATIONS, PermissionDenied, authorize, is_read


def test_suffix_is_never_classified_or_owner_authorized(core_env, owner):
    with SessionLocal() as db:
        for operation in ('secrets.read','anything.list','policy.query','firewall.status'):
            assert not is_read(operation)
            with pytest.raises(PermissionDenied):
                authorize(db,owner,operation,'node1')


def test_all_current_integration_reads_remain_grantable():
    assert all(op.name in READ_OPERATIONS for op in OPERATIONS.values() if not op.writes)
    assert {'home_assistant.states','home_assistant.status','adguard.refresh_filters'} <= ADULT_OPS
    assert not {'homeassistant.states','adguard.filter.refresh'} & ADULT_OPS


@pytest.mark.parametrize('role', ['owner','readonly'])
def test_read_classification_does_not_bypass_query_argument_scope(core_env,role):
    identity='owner' if role=='owner' else 'reader'
    actor=Principal(identity,role,identity)
    with SessionLocal() as db:
        db.add(Policy(name='one query',subject_id=identity,host_id='node1',environment='read',operations=['prometheus.query'],
            constraints={'integration_id':['metrics'],'query':['cpu']},expires_at=utcnow()+timedelta(hours=1),created_by='owner'))
        db.commit()
        assert is_read('prometheus.query')
        authorize(db,actor,'prometheus.query','node1',arguments={'integration_id':'metrics','query':'cpu'})
        for arguments in ({'integration_id':'metrics','query':'secrets'},{'integration_id':'other','query':'cpu'},{}):
            with pytest.raises(PermissionDenied):
                authorize(db,actor,'prometheus.query','node1',arguments=arguments)
        with pytest.raises(PermissionDenied):
            authorize(db,actor,'prometheus.query','node2',arguments={'integration_id':'metrics','query':'cpu'})


def test_owner_integration_reads_respect_integration_argument_grants(core_env,owner):
    with SessionLocal() as db:
        db.add(Policy(name='integration',subject_id='owner',host_id='node1',operations=['adguard.status'],
            constraints={'integration_ids':['approved']},expires_at=utcnow()+timedelta(hours=1),created_by='owner'))
        db.commit()
        authorize(db,owner,'adguard.status','node1',arguments={'integration_id':'approved'})
        with pytest.raises(PermissionDenied):
            authorize(db,owner,'adguard.status','node1',arguments={'integration_id':'private'})
