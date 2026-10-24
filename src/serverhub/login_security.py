"""Persistent login admission counters, independent of account-wide lockout.

Only the exact login route uses them. OAuth, MCP and existing proxy routing are
unchanged. Counters are shared across API processes in PostgreSQL, and contain
hashed client/username keys, never passwords, tokens or raw forwarded headers.
"""
import hashlib
import ipaddress
import math
import threading
import time
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import select

from .database import utcnow
from .models import SystemState
from .settings import get_settings

_LOCK = threading.RLock()
PREFIX = 'login-rate:'


def client_address(request):
    peer = request.client.host if request.client else 'unknown'
    settings = get_settings()
    try:
        address = ipaddress.ip_address(peer)
        trusted = [ipaddress.ip_network(cidr) for cidr in settings.trusted_proxy_cidrs]
        if not any(address in network for network in trusted):
            return str(address)
        forwarded = request.headers.get('x-forwarded-for','')
        if not forwarded or len(forwarded)>2048:
            return str(address)
        chain = [ipaddress.ip_address(item.strip()) for item in forwarded.split(',')]
        if len(chain)>20:
            return str(address)
        # Traverse from the actual peer; never trust a leftmost spoofed value.
        for hop in reversed(chain):
            if not any(hop in network for network in trusted):
                return str(hop)
        return str(chain[0])
    except ValueError:
        return peer  # malformed headers cannot allocate new counter identities


def _key(kind, value):
    return PREFIX + hashlib.sha256((kind + ':' + value).encode()).hexdigest()


def _counter(db, key, period):
    now = time.time()
    row = db.get(SystemState, key)
    if row is None:
        row = SystemState(key=key, value={'start':now,'count':0,'period':period})
        db.add(row)
    state = dict(row.value)
    if now - state['start'] >= period:
        state = {'start':now,'count':0,'period':period}
    return row,state,now


def admit(db, request, username):
    """Serialized short transaction; release the lock before expensive Argon work."""
    settings = get_settings()
    identity = client_address(request)
    with _LOCK:
        if db.bind.dialect.name == 'postgresql':
            # Same lock for admission and failures: nonexistent-row races are bounded.
            from sqlalchemy import text
            db.execute(text('SELECT pg_advisory_xact_lock(734882109)'))
        # Expired state is bounded by time. Refuse allocation at capacity instead
        # of evicting active counters and allowing distributed admission bypass.
        from sqlalchemy import func
        # Reject a saturated global bucket before scanning/pruning admission keys.
        global_key = _key('global','all')
        global_row = db.get(SystemState, global_key)
        now = time.time()
        if global_row and now-global_row.value['start'] < 60 and global_row.value['count'] >= settings.login_global_limit:
            db.rollback()
            raise HTTPException(429,'Too many login attempts; retry later',headers={'Retry-After':'60'})
        from sqlalchemy import delete
        db.execute(delete(SystemState).where(SystemState.key.like(PREFIX+'%'),
            SystemState.updated_at < utcnow()-timedelta(seconds=max(120,settings.login_lock_seconds+60))))
        db.flush()
        count = db.scalar(select(func.count()).select_from(SystemState).where(SystemState.key.like(PREFIX+'%')))
        keys = [_key('ip',identity),_key('account-ip',identity+'\0'+username)]
        if count >= 10000 and any(db.get(SystemState,key) is None for key in keys):
            db.commit()
            raise HTTPException(429,'Login admission capacity reached; retry later',headers={'Retry-After':'60'})
        limits = [(_key('global','all'),settings.login_global_limit,60),
                  (keys[0],settings.login_ip_limit,60),
                  (keys[1],settings.login_failures,settings.login_lock_seconds)]
        pending=[]
        for key,limit,period in limits:
            row,state,now = _counter(db,key,period)
            if state['count']>=limit:
                retry=max(1,math.ceil(period-(now-state['start'])))
                db.rollback()
                raise HTTPException(429,'Too many login attempts; retry later',headers={'Retry-After':str(retry)})
            pending.append((row,state,key))
        for row,state,key in pending:
            if key != keys[1]:
                state['count'] += 1
            row.value = state
        db.commit()
    return keys[1]


def failure(db, key):
    with _LOCK:
        if db.bind.dialect.name == 'postgresql':
            from sqlalchemy import text
            db.execute(text('SELECT pg_advisory_xact_lock(734882109)'))
        row,state,_ = _counter(db,key,get_settings().login_lock_seconds)
        state['count'] += 1
        row.value = state
        db.commit()


def success(db, key):
    row = db.get(SystemState,key)
    if row:
        row.value = {**row.value,'count':0}
