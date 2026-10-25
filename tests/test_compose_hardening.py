import hashlib
from pathlib import Path
import pytest
import yaml
from serverhub.node import broker


@pytest.fixture
def approved(tmp_path, monkeypatch):
    monkeypatch.setattr(broker, 'trusted_file', lambda path: Path(path))
    return tmp_path, {'image':'alpine@sha256:'+'a'*64,'user':'1000:1000','read_only':True,
        'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
        'healthcheck':{'test':['CMD','true']}}


def validate(approved, **changes):
    directory,service = approved
    service.update(changes)
    path = directory/'compose.yaml'
    path.write_text(yaml.safe_dump({'services':{'app':service}}))
    return broker._compose_file({'path':str(directory),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})


@pytest.mark.parametrize('user',['0','00','000:1000','0x0','root','root:root','1000:0','1000:00','-1','',False,0,'1.0'])
def test_root_and_ambiguous_uids_denied(approved,user):
    with pytest.raises(broker.BrokerDenied):
        validate(approved,user=user)


@pytest.mark.parametrize('options',[
    ['no-new-privileges:true','seccomp=unconfined'],['no-new-privileges:true','apparmor=unconfined'],
    ['no-new-privileges:true','label=disable'],['no-new-privileges:false'], 'no-new-privileges:true',[]])
def test_security_options_must_be_exactly_restrictive(approved,options):
    with pytest.raises(broker.BrokerDenied):
        validate(approved,security_opt=options)


@pytest.mark.parametrize('value',['false',False,[],1])
def test_readonly_requires_yaml_boolean_true(approved,value):
    with pytest.raises(broker.BrokerDenied):
        validate(approved,read_only=value)


@pytest.mark.parametrize('command',['echo $HOME','echo ${SECRET}','echo $$$SECRET'])
def test_unbraced_interpolation_is_rejected(approved,command):
    with pytest.raises(broker.BrokerDenied,match='interpolation'):
        validate(approved,command=command)


def test_approved_nonroot_compose_and_literal_dollar_remain_valid(approved):
    assert validate(approved,command='echo $$LITERAL')
