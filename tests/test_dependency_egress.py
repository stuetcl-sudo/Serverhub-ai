"""Negative network tests never contact live servers or change host networking."""
import ipaddress
from pathlib import Path
import socket
import pytest
from serverhub.development.config import Command, Project
from serverhub.development.egress import EgressDenied, destination, gateway
from serverhub.development.sandbox import SandboxRunner


def test_only_exact_public_https_destinations_are_allowed(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('1.1.1.1',443))])
    assert destination('pypi.org:443',{'pypi.org'})[0][3] == ('1.1.1.1',443)
    for authority in ('localhost:443','pypi.org:9080','pypi.org.evil:443','pypi.org:80','user@pypi.org:443','127.0.0.1:443'):
        with pytest.raises(EgressDenied):
            destination(authority,{'pypi.org'})


@pytest.mark.parametrize('ip',['127.0.0.1','10.0.0.1','192.168.68.135','172.17.0.1','169.254.169.254','0.0.0.0',
    '::1','fc00::1','fe80::1','::ffff:127.0.0.1','64:ff9b::7f00:1','2002:7f00:1::'])
def test_private_or_translated_dns_cannot_rebind_the_gateway(monkeypatch,ip):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(family,socket.SOCK_STREAM,6,'',(ip,443))])
    with pytest.raises(EgressDenied):
        destination('pypi.org:443',{'pypi.org'})


def test_mixed_dns_and_local_public_lan_are_denied(monkeypatch):
    def record(ip):
        return (socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[record('1.1.1.1'),record('127.0.0.1')])
    with pytest.raises(EgressDenied):
        destination('pypi.org:443',{'pypi.org'})
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[record('1.1.1.1')])
    with pytest.raises(EgressDenied):
        destination('pypi.org:443',{'pypi.org'},[ipaddress.ip_network('1.1.1.0/24')])


def test_actual_unix_gateway_rejects_unapproved_connect_without_upstream(tmp_path):
    import os
    try:
        probe = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        probe.close()
    except PermissionError:
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            raise
        pytest.skip('Local execution sandbox denies Unix sockets; Ubuntu CI requires the real gateway test')
    project=Project(name='egress',repository=str(tmp_path),tests=[Command(argv=['true'])])
    with gateway(tmp_path,project,10) as path:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(path))
            client.sendall(b'CONNECT 127.0.0.1:9080 HTTP/1.1\r\n\r\n')
            assert client.recv(1024).startswith(b'HTTP/1.1 403')
        assert path.stat().st_mode & 0o777 == 0o600


def test_dependency_commands_keep_private_net_and_never_mount_dns(tmp_path):
    project=Project(name='egress',repository=str(tmp_path),allow_dependency_network=True,tests=[Command(argv=['true'])])
    runner=SandboxRunner(project,binary='/usr/bin/bwrap')
    command=Command(argv=['/usr/bin/python3','-m','pip','install','pytest'],network=True)
    with pytest.raises(Exception,match='isolated HTTPS gateway'):
        runner.arguments(tmp_path,command)
    args=runner.arguments(tmp_path,command,proxy_socket=Path('/tmp/fixture/egress.sock'))
    assert '--unshare-all' in args and '--share-net' not in args
    assert '/etc/resolv.conf' not in args and '/run/serverhub-egress.sock' in args
    assert '/sandbox-net.py' in args and '/var/run/docker.sock' not in args


def test_ipv6_only_gateway_transport_fails_closed(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET6,socket.SOCK_STREAM,6,'',('2606:4700:4700::1111',443))])
    with pytest.raises(EgressDenied,match='IPv4 transport'):
        destination('pypi.org:443',{'pypi.org'})
