"""Real child-process regressions for output and data-file limits."""
import sys
import pytest
from serverhub.node.discovery import bounded_run, CollectionError


def test_capture_limit_does_not_truncate_legitimate_large_data_files(tmp_path):
    target=tmp_path/'package-cache'
    script="from pathlib import Path; Path("+repr(str(target))+").write_bytes(b'x'*65536); print('ok')"
    assert bounded_run([sys.executable,'-c',script],limit=128).strip()=='ok'
    assert target.stat().st_size==65536


@pytest.mark.parametrize('stream',['stdout','stderr'])
def test_both_captured_streams_are_bounded(stream):
    with pytest.raises(CollectionError,match='output limit'):
        bounded_run([sys.executable,'-c',f"import sys;sys.{stream}.write('x'*65536)"],limit=128)


def test_timeout_terminates_child_process():
    with pytest.raises(CollectionError,match='timed out'):
        bounded_run([sys.executable,'-c',"import time;time.sleep(30)"],timeout=.1)
