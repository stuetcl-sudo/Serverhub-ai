"""Exercise fixture runner without importing its root-only destructive setup."""
import ast
from pathlib import Path
import subprocess


def test_fixture_git_commands_disable_background_maintenance(monkeypatch):
    module = ast.parse((Path(__file__).parents[1] / 'scripts/test-jarvis-pilot.py').read_text())
    function = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
    namespace = {'subprocess': subprocess}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<fixture runner>', 'exec'), namespace)
    calls = []
    def record(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, 'ok')
    monkeypatch.setattr(subprocess, 'run', record)
    for command in (['git', 'clone', 'source', 'target'], ['git', '-C', 'target', 'commit', '-am', 'fixture']):
        assert namespace['run'](command) == 'ok'
        assert calls[-1] == ['git', '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', *command[1:]]
    namespace['run'](['apt-get', 'update'])
    assert calls[-1] == ['apt-get', 'update']
