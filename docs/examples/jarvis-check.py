"""Example independent root-owned acceptance check for reviewed Jarvis main 0.23.0.

Copy under the protected checks_path and update only after reviewing upstream.
The development worker/model must never be able to modify this file.
"""
import ast
from pathlib import Path

module = ast.parse(Path('/workspace/app/version.py').read_text())
assert any(
    isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == 'VERSION' for target in node.targets)
    and ast.literal_eval(node.value) == '0.23.0'
    for node in module.body
), 'Jarvis release version does not match the independently reviewed expectation'
print('Independent version acceptance passed')
