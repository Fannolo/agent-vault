"""Keep the rotation driver's source restoration on the shared interruption-safe path."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def uses_canonical_source_guard(source):
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 'source'
                and node.func.attr == 'write_bytes'):
            return False
    guards = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        for item in node.items:
            call = item.context_expr
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name) and call.func.value.id == 'helper'
                    and call.func.attr == 'changed_source'
                    and len(call.args) == 3 and not call.keywords
                    and all(isinstance(arg, ast.Name) for arg in call.args)
                    and [arg.id for arg in call.args] == ['source', 'original', 'mutated']):
                guards.append(node)
    if len(guards) != 1:
        return False
    # Merely mentioning the helper cannot protect commands executed outside its context.
    return any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id == 'execute' and node.args
               and isinstance(node.args[0], ast.Constant) and node.args[0].value == 'noop-build'
               for statement in guards[0].body for node in ast.walk(statement))


class SecretBoundarySourceGuardTests(unittest.TestCase):
    def test_driver_uses_canonical_guard_for_its_mutation_commands(self):
        source = (ROOT / 'scripts/verify-secret-boundary.py').read_text()
        self.assertTrue(uses_canonical_source_guard(source))

    def test_old_direct_write_and_finally_pattern_is_rejected(self):
        old_pattern = '''
try:
    source.write_bytes(mutated)
    execute('noop-build', command, 600)
finally:
    source.write_bytes(original)
'''
        self.assertFalse(uses_canonical_source_guard(old_pattern))

    def test_helper_call_outside_context_is_rejected(self):
        unguarded = '''
helper.changed_source(source, original, mutated)
execute('noop-build', command, 600)
'''
        self.assertFalse(uses_canonical_source_guard(unguarded))

    def test_canonical_guard_does_not_allow_an_additional_direct_write(self):
        direct_write = '''
with helper.changed_source(source, original, mutated):
    execute('noop-build', command, 600)
source.write_bytes(original)
'''
        self.assertFalse(uses_canonical_source_guard(direct_write))


if __name__ == '__main__':
    unittest.main()
