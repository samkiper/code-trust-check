import ast
import unittest
from shell_literal_review import literal_shell_calls

class LiteralShellReview(unittest.TestCase):
    def test_truthy_falsey_and_unknown(self):
        for value, expected in [('1',True),('"False"',True),('[True]',True),('{"x":0}',True),('False',False),('0',False),('None',False),('[]',False),('{}',False),('""',False),('option',False),('get_option()',False)]:
            with self.subTest(value=value):
                t=ast.parse('import subprocess\nsubprocess.check_output("echo hello", shell='+value+')')
                self.assertEqual(bool(list(literal_shell_calls(t))),expected)
    def test_alias_and_shadow(self):
        for code,expected in [('import subprocess as sp\nsp.run("x",shell=1)',True),('import subprocess\nsubprocess = object()\nsubprocess.run("x",shell=1)',False),('import subprocess\ndef f(subprocess):\n subprocess.run("x",shell=1)',False)]:
            self.assertEqual(bool(list(literal_shell_calls(ast.parse(code)))),expected)

    def test_conflicting_imports_and_exception_binding(self):
        for middle in ('from other import subprocess', 'import other as subprocess', 'try:\n pass\nexcept Exception as subprocess:\n pass'):
            code='import subprocess\n'+middle+'\nsubprocess.run("x",shell=1)'
            self.assertFalse(list(literal_shell_calls(ast.parse(code))))
