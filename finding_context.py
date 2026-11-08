"""Conservative context for fixed process operands and same-operation evidence."""
import ast


def fixed_cat_operand(call, call_name):
    """Only this exact argv shape ends cat options before a single filename.

    Do not generalize -- to interpreters, arbitrary programs or executable overrides.
    The caller still reports a file-access review notice, not a safety guarantee.
    """
    if call_name not in {'subprocess.run', 'subprocess.call', 'subprocess.Popen',
                         'subprocess.check_call', 'subprocess.check_output'}:
        return False
    if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)):
        return False
    args = call.args[0].elts
    if len(args) != 3 or any(isinstance(a, ast.Starred) for a in args):
        return False
    if any(k.arg is None or k.arg == 'executable' for k in call.keywords):
        return False
    shell = next((k.value for k in call.keywords if k.arg == 'shell'), None)
    if shell is not None and not (isinstance(shell, ast.Constant) and shell.value is False):
        return False
    return (isinstance(args[0], ast.Constant) and args[0].value in {'cat', '/bin/cat', '/usr/bin/cat'}
            and isinstance(args[1], ast.Constant) and args[1].value == '--')


def annotate_operation_evidence(code, flags, engine_findings):
    """Correlate known rule pairs only with one relevant AST call on that line."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return
    calls = {}
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        name = ast.unparse(n.func)
        family = 'dynamic' if name in {'eval', 'exec'} else 'shell' if name.startswith('subprocess.') else None
        if family:
            calls.setdefault((n.lineno, family), []).append(n)
    for f in flags + engine_findings:
        rule = f.get('rule_id')
        pattern = f.get('pattern')
        family = 'dynamic' if pattern in {'eval(', 'exec('} or rule == 'python.dynamic-eval' else 'shell' if pattern == 'subprocess' or rule == 'python.shell-true' else None
        nodes = calls.get((f.get('line'), family), [])
        if len(nodes) != 1:
            continue
        node = nodes[0]
        f['correlation_key'] = f'{family}:{node.lineno}:{node.col_offset}'
        if rule == 'python.dynamic-eval':
            operation = ast.unparse(node.func)
            if f.get('severity', 0) >= 18:
                f['message'] = f'Dynamic {operation}() can execute attacker-controlled Python'

