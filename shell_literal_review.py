"""Bounded literal shell-option review; never execute submitted expressions."""
import ast

APIS = {'run', 'Popen', 'call', 'check_call', 'check_output'}

def literal_shell_calls(tree):
    aliases = {a.asname or a.name for n in tree.body if isinstance(n, ast.Import)
               for a in n.names if a.name == 'subprocess'}
    # Do not infer module identity after rebinding or a conflicting declaration.
    rebound = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    rebound |= {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    rebound |= {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                bound = a.asname or a.name.split(".")[0]
                if not (isinstance(n, ast.Import) and n in tree.body and a.name == "subprocess"):
                    rebound.add(bound)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            rebound.add(n.name)
    aliases -= rebound
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name) and n.func.value.id in aliases
                and n.func.attr in APIS):
            continue
        for kw in n.keywords:
            if kw.arg != 'shell' or sum(1 for _ in ast.walk(kw.value)) > 32:
                continue
            try:
                value = ast.literal_eval(kw.value)
            except (ValueError, TypeError, SyntaxError, RecursionError):
                continue
            if value is not True and bool(value):
                yield n.lineno
