"""Bounded, intraprocedural evidence for environment payloads and executor aliases.

No submitted expression is evaluated. Unknown calls and cross-file flows remain
outside this pass; existing engines still run in full.
"""
import ast


def inert_literal_eval(call):
    """Only downgrade literal arithmetic/data expressions; never arbitrary source."""
    if not isinstance(call, ast.Call) or not call.args or call.keywords or len(call.args) != 1:
        return False
    value = call.args[0]
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str) or len(value.value) > 1000:
        return False
    try:
        expression = ast.parse(value.value, mode='eval')
    except (SyntaxError, ValueError, RecursionError):
        return False
    allowed = (ast.Expression, ast.Constant, ast.BinOp, ast.UnaryOp, ast.Add,
               ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.UAdd,
               ast.USub, ast.List, ast.Tuple, ast.Dict, ast.Set, ast.Load)
    # Pow, calls, names, comprehensions and attributes are intentionally excluded.
    return all(isinstance(n, allowed) for n in ast.walk(expression))


def literal_eval_locations(code):
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return set()
    return {(n.lineno, n.col_offset + 1) for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == 'eval' and inert_literal_eval(n)}


def supplemental_flows(code):
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return []
    findings = []
    sinks = {'requests.' + m for m in ('get','post','put','patch','delete','request')}
    sinks |= {'httpx.' + m for m in ('get','post','put','patch','delete','request')}
    sinks |= {'urllib.request.urlopen'}  # Request only constructs an object.

    def resolved(node, aliases):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return resolved(node.value, aliases) + '.' + node.attr
        return ''

    def environment(node, aliases, sources):
        if isinstance(node, ast.Name):
            return node.id in sources or resolved(node, aliases) == 'os.environ'
        if isinstance(node, ast.Attribute):
            return resolved(node, aliases) == 'os.environ'
        if isinstance(node, ast.Subscript):
            # A selected environment key is handled by the credential-source pass.
            if resolved(node.value, aliases) == 'os.environ':
                return False
            return environment(node.value, aliases, sources)
        if isinstance(node, ast.Call):
            name = resolved(node.func, aliases)
            if name in {'os.environ.keys', 'os.environ.get', 'len', 'bool', 'all', 'any'}:
                return False
            if name in {'list', 'tuple', 'set', 'sorted'} and node.args and resolved(node.args[0], aliases) == 'os.environ':
                return False  # Iterating a mapping emits keys, not credential values.
            if name in {'os.environ.copy', 'os.environ.items', 'os.environ.values'}:
                return True
            receiver = isinstance(node.func, ast.Attribute) and environment(node.func.value, aliases, sources)
            return receiver or any(environment(n, aliases, sources) for n in node.args) or any(environment(k.value, aliases, sources) for k in node.keywords)
        return any(environment(n, aliases, sources) for n in ast.iter_child_nodes(node))

    def inspect_calls(expression, aliases, sources):
        for call in (n for n in ast.walk(expression) if isinstance(n, ast.Call)):
            name = resolved(call.func, aliases)
            if name in sinks and any(environment(n, aliases, sources) for n in call.args + [k.value for k in call.keywords]):
                url = next((k.value for k in call.keywords if k.arg == 'url'), call.args[1] if name.endswith('.request') and len(call.args)>1 else call.args[0] if call.args else None)
                destination = url.value if isinstance(url, ast.Constant) and isinstance(url.value, str) else 'dynamic or unresolved'
                findings.append(dict(line=call.lineno, type='secret_exfiltration', pattern='whole_environment_egress', severity=32,
                    message='Process environment flows into an outbound request',
                    explanation=f'Source: the process environment or its copied values. Destination: {destination}. The payload can include credentials; this is a detected transmission path, not proof of malicious intent.',
                    what_to_check='Review which environment values reach the request and whether this destination is authorized to receive each value.',
                    when_legitimate='Explicitly approved diagnostics can transmit selected nonsecret configuration. Sending the entire environment requires review because secrets may be present.',
                    suggested_fix='Build an allowlisted payload of necessary nonsecret values instead of sending the environment.'))
            if name in {'eval','exec','builtins.eval','builtins.exec'} and ast.unparse(call.func) not in {'eval','exec'}:
                operation = name.split('.')[-1]
                safe = operation == 'eval' and inert_literal_eval(call)
                findings.append(dict(line=call.lineno, type='dynamic_execution', pattern=operation+'(', severity=4 if safe else 25,
                    message='Fixed literal expression evaluated through an alias' if safe else f'Alias resolves to {operation}()',
                    explanation='A fixed expression contains only literal data and arithmetic; no untrusted input path is present in this expression.' if safe else f'{ast.unparse(call.func)} resolves to Python {operation}(). Its argument is executable Python; the supported checks have not established an inert literal expression.',
                    what_to_check='Trace the argument source and trust boundary. An alias does not make dynamic execution safe.',
                    when_legitimate='Trusted, deliberately authored code may use dynamic execution. Unknown or user-controlled source must not be treated as trusted.',
                    suggested_fix='Use direct arithmetic or a non-executable data parser where possible.'))

    def block(statements, aliases=None, sources=None):
        aliases, sources = dict(aliases or {}), set(sources or ())
        for statement in statements:
            if isinstance(statement, ast.Import):
                for a in statement.names:
                    aliases[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
                continue
            if isinstance(statement, ast.ImportFrom):
                for a in statement.names:
                    aliases[a.asname or a.name] = (statement.module or '') + '.' + a.name
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                aliases[statement.name] = '<local>'
                inner = dict(aliases)
                inner_sources = set(sources)
                if hasattr(statement, 'args'):
                    parameters = statement.args.posonlyargs + statement.args.args + statement.args.kwonlyargs
                    parameters += [p for p in (statement.args.vararg, statement.args.kwarg) if p]
                    for p in parameters:
                        inner[p.arg] = '<parameter>'
                        inner_sources.discard(p.arg)
                block(statement.body, inner, inner_sources)
                continue
            if isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)):
                for field in ('test', 'iter'):
                    expression = getattr(statement, field, None)
                    if expression is not None: inspect_calls(expression, aliases, sources)
                for item in getattr(statement, 'items', []):
                    inspect_calls(item.context_expr, aliases, sources)
                if isinstance(statement, ast.If) and isinstance(statement.test, ast.Constant):
                    aliases, sources = block(statement.body if statement.test.value else statement.orelse, aliases, sources)
                    continue
                # Branches are analyzed separately and possible bindings are retained.
                branches = [getattr(statement, k, []) for k in ('body', 'orelse', 'finalbody')]
                branches += [h.body for h in getattr(statement, 'handlers', [])]
                for branch in branches:
                    child_aliases, child_sources = block(branch, aliases, sources)
                    for key, value in child_aliases.items():
                        if value in {'eval', 'exec', 'builtins.eval', 'builtins.exec'} or key not in aliases:
                            aliases[key] = value
                    sources |= child_sources
                continue
            inspect_calls(statement, aliases, sources)
            if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                name = resolved(statement.value, aliases)
                has_env = environment(statement.value, aliases, sources)
                for target in targets:
                    if isinstance(target, ast.Name):
                        aliases[target.id] = name or '<value>'
                        if has_env: sources.add(target.id)
                        else: sources.discard(target.id)
                    elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and has_env:
                        sources.add(target.value.id)
        return aliases, sources

    block(tree.body)
    return findings
