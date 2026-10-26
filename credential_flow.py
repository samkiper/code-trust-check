"""Bounded Python credential tracing. Never evaluates submitted expressions."""
import ast
import re
from urllib.parse import urlparse

SENSITIVE = re.compile(r'key|token|secret|password|credential', re.I)
SINKS = {f'{module}.{verb}' for module in ('requests', 'httpx') for verb in ('get','post','put','patch','delete','request','head')}
SINKS |= {'urllib.request.Request', 'urllib.request.urlopen'}


def credential_flows(code, intent, affirmative):
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return []
    findings = []

    def resolve(node, aliases):
        if isinstance(node, ast.Name): return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute): return resolve(node.value, aliases) + '.' + node.attr
        return ''

    def secrets(node, aliases, values):
        if isinstance(node, ast.Name): return values.get(node.id, set())
        key = None
        if isinstance(node, ast.Call) and resolve(node.func, aliases) in {'os.getenv', 'os.environ.get'} and node.args:
            key = node.args[0]
        elif isinstance(node, ast.Subscript) and resolve(node.value, aliases) == 'os.environ': key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str) and SENSITIVE.search(key.value): return {key.value}
        if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)): return set()
        return set().union(*(secrets(n, aliases, values) for n in ast.iter_child_nodes(node)))

    def block(statements, aliases=None, values=None):
        aliases, values = dict(aliases or {}), dict(values or {})
        for stmt in statements:
            if isinstance(stmt, ast.Import):
                for a in stmt.names: aliases[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
                continue
            if isinstance(stmt, ast.ImportFrom):
                for a in stmt.names: aliases[a.asname or a.name] = (stmt.module or '') + '.' + a.name
                continue
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                aliases[stmt.name] = '<local>'
                inner, vals = dict(aliases), dict(values)
                if hasattr(stmt, 'args'):
                    for p in stmt.args.posonlyargs + stmt.args.args + stmt.args.kwonlyargs + [p for p in (stmt.args.vararg, stmt.args.kwarg) if p]:
                        inner[p.arg] = '<parameter>'; vals.pop(p.arg, None)
                block(stmt.body, inner, vals)
                continue
            if isinstance(stmt, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.AsyncFor)):
                if isinstance(stmt, ast.If) and isinstance(stmt.test, ast.Constant):
                    aliases, values = block(stmt.body if stmt.test.value else stmt.orelse, aliases, values)
                    continue
                for branch in [getattr(stmt,k,[]) for k in ('body','orelse','finalbody')] + [h.body for h in getattr(stmt,'handlers',[])]:
                    a, v = block(branch, aliases, values)
                    for key, val in a.items():
                        if key not in aliases or val in SINKS: aliases[key] = val
                    for key, val in v.items(): values[key] = values.get(key,set()) | val
                continue
            for call in (n for n in ast.walk(stmt) if isinstance(n, ast.Call)):
                name = resolve(call.func, aliases)
                if name not in SINKS: continue
                exposed = secrets(call, aliases, values)
                if not exposed: continue
                url = next((k.value for k in call.keywords if k.arg=='url'), call.args[1] if name.endswith('.request') and len(call.args)>1 else call.args[0] if call.args else None)
                dest = url.value if isinstance(url,ast.Constant) and isinstance(url.value,str) else ''
                host = urlparse(dest).hostname or ''
                headers = next((k.value for k in call.keywords if k.arg=='headers'), None)
                other = set().union(*(secrets(n,aliases,values) for n in call.args + [k.value for k in call.keywords if k.arg!='headers']))
                # A small explicit provider vocabulary; never arbitrary host substrings.
                named = affirmative(intent,[host]) if host else False
                if host == 'api.openai.com': named = named or affirmative(intent,['OpenAI'])
                expected = dest.startswith('https://') and named and affirmative(intent,['authenticate','authentication','authorization','api key','credential']) and headers is not None and not other
                findings.append(dict(line=call.lineno,type='credential_use' if expected else 'secret_exfiltration',pattern='credential_authentication' if expected else 'secret_exfiltration_chain',severity=3 if expected else 32,
                    message='Environment credential used for expected API authentication' if expected else 'Environment credential flows into an outbound request',
                    explanation=f"Credential source: {', '.join(sorted(exposed))}. Destination: {dest or 'dynamic or unresolved'}. " + ('The credential is confined to headers and the HTTPS provider matches the stated authentication purpose. Verify provider ownership and redirect behavior.' if expected else 'A credential value reaches this request. Verify that the destination is authorized to receive it; this does not establish malicious intent.'),
                    what_to_check='Check the source, destination, headers, payload, and redirect behavior.',when_legitimate='An expected provider may receive its own scoped credential for authentication.',suggested_fix='Keep credentials server-side and send them only to their intended provider. Remove credentials from unrelated payloads.'))
            if isinstance(stmt,(ast.Assign,ast.AnnAssign)) and stmt.value is not None:
                value = secrets(stmt.value, aliases, values); target_name = resolve(stmt.value, aliases)
                for target in stmt.targets if isinstance(stmt,ast.Assign) else [stmt.target]:
                    if isinstance(target,ast.Name): values[target.id]=value; aliases[target.id]=target_name or '<value>'
                    elif isinstance(target,ast.Subscript) and isinstance(target.value,ast.Name): values[target.value.id]=values.get(target.value.id,set())|value
        return aliases,values
    block(tree.body)
    return findings
