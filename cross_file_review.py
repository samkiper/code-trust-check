"""Narrow Python cross-file evidence prototype; never imports or executes source.

Only a direct absolute or resolvable relative import of a
parameterless synchronous single-return credential getter passed directly into a requests/httpx payload is
recognized. It is deliberately incomplete and must not be described as whole-app
analysis. The caller must provide already-selected, bounded source files.
"""
import ast
import re
from pathlib import PurePosixPath

_SECRET = re.compile(r'(?:^|[_-])(API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL)(?:$|[_-]|\d)',re.I)
_METHODS = {'post','put','patch','request'}


def module_name(path):
    p=PurePosixPath(path)
    if p.suffix!='.py' or p.is_absolute() or '..' in p.parts:return ''
    parts=list(p.with_suffix('').parts)
    if parts and parts[-1]=='__init__':parts.pop()
    return '.'.join(parts) if parts and all(x.isidentifier() for x in parts) else ''


def imported_module(path, node):
    """Resolve only syntactic package-relative imports; never import code."""
    if node.level == 0:
        return node.module or ''
    name = module_name(path)
    if not name:
        return ''
    parts = name.split('.')
    package = parts if PurePosixPath(path).name == '__init__.py' else parts[:-1]
    ascend = node.level - 1
    if not package or ascend >= len(package):
        return ''
    prefix = package[:len(package)-ascend]
    if node.module:
        prefix.extend(node.module.split('.'))
    return '.'.join(prefix)


def shadowed(tree,name):
    # Conservative: any assignment or function parameter with this name makes
    # its binding ambiguous for this prototype, even in a different scope.
    bindings=0
    for node in ast.walk(tree):
        if isinstance(node,ast.arg) and node.arg==name:return True
        if isinstance(node,ast.Name) and isinstance(node.ctx,(ast.Store,ast.Del)) and node.id==name:return True
        if isinstance(node,ast.Attribute) and isinstance(node.ctx,(ast.Store,ast.Del)) and isinstance(node.value,ast.Name) and node.value.id==name:return True
        if isinstance(node,ast.Subscript) and isinstance(node.ctx,(ast.Store,ast.Del)) and isinstance(node.value,ast.Attribute) and isinstance(node.value.value,ast.Name) and node.value.value.id==name:return True
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and node.name==name:return True
        if isinstance(node,(ast.Import,ast.ImportFrom)):
            bindings+=sum((a.asname or a.name.split('.')[0])==name for a in node.names)
            if bindings>1:return True
    return False


def getter_exports(tree):
    aliases={}
    for node in tree.body:
        if isinstance(node,ast.Import):
            for alias in node.names:
                if alias.name=='os':aliases[alias.asname or 'os']='os'
        elif isinstance(node,ast.ImportFrom) and node.module=='os' and node.level==0:
            for alias in node.names:
                if alias.name=='getenv':aliases[alias.asname or 'getenv']='getenv'
    aliases={k:v for k,v in aliases.items() if not shadowed(tree,k)}
    exports={}
    for node in tree.body:
        if not isinstance(node,ast.FunctionDef):continue
        # A decorator or another binding can replace the function object. Do
        # not infer that the imported name still calls this getter in that case.
        if node.decorator_list:continue
        if sum(isinstance(other,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and other.name==node.name for other in ast.walk(tree)) != 1:continue
        if any(isinstance(other,ast.Name) and isinstance(other.ctx,(ast.Store,ast.Del)) and other.id==node.name for other in ast.walk(tree)):continue
        if any(isinstance(other,(ast.Import,ast.ImportFrom)) and any((alias.asname or alias.name.split('.')[0])==node.name for alias in other.names) for other in ast.walk(tree)):continue
        if node.args.posonlyargs or node.args.args or node.args.kwonlyargs or node.args.vararg or node.args.kwarg:continue
        body=list(node.body)
        if body and isinstance(body[0],ast.Expr) and isinstance(body[0].value,ast.Constant) and isinstance(body[0].value.value,str):body=body[1:]
        if len(body)!=1 or not isinstance(body[0],ast.Return) or not isinstance(body[0].value,ast.Call):continue
        call=body[0].value
        is_getenv=(isinstance(call.func,ast.Name) and aliases.get(call.func.id)=='getenv') or (isinstance(call.func,ast.Attribute) and call.func.attr=='getenv' and isinstance(call.func.value,ast.Name) and aliases.get(call.func.value.id)=='os')
        if not is_getenv or not call.args or not isinstance(call.args[0],ast.Constant) or not isinstance(call.args[0].value,str):continue
        if _SECRET.search(call.args[0].value):exports[node.name]=body[0].lineno
    return exports


def direct_getters(node, imported):
    if isinstance(node,ast.Call) and not node.args and not node.keywords and isinstance(node.func,ast.Name) and node.func.id in imported:
        yield node.func.id
    elif isinstance(node,ast.Dict):
        for value in node.values:
            yield from direct_getters(value,imported)
    elif isinstance(node,(ast.List,ast.Tuple)):
        for value in node.elts:
            yield from direct_getters(value,imported)


def direct_payload_name(node, name):
    if isinstance(node, ast.Name):return node.id==name and isinstance(node.ctx,ast.Load)
    if isinstance(node, ast.Dict):return any(direct_payload_name(value,name) for value in node.values if value is not None)
    if isinstance(node, (ast.List,ast.Tuple)):return any(direct_payload_name(value,name) for value in node.elts)
    return False


def analyze(files: dict[str,str]) -> dict:
    if not isinstance(files,dict) or len(files)>500 or any(not isinstance(k,str) or not isinstance(v,str) for k,v in files.items()):
        raise ValueError('Supply at most 500 selected source files.')
    if sum(len(v.encode('utf-8')) for v in files.values())>25_000_000:
        raise ValueError('Selected source exceeds 25 MB.')
    modules={};ambiguous=set();failed=[];seen=set()
    for path,code in files.items():
        name=module_name(path)
        if not name:continue
        if name in seen:ambiguous.add(name);continue
        seen.add(name)
        try:tree=ast.parse(code)
        except (SyntaxError,ValueError,RecursionError):failed.append(path);continue
        modules[name]=(path,tree,getter_exports(tree))
    findings=[]
    for path,tree,_ in modules.values():
        imported={};network=set()
        for node in tree.body:
            if isinstance(node,ast.Import):
                for alias in node.names:
                    if alias.name in {'requests','httpx'}:network.add(alias.asname or alias.name)
            elif isinstance(node,ast.ImportFrom) and imported_module(path,node) in modules and imported_module(path,node) not in ambiguous:
                source_path,_,exports=modules[imported_module(path,node)]
                for alias in node.names:
                    if alias.name in exports:imported[alias.asname or alias.name]=(source_path,exports[alias.name])
        imported={k:v for k,v in imported.items() if not shadowed(tree,k)}
        network={name for name in network if not shadowed(tree,name)}
        for node in ast.walk(tree):
            if not isinstance(node,ast.Call) or not isinstance(node.func,ast.Attribute) or node.func.attr not in _METHODS or not isinstance(node.func.value,ast.Name) or node.func.value.id not in network:continue
            payloads=[kw.value for kw in node.keywords if kw.arg in {'json','data'}]
            for payload in payloads:
                for getter in direct_getters(payload,imported):
                    source_path,source_line=imported[getter]
                    findings.append({'pattern':'cross_file_credential_payload','file':path,'line':node.lineno,'source_file':source_path,'source_line':source_line,'message':'An imported function that reads a credential is called in a network request payload. Verify the destination and intended behavior.'})
        # Narrow local propagation: a simple getter assignment immediately
        # followed by a standalone request using that variable in its payload.
        # Do not infer through intervening statements or branches.
        for parent in ast.walk(tree):
            for _, body in ast.iter_fields(parent):
                if not isinstance(body,list) or not all(isinstance(s,ast.stmt) for s in body):continue
                for first, second in zip(body,body[1:]):
                    if not isinstance(first,ast.Assign) or len(first.targets)!=1 or not isinstance(first.targets[0],ast.Name):continue
                    getters=list(direct_getters(first.value,imported)) if isinstance(first.value,ast.Call) else []
                    if len(getters)!=1 or not isinstance(second,ast.Expr) or not isinstance(second.value,ast.Call):continue
                    call=second.value
                    if not isinstance(call.func,ast.Attribute) or call.func.attr not in _METHODS or not isinstance(call.func.value,ast.Name) or call.func.value.id not in network:continue
                    variable=first.targets[0].id
                    if not any(direct_payload_name(kw.value,variable) for kw in call.keywords if kw.arg in {'json','data'}):continue
                    source_path,source_line=imported[getters[0]]
                    findings.append({'pattern':'cross_file_credential_payload','file':path,'line':call.lineno,'source_file':source_path,'source_line':source_line,'assignment_line':first.lineno,'message':'A credential-reading imported function supplies a value to the next network request payload. Verify the destination and intended behavior.'})
    return {'findings':findings,'parse_failures':failed,'ambiguous_modules':sorted(ambiguous),'limitations':['Prototype: direct absolute or resolvable relative Python imports, parameterless synchronous single-return getenv getters, and direct or immediately assigned requests/httpx JSON or data payloads only. Other cross-file flows are not traced.','Static evidence does not prove that a call executed or that code is safe.']}
