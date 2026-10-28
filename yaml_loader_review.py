"""Recognize only unambiguous imported PyYAML safe-loader references."""
import ast

def safe_yaml_calls(tree):
    nodes=list(ast.walk(tree))
    modules={a.asname or a.name for n in tree.body if isinstance(n,ast.Import) for a in n.names if a.name=='yaml'}
    loaders={a.asname or a.name for n in tree.body if isinstance(n,ast.ImportFrom) and n.module=='yaml' for a in n.names if a.name in {'SafeLoader','CSafeLoader'}}
    invalid=set()
    for n in nodes:
        if isinstance(n,ast.Name) and isinstance(n.ctx,(ast.Store,ast.Del)):
            invalid.add(n.id)
        elif isinstance(n,ast.Attribute) and isinstance(n.ctx,(ast.Store,ast.Del)) and isinstance(n.value,ast.Name):
            invalid.add(n.value.id)
        elif isinstance(n,ast.arg): invalid.add(n.arg)
        elif isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)): invalid.add(n.name)
        elif isinstance(n,ast.ExceptHandler) and n.name: invalid.add(n.name)
        elif isinstance(n,(ast.Import,ast.ImportFrom)):
            for a in n.names:
                if n not in tree.body or not ((isinstance(n,ast.Import) and a.name=='yaml') or (isinstance(n,ast.ImportFrom) and n.module=='yaml' and a.name in {'SafeLoader','CSafeLoader'})):
                    invalid.add(a.asname or a.name.split('.')[0])
    modules-=invalid; loaders-=invalid
    result=set()
    for n in nodes:
        if not (isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id in modules and n.func.attr=='load'): continue
        if any(k.arg is None for k in n.keywords): continue
        candidates=[k.value for k in n.keywords if k.arg=='Loader']
        if len(n.args)==2: candidates.append(n.args[1])
        if len(candidates)!=1: continue
        loader=candidates[0]
        if (isinstance(loader,ast.Name) and loader.id in loaders) or (isinstance(loader,ast.Attribute) and isinstance(loader.value,ast.Name) and loader.value.id in modules and loader.attr in {'SafeLoader','CSafeLoader'}):
            result.add((n.lineno,n.col_offset))
    return result
