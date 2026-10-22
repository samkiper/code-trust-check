"""Evidence-based coverage contract. This module never executes submitted code."""
import ast
import re
from pathlib import Path

LANGUAGE_EXTENSIONS = {"Python": ".py", "JavaScript": ".js", "TypeScript": ".ts", "PHP": ".php", "SQL": ".sql", "Shell": ".sh", "HTML": ".html", "Rust": ".rs", "Go": ".go", "Java": ".java", "C": ".c", "C++": ".cpp", "Ruby": ".rb", "C#": ".cs", "Swift": ".swift", "Kotlin": ".kt", "CSS": ".css", "JSON": ".json", "YAML": ".yaml", "XML": ".xml"}


def select_filename(code, language=None, filename=None):
    if language:
        if language not in LANGUAGE_EXTENSIONS:
            return "snippet.unknown"
        suffix = LANGUAGE_EXTENSIONS[language]
        if filename and Path(filename).suffix != suffix:
            return "snippet.unknown"
        return "snippet" + suffix
    if filename:
        return Path(filename).name
    # Legacy callers: only use Python after successful parsing, never as fallback.
    try:
        ast.parse(code)
        return "snippet.py"
    except (SyntaxError, ValueError, RecursionError):
        return "snippet.unknown"


def inspect_source(code, filename):
    suffix = Path(filename).suffix.lower()
    language = next((k for k, v in LANGUAGE_EXTENSIONS.items() if v == suffix), "Unknown")
    if suffix in {".jsx", ".mjs", ".cjs"}: language = "JavaScript"
    if suffix == ".tsx": language = "TypeScript"
    state = {"language": language, "parse_status": "unsupported", "executable_lines": 0, "meaningful_coverage": False}
    if language == "Python":
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError, RecursionError):
            return {**state, "parse_status": "failed"}
        # Module/function docstrings are documentation, not executable coverage.
        nodes = [n for n in ast.walk(tree) if isinstance(n, ast.stmt) and not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
        return {**state, "parse_status": "complete" if nodes else "empty", "executable_lines": len({n.lineno for n in nodes}), "meaningful_coverage": bool(nodes)}
    if language in {"JavaScript", "TypeScript"}:
        from tree_sitter import Language, Parser
        import tree_sitter_javascript
        import tree_sitter_typescript
        grammar = tree_sitter_javascript.language() if language == "JavaScript" else tree_sitter_typescript.language_tsx() if suffix == ".tsx" else tree_sitter_typescript.language_typescript()
        root = Parser(Language(grammar)).parse(code.encode("utf-8")).root_node
        if root.has_error:
            return {**state, "parse_status": "failed"}
        nodes = [n for n in root.named_children if n.type not in {"comment", "empty_statement"}]
        return {**state, "parse_status": "complete" if nodes else "empty", "executable_lines": len({n.start_point.row for n in nodes}), "meaningful_coverage": bool(nodes)}
    return state


def finalize_snippet(result, code, filename, semgrep):
    source = inspect_source(code, filename)
    result["coverage"].update(source)
    result["coverage"]["lines_analyzed"] = source["executable_lines"] if source["meaningful_coverage"] else 0
    result["coverage"]["lines_submitted"] = len(code.splitlines())
    limitations = result["coverage"]["limitations"]
    if not source["meaningful_coverage"]:
        limitations.append("Parser status: " + source["parse_status"] + ". Meaningful code coverage was not established; no score is available.")
        result["coverage"]["analysis_depth"] = "Unsupported" if source["parse_status"] == "unsupported" else "Unverified"
        result["coverage"]["summary"] = "Pattern findings may be available, but successful structural analysis was not established."
    result["analysis_engines"][0]["status"] = "complete" if source["meaningful_coverage"] else "partial"
    status = "complete" if source["meaningful_coverage"] and semgrep.get("status") == "complete" else "partial"
    if not source["meaningful_coverage"] or result.get("risk") in {"limit", "limited"}: status = "not-rated"
    result.update(scan_status=status, coverage_validated=True)
    all_flags = (result.get("flags") or []) + (result.get("engine_findings") or [])
    high = any(float(f.get("severity") or 0) >= 18 for f in all_flags)
    medium = any(float(f.get("severity") or 0) >= 8 for f in all_flags)
    if status == "not-rated":
        result["trust_score"] = None
        result["scan_confidence"] = {"level": "Insufficient", "lines": ["A rating requires meaningful coverage with the selected language."]}
        result["verdict"] = {"id":"not_rated", "label":"Not enough was scanned", "action":"Correct syntax or provide supported executable code, then retry.", "tone":"neutral"}
    if high:
        result["risk"] = "red"
        if result["trust_score"] is not None: result["trust_score"] = min(result["trust_score"], 65)
        result["verdict"] = {"id":"do_not_run", "label":"Do not run this yet", "action":"Fix the high-risk findings first, then scan the revised code again. Incomplete coverage may hide additional issues.", "tone":"danger"}
    elif medium:
        result["risk"] = "yellow"
        if result["trust_score"] is not None: result["trust_score"] = min(result["trust_score"], 90)
        result["verdict"] = {"id":"review_first", "label":"Review before running", "action":"Confirm the reported behavior against its evidence before running this code.", "tone":"warning"}
    elif status == "partial":
        result["verdict"] = {"id":"review_first", "label":"Partial analysis — review coverage", "action":"Review the available findings and rerun when all checks are available.", "tone":"warning"}
    if status != "complete": result["trust_score"] = None
    result["trust_badge"] = {"label":result["verdict"]["label"], "message":result["verdict"]["action"], "color":"red" if high else "gray" if status != "complete" else "yellow" if medium else "green"}
    return result
