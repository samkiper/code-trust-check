#!/usr/bin/env python3
"""Reproducible accuracy gate for internal and OWASP BenchmarkPython cases."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from main import analyze_code  # noqa: E402
from tests.test_scanner_benchmark import DANGEROUS_CASES, SAFE_CASES  # noqa: E402

OWASP_REPOSITORY = "https://github.com/OWASP-Benchmark/BenchmarkPython.git"
OWASP_REVISION = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"


def empty_counts() -> dict[str, int]:
    return {"tp": 0, "fp": 0, "tn": 0, "fn": 0}


def add_result(counts: dict[str, int], expected: bool, detected: bool) -> None:
    key = "tp" if expected and detected else "fn" if expected else "fp" if detected else "tn"
    counts[key] += 1


def rates(counts: dict[str, int]) -> dict:
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    return {
        **counts,
        "cases": tp + fp + tn + fn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "f1": round((2 * tp) / (2 * tp + fp + fn), 4) if 2 * tp + fp + fn else None,
    }


def internal_metrics() -> dict:
    overall = empty_counts()
    by_language = defaultdict(empty_counts)
    by_category = defaultdict(empty_counts)
    for name, language, intent, code in SAFE_CASES:
        detected = analyze_code(intent, code)["risk"] != "green"
        add_result(overall, False, detected)
        add_result(by_language[language], False, detected)
        add_result(by_category[name.split("_", 1)[0]], False, detected)
    for name, language, intent, code, _expected_risks in DANGEROUS_CASES:
        detected = analyze_code(intent, code)["risk"] != "green"
        add_result(overall, True, detected)
        add_result(by_language[language], True, detected)
        add_result(by_category[name.rsplit("_", 1)[0]], True, detected)
    return {
        "overall": rates(overall),
        "by_language": {key: rates(value) for key, value in sorted(by_language.items())},
        "by_vulnerability": {key: rates(value) for key, value in sorted(by_category.items())},
    }


def load_owasp_rows(root: Path) -> list[dict]:
    expected_path = root / "expectedresults-0.1.csv"
    rows = []
    with expected_path.open(encoding="utf-8") as handle:
        reader = csv.reader(line for line in handle if not line.startswith("#"))
        for name, category, truth, cwe in reader:
            rows.append({"name": name, "category": category, "expected": truth.lower() == "true", "cwe": cwe})
    return rows


def balanced_subset(rows: list[dict], limit: int) -> list[dict]:
    """Round-robin categories so a large category cannot dominate the gate."""
    buckets = defaultdict(list)
    for row in rows:
        buckets[row["category"]].append(row)
    selected = []
    keys = sorted(buckets)
    index = 0
    while len(selected) < min(limit, len(rows)):
        made_progress = False
        for key in keys:
            if index < len(buckets[key]) and len(selected) < limit:
                selected.append(buckets[key][index])
                made_progress = True
        if not made_progress:
            break
        index += 1
    return selected


def owasp_metrics(root: Path, limit: int) -> dict:
    rows = balanced_subset(load_owasp_rows(root), limit)
    overall = empty_counts()
    by_category = defaultdict(empty_counts)
    for row in rows:
        code = (root / "testcode" / f"{row['name']}.py").read_text(encoding="utf-8")
        detected = analyze_code(f"Review this {row['category']} security case", code)["risk"] != "green"
        add_result(overall, row["expected"], detected)
        add_result(by_category[row["category"]], row["expected"], detected)
    return {
        "source": "OWASP BenchmarkPython v0.1",
        "revision": OWASP_REVISION,
        "selection": "deterministic category-balanced subset",
        "overall": rates(overall),
        "by_vulnerability": {key: rates(value) for key, value in sorted(by_category.items())},
    }


def check_gate(report: dict, thresholds: dict) -> list[str]:
    failures = []
    for suite in ("internal", "owasp"):
        actual = report[suite]["overall"]
        expected = thresholds[suite]
        if actual["cases"] < expected["minimum_cases"]:
            failures.append(f"{suite}: {actual['cases']} cases is below {expected['minimum_cases']}")
        if (actual["recall"] or 0) < expected["minimum_recall"]:
            failures.append(f"{suite}: recall {actual['recall']} is below {expected['minimum_recall']}")
        if (actual["false_positive_rate"] or 0) > expected["maximum_false_positive_rate"]:
            failures.append(f"{suite}: false-positive rate {actual['false_positive_rate']} exceeds {expected['maximum_false_positive_rate']}")
    for category, expected in thresholds.get("owasp_categories", {}).items():
        actual = report["owasp"]["by_vulnerability"].get(category)
        if not actual:
            failures.append(f"owasp/{category}: category missing")
            continue
        if actual["recall"] is not None and actual["recall"] < expected.get("minimum_recall", 0):
            failures.append(f"owasp/{category}: recall {actual['recall']} regressed")
        if actual["false_positive_rate"] is not None and actual["false_positive_rate"] > expected.get("maximum_false_positive_rate", 1):
            failures.append(f"owasp/{category}: false-positive rate {actual['false_positive_rate']} regressed")
    return failures


def clone_official(destination: Path) -> Path:
    subprocess.run(
        ["git", "clone", "--quiet", OWASP_REPOSITORY, str(destination)],
        check=True,
        timeout=120,
    )
    subprocess.run(
        ["git", "-C", str(destination), "checkout", "--quiet", OWASP_REVISION],
        check=True,
        timeout=30,
    )
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--owasp-dir", type=Path)
    parser.add_argument("--download-official", action="store_true")
    parser.add_argument("--limit", type=int, default=750)
    parser.add_argument("--report", type=Path, default=PROJECT_ROOT / "accuracy-report.json")
    parser.add_argument("--thresholds", type=Path, default=PROJECT_ROOT / "tests" / "accuracy_thresholds.json")
    args = parser.parse_args()

    temp = None
    owasp_root = args.owasp_dir
    if args.download_official:
        temp = tempfile.TemporaryDirectory(prefix="owasp-benchmark-")
        owasp_root = clone_official(Path(temp.name) / "BenchmarkPython")
    if not owasp_root:
        parser.error("provide --owasp-dir or --download-official")

    report = {
        "schema_version": 1,
        "internal": internal_metrics(),
        "owasp": owasp_metrics(owasp_root, args.limit),
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    thresholds = json.loads(args.thresholds.read_text(encoding="utf-8"))
    failures = check_gate(report, thresholds)
    print(json.dumps({"internal": report["internal"]["overall"], "owasp": report["owasp"]["overall"], "failures": failures}, indent=2))
    if temp:
        temp.cleanup()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
