"""Reproducible, local-only capability measurement; not an Internet accuracy claim."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import time

from auditkit import __version__
from auditkit.active import verify
from auditkit.reports import write_report
from tests.active_fixture import active_server, MATRIX, matrix_plan
from tests.test_active import fixture_scope


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="validation/active-benchmark")
    args = parser.parse_args()
    started = time.monotonic()
    with active_server() as (server, base):
        data = verify(fixture_scope(base), matrix_plan(base), max_requests=100)
        requests_observed = len(server.requests)
    elapsed = round(time.monotonic() - started, 3)
    rows = [{"case": expected[4], "type": expected[0], "expected": expected[3], "actual": actual["status"],
             "passed": expected[3] == actual["status"], "requests": len(actual["requests"])}
            for expected, actual in zip(MATRIX, data["active_results"])]
    positives = [row for row in rows if row["expected"] == "finding"]
    negatives = [row for row in rows if row["expected"] == "not-detected"]
    edges = [row for row in rows if row["expected"] == "inconclusive"]
    summary = {"generated_utc": datetime.now(timezone.utc).isoformat(), "version": __version__, "python": platform.python_version(),
               "environment": "local HTTP server; genuine SQLite queries; synthetic data only",
               "cases": len(rows), "passed": sum(row["passed"] for row in rows),
               "positive_cases": len(positives), "positive_detections": sum(x["actual"] == "finding" for x in positives),
               "negative_cases": len(negatives), "false_positives": sum(x["actual"] == "finding" for x in negatives),
               "inconclusive_cases": len(edges), "correct_inconclusive": sum(x["actual"] == "inconclusive" for x in edges),
               "requests": data["requests"], "server_requests": requests_observed, "elapsed_seconds": elapsed,
               "limits": "Small implementation-owned regression matrix, not independent validation or real-world detection rate.", "results": rows}
    output = Path(args.out)
    write_report(data, output)
    (output / "benchmark.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=2, ensure_ascii=False))
    return 0 if summary["passed"] == len(MATRIX) and len(rows) == len(MATRIX) and summary["requests"] == requests_observed else 1


if __name__ == "__main__":
    raise SystemExit(main())
