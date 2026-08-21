#!/usr/bin/env python3
"""Run the Endpoint Remediation Verification Benchmark end to end.

    python run_experiment.py            # rebuild corpus, run all arms, score, report
    python run_experiment.py --no-emit  # reuse the frozen corpus on disk

Everything runs in-process against the simulator.  No network, no host changes.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from rvbench.analysis.false_safe_review import write_review  # noqa: E402
from rvbench.analysis.report import generate  # noqa: E402
from rvbench.corpus.emit import emit  # noqa: E402
from rvbench.runner import run  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-emit", action="store_true",
                    help="do not regenerate the case corpus; run against the frozen files on disk")
    args = ap.parse_args()

    if not args.no_emit:
        emit(ROOT)
        print("corpus emitted")

    result = run(ROOT)
    manifest = result["manifest"]["manifest_sha256"]
    summary = write_review(ROOT)
    report = generate(ROOT)

    print(f"\ncase-manifest SHA-256: {manifest}\n")
    print(f"{'arm':<22} {'acc':>7} {'false-safe':>12} {'95% CI':>18} {'macroF1':>8}")
    for arm in ("STATUS_ONLY", "TARGET_STATE", "INDEPENDENT_VERIFIER"):
        m = result["metrics"][arm]
        lo, hi = m["false_safe_rate_ci95"]
        print(f"{arm:<22} {m['accuracy']:>7.3f} {m['false_safe_count']:>4}/{m['n']:<3} "
              f"{m['false_safe_rate']:>5.3f} [{lo:.3f}, {hi:.3f}] {m['macro_f1']:>8.3f}")

    print("\npaired comparisons (primary metric: false-safe)")
    for c in result["comparisons"]:
        if c["metric"] != "false_safe":
            continue
        print(f"  {c['comparison']:<45} b={c['b']:<3} c={c['c']:<3} "
              f"p_exact={c['p_exact']:.3g}  {c['interpretation']}")

    print(f"\nfalse-safe predictions reviewed: {summary['count']} {summary['by_arm']}")
    print(f"report: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
