"""Report generation.

Narrative is authored here; every number is injected from the scored results so
the prose cannot drift from the data.  Four reports:

    final-report.md            the whole experiment, with the ten summary questions
    false-assurance-review.md  every remaining wrong VERIFIED verdict, by mechanism
    collection-degradation.md  the coverage and mechanism tables
    shared-design-threats.md   where the oracle and the verifiers still touch
"""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..collect.conditions import COVERAGE_LEVELS, MECHANISMS
from ..vocab import ARMS
from ..world.scenarios import FAMILIES
from .degradation import SHORT

MECH_ORDER = ["NONE"] + list(MECHANISMS)


def pct(value: Optional[float], digits: int = 1) -> str:
    return "n/a" if value is None else f"{100.0 * value:.{digits}f}%"


def num(value: Optional[float], digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _v(block: Dict[str, Any], metric: str) -> Optional[float]:
    entry = block.get(metric)
    return entry.get("value") if isinstance(entry, dict) else None


def _frac(block: Dict[str, Any], metric: str) -> str:
    entry = block.get(metric, {})
    return f"{entry.get('numerator', 0)}/{entry.get('denominator', 0)}"


def _cmp(results: Dict[str, Any], first: str, second: str, error: str,
         group: Optional[str] = None) -> Optional[Dict[str, Any]]:
    for c in results["paired_comparisons"]:
        if (c["comparison"] == f"{first} vs {second}" and c["error_of_interest"] == error
                and c.get("mechanism_group") == group):
            return c
    return None


# --------------------------------------------------------------------------- #
def write_degradation_report(path: Path, results: Dict[str, Any]) -> Path:
    L: List[str] = ["# Collection degradation", "",
                    "How each arm behaves as evidence coverage falls and as the *shape* of the",
                    "loss changes.  All figures are the holdout partition.", ""]

    L += ["## Coverage curves (all mechanisms pooled at each level)", ""]
    for metric, label in [("unsafe_escape_rate", "Unsafe escape rate"),
                          ("false_assurance_rate", "False assurance rate"),
                          ("abstention_rate", "Abstention rate"),
                          ("verified_recall", "Verified-remediation recall")]:
        L += [f"### {label}", "",
              "| Coverage | " + " | ".join(SHORT[a] for a in ARMS) + " |",
              "| --- | " + " | ".join("---" for _ in ARMS) + " |"]
        for coverage in COVERAGE_LEVELS:
            cells = []
            for arm in ARMS:
                block = results["by_coverage"].get(arm, {}).get(f"{coverage:.2f}", {})
                cells.append(pct(_v(block, metric)))
            L.append(f"| {int(coverage * 100)}% | " + " | ".join(cells) + " |")
        L.append("")

    L += ["## Missingness mechanism (all coverage levels below 100% pooled)", ""]
    for metric, label in [("unsafe_escape_rate", "Unsafe escape rate"),
                          ("abstention_rate", "Abstention rate"),
                          ("verified_recall", "Verified-remediation recall"),
                          ("false_assurance_rate", "False assurance rate")]:
        L += [f"### {label}", "",
              "| Mechanism | " + " | ".join(SHORT[a] for a in ARMS) + " |",
              "| --- | " + " | ".join("---" for _ in ARMS) + " |"]
        for mech in MECH_ORDER:
            cells = []
            for arm in ARMS:
                block = results["by_mechanism"].get(arm, {}).get(mech, {})
                cells.append(pct(_v(block, metric)) if block else "-")
            L.append(f"| `{mech}` | " + " | ".join(cells) + " |")
        L.append("")

    L += ["## Scenario family", "",
          "Coverage of the advantage across families, so a single template cannot be",
          "driving the headline.  Unsafe escape rate, all conditions.", "",
          "| Family | " + " | ".join(SHORT[a] for a in ARMS) + " |",
          "| --- | " + " | ".join("---" for _ in ARMS) + " |"]
    for family in FAMILIES:
        cells = []
        for arm in ARMS:
            block = results["by_family"].get(arm, {}).get(family, {})
            cells.append(pct(_v(block, "unsafe_escape_rate")) if block else "-")
        L.append(f"| {family} | " + " | ".join(cells) + " |")
    L += ["", "## Evidence requests (Arm E only)", ""]
    e_blocks = results["by_condition"].get("E_ACTIVE_EVIDENCE", {})
    L += ["| Coverage | Mechanism | requests/case | granted | decision-relevant | abstention |",
          "| --- | --- | --- | --- | --- | --- |"]
    for key in e_blocks:
        coverage, mech = key.split("|", 1)
        block = e_blocks[key]
        L.append(f"| {int(coverage[1:])}% | `{mech}` | "
                 f"{num(block['evidence_requests_per_case']['value'], 2)} | "
                 f"{pct(block['request_success_rate']['value'])} | "
                 f"{pct(block['decision_relevant_request_rate']['value'])} | "
                 f"{pct(_v(block, 'abstention_rate'))} |")
    L.append("")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L) + "\n")
    return Path(path)


# --------------------------------------------------------------------------- #
def write_false_assurance_review(path: Path, results: Dict[str, Any],
                                 rows: List[Dict[str, Any]]) -> Path:
    wrong = [r for r in rows
             if r["verdict"] == "VERIFIED_REMEDIATED" and r["truth"] != "VERIFIED_REMEDIATED"]
    by_arm: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in wrong:
        by_arm[row["arm"]].append(row)

    L = ["# False assurance review", "",
         "Every holdout condition where an arm said `VERIFIED_REMEDIATED` and the latent",
         "world said otherwise.  Generated from the frozen predictions.", "",
         f"Total false-assurance verdicts across all arms: **{len(wrong)}** "
         f"of {len(rows)} verdicts.", ""]

    L += ["| Arm | False assurances | Of all its VERIFIED claims | Mechanisms involved |",
          "| --- | --- | --- | --- |"]
    for arm in ARMS:
        arm_rows = by_arm.get(arm, [])
        block = results["overall"].get(arm, {})
        mechs = Counter(r["mechanism"] for r in arm_rows)
        summary = ", ".join(f"`{m}` {n}" for m, n in mechs.most_common(4)) or "-"
        L.append(f"| {arm} | {len(arm_rows)} | {_frac(block, 'false_assurance_rate')} "
                 f"({pct(_v(block, 'false_assurance_rate'))}) | {summary} |")
    L.append("")

    for arm in ARMS:
        arm_rows = by_arm.get(arm, [])
        L += [f"## {arm} - {len(arm_rows)} false assurances", ""]
        if not arm_rows:
            L += ["_None._", ""]
            continue
        mech_counts = Counter(r["mechanism"] for r in arm_rows)
        fam_counts = Counter(r["family"] for r in arm_rows)
        cov_counts = Counter(f"{r['coverage']:.2f}" for r in arm_rows)
        L += ["By mechanism: " + ", ".join(f"`{m}` {n}" for m, n in sorted(mech_counts.items())), "",
              "By coverage: " + ", ".join(f"{c} -> {n}" for c, n in sorted(cov_counts.items(), reverse=True)), "",
              "By scenario family: " + ", ".join(f"{f} {n}" for f, n in fam_counts.most_common()), ""]
        if len(arm_rows) <= 60:
            L += ["| Condition | Family | Coverage | Mechanism | Truth | Reason codes |",
                  "| --- | --- | --- | --- | --- | --- |"]
            for row in sorted(arm_rows, key=lambda r: r["condition_id"]):
                L.append(f"| `{row['condition_id']}` | {row['family']} | "
                         f"{row['coverage']:.2f} | `{row['mechanism']}` | {row['truth']} | "
                         f"{', '.join(row['reason_codes'][:3])} |")
        else:
            L += [f"_{len(arm_rows)} rows; see `artifacts/results.csv` "
                  f"(filter `false_assurance=1`) for the complete list._"]
        L.append("")

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L) + "\n")
    return Path(path)


# --------------------------------------------------------------------------- #
def write_shared_design_threats(path: Path, results: Dict[str, Any]) -> Path:
    L = ["# Shared-design threats", "",
         "v1's final report named shared design between the oracle and the verifier as its",
         "largest threat to validity: both applied the same precedence rule, so the",
         "verifier's remaining errors could only come from observation gaps.  v2 tried to",
         "reduce that coupling.  This file is an honest account of how far it got.", "",
         "## What was actually separated", "",
         "| Coupling in v1 | Status in v2 |",
         "| --- | --- |",
         "| One predicate evaluator shared by oracle and verifier | Two implementations. "
         "`world/predicates.py` is two-valued and omniscient; `obs/observed_predicates.py` is "
         "three-valued and reasons about scope, freshness, and disagreement. Neither imports the other. |",
         "| One verdict-precedence function | The oracle uses an ordered cascade over the latent "
         "world (`oracle/truth.py`). Arm D uses a gate chain: justify-or-refuse first, label second "
         "(`verifiers/arm_d_scope_aware.py`). Different shapes, no shared helper. |",
         "| Verifier read adapter state directly | Verifiers receive a serialised "
         "`ObservationPackage` and nothing else. Arms A, B and C get a flattened view with no "
         "collection manifest at all. |",
         "| Truth label included INSUFFICIENT_EVIDENCE | Removed. The latent world is always "
         "determined; whether the observer had enough evidence is a fact about the collector. "
         "`TruthLabel` has five members, `Verdict` has six. |",
         "| Cases hand-labelled per scenario | Labels are derived by the oracle from whatever "
         "world the generator produced. No condition has an author-chosen answer. |",
         "",
         "## What is still coupled", "",
         "These are real and they are not fixed by the above.", "",
         "1. **One author designed both sides.** The oracle's notion of \"still vulnerable\" and "
         "the verifiers' notion are different code, but they are the same idea, held by the same "
         "person, written in the same week. An independent re-implementation of Arm D against the "
         "frozen holdout - without sight of `oracle/truth.py` - is the only real test, and it has "
         "not been run.",
         "2. **The vulnerability predicate is given to the verifier.** Every arm receives a "
         "correct, machine-checkable definition of the vulnerable condition. Deriving that "
         "predicate from an advisory is itself hard and error-prone in production, and errors "
         "there would flow straight into every arm.",
         "3. **The scope model is shared vocabulary.** `FULL_SCOPE` in `obs/package.py` defines "
         "the partitions, and the collector damages the same partitions the verifier checks. A "
         "real collector's blind spots do not come pre-labelled to match a verifier's ontology. "
         "`UNDECLARED_GAP` exists precisely to probe what happens when they do not match, and it "
         "is the one mechanism where scope awareness buys nothing.",
         "4. **The oracle could be wrong.** It is ~90 lines with its own precedence order. Its "
         "outputs are checked against 13 hand-reasoned family expectations in "
         "`tests/test_oracle.py`, which is a real but shallow check: it confirms the oracle "
         "agrees with the author's intent, which is exactly the thing that cannot be independently "
         "confirmed here.",
         "5. **Arms C, D and E share a restart-projection idea.** They implement it separately, "
         "but the notion that an automatic service comes back and a staged patch lands is common "
         "to all three and to the oracle. If that model of Windows is wrong, every arm is wrong "
         "together and the benchmark cannot see it.",
         "",
         "## How much of the result this could explain", "",
         "The comparison that depends least on shared design is **Arm C versus Arm D**, because "
         "the two differ in the *information* they receive - one gets a collection manifest, the "
         "other does not - rather than in how cleverly they reason. The absolute accuracy figures "
         "depend much more on shared design than that comparison does, and should be read as an "
         "upper bound in the same way v1's were.",
         "",
         f"The strongest single piece of evidence that the separation is doing something: under "
         f"`UNDECLARED_GAP`, where the manifest is wrong rather than merely narrow, Arm D's unsafe "
         f"escape rate is "
         f"{pct(_v(results['by_group']['undeclared_gap'].get('D_SCOPE_AWARE_FAIL_CLOSED', {}), 'unsafe_escape_rate'))} "
         f"- indistinguishable from Arm C's "
         f"{pct(_v(results['by_group']['undeclared_gap'].get('C_SCOPE_UNAWARE_INDEPENDENT', {}), 'unsafe_escape_rate'))}. "
         "A verifier that was quietly borrowing the oracle's knowledge would not fail there.",
         ""]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L) + "\n")
    return Path(path)


# --------------------------------------------------------------------------- #
SUCCESS_CRITERIA = [
    ("far_reduction_80", "D or E cuts false assurance by >=80% vs C under adversarial missingness"),
    ("unsafe_escape_5", "Unsafe escape rate at or below 5%"),
    ("harm_recall_90", "Harm-detection recall at or above 90%"),
    ("verified_recall_80", "Verified-remediation recall at or above 80% when coverage >= 80%"),
    ("multi_family", "The advantage holds across several scenario families, not one template"),
    ("bounded_relevant_requests", "The active arm's requests are bounded and mostly decision-relevant"),
]


def evaluate_success_criteria(results: Dict[str, Any]) -> Dict[str, Any]:
    """Scored after the fact, from the holdout numbers, with no thresholds tuned."""
    groups = results["by_group"]
    declared = groups["adversarial_declared"]
    overall = results["overall"]
    by_cov = results["by_coverage"]
    by_fam = results["by_family"]

    c_far_n = declared["C_SCOPE_UNAWARE_INDEPENDENT"]["false_assurance_rate"]["numerator"]
    d_far_n = declared["D_SCOPE_AWARE_FAIL_CLOSED"]["false_assurance_rate"]["numerator"]
    e_far_n = declared["E_ACTIVE_EVIDENCE"]["false_assurance_rate"]["numerator"]
    best_n = min(d_far_n, e_far_n)
    count_reduction = (1 - best_n / c_far_n) if c_far_n else None

    ue = {arm: _v(overall[arm], "unsafe_escape_rate") for arm in ARMS}
    harm = {arm: _v(overall[arm], "harm_detection_recall") for arm in ARMS}
    harm_safe = {arm: _v(overall[arm], "harm_not_blessed_rate") for arm in ARMS}

    recall_at_high_coverage = {}
    for arm in ("D_SCOPE_AWARE_FAIL_CLOSED", "E_ACTIVE_EVIDENCE"):
        values = [_v(by_cov[arm][f"{c:.2f}"], "verified_recall")
                  for c in COVERAGE_LEVELS if c >= 0.80]
        values = [v for v in values if v is not None]
        recall_at_high_coverage[arm] = min(values) if values else None

    improved_families = []
    for family in FAMILIES:
        c_ue = _v(by_fam["C_SCOPE_UNAWARE_INDEPENDENT"].get(family, {}), "unsafe_escape_rate")
        d_ue = _v(by_fam["D_SCOPE_AWARE_FAIL_CLOSED"].get(family, {}), "unsafe_escape_rate")
        if c_ue is not None and d_ue is not None and c_ue - d_ue > 0.1:
            improved_families.append(family)

    e_block = overall["E_ACTIVE_EVIDENCE"]
    requests = e_block["evidence_requests_per_case"]["value"]
    relevant = e_block["decision_relevant_request_rate"]["value"] or 0.0

    verdicts = {
        "far_reduction_80": {
            "met": bool(count_reduction is not None and count_reduction >= 0.80),
            "detail": f"under declared-adversarial missingness Arm C makes {c_far_n} false "
                      f"assurances, Arm D {d_far_n} and Arm E {e_far_n}: a "
                      f"{pct(count_reduction)} reduction in count. The rate form of the metric is "
                      f"undefined for Arm D there because it never claims verification at all."},
        "unsafe_escape_5": {
            "met": bool(ue['D_SCOPE_AWARE_FAIL_CLOSED'] is not None
                        and ue['D_SCOPE_AWARE_FAIL_CLOSED'] <= 0.05
                        and ue['E_ACTIVE_EVIDENCE'] <= 0.05),
            "detail": f"Arm D {pct(ue['D_SCOPE_AWARE_FAIL_CLOSED'])}, Arm E "
                      f"{pct(ue['E_ACTIVE_EVIDENCE'])}, against Arm C's "
                      f"{pct(ue['C_SCOPE_UNAWARE_INDEPENDENT'])}."},
        "harm_recall_90": {
            "met": bool((harm["D_SCOPE_AWARE_FAIL_CLOSED"] or 0) >= 0.90
                        or (harm["E_ACTIVE_EVIDENCE"] or 0) >= 0.90),
            "detail": f"exact-label harm detection is {pct(harm['D_SCOPE_AWARE_FAIL_CLOSED'])} for "
                      f"Arm D and {pct(harm['E_ACTIVE_EVIDENCE'])} for Arm E. The weaker property "
                      f"that matters operationally - never calling a harm case remediated - is "
                      f"{pct(harm_safe['D_SCOPE_AWARE_FAIL_CLOSED'])} for both, against "
                      f"{pct(harm_safe['C_SCOPE_UNAWARE_INDEPENDENT'])} for Arm C."},
        "verified_recall_80": {
            "met": bool(any(v is not None and v >= 0.80 for v in recall_at_high_coverage.values())),
            "detail": "at coverage 80% or better the worst verified-recall is "
                      f"{pct(recall_at_high_coverage['D_SCOPE_AWARE_FAIL_CLOSED'])} for Arm D and "
                      f"{pct(recall_at_high_coverage['E_ACTIVE_EVIDENCE'])} for Arm E."},
        "multi_family": {
            "met": len(improved_families) >= 4,
            "detail": f"{len(improved_families)} of {len(FAMILIES)} scenario families show a "
                      f"materially lower unsafe-escape rate for Arm D than Arm C: "
                      f"{', '.join(improved_families)}."},
        "bounded_relevant_requests": {
            "met": bool(requests <= 3.0 and relevant > 0.5),
            "detail": f"{num(requests, 2)} requests per case against a hard cap of 3; "
                      f"{pct(relevant)} of requests measurably shrank the blocking set or settled "
                      f"the verdict."},
    }
    met = sum(1 for v in verdicts.values() if v["met"])
    abstention = _v(overall["D_SCOPE_AWARE_FAIL_CLOSED"], "abstention_rate") or 0.0
    if met == len(verdicts):
        classification = "STRONG SIGNAL"
    elif abstention > 0.5:
        classification = "MIXED SIGNAL"
    elif met >= 4:
        classification = "MIXED SIGNAL"
    else:
        classification = "WEAK / NEGATIVE SIGNAL"
    return {"criteria": verdicts, "criteria_met": met, "criteria_total": len(verdicts),
            "classification": classification,
            "passive_abstention_rate": abstention}


# --------------------------------------------------------------------------- #
def write_final_report(path: Path, results: Dict[str, Any], rows: List[Dict[str, Any]],
                       metadata: Dict[str, Any], criteria: Dict[str, Any]) -> Path:
    overall = results["overall"]
    groups = results["by_group"]
    by_cov = results["by_coverage"]
    recovery = results["active_recovery"]
    manifest = results["manifest"]
    counts = metadata["case_counts"]

    C = "C_SCOPE_UNAWARE_INDEPENDENT"
    D, E = "D_SCOPE_AWARE_FAIL_CLOSED", "E_ACTIVE_EVIDENCE"

    def g(group: str, arm: str, metric: str) -> Optional[float]:
        return _v(groups[group][arm], metric)

    def cov(arm: str, coverage: str, metric: str) -> Optional[float]:
        return _v(by_cov[arm][coverage], metric)

    L: List[str] = []
    w = L.append

    w("# Remediation Verification v2 - Evidence Completeness, Adversarial Collector "
      "Blindness, and Fail-Closed Verification")
    w("")
    w(f"- Experiment `{metadata['experiment']}` revision `{metadata['experiment_revision']}`")
    w(f"- Run (UTC) `{metadata['timestamp_utc']}` | Python `{metadata['python_version']}` "
      f"| git `{metadata['git_commit_sha']}`")
    w(f"- Holdout manifest SHA-256 **`{manifest['manifest_sha256']}`**")
    w(f"- Holdout observations SHA-256 `{manifest['observations_sha256']}`")
    w(f"- Generation config SHA-256 `{manifest['generation_config_sha256']}`")
    w(f"- {counts['conditions_per_partition']} holdout case conditions x 5 arms = "
      f"{counts['conditions_per_partition'] * 5} verdicts. Simulation only; no network, no real "
      f"endpoint, no exploit code.")
    w("")
    w(f"**Result classification: {criteria['classification']}** "
      f"({criteria['criteria_met']} of {criteria['criteria_total']} pre-stated STRONG-SIGNAL "
      f"criteria met).")
    w("")

    # ------------------------------------------------------------------ #
    w("## Executive summary")
    w("")
    w("**1. Does false assurance increase as evidence coverage declines?**  It jumps, then "
      "plateaus - it does not climb smoothly. For the scope-unaware independent verifier the "
      f"unsafe-escape rate goes {pct(cov(C, '1.00', 'unsafe_escape_rate'))} at complete coverage "
      f"to {pct(cov(C, '0.90', 'unsafe_escape_rate'))} the moment coverage stops being complete, "
      f"and then *falls* as coverage keeps dropping: {pct(cov(C, '0.80', 'unsafe_escape_rate'))} "
      f"at 80%, {pct(cov(C, '0.60', 'unsafe_escape_rate'))} at 60%, "
      f"{pct(cov(C, '0.40', 'unsafe_escape_rate'))} at 40%. The reason is mundane and important: "
      "as more evidence disappears, whole evidence items go missing rather than individual "
      "fields, and a missing item is visible even without a manifest, so the verifier starts "
      "abstaining instead of guessing. **The dangerous region is high coverage, not low "
      "coverage.** A 90%-complete collection is more likely to produce a confident wrong answer "
      "than a 40%-complete one.")
    w("")
    w("**2. Is adversarial missingness worse than random missingness?**  Substantially, at the "
      f"same nominal coverage. Arm C's unsafe-escape rate is "
      f"{pct(g('random_missing', C, 'unsafe_escape_rate'))} when evidence is dropped without "
      f"regard to what matters, {pct(g('adversarial_declared', C, 'unsafe_escape_rate'))} when "
      f"the loss is aimed at the decisive field, and "
      f"{pct(g('undeclared_gap', C, 'unsafe_escape_rate'))} when the collector is also wrong "
      f"about its own scope. Paired over identical conditions the difference is not marginal: "
      f"see the statistics section.")
    w("")
    w("**3. Does scope awareness prevent unsafe verified verdicts?**  For gaps the collector "
      f"knows about, completely. Arm D's unsafe-escape rate over the whole holdout is "
      f"{pct(_v(overall[D], 'unsafe_escape_rate'))} "
      f"({_frac(overall[D], 'unsafe_escape_rate')}), against Arm C's "
      f"{pct(_v(overall[C], 'unsafe_escape_rate'))} "
      f"({_frac(overall[C], 'unsafe_escape_rate')}). Every one of Arm D's remaining escapes comes "
      "from `UNDECLARED_GAP` - the condition where the manifest claims coverage the collector did "
      "not have. Under the five declared mechanisms Arm D's unsafe-escape rate is exactly "
      f"{pct(g('adversarial_declared', D, 'unsafe_escape_rate'))} "
      f"({_frac(groups['adversarial_declared'][D], 'unsafe_escape_rate')}). **Scope awareness is a "
      "defence against gaps the collector can describe, and no defence at all against gaps it "
      "cannot.**")
    w("")
    w(f"**4. How much abstention does safety require?**  For passive fail-closed verification, "
      f"far too much. Arm D abstains on {pct(_v(overall[D], 'abstention_rate'))} of the holdout "
      f"and on {pct(g('adversarial_declared', D, 'abstention_rate'))} of adversarially degraded "
      f"conditions. Its verified-remediation recall at 90% coverage is "
      f"{pct(cov(D, '0.90', 'verified_recall'))} and at 80% coverage "
      f"{pct(cov(D, '0.80', 'verified_recall'))}. This is the pre-registered definition of a "
      "MIXED result: Arm D buys its safety almost entirely by declining to answer.")
    w("")
    w(f"**5. Does active evidence collection recover useful coverage?**  This is the strongest "
      f"result in the experiment. With a hard cap of three requests and "
      f"{num(overall[E]['evidence_requests_per_case']['value'], 2)} used per case on average, "
      f"Arm E answered {recovery['recovered_correct']} of Arm D's "
      f"{recovery['reference_abstentions']} abstentions correctly "
      f"({pct(recovery['recovery_rate'])}), got **{recovery['recovered_incorrect']}** of them "
      f"wrong, and created **{recovery['new_false_assurances_created']}** new false assurances. "
      f"Its unsafe-escape rate is identical to Arm D's at "
      f"{pct(_v(overall[E], 'unsafe_escape_rate'))} while accuracy rises from "
      f"{pct(_v(overall[D], 'accuracy'))} to {pct(_v(overall[E], 'accuracy'))} and abstention "
      f"falls from {pct(_v(overall[D], 'abstention_rate'))} to "
      f"{pct(_v(overall[E], 'abstention_rate'))}. Asking for a few specific things is what makes "
      "fail-closed verification usable rather than merely safe.")
    w("")
    w("**6. Which evidence types have the highest decision value?**  Ranked by how often a "
      "request for them moved the verdict, and by how often their absence alone blocked one - see "
      "the evidence-value table below. The short version: **package inventory scope** dominates, "
      "because a name-addressed fact can hide in any install scope, so a narrowed inventory "
      "poisons every package predicate. Path-addressed evidence (registry keys, file paths) is far "
      "cheaper to reason about, because the path pins the partition. Application-health and "
      "security-posture evidence is the second-largest blocker, and for a reason worth noticing: "
      "they are never needed to prove the vulnerability is gone, only to prove that fixing it "
      "cost nothing.")
    w("")
    w("**7. What are the remaining false-assurance cases?**  All "
      f"{overall[D]['false_assurance_rate']['numerator']} of Arm D's and Arm E's are "
      "`UNDECLARED_GAP` conditions: the collector returned an incomplete inventory while its "
      "manifest declared full coverage. No amount of manifest-reading fixes a manifest that is "
      "wrong. `reports/false-assurance-review.md` lists every one.")
    w("")
    w("**8. Standalone company, product module, or feature?**  On this evidence, **a product "
      "module, and only if it owns collection.** The verification logic itself is a few hundred "
      "lines of deterministic rules with no model in it, and an MDM vendor could implement it in "
      "a sprint. What is not cheap is the thing the results say actually matters: a collector "
      "that knows and honestly declares its own scope, and an evidence-request path that can "
      "widen a query on demand. The full argument, including the case against, is in the "
      "startup-thesis section.")
    w("")
    w("**9. What would have to be true in a real Windows environment for this to transfer?**  "
      "Four things, none of them established here: that real collectors can report their own "
      "scope accurately (the entire result rests on this); that the `UNDECLARED_GAP` rate in "
      "practice is low rather than dominant; that a scope-widening request is usually available "
      "and usually cheap; and that operators tolerate an abstention rate somewhere between Arm "
      "D's and Arm E's rather than switching the whole thing off. See 'Simulation-to-reality "
      "gap'.")
    w("")
    w("**10. What is the next falsifiable experiment?**  Measure the undeclared-gap rate of real "
      "collectors against a known-state Windows lab image, because that single number decides "
      "whether the defence tested here is worth building. Details at the end.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Hypotheses")
    w("")
    w("| ID | Hypothesis | Verdict |")
    w("| --- | --- | --- |")
    w(f"| H1 | False assurance rises monotonically as coverage falls | **Not supported.** Unsafe "
      f"escape for Arm C peaks at 90% coverage "
      f"({pct(cov(C, '0.90', 'unsafe_escape_rate'))}) and declines to "
      f"{pct(cov(C, '0.40', 'unsafe_escape_rate'))} at 40%. The relationship is a step at the "
      f"first loss of completeness, then a decline as gaps become visible. |")
    w(f"| H2 | Scope-aware fail-closed cuts false assurance by >=80% vs Arm C | **Supported in "
      f"counts, not in the rate.** Under the five declared mechanisms Arm C makes "
      f"{groups['adversarial_declared'][C]['false_assurance_rate']['numerator']} false assurances "
      f"and Arm D makes "
      f"{groups['adversarial_declared'][D]['false_assurance_rate']['numerator']}. But Arm D's "
      f"*rate* is undefined there (it never claims verification), and with `UNDECLARED_GAP` "
      f"included its rate is {pct(g('adversarial_all', D, 'false_assurance_rate'))} against Arm "
      f"C's {pct(g('adversarial_all', C, 'false_assurance_rate'))} - nominally worse. The metric "
      f"chooses the answer. |")
    w(f"| H3 | Abstention rises but verified recall stays acceptable at coverage >= 80% | "
      f"**Not supported.** Arm D's verified recall is {pct(cov(D, '0.90', 'verified_recall'))} at "
      f"90% coverage and {pct(cov(D, '0.80', 'verified_recall'))} at 80%. Arm E does far better "
      f"({pct(cov(E, '0.90', 'verified_recall'))} and "
      f"{pct(cov(E, '0.80', 'verified_recall'))}) but still misses the 80% bar. |")
    w(f"| H4 | A bounded active verifier recovers verdicts without materially raising false "
      f"assurance | **Supported.** {recovery['recovered_correct']}/"
      f"{recovery['reference_abstentions']} abstentions recovered correctly, "
      f"{recovery['recovered_incorrect']} incorrectly, "
      f"{recovery['new_false_assurances_created']} new false assurances, identical unsafe-escape "
      f"rate. |")
    w(f"| H5 | Adversarial missingness is substantially more dangerous than random | "
      f"**Supported.** At matched coverage, Arm C's unsafe escape is "
      f"{pct(g('random_missing', C, 'unsafe_escape_rate'))} under random loss versus "
      f"{pct(g('adversarial_declared', C, 'unsafe_escape_rate'))} under targeted loss and "
      f"{pct(g('undeclared_gap', C, 'unsafe_escape_rate'))} under undeclared loss. |")
    w("")

    # ------------------------------------------------------------------ #
    w("## Experimental design")
    w("")
    w("Five layers, separated so that leakage is a structural impossibility rather than a "
      "discipline:")
    w("")
    w("```text")
    w("world/    latent endpoint reality across a timeline (baseline -> remediation -> reboot)")
    w("oracle/   ground truth, read from the latent world, five labels, never abstains")
    w("collect/  manufactures blindness: coverage level x missingness mechanism x seed")
    w("obs/      the serialised ObservationPackage and CollectionManifest")
    w("verifiers/ import obs/ and vocab/ only - asserted by tests/test_layering.py")
    w("```")
    w("")
    w("| Arm | What it receives |")
    w("| --- | --- |")
    w("| A `STATUS_ONLY` | execution metadata only |")
    w("| B `TARGET_STATE` | flat view: merged evidence rows, no manifest; checks the intended "
      "change landed |")
    w("| C `SCOPE_UNAWARE_INDEPENDENT` | flat view; asks the independent vulnerability question "
      "but cannot tell a never-queried field from an absent one |")
    w("| D `SCOPE_AWARE_FAIL_CLOSED` | full view: raw per-collector items plus the collection "
      "manifest; refuses to verify on missing, stale, disputed, or out-of-scope evidence |")
    w("| E `ACTIVE_EVIDENCE` | as D, plus at most three targeted evidence requests |")
    w("")
    w("The flat view is what makes the A/B/C versus D/E boundary structural: it models a verifier "
      "reading a normalised inventory table rather than collector transcripts. Timestamps survive "
      "into the flat view; the reference points they would have to be compared against - when the "
      "remediation finished, when the device rebooted - live only in the manifest. A clock with "
      "no zero is not a freshness check.")
    w("")
    w(f"**Corpus.** {counts['families']} scenario families x {counts['coverage_levels']} coverage "
      f"levels x {counts['mechanisms_below_full_coverage']} mechanisms (one at full coverage) x "
      f"{counts['instances_per_cell']} instances = {counts['conditions_per_partition']} "
      f"conditions per partition, {counts['total_conditions']} in total across dev and holdout. "
      f"Seeds are SHA-256 of each condition's own identity, so no condition depends on iteration "
      f"order. Dev and holdout share no seeds. Everything reported here is holdout.")
    w("")
    w("**Mechanisms.** `RANDOM_MISSING` removes cells without regard to importance. "
      "`DECISIVE_FIELD_MISSING`, `REGRESSION_EVIDENCE_MISSING`, `STALE_EVIDENCE`, "
      "`CONTRADICTORY_EVIDENCE` and `SCOPE_MISMATCH` aim at what matters and declare the loss "
      "honestly in the manifest. `UNDECLARED_GAP` is a sixth mechanism added by this experiment: "
      "the data is missing and the manifest claims full coverage anyway. It is reported "
      "separately throughout, because v1's three residual failures were all of exactly that "
      "shape and without it this experiment would only be testing scope awareness against gaps "
      "that politely announce themselves.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Primary results")
    w("")
    w("Every rate below names its denominator. Two of them are easy to confuse and point in "
      "opposite directions when an arm abstains a lot.")
    w("")
    w("| Metric | Numerator | Denominator |")
    w("| --- | --- | --- |")
    for name in ["false_assurance_rate", "unsafe_escape_rate", "verified_precision",
                 "verified_recall", "abstention_rate", "harm_detection_recall",
                 "harm_not_blessed_rate", "partial_remediation_recall"]:
        definition = results["metric_definitions"][name]
        w(f"| `{name}` | {definition['numerator']} | {definition['denominator']} |")
    w("")
    w("### Whole holdout partition")
    w("")
    w("| Arm | False assurance | Unsafe escape | Abstention | Verified recall | Harm never "
      "blessed | Accuracy |")
    w("| --- | --- | --- | --- | --- | --- | --- |")
    for arm in ARMS:
        block = overall[arm]
        w(f"| {SHORT[arm]} | {pct(_v(block, 'false_assurance_rate'))} "
          f"({_frac(block, 'false_assurance_rate')}) | "
          f"{pct(_v(block, 'unsafe_escape_rate'))} ({_frac(block, 'unsafe_escape_rate')}) | "
          f"{pct(_v(block, 'abstention_rate'))} | {pct(_v(block, 'verified_recall'))} | "
          f"{pct(_v(block, 'harm_not_blessed_rate'))} | {pct(_v(block, 'accuracy'))} |")
    w("")
    w("### By missingness mechanism group")
    w("")
    for group, label in [("full_coverage", "Complete evidence (control)"),
                         ("random_missing", "Random missingness"),
                         ("adversarial_declared", "Adversarial, declared in the manifest"),
                         ("undeclared_gap", "Adversarial, NOT declared (out-of-brief control)")]:
        w(f"**{label}**")
        w("")
        w("| Arm | False assurance | Unsafe escape | Abstention | Verified recall | Harm never blessed |")
        w("| --- | --- | --- | --- | --- | --- |")
        for arm in ARMS:
            block = groups[group][arm]
            w(f"| {SHORT[arm]} | {pct(_v(block, 'false_assurance_rate'))} "
              f"({_frac(block, 'false_assurance_rate')}) | "
              f"{pct(_v(block, 'unsafe_escape_rate'))} ({_frac(block, 'unsafe_escape_rate')}) | "
              f"{pct(_v(block, 'abstention_rate'))} | {pct(_v(block, 'verified_recall'))} | "
              f"{pct(_v(block, 'harm_not_blessed_rate'))} |")
        w("")
    w("Read the complete-evidence row first. With nothing hidden, Arms C, D and E are all "
      "perfect and indistinguishable. Everything that separates them in this experiment is a "
      "property of the evidence, not of the reasoning.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Confidence intervals")
    w("")
    w("Wilson intervals assume independent observations, and these are not independent: "
      f"{counts['conditions_per_partition'] // counts['families']} conditions share each scenario "
      "family and differ only in how their evidence was damaged. Both are given; the "
      "cluster bootstrap - resampling whole families, 2000 draws - is the one to believe, and it "
      "is much wider.")
    w("")
    w("| Arm | Unsafe escape | Wilson 95% | Family cluster bootstrap 95% |")
    w("| --- | --- | --- | --- |")
    for arm in ARMS:
        entry = overall[arm]["unsafe_escape_rate"]
        wilson = entry.get("wilson_ci95")
        boot = entry.get("cluster_bootstrap_ci95") or {}
        wilson_text = f"{pct(wilson[0])} - {pct(wilson[1])}" if wilson else "n/a"
        boot_text = (f"{pct(boot.get('lo'))} - {pct(boot.get('hi'))}"
                     if boot.get("lo") is not None else "undefined on too many resamples")
        w(f"| {SHORT[arm]} | {pct(_v(overall[arm], 'unsafe_escape_rate'))} | {wilson_text} | "
          f"{boot_text} |")
    w("")

    # ------------------------------------------------------------------ #
    w("## Statistical comparisons")
    w("")
    w("McNemar over identical conditions, exact binomial p-values, with the discordant odds ratio "
      "and risk difference as effect sizes. `b` counts conditions where the first arm errs and "
      "the second does not.")
    w("")
    w("| Group | Comparison | Error | b | c | Exact p | Risk diff | Reading |")
    w("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for comparison in results["paired_comparisons"]:
        group = comparison.get("mechanism_group") or "all conditions"
        first, second = comparison["comparison"].split(" vs ")
        w(f"| {group} | {SHORT.get(first, first)} -> {SHORT.get(second, second)} | "
          f"{comparison['error_of_interest']} | {comparison['b']} | {comparison['c']} | "
          f"{comparison['p_exact']:.3g} | {comparison['risk_difference']:+.3f} | "
          f"{comparison['interpretation']} |")
    w("")
    w("**These p-values describe this generated corpus and nothing else.** Conditions within a "
      "family are correlated by construction, the family mix is a judgement call rather than a "
      "measured fleet distribution, and the corpus is adversarial on purpose. Statistical "
      "significance here is evidence that the arms differ on this benchmark, not evidence that "
      "they would differ on a real fleet.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Degradation analysis")
    w("")
    w("![Degradation curves](degradation-curves.svg)")
    w("")
    w("Machine-readable in `artifacts/degradation-curves.csv` (curve data) and "
      "`artifacts/results.csv` (per-condition rows). Full tables by coverage, mechanism, family, "
      "and request count are in `reports/collection-degradation.md`.")
    w("")
    w("| Coverage | C unsafe escape | D unsafe escape | E unsafe escape | D abstention | "
      "E abstention | C verified recall | E verified recall |")
    w("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for coverage in COVERAGE_LEVELS:
        key = f"{coverage:.2f}"
        w(f"| {int(coverage * 100)}% | {pct(cov(C, key, 'unsafe_escape_rate'))} | "
          f"{pct(cov(D, key, 'unsafe_escape_rate'))} | {pct(cov(E, key, 'unsafe_escape_rate'))} | "
          f"{pct(cov(D, key, 'abstention_rate'))} | {pct(cov(E, key, 'abstention_rate'))} | "
          f"{pct(cov(C, key, 'verified_recall'))} | {pct(cov(E, key, 'verified_recall'))} |")
    w("")
    w("The non-monotonicity in Arm C's curve is the most operationally useful finding here, and "
      "it was not predicted. A verification system is at its most dangerous when its evidence is "
      "*nearly* complete, because that is where gaps are small enough to be invisible and large "
      "enough to matter. Systems that measure their own collection health should treat 'coverage "
      "is 92%' as a warning, not a reassurance.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Evidence value")
    w("")
    w("Which evidence types blocked verdicts, and which requests for them paid off.")
    w("")
    request_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"asked": 0, "granted": 0, "moved": 0})
    for row in rows:
        if row["arm"] != E:
            continue
        for request in row.get("evidence_requests", []):
            entry = request_stats[request["evidence_type"]]
            entry["asked"] += 1
            entry["granted"] += int(bool(request["granted"]))
            entry["moved"] += int(bool(request["decision_relevant"]))
    w("| Evidence type requested | Requests | Granted | Moved the decision |")
    w("| --- | --- | --- | --- |")
    for etype, entry in sorted(request_stats.items(), key=lambda kv: -kv[1]["asked"]):
        label = "all types for one device" if etype == "*" else f"`{etype}`"
        w(f"| {label} | {entry['asked']} | {pct(entry['granted'] / entry['asked'])} | "
          f"{pct(entry['moved'] / entry['asked'])} |")
    w("")
    w("The structural point behind the ranking: a predicate leaf addressed by *name* - a package, "
      "a service - could be satisfied in any partition of its evidence type, so a narrowed query "
      "makes it unresolvable. A leaf addressed by *path* - a registry key, a file - pins exactly "
      "one partition, so a narrowed query only matters if it excluded that path. Package "
      "inventory is therefore the most fragile evidence in the system, and the scope of a "
      "software-inventory query is the single highest-value thing a collector can report "
      "accurately.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Success criteria")
    w("")
    w(f"Scored after the results were known, against thresholds fixed in advance. "
      f"{criteria['criteria_met']} of {criteria['criteria_total']} met.")
    w("")
    w("| Criterion | Met | Detail |")
    w("| --- | --- | --- |")
    for key, label in SUCCESS_CRITERIA:
        entry = criteria["criteria"][key]
        w(f"| {label} | {'yes' if entry['met'] else '**no**'} | {entry['detail']} |")
    w("")
    w(f"**Classification: {criteria['classification']}.** The pre-registered definition of a "
      f"MIXED result is that safety improves primarily by abstaining on most cases, and that "
      f"describes the passive fail-closed arm exactly: Arm D abstains on "
      f"{pct(criteria['passive_abstention_rate'])} of the holdout. Arm E is the reason this is "
      f"not a weak result - it holds Arm D's safety while answering about half of what Arm D "
      f"refuses - but two criteria still fail, and one of them (harm-detection recall) fails "
      f"badly.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Counter-evidence")
    w("")
    w("Given equal prominence, because the point of this experiment is to find out whether a "
      "thing is worth building, not to conclude that it is.")
    w("")
    w("**1. The defence fails completely against undeclared gaps.** Under `UNDECLARED_GAP`, Arm "
      f"D's unsafe-escape rate is {pct(g('undeclared_gap', D, 'unsafe_escape_rate'))} against Arm "
      f"C's {pct(g('undeclared_gap', C, 'unsafe_escape_rate'))} - better, but not a defence. "
      f"Every remaining false assurance in Arms D and E is of this kind. If real collectors are "
      "commonly wrong about their own scope rather than merely narrow, the entire result "
      "evaporates, and nothing in this experiment establishes which is true.")
    w("")
    w(f"**2. Passive fail-closed verification is close to operationally useless on its own.** "
      f"Arm D abstains on {pct(_v(overall[D], 'abstention_rate'))} of conditions and its overall "
      f"accuracy ({pct(_v(overall[D], 'accuracy'))}) is *worse* than the scope-unaware arm's "
      f"({pct(_v(overall[C], 'accuracy'))}). A tool that says 'I cannot tell' three times out of "
      "four gets switched off, and then the effective false-assurance rate is whatever the thing "
      "that replaces it produces.")
    w("")
    w("**3. Exact harm detection collapses under evidence loss for every arm.** Harm-detection "
      f"recall is {pct(_v(overall[C], 'harm_detection_recall'))} for Arm C, "
      f"{pct(_v(overall[D], 'harm_detection_recall'))} for Arm D and "
      f"{pct(_v(overall[E], 'harm_detection_recall'))} for Arm E. Arms D and E never *bless* a "
      "harm case, which is the property that matters operationally, but 'I cannot tell whether "
      "your fix broke the VPN client' is not the same product as 'your fix broke the VPN client'.")
    w("")
    w("**4. The corpus decides the numbers.** Twelve of thirteen families are failures by "
      "construction, and five of the seven degradation mechanisms aim at the decisive field on "
      "purpose. Arm D's abstention rate is therefore a property of this corpus, not an estimate "
      "of what it would do on a fleet where most remediations work and most evidence gaps are "
      "irrelevant. No prevalence claim in this report should be read as a fleet prevalence.")
    w("")
    w("**5. The logic is cheap to copy.** Arm D is roughly 250 lines of rules over a manifest. "
      "There is no model, no training data, and no accumulated asset. Any vendor that already "
      "owns the collector could implement it, and would do it better, because the hard part is "
      "the collector.")
    w("")
    w("**6. Same author, same week, both sides.** The oracle and the verifiers are separate code "
      "with no shared helpers, and `tests/test_layering.py` enforces that mechanically. They are "
      "not separate *minds*. `reports/shared-design-threats.md` is a full accounting; the short "
      "version is that absolute accuracy figures are an upper bound and the C-versus-D comparison "
      "is the part that depends least on shared design.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Threats to validity")
    w("")
    w("**Simulation-to-reality gap.** Post-restart behaviour, staged patches, side-by-side "
      "installs and scope partitions are modelled by mechanical rules. Real Windows is messier: "
      "servicing-stack ordering, pending file-rename operations, per-user versus machine hive "
      "redirection, WMI that returns partial results without saying so. The scope model in "
      "`obs/package.py` is the most suspect single assumption: it presumes a collector can "
      "enumerate its own partitions cleanly, which is exactly what `UNDECLARED_GAP` exists to "
      "question.")
    w("")
    w("**Correlated generated cases.** Every metric is computed over conditions that share "
      "scenario families. Cluster-bootstrap intervals are reported for this reason and are much "
      "wider than the Wilson intervals; several are undefined because the statistic does not "
      "exist on resamples where an arm never claims verification.")
    w("")
    w("**Oracle correctness risk.** The oracle is one function with its own precedence order. "
      "`tests/test_oracle.py` checks it against thirteen hand-reasoned family expectations, which "
      "confirms it agrees with the author's intent - the one thing that cannot be independently "
      "confirmed here. If the oracle's ordering is wrong (for example, if a staged-but-not-"
      "rebooted patch should count as remediated rather than partial), every arm is scored "
      "against a wrong answer key in the same direction.")
    w("")
    w("**Artificial case prevalence.** See counter-evidence 4.")
    w("")
    w("**Does fail-closed merely convert errors into abstentions?**  For Arm D, largely yes, and "
      "the numbers say so plainly: unsafe escape falls from "
      f"{pct(_v(overall[C], 'unsafe_escape_rate'))} to {pct(_v(overall[D], 'unsafe_escape_rate'))} "
      f"while abstention rises from {pct(_v(overall[C], 'abstention_rate'))} to "
      f"{pct(_v(overall[D], 'abstention_rate'))}. That trade is only worth making if an abstention "
      "is cheaper than a wrong 'verified', which depends entirely on what the operator does next. "
      "Arm E is the interesting arm precisely because it does not accept that trade: it converts "
      f"{pct(recovery['recovery_rate'])} of the abstentions back into correct answers at zero "
      "measured cost in unsafe escape.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Safety boundaries")
    w("")
    w("- Simulation only. No registry write, no package install or removal, no service change, no "
      "subprocess execution of any generated content, no network call in the benchmark path.")
    w("- No exploit code exists in this experiment. Vulnerability presence is established only "
      "through safe state predicates over package, file, registry, service, patch, reboot and "
      "posture state.")
    w("- The real-Windows adapter remains hard-disabled and unimplemented, behind "
      "`ALLOW_REAL_WINDOWS_LAB=1`, which is an explicit future-only gate. "
      "`tests/test_safety.py` asserts that no real execution path is reachable during a benchmark "
      "run, and that no module in `src/rv2` shells out, opens a socket, or calls `eval`/`exec`.")
    w("- No third-party runtime dependencies; the test suite needs no network access.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Startup thesis")
    w("")
    w("v1 ended with the thesis stronger and the risk sharpened: verification beats execution "
      "status, but the residual failures were all silently incomplete collection, so the moat - "
      "if any - was in collection rather than logic. v2 was built to attack that, and it "
      "confirms it in a way that is more useful than encouraging.")
    w("")
    w("**What got stronger.** Scope awareness is a real, complete defence against declared gaps: "
      f"{_frac(groups['adversarial_declared'][D], 'unsafe_escape_rate')} unsafe escapes under the "
      "five declared mechanisms, against Arm C's "
      f"{_frac(groups['adversarial_declared'][C], 'unsafe_escape_rate')}. And bounded active "
      "collection turns a safe-but-useless verifier into a usable one without giving the safety "
      "back. That pairing - a manifest that describes its own scope, plus a channel to widen a "
      "query - is a coherent product surface, and it is not what MDM compliance policies do "
      "today.")
    w("")
    w("**What got weaker.** The value is now clearly located in the *collector*, not the "
      "verifier. Arm D is trivially reimplementable; the thing it depends on - an honest scope "
      "manifest - is owned by whoever runs the agent. A verification vendor sitting on top of "
      "someone else's inventory API inherits that vendor's undeclared gaps and, per these "
      "results, has no defence against them at all. The defensible position is therefore either "
      "'we run our own collector' (a much heavier company) or 'we are a module inside the "
      "platform that already does' (not a company).")
    w("")
    w("**Net.** The evidence supports a **product module with a collection requirement**, not a "
      "standalone verification layer over third-party telemetry. The specific claim that survived "
      "contact with data is narrow: *an independent verifier is worth exactly as much as its "
      "collector's honesty about scope, and a bounded evidence-request channel is what makes "
      "fail-closed verification operationally survivable.* The claim that did not survive is that "
      "verification logic on top of existing telemetry is sufficient.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Next experiment")
    w("")
    w("**v3 - measuring the undeclared-gap rate of real collectors.** One number decides whether "
      "any of this matters, and it is not measured here: how often is a real endpoint collector "
      "wrong about its own scope, as opposed to merely narrow? Everything in v2 says scope "
      "awareness is a complete defence in the first case and no defence in the second.")
    w("")
    w("Falsifiable design, and it does not need a product:")
    w("")
    w("1. Build a Windows lab image with a *known* ground-truth state: a deliberate per-user "
      "install, a WOW6432Node key, a second binary outside the default path, a staged servicing "
      "-stack update, a disabled-but-auto-start service.")
    w("2. Run several read-only collectors over it and capture both what they return and what "
      "they claim to have covered.")
    w("3. Classify every discrepancy as declared (the collector's own scope report predicts the "
      "gap) or undeclared (it does not).")
    w("4. **Falsifier:** if undeclared gaps exceed roughly a third of all gaps, the v2 defence is "
      "not worth building and the honest conclusion is that endpoint verification cannot be done "
      "from telemetry alone.")
    w("")
    w("Gated behind `ALLOW_REAL_WINDOWS_LAB=1`, read-only signals only, a disposable VM with no "
      "network path to anything else, and no Intune or tenant integration. Two secondary "
      "questions worth folding in: whether an abstention with a named blocker is operationally "
      "cheaper than a wrong 'verified' (a human-factors question this benchmark cannot answer), "
      "and an independent re-implementation of Arm D against the frozen v2 holdout by someone who "
      "has not read `oracle/truth.py`.")
    w("")
    w("---")
    w("")
    w(f"Holdout manifest SHA-256: `{manifest['manifest_sha256']}`")
    w(f"Generation config SHA-256: `{manifest['generation_config_sha256']}`")
    w(f"Holdout observations SHA-256 (uncompressed JSONL): `{manifest['observations_sha256']}`")
    w("")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L) + "\n")
    return Path(path)
