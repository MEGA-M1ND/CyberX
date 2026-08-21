"""The ten primary metrics, each with its numerator and denominator written down.

v2's lesson was that the choice of denominator can decide the conclusion, so
every rate here carries its counts and a plain-English statement of what it
divides by.  No overall accuracy is reported: the fixture corpus is constructed,
so class prevalence carries no information.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from ..contracts.catalog import BY_ID
from ..fixtures.spec import FixtureSpec
from ..vocab import COMPOSITE_COLLECTOR, OPTIONAL_IMPORT_COLLECTORS, PASSIVE_COLLECTORS
from .classify import Classification

VULNERABILITY = "VULNERABILITY"
PERSISTENCE = "PERSISTENCE"
REGRESSION = "REGRESSION"

METRIC_DEFINITIONS: Dict[str, Dict[str, str]] = {
    "decisive_undeclared_gap_rate": {
        "numerator": "decisive facts silently missed (UNDECLARED_GAP) by this collector",
        "denominator": "decisive facts whose evidence type this collector claims to cover completely",
    },
    "fixture_undeclared_gap_rate": {
        "numerator": "fixtures with at least one decisive undeclared gap",
        "denominator": "all fixtures",
    },
    "false_coverage_claim_rate": {
        "numerator": "(fixture, evidence type) completeness claims contradicted by at least one "
                     "silently missed decisive fact",
        "denominator": "all (fixture, evidence type) completeness claims this collector makes "
                       "where a decisive fact of that type exists",
    },
    "verification_feasibility": {
        "numerator": "fixtures where this collector resolves every decisive fact",
        "denominator": "all fixtures",
    },
    "cross_collector_rescue_rate": {
        "numerator": "decisive facts missed by a passive collector that at least one other "
                     "implemented channel covers",
        "denominator": "all decisive facts missed by a passive collector",
    },
    "active_request_success_rate": {
        "numerator": "scope-widening requests the composite collector can satisfy",
        "denominator": "decisive facts unresolved by the passive union that a widening could reach",
    },
    "remaining_false_assurance_rate": {
        "numerator": "vulnerable fixtures where the composite collector silently misses a "
                     "decisive vulnerability fact, so a verifier would bless them",
        "denominator": "all vulnerable fixtures",
    },
    "harm_fixture_blessed_rate": {
        "numerator": "regression fixtures whose decisive regression fact is silently missed",
        "denominator": "all regression fixtures",
    },
    "unresolved_decisive_fact_rate": {
        "numerator": "decisive facts this collector does not settle, for any reason",
        "denominator": "all decisive facts across all fixtures",
    },
}


def _rate(numerator: int, denominator: int) -> Optional[float]:
    return (numerator / denominator) if denominator else None


def _entry(name: str, numerator: int, denominator: int, extra: Any = None) -> Dict[str, Any]:
    out = {
        "value": _rate(numerator, denominator),
        "numerator": numerator,
        "denominator": denominator,
        "numerator_meaning": METRIC_DEFINITIONS[name]["numerator"],
        "denominator_meaning": METRIC_DEFINITIONS[name]["denominator"],
    }
    if extra is not None:
        out["detail"] = extra
    return out


# --------------------------------------------------------------------------- #
# metric 1-3: what a single collector silently misses
# --------------------------------------------------------------------------- #
def decisive_undeclared_gap(rows: List[Classification]) -> Dict[str, Any]:
    claimed = [c for c in rows if c.completeness_claimed]
    missed = [c for c in claimed if c.is_silent_miss]
    return _entry("decisive_undeclared_gap_rate", len(missed), len(claimed),
                  sorted({c.fact_id for c in missed})[:20])


def unresolved_decisive_facts(rows: List[Classification]) -> Dict[str, Any]:
    """Denominator-stable companion to the undeclared-gap rate.

    A collector that claims completeness for nothing has an undefined
    undeclared-gap rate.  That is not the same as being useful, so the share of
    decisive facts it leaves unsettled is reported alongside.
    """
    unresolved = [c for c in rows if not c.resolved]
    return _entry("unresolved_decisive_fact_rate", len(unresolved), len(rows))


def fixture_undeclared_gap(rows: List[Classification], fixtures: List[FixtureSpec]) -> Dict[str, Any]:
    affected = {c.fixture_id for c in rows if c.is_silent_miss}
    return _entry("fixture_undeclared_gap_rate", len(affected), len(fixtures),
                  sorted(affected)[:20])


def false_coverage_claim(rows: List[Classification]) -> Dict[str, Any]:
    claims: Dict[Any, List[Classification]] = defaultdict(list)
    for row in rows:
        if row.completeness_claimed:
            claims[(row.fixture_id, row.evidence_type)].append(row)
    wrong = [k for k, group in claims.items() if any(c.is_silent_miss for c in group)]
    return _entry("false_coverage_claim_rate", len(wrong), len(claims),
                  [list(k) for k in sorted(wrong)][:20])


# --------------------------------------------------------------------------- #
# metric 4-5: can this channel decide a fixture at all
# --------------------------------------------------------------------------- #
def verification_feasibility(rows: List[Classification], fixtures: List[FixtureSpec]
                             ) -> Dict[str, Any]:
    by_fixture: Dict[str, List[Classification]] = defaultdict(list)
    for row in rows:
        by_fixture[row.fixture_id].append(row)
    feasible = [fid for fid, group in by_fixture.items() if all(c.resolved for c in group)]
    return _entry("verification_feasibility", len(feasible), len(fixtures), sorted(feasible)[:20])


# --------------------------------------------------------------------------- #
# metric 6: does an independent channel recover what one channel missed
# --------------------------------------------------------------------------- #
def cross_collector_rescue(all_rows: List[Classification]) -> Dict[str, Any]:
    covered_by: Dict[Any, set] = defaultdict(set)
    for row in all_rows:
        if row.resolved:
            covered_by[(row.fixture_id, row.fact_id)].add(row.collector_id)

    misses: List[Classification] = [
        r for r in all_rows if r.collector_id in PASSIVE_COLLECTORS and not r.resolved]
    rescued, unrescued = [], []
    by_channel: Dict[str, int] = defaultdict(int)
    for miss in misses:
        # Peers only. The composite is built from these channels, so letting it
        # count as the rescuer would make the metric circular.
        others = covered_by[(miss.fixture_id, miss.fact_id)] - {miss.collector_id}
        others = {o for o in others if o in PASSIVE_COLLECTORS}
        if others:
            rescued.append(miss)
            for channel in sorted(others):
                by_channel[channel] += 1
        else:
            unrescued.append(miss)
    return _entry("cross_collector_rescue_rate", len(rescued), len(misses),
                  {"rescuing_channel_counts": dict(sorted(by_channel.items())),
                   "unrescued_examples": sorted({(m.family, m.fact_id) for m in unrescued})[:20]})


def active_request_success(all_rows: List[Classification]) -> Dict[str, Any]:
    """Facts the passive union cannot settle, that a widening could reach."""
    passive_resolved: Dict[Any, bool] = defaultdict(bool)
    composite_resolved: Dict[Any, bool] = defaultdict(bool)
    keys = set()
    for row in all_rows:
        key = (row.fixture_id, row.fact_id)
        keys.add(key)
        if row.collector_id in PASSIVE_COLLECTORS and row.resolved:
            passive_resolved[key] = True
        if row.collector_id == COMPOSITE_COLLECTOR and row.resolved:
            composite_resolved[key] = True
    candidates = [k for k in keys if not passive_resolved[k]]
    satisfied = [k for k in candidates if composite_resolved[k]]
    return _entry("active_request_success_rate", len(satisfied), len(candidates),
                  {"unsatisfiable": sorted(set(candidates) - set(satisfied))[:20]})


# --------------------------------------------------------------------------- #
# metric 7-8: what still gets blessed
# --------------------------------------------------------------------------- #
def remaining_false_assurance(all_rows: List[Classification], fixtures: List[FixtureSpec],
                              collector_id: str = COMPOSITE_COLLECTOR) -> Dict[str, Any]:
    vulnerable = [f for f in fixtures if f.expected_vulnerable]
    vulnerable_ids = {f.fixture_id for f in vulnerable}
    blessed = {r.fixture_id for r in all_rows
               if r.collector_id == collector_id and r.fixture_id in vulnerable_ids
               and r.decides == VULNERABILITY and r.is_silent_miss}
    return _entry("remaining_false_assurance_rate", len(blessed), len(vulnerable),
                  sorted(blessed))


def harm_fixture_blessed(all_rows: List[Classification], fixtures: List[FixtureSpec],
                         collector_id: str = COMPOSITE_COLLECTOR) -> Dict[str, Any]:
    harm = [f for f in fixtures if f.expected_regression]
    harm_ids = {f.fixture_id for f in harm}
    blessed = {r.fixture_id for r in all_rows
               if r.collector_id == collector_id and r.fixture_id in harm_ids
               and r.decides == REGRESSION and r.is_silent_miss}
    return _entry("harm_fixture_blessed_rate", len(blessed), len(harm), sorted(blessed))


# --------------------------------------------------------------------------- #
# metric 9-10: cost and breakdowns
# --------------------------------------------------------------------------- #
def collection_cost(collector_ids: List[str]) -> Dict[str, Any]:
    return {
        "note": "Contract estimates, not measurements. A real run replaces these with "
                "wall-clock seconds and record counts from the collector output.",
        "per_collector": {
            cid: {"approximate_seconds": BY_ID[cid].approximate_seconds,
                  "approximate_records": BY_ID[cid].approximate_records}
            for cid in collector_ids
        },
    }


def _group_rates(rows: List[Classification], key) -> Dict[str, Dict[str, Any]]:
    groups: Dict[str, List[Classification]] = defaultdict(list)
    for row in rows:
        groups[key(row)].append(row)
    out = {}
    for name, group in sorted(groups.items()):
        claimed = [c for c in group if c.completeness_claimed]
        missed = [c for c in claimed if c.is_silent_miss]
        out[name] = {
            "facts": len(group),
            "claimed_in_scope": len(claimed),
            "undeclared_gaps": len(missed),
            "undeclared_gap_rate": _rate(len(missed), len(claimed)),
            "resolved": sum(1 for c in group if c.resolved),
            "gap_classes": dict(sorted(
                (g, sum(1 for c in group if c.gap_class == g))
                for g in {c.gap_class for c in group})),
        }
    return out


def breakdowns(all_rows: List[Classification]) -> Dict[str, Any]:
    passive = [r for r in all_rows if r.collector_id in PASSIVE_COLLECTORS]
    return {
        "by_family": _group_rates(passive, lambda r: r.family),
        "by_user_scope": _group_rates(passive, lambda r: r.coordinates.get("user_scope") or "n/a"),
        "by_registry_view": _group_rates(
            passive, lambda r: r.coordinates.get("registry_view") or "not_registry"),
        "by_installation_type": _group_rates(
            passive, lambda r: r.coordinates.get("provider") or "not_a_package"),
        "by_evidence_type": _group_rates(passive, lambda r: r.evidence_type),
        "by_path_root": _group_rates(
            passive, lambda r: r.coordinates.get("path_root") or "not_a_file"),
        "note": "Pooled across the five passive collectors. Composite and import adapters "
                "are reported separately.",
    }


# --------------------------------------------------------------------------- #
def score(all_rows: List[Classification], fixtures: List[FixtureSpec],
          collector_ids: List[str]) -> Dict[str, Any]:
    by_collector: Dict[str, List[Classification]] = defaultdict(list)
    for row in all_rows:
        by_collector[row.collector_id].append(row)

    per_collector = {}
    for cid in collector_ids:
        rows = by_collector.get(cid, [])
        per_collector[cid] = {
            "contract_basis": BY_ID[cid].basis,
            "claims_complete_for": BY_ID[cid].claims_complete_for,
            "decisive_undeclared_gap_rate": decisive_undeclared_gap(rows),
            "unresolved_decisive_fact_rate": unresolved_decisive_facts(rows),
            "silent_misses": sum(1 for c in rows if c.is_silent_miss),
            "fixture_undeclared_gap_rate": fixture_undeclared_gap(rows, fixtures),
            "false_coverage_claim_rate": false_coverage_claim(rows),
            "verification_feasibility": verification_feasibility(rows, fixtures),
            "gap_class_totals": dict(sorted(
                (g, sum(1 for c in rows if c.gap_class == g))
                for g in {c.gap_class for c in rows})),
        }

    implemented = [c for c in collector_ids if c not in OPTIONAL_IMPORT_COLLECTORS]
    implemented_rows = [r for r in all_rows if r.collector_id in implemented]

    # "Best single passive collector" is ambiguous and the ambiguity matters: a
    # collector that claims almost nothing scores a perfect undeclared-gap rate
    # while deciding almost nothing. Both readings are reported.
    def feasible_count(cid: str) -> int:
        return per_collector.get(cid, {}).get("verification_feasibility", {}).get("numerator", 0)

    best_by_feasibility = max(PASSIVE_COLLECTORS, key=feasible_count)
    silent_misses = {cid: sum(1 for r in by_collector.get(cid, []) if r.is_silent_miss)
                     for cid in PASSIVE_COLLECTORS}
    best_by_silence = min(PASSIVE_COLLECTORS, key=lambda c: silent_misses[c])

    composite_misses = sum(1 for r in by_collector.get(COMPOSITE_COLLECTOR, []) if r.is_silent_miss)
    baseline_misses = silent_misses[best_by_feasibility]
    reduction = (1 - composite_misses / baseline_misses) if baseline_misses else None
    # H3 asks for a reduction against "the best single passive collector", which
    # turns out to be ambiguous in a way that decides the answer. Report the
    # composite against every passive baseline and let the reader see it.
    reduction_by_baseline = {
        cid: {
            "baseline_silent_misses": silent_misses[cid],
            "composite_silent_misses": composite_misses,
            "reduction": (1 - composite_misses / silent_misses[cid]) if silent_misses[cid] else None,
            "baseline_fixtures_decided": feasible_count(cid),
            "composite_fixtures_decided": per_collector.get(COMPOSITE_COLLECTOR, {}).get(
                "verification_feasibility", {}).get("numerator", 0),
        }
        for cid in PASSIVE_COLLECTORS
    }
    best_passive = best_by_feasibility
    best_rate = per_collector.get(best_passive, {}).get(
        "decisive_undeclared_gap_rate", {}).get("value")

    return {
        "metric_definitions": METRIC_DEFINITIONS,
        "per_collector": per_collector,
        "best_single_passive_collector": best_passive,
        "best_single_passive_selected_by": "most fixtures fully decided",
        "best_single_passive_undeclared_gap_rate": best_rate,
        "lowest_silent_miss_passive_collector": best_by_silence,
        "passive_silent_miss_counts": silent_misses,
        "composite_silent_misses": composite_misses,
        "composite_vs_best_passive_reduction": reduction,
        "composite_reduction_by_baseline": reduction_by_baseline,
        "reduction_basis": "absolute silent-miss counts, because the composite claims "
                           "completeness for nothing and its rate form is undefined",
        "composite_unresolved": per_collector.get(COMPOSITE_COLLECTOR, {}).get(
            "unresolved_decisive_fact_rate"),
        "cross_collector_rescue_rate": cross_collector_rescue(implemented_rows),
        "active_request_success_rate": active_request_success(implemented_rows),
        "remaining_false_assurance_rate": remaining_false_assurance(all_rows, fixtures),
        "harm_fixture_blessed_rate": harm_fixture_blessed(all_rows, fixtures),
        "collection_cost": collection_cost(collector_ids),
        "breakdowns": breakdowns(all_rows),
        "silent_miss_totals": {
            cid: sum(1 for r in by_collector.get(cid, []) if r.is_silent_miss)
            for cid in collector_ids
        },
    }
