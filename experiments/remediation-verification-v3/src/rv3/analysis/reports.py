"""Report generation.

Narrative is authored here; numbers are injected from the scored results so the
prose cannot drift.  Every report opens with the same banner stating whether the
figures below were measured on a lab VM or deduced from collector contracts,
because that distinction decides what the numbers are worth.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..contracts.catalog import BY_ID, IMPLEMENTED_CONTRACTS
from ..vocab import COMPOSITE_COLLECTOR, FAMILIES, OPTIONAL_IMPORT_COLLECTORS, PASSIVE_COLLECTORS, RunStatus

SHORT = {
    "A_UNINSTALL_REGISTRY": "A uninstall-registry",
    "B_EXPANDED_REGISTRY": "B expanded-registry",
    "C_PACKAGE_PROVIDER": "C package-provider",
    "D_FILE_VERSION": "D file-version",
    "E_SERVICE_TASK": "E service/task",
    "F_COMPOSITE_ACTIVE": "F composite",
    "X_INTUNE_EXPORT": "Intune export",
    "X_DEFENDER_EXPORT": "Defender export",
    "X_TENABLE_EXPORT": "Tenable export",
    "X_SCCM_EXPORT": "SCCM export",
}


def pct(value: Optional[float], digits: int = 1) -> str:
    return "n/a" if value is None else f"{100.0 * value:.{digits}f}%"


def frac(entry: Dict[str, Any]) -> str:
    return f"{entry.get('numerator', 0)}/{entry.get('denominator', 0)}"


def rate(entry: Dict[str, Any]) -> str:
    return f"{pct(entry.get('value'))} ({frac(entry)})"


def banner(results: Dict[str, Any]) -> List[str]:
    measured = results["measurement_status"] == RunStatus.MEASURED_ON_LAB_VM.value
    lines = ["> **Measurement status**"]
    if measured:  # pragma: no cover - requires a lab VM
        lines += ["> ", "> Figures below were **measured** on a disposable Windows lab VM."]
    else:
        lines += [
            "> ",
            f"> **{results['run_status']}.** No disposable Windows VM was reachable from this "
            f"session, so no collector was run against a real machine. Reason: "
            f"{results['blocked_reason']}.",
            "> ",
            "> Every figure below is **PREDICTED FROM COLLECTOR CONTRACTS** - deduced from what "
            "each collector's declared scope says it queries, applied to where each fixture's "
            "decisive evidence sits. That is a deduction, not a measurement. It says what should "
            "happen if the contracts are accurate; the entire point of a lab run is to find out "
            "where they are not.",
            "> ",
            "> **Do not cite any number in this experiment as a measured property of real Windows "
            "inventory tooling.**",
        ]
    return lines + [""]


# --------------------------------------------------------------------------- #
def write_gap_matrix(path: Path, results: Dict[str, Any], rows) -> Path:
    per = results["per_collector"]
    L = ["# Collector gap matrix", ""] + banner(results)
    L += [
        "Which channel can settle which fixture family, and what it does when it cannot.",
        "",
        "`silent` counts decisive facts a collector misses **while claiming to cover that "
        "evidence type completely** - the class v2 showed no verifier can defend against. "
        "`declared` counts facts it misses and says so, which a scope-aware verifier can turn "
        "into an abstention.",
        "",
        "| Collector | Claims complete for | Silent misses | Declared gaps | Decisive facts unresolved | Fixtures fully decided |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for cid in [c.collector_id for c in IMPLEMENTED_CONTRACTS] + OPTIONAL_IMPORT_COLLECTORS:
        entry = per.get(cid)
        if not entry:
            continue
        totals = entry["gap_class_totals"]
        claims = ", ".join(entry["claims_complete_for"]) or "_nothing_"
        L.append(f"| {SHORT[cid]} | {claims} | **{entry['silent_misses']}** | "
                 f"{totals.get('DECLARED_GAP', 0)} | {frac(entry['unresolved_decisive_fact_rate'])} | "
                 f"{frac(entry['verification_feasibility'])} |")
    L += ["", "## Decisive undeclared-gap rate", "",
          "Numerator: decisive facts silently missed. Denominator: decisive facts whose evidence "
          "type the collector claims to cover completely. A collector claiming completeness for "
          "nothing has no denominator, which is not the same as being safe - see the unresolved "
          "column above.", "",
          "| Collector | Rate | Contract basis |", "| --- | --- | --- |"]
    for cid in [c.collector_id for c in IMPLEMENTED_CONTRACTS] + OPTIONAL_IMPORT_COLLECTORS:
        entry = per.get(cid)
        if not entry:
            continue
        L.append(f"| {SHORT[cid]} | {rate(entry['decisive_undeclared_gap_rate'])} | "
                 f"`{entry['contract_basis']}` |")

    L += ["", "## By fixture family", "",
          "Pooled across the five passive collectors: how many of their decisive-fact readings "
          "were silent misses.", "",
          "| Family | Facts examined | Claimed in scope | Silent misses | Rate |",
          "| --- | --- | --- | --- | --- |"]
    for family in FAMILIES:
        entry = results["breakdowns"]["by_family"].get(family)
        if not entry:
            continue
        L.append(f"| {family} | {entry['facts']} | {entry['claimed_in_scope']} | "
                 f"{entry['undeclared_gaps']} | {pct(entry['undeclared_gap_rate'])} |")

    for label, key in [("user scope", "by_user_scope"), ("registry view", "by_registry_view"),
                       ("installation type", "by_installation_type"),
                       ("filesystem root", "by_path_root"), ("evidence type", "by_evidence_type")]:
        L += ["", f"## By {label}", "",
              "| Value | Facts | Claimed in scope | Silent misses | Rate |",
              "| --- | --- | --- | --- | --- |"]
        for name, entry in results["breakdowns"][key].items():
            L.append(f"| `{name}` | {entry['facts']} | {entry['claimed_in_scope']} | "
                     f"{entry['undeclared_gaps']} | {pct(entry['undeclared_gap_rate'])} |")
    L.append("")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L) + "\n")
    return Path(path)


# --------------------------------------------------------------------------- #
def write_undeclared_gap_review(path: Path, results: Dict[str, Any], rows, fixtures) -> Path:
    by_id = {f.fixture_id: f for f in fixtures}
    silent = [r for r in rows if r.is_silent_miss]
    L = ["# Undeclared-gap review", ""] + banner(results)
    L += [
        f"Every decisive fact a collector would silently miss: **{len(silent)}** across all "
        f"collectors and all {len(fixtures)} fixtures.",
        "",
        "A silent miss is a fact the collector does not reach *and does not report as missing*, "
        "on an evidence type it presents as complete. It is the only gap class that survives a "
        "scope-aware verifier, which is why it is the whole subject of this experiment.",
        "",
        "| Fixture | Family | Fact | Evidence type | Collector | Why it is invisible |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in sorted(silent, key=lambda r: (r.collector_id, r.family, r.fact_id)):
        contract = BY_ID[row.collector_id]
        coords = row.coordinates
        reason_parts = []
        if coords.get("registry_view") and coords["registry_view"] not in contract.registry_views:
            reason_parts.append(f"{coords['registry_view']} view not queried")
        if coords.get("hive") and coords["hive"] not in contract.hives:
            reason_parts.append(f"{coords['hive']} hive not queried")
        if coords.get("user_scope") and coords["user_scope"] not in contract.user_scopes:
            reason_parts.append(f"user scope `{coords['user_scope']}` not enumerated")
        if coords.get("provider") and coords["provider"] not in contract.providers:
            reason_parts.append(f"provider `{coords['provider']}` not enumerated")
        if coords.get("path_root") and coords["path_root"] not in contract.path_roots:
            reason_parts.append(f"path root `{coords['path_root']}` not scanned")
        reason = "; ".join(reason_parts) or "outside declared reach"
        L.append(f"| `{row.fixture_id}` | {row.family} | `{row.fact_id}` | {row.evidence_type} | "
                 f"{SHORT[row.collector_id]} | {reason} |")

    L += ["", "## By collector", "",
          "| Collector | Silent misses | Families affected |", "| --- | --- | --- |"]
    grouped: Dict[str, List[Any]] = defaultdict(list)
    for row in silent:
        grouped[row.collector_id].append(row)
    for cid in sorted(grouped):
        families = sorted({r.family for r in grouped[cid]})
        L.append(f"| {SHORT[cid]} | {len(grouped[cid])} | {', '.join(families)} |")

    L += ["", "## What survives the composite collector", ""]
    composite_silent = [r for r in silent if r.collector_id == COMPOSITE_COLLECTOR]
    if composite_silent:  # pragma: no cover - not reachable with the current contracts
        L += [f"{len(composite_silent)} decisive facts are still silently missed after composite "
              "collection:", ""]
        for row in composite_silent:
            L.append(f"- `{row.fixture_id}` {row.family} / `{row.fact_id}`")
    else:
        L += [
            "None. The composite collector claims completeness for nothing, so by construction it "
            "cannot produce a silent miss: everything it fails to reach it reports as a declared "
            "gap.",
            "",
            "That is a weaker statement than it looks, and it is worth being blunt about. It does "
            "not mean the composite sees everything. It means the composite is honest about what "
            "it does not see, which converts silent misses into abstentions. The cost shows up as "
            f"{frac(results['per_collector'][COMPOSITE_COLLECTOR]['unresolved_decisive_fact_rate'])} "
            "decisive facts left unresolved:",
            "",
        ]
        unresolved = [r for r in rows if r.collector_id == COMPOSITE_COLLECTOR and not r.resolved]
        for row in sorted(unresolved, key=lambda r: (r.family, r.fact_id)):
            spec = by_id[row.fixture_id]
            L.append(f"- **{row.family}** / `{row.fact_id}` ({row.evidence_type}) - "
                     f"{spec.title}. Classified `{row.gap_class}`.")
        L += ["",
              "Two structural limits produce all of them. Reaching an unloaded user profile means "
              "`reg load` of NTUSER.DAT, which mutates the live registry namespace and is outside "
              "a read-only boundary - so a machine with a profile that has not signed in is not "
              "fully verifiable read-only. And no Windows inventory channel reports whether an "
              "application still works, so a functional regression is invisible to every collector "
              "here, including the composite.", ""]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L) + "\n")
    return Path(path)


# --------------------------------------------------------------------------- #
def write_cross_collector_recovery(path: Path, results: Dict[str, Any], rows) -> Path:
    rescue = results["cross_collector_rescue_rate"]
    active = results["active_request_success_rate"]
    L = ["# Cross-collector recovery", ""] + banner(results)
    L += [
        "When one channel misses a decisive fact, does another channel have it?",
        "",
        f"**Cross-collector rescue rate: {rate(rescue)}.**",
        "",
        f"Numerator: {rescue['numerator_meaning']}. Denominator: {rescue['denominator_meaning']}. "
        "The composite collector is excluded from the rescuer set - it is built from these "
        "channels, so counting it as an independent rescuer would make the metric circular.",
        "",
        "## Which channel does the rescuing", "",
        "| Rescuing channel | Facts it covers that another passive channel missed |",
        "| --- | --- |",
    ]
    for channel, count in sorted(rescue["detail"]["rescuing_channel_counts"].items(),
                                 key=lambda kv: -kv[1]):
        L.append(f"| {SHORT[channel]} | {count} |")
    L += ["",
          "The filesystem/version channel is the largest single rescuer, which is the mechanism "
          "H2 predicted: package inventory answers *what is registered*, and a file version "
          "answers *what is actually there*. Those are different questions and only the second "
          "one decides a vulnerability.",
          "",
          "## What nothing rescues", "",
          "Decisive facts no passive channel covers:", ""]
    for family, fact_id in rescue["detail"]["unrescued_examples"]:
        L.append(f"- **{family}** / `{fact_id}`")
    L += ["",
          "These fall into three groups, and the grouping is the useful part:",
          "",
          "1. **Outside every default path list** - portable executables, renamed binaries, "
          "orphaned installs under a user profile. Recoverable, but only by widening the search, "
          "which is what the composite's active step does.",
          "2. **Behind an access boundary** - a directory the collector cannot read, an unloaded "
          "user hive. The first is recoverable with elevation; the second is not recoverable at "
          "all without a write.",
          "3. **Not modelled by any Windows inventory channel** - application health. No amount "
          "of cross-collection helps, because no collector asks the question.",
          "",
          "## Bounded active collection", "",
          f"**Active-request success rate: {rate(active)}.**",
          "",
          f"Numerator: {active['numerator_meaning']}. Denominator: {active['denominator_meaning']}.",
          "",
          "The composite collector widens the file-version search one root class at a time, up to "
          "a cap of three widenings. What it cannot satisfy is exactly group 2 and group 3 above.",
          ""]
    unsat = active["detail"]["unsatisfiable"]
    if unsat:
        L += ["Requests that no widening can satisfy:", ""]
        for fixture_id, fact_id in unsat:
            L.append(f"- `{fixture_id}` / `{fact_id}`")
        L.append("")
    L += ["## Are the failures correlated?", "",
          "Yes, and in a way that matters. The registry channels (A, B, C) fail *together* on "
          "per-user, second-user, and non-ARP installs, because they share a mechanism: they all "
          "read package registrations. Adding a second registry-based channel buys almost nothing. "
          "The only channel that fails independently is the filesystem one, because it asks a "
          "different question of a different subsystem.",
          "",
          "This is the practical form of the finding: **evidence-channel diversity has to be "
          "mechanism diversity.** Two inventories are one channel.", ""]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L) + "\n")
    return Path(path)


# --------------------------------------------------------------------------- #
def write_safety_procedure(path: Path, results: Dict[str, Any], preflight_result: Dict[str, Any],
                           plan: Dict[str, Any]) -> Path:
    L = ["# Safety and lab procedure", "",
         "This experiment may run against exactly one kind of machine: a disposable Windows VM "
         "you are prepared to destroy. Everything below exists to make any other outcome hard.",
         "",
         "## What this run did", "",
         "```text", preflight_result["rendered"], "```", "",
         "## The three gates", "",
         "| Gate | Purpose | Effect if unset |",
         "| --- | --- | --- |",
         "| `ALLOW_REAL_WINDOWS_LAB=1` | permits running read-only collectors on a real machine | "
         "`GateNotSet` before any command is assembled |",
         "| `ALLOW_WINDOWS_FIXTURE_SETUP=1` | permits creating or removing fixtures, the only "
         "writing path | `GateNotSet` before any command is assembled |",
         "| `RV3_LAB_CONFIRMATION=<hostname>` | the operator naming the target machine | "
         "`ConfirmationMissing`, and a mismatch with the live hostname is also refused |",
         "",
         "The third gate is deliberately not a boolean. A flag can be set by a stray environment "
         "file or an inherited shell; typing the name of the machine you are about to modify "
         "cannot be done by accident. Both the Python harness and the PowerShell scripts check "
         "all three independently, so bypassing one layer is not enough.",
         "",
         "A non-Windows host is refused before the gates are even considered, which is what "
         "happened here.",
         "",
         "## What may never be touched", "",
         "- the host machine",
         "- any corporate or managed endpoint",
         "- a production tenant of any kind",
         "- a live Intune, Configuration Manager, or Defender environment",
         "- any machine not explicitly designated as the disposable lab",
         "",
         "Vendor adapters are import-only. They read a file someone exported by hand; they do not "
         "authenticate, do not open a socket, and have no live-tenant code path.",
         "",
         "## What the fixtures are made of", "",
         "Nothing vulnerable is installed and no exploit is reproduced. A \"vulnerable\" fixture is "
         "a version string below a threshold, sitting at a particular coordinate in the evidence "
         "surface. The material is:",
         "",
         "- copies of an existing benign system binary (`notepad.exe`) placed under `C:\\RV3Lab`",
         "- synthetic Add/Remove Programs entries prefixed `RV3Lab_`",
         "- registry values under `SOFTWARE\\RV3Lab`",
         "- disposable services and scheduled tasks prefixed `RV3Lab_`",
         "- disposable local accounts prefixed `rv3lab_`",
         "",
         f"The provisioning plan is {plan['operation_count']} operations, hashed "
         f"`{plan['plan_sha256']}`.",
         "",
         "## Win32_Product", "",
         "Not used anywhere. Enumerating that WMI class triggers an MSI consistency check against "
         "every registered product on the machine, which can reconfigure software as a side effect "
         "of a supposedly read-only query. It is excluded by name in the collector contracts, in "
         "the PowerShell, and in the tests.",
         "",
         "## Cleanup", "",
         "`Remove-LabFixtures.ps1` cleans by prefix rather than by plan, so an interrupted or "
         "partially-applied provisioning run still cleans up completely. It drops the deny-ACE "
         "from the permission-denied fixture first, then removes tasks, services, local accounts, "
         "ARP keys, the lab registry namespace, and the lab directory, and reports any residue.",
         "",
         "## Running it for real", "",
         "```powershell",
         "# On the disposable Windows VM only. Take a snapshot first.",
         "$env:ALLOW_REAL_WINDOWS_LAB = '1'",
         "$env:ALLOW_WINDOWS_FIXTURE_SETUP = '1'",
         "$env:RV3_LAB_CONFIRMATION = $env:COMPUTERNAME",
         "python run_experiment.py --preflight-only   # read this before going further",
         "python run_experiment.py",
         "```",
         "",
         "Requirements: Windows 10/11 or Server 2019+, PowerShell 5.1 or later, Python 3.11+, "
         "local administrator (the composite collector and the permission-denied fixture need it), "
         "no network, and a snapshot taken beforehand. Expect the run to create a second local "
         "account and two scheduled tasks; both are removed by the cleanup script.", ""]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L) + "\n")
    return Path(path)


# --------------------------------------------------------------------------- #
def write_transfer_report(path: Path, results: Dict[str, Any]) -> Path:
    per = results["per_collector"]
    L = ["# Simulation-to-Windows transfer", ""] + banner(results)
    L += [
        "v2 measured verification behaviour against a simulated collector whose blindness was "
        "manufactured by the experiment. v3 was supposed to replace that simulation with real "
        "Windows measurements. It could not, so this file records precisely which v2 assumptions "
        "remain untested and what would settle each one.",
        "",
        "## v2's model versus the Windows evidence surface", "",
        "| v2 assumption | Windows analogue | Status after v3 |",
        "| --- | --- | --- |",
        "| Evidence partitions into disjoint scope keys a collector either queries or does not | "
        "registry views, hives, per-user profiles, package providers, filesystem roots | "
        "**Modelled and encoded, not verified.** The partition structure is real; whether a given "
        "collector's boundaries align with it is exactly what a lab run would show. |",
        "| A collector can declare its own scope accurately | `Get-Package` reports a provider; "
        "`Get-ChildItem` knows its root list; `Get-Service` is genuinely exhaustive | "
        "**Partly demonstrable from the mechanism.** A path-list collector always knows its roots. "
        "A registry enumeration knows its views. Whether *shipped* collectors emit that is untested. |",
        "| Some gaps are declared and some are silent, and the split is a property of the collector "
        "| the difference between enumerating ProfileList and not | **Reproduced in code.** "
        "Collector B differs from collector A by about ten lines and turns every silent miss into "
        "a declared one. That is a claim about implementations, and it is checkable. |",
        "| A verifier can request more evidence and sometimes get it | widening a file-version "
        "root list, re-running with elevation | **Modelled with a bounded widening step.** Real "
        "cost, real failure modes, unmeasured. |",
        "| `UNDECLARED_GAP` is the residual risk | a collector that claims a complete software "
        "inventory while reading one hive in one view | **This is the number v3 exists to "
        "measure and did not.** |",
        "",
        "## What the contract analysis predicts, and what would falsify it", "",
        "| Prediction | Falsified if a lab run shows |",
        "| --- | --- |",
        f"| The ubiquitous uninstall-registry script silently misses "
        f"{per['A_UNINSTALL_REGISTRY']['silent_misses']} of the 48 decisive facts, a "
        f"{pct(per['A_UNINSTALL_REGISTRY']['decisive_undeclared_gap_rate']['value'])} "
        f"undeclared-gap rate on what it claims | it reaches per-user or WOW6432Node "
        f"registrations after all, or reports them as excluded |",
        f"| `Get-Package -ProviderName Programs` silently misses "
        f"{per['C_PACKAGE_PROVIDER']['silent_misses']} | the Programs provider enumerates other "
        f"users' hives, or declines to claim completeness |",
        "| An expanded registry enumeration that cross-references ProfileList produces zero silent "
        "misses | ProfileList enumeration is unavailable or unreliable in practice |",
        "| The filesystem/version channel is the largest independent rescuer | file version "
        "metadata is absent or wrong on real vendor binaries often enough to break the channel |",
        "| Unloaded user hives are unreachable read-only | a read-only mechanism exists that this "
        "analysis missed |",
        "",
        "The fourth is the one most likely to break. Real executables carry inconsistent "
        "`FileVersion` and `ProductVersion` metadata, some carry none, and marketing version "
        "strings routinely disagree with the version an advisory names. The lab fixtures here use "
        "copies of one Microsoft binary with clean metadata, which is the friendliest possible "
        "case and is not representative.",
        "",
        "## What does not transfer at all", "",
        "- **Prevalence.** The fixture corpus was constructed to contain every awkward "
        "installation pattern in roughly equal numbers. Real fleets are mostly ordinary "
        "machine-wide 64-bit installs. Nothing here estimates how often the awkward cases occur, "
        "and that frequency decides whether any of this matters.",
        "- **The vendor adapters.** Four of the ten contracts are models of published behaviour "
        "with no implementation and no verification. They are the weakest evidence in the "
        "experiment and are reported separately for that reason.",
        "- **Cost.** Collection times are contract estimates. A real `Get-ChildItem -Recurse` over "
        "a populated `C:\\Program Files` is minutes, not the seconds assumed here, and that "
        "difference decides whether targeted post-remediation verification is practical.",
        "",
        "## The one number that decides the thesis", "",
        "How often is a real Windows collector wrong about its own scope, rather than merely "
        "narrow? v2 showed scope awareness is a complete defence in the first case and no defence "
        "in the second. v3's contract analysis predicts the answer depends almost entirely on "
        "which collector you use - near-total for the ubiquitous script, zero for one written "
        "with ten extra lines. **That prediction is cheap to test and has not been tested.**", ""]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L) + "\n")
    return Path(path)


# --------------------------------------------------------------------------- #
DECISION_CRITERIA = [
    ("composite_reduction_80", "Composite collection cuts decisive undeclared gaps by >=80% "
                               "versus the best single passive collector"),
    ("fixture_residual_5", "Fixture-level remaining decisive undeclared gaps at or below 5%"),
    ("rescue_80", "Cross-collector rescue at or above 80%"),
    ("no_harm_blessed", "No regression or new-risk fixture incorrectly blessed"),
    ("bounded_cost", "Collection cost bounded enough for targeted post-remediation use"),
]


def evaluate_decision_rule(results: Dict[str, Any]) -> Dict[str, Any]:
    """Scored from the numbers, then withheld if the numbers were not measured."""
    per = results["per_collector"]
    composite = per[COMPOSITE_COLLECTOR]
    baselines = results["composite_reduction_by_baseline"]
    rescue = results["cross_collector_rescue_rate"]
    residual = results["remaining_false_assurance_rate"]
    harm = results["harm_fixture_blessed_rate"]
    cost = results["collection_cost"]["per_collector"]

    reductions = {cid: d["reduction"] for cid, d in baselines.items() if d["reduction"] is not None}
    best_reduction = max(reductions.values()) if reductions else None
    fixture_residual = composite["fixture_undeclared_gap_rate"]["value"]

    composite_seconds = cost[COMPOSITE_COLLECTOR]["approximate_seconds"]
    cheapest_passive = min(cost[c]["approximate_seconds"] for c in PASSIVE_COLLECTORS)

    criteria = {
        "composite_reduction_80": {
            "met": bool(best_reduction is not None and best_reduction >= 0.80),
            "detail": (
                "the comparison is ambiguous and the ambiguity decides the answer. Against the "
                f"ubiquitous uninstall-registry script the reduction is "
                f"{pct(baselines['A_UNINSTALL_REGISTRY']['reduction'])} "
                f"({baselines['A_UNINSTALL_REGISTRY']['baseline_silent_misses']} silent misses to "
                f"{baselines['A_UNINSTALL_REGISTRY']['composite_silent_misses']}); against an "
                "expanded registry enumeration that declares its exclusions the reduction is "
                "undefined, because that collector already has zero silent misses - while "
                f"deciding only {baselines['B_EXPANDED_REGISTRY']['baseline_fixtures_decided']} "
                f"of 40 fixtures against the composite's "
                f"{baselines['B_EXPANDED_REGISTRY']['composite_fixtures_decided']}."),
        },
        "fixture_residual_5": {
            "met": bool(fixture_residual is not None and fixture_residual <= 0.05),
            "detail": f"composite fixture-level undeclared-gap rate "
                      f"{rate(composite['fixture_undeclared_gap_rate'])}; residual false assurance "
                      f"on vulnerable fixtures {rate(residual)}.",
        },
        "rescue_80": {
            "met": bool(rescue["value"] is not None and rescue["value"] >= 0.80),
            "detail": f"cross-collector rescue {rate(rescue)}, below the 80% bar. The channels "
                      "that fail together share a mechanism: three of the five are registry "
                      "enumerations.",
        },
        "no_harm_blessed": {
            "met": harm["value"] == 0 if harm["value"] is not None else False,
            "detail": f"regression fixtures blessed {rate(harm)} - but for an unflattering reason: "
                      "no collector models application health at all, so the fact is a declared "
                      "gap for every channel and the verifier abstains rather than detects.",
        },
        "bounded_cost": {
            "met": composite_seconds <= 120.0,
            "detail": f"composite estimated at {composite_seconds:.0f}s against {cheapest_passive:.0f}s "
                      "for the cheapest passive channel. These are contract estimates, not "
                      "measurements; a real recursive scan of a populated Program Files is minutes.",
        },
    }
    met = sum(1 for c in criteria.values() if c["met"])
    if met == len(criteria):
        predicted = "STRONG SIGNAL"
    elif not criteria["fixture_residual_5"]["met"]:
        predicted = "NEGATIVE SIGNAL"
    else:
        predicted = "MIXED SIGNAL"

    measured = results["measurement_status"] == RunStatus.MEASURED_ON_LAB_VM.value
    return {
        "criteria": criteria,
        "criteria_met": met,
        "criteria_total": len(criteria),
        "predicted_classification": predicted,
        "classification": predicted if measured else "WITHHELD",
        "classification_note": (
            "Classified from measured results." if measured else
            "Withheld. The decision rule classifies a measurement, and no measurement was taken. "
            "The predicted classification below is what the contract analysis implies and must "
            "not be reported as a result."),
    }


def vendor_silent_summary(per: Dict[str, Any]) -> str:
    return ", ".join(f"{SHORT[cid]} {per[cid]['silent_misses']}"
                     for cid in OPTIONAL_IMPORT_COLLECTORS if cid in per)


def write_final_report(path: Path, results: Dict[str, Any], rows, fixtures,
                       metadata: Dict[str, Any], decision: Dict[str, Any],
                       preflight_result: Dict[str, Any]) -> Path:
    per = results["per_collector"]
    manifest = results["fixture_manifest"]
    rescue = results["cross_collector_rescue_rate"]
    active = results["active_request_success_rate"]
    composite = per[COMPOSITE_COLLECTOR]

    L: List[str] = []
    w = L.append

    w("# Remediation Verification v3 - Real Windows Collector Blindness and Cross-Collector "
      "Evidence Recovery")
    w("")
    w(f"- Experiment `{metadata['experiment']}` revision `{metadata['experiment_revision']}`")
    w(f"- Run (UTC) `{metadata['timestamp_utc']}` | Python `{metadata['python_version']}` "
      f"| git `{metadata['git_commit_sha']}`")
    w(f"- Mode **{metadata['mode']}** | status **{metadata['run_status']}**")
    w(f"- Fixture manifest SHA-256 **`{manifest['manifest_sha256']}`**")
    w(f"- Full fixture specifications SHA-256 `{manifest['full_specifications_sha256']}`")
    w(f"- Collector contracts SHA-256 `{results['collector_contracts_sha256']}`")
    w(f"- Classifications SHA-256 `{results['classifications_sha256']}`")
    w(f"- {manifest['fixture_count']} fixtures across {manifest['family_count']} families, "
      f"{manifest['decisive_fact_count']} decisive facts, "
      f"{len(results['per_collector'])} collector contracts")
    w("")
    L.extend(banner(results))

    # ------------------------------------------------------------------ #
    w("## Executive summary")
    w("")
    w("**The measurement this experiment exists to take was not taken.** No disposable Windows VM "
      "was reachable from this session: the host is Linux, no hypervisor or PowerShell is present, "
      "and both safety gates are unset. What was built instead is the complete, tested, gated "
      "harness - 40 fixtures, six read-only collectors, a provisioning plan, a preflight, and a "
      "cleanup path - together with a prediction, derived from each collector's declared scope, of "
      "what a lab run would find. The prediction is the hypothesis. It is not the result.")
    w("")
    a_gap = per["A_UNINSTALL_REGISTRY"]["decisive_undeclared_gap_rate"]
    c_gap = per["C_PACKAGE_PROVIDER"]["decisive_undeclared_gap_rate"]
    w(f"**1. Which real collectors silently missed decisive evidence?**  Predicted, not observed. "
      f"The ubiquitous uninstall-registry script silently misses "
      f"{a_gap['numerator']} decisive facts - {pct(a_gap['value'])} of the {a_gap['denominator']} "
      f"whose evidence type it claims to cover completely - while presenting itself as a complete "
      f"software inventory. `Get-Package -ProviderName Programs` silently misses "
      f"{c_gap['numerator']} of {c_gap['denominator']} ({pct(c_gap['value'])}). The expanded "
      f"registry enumeration, the file-version channel and the service/task channel silently miss "
      f"none - the first two because they decline to claim completeness, the third because its "
      f"enumeration genuinely is exhaustive.")
    w("")
    w("**2. Which installation patterns caused the most blindness?**  Per-user installations, "
      "second-user installations, WOW6432Node registrations, and anything with no package record "
      "at all. Every one of them is invisible to a machine-scope 64-bit-view enumeration, and "
      "three of the five passive channels are exactly that. The breakdown by user scope in "
      "`collector-gap-matrix.md` is the sharpest cut: facts sitting at `current_user` or "
      "`other_user_loaded` are where the silent misses concentrate.")
    w("")
    w(f"**3. How often did collectors incorrectly imply complete coverage?**  Of the "
      f"{len(per)} contracts modelled, "
      f"{sum(1 for c in per.values() if c['claims_complete_for'])} claim completeness for at least "
      f"one evidence type. Of those, "
      f"{sum(1 for cid, c in per.items() if c['claims_complete_for'] and c['silent_misses'])} have "
      f"at least one decisive fact that contradicts the claim. False coverage-claim rates per "
      f"collector are in the gap matrix; for the ubiquitous script it is "
      f"{rate(per['A_UNINSTALL_REGISTRY']['false_coverage_claim_rate'])}.")
    w("")
    w(f"**4. Which independent channel recovered each gap?**  Cross-collector rescue is "
      f"{rate(rescue)}. The filesystem/version channel is the single largest rescuer "
      f"({rescue['detail']['rescuing_channel_counts'].get('D_FILE_VERSION', 0)} facts), which is "
      f"the mechanism H2 predicted: inventory answers what is *registered*, a file version answers "
      f"what is actually *there*, and only the second decides a vulnerability. Full attribution in "
      f"`cross-collector-recovery.md`.")
    w("")
    w("**5. Were collector failures correlated?**  Strongly, and this is the most useful finding "
      "in the analysis. The three package-inventory channels fail on the *same* fixtures, because "
      "they share a mechanism - they all read package registrations. Adding a second inventory "
      "source buys almost nothing. The only channel that fails independently is the filesystem "
      "one, because it queries a different subsystem. **Evidence diversity has to be mechanism "
      "diversity; two inventories are one channel.**")
    w("")
    w(f"**6. Can active collection reduce gaps without exhaustive scanning?**  Predicted yes, with "
      f"a caveat. A bounded widening - three additional root classes, one request each - satisfies "
      f"{rate(active)} of the facts the passive union cannot settle. The caveat is that the cost "
      f"estimate here is a contract number ({results['collection_cost']['per_collector'][COMPOSITE_COLLECTOR]['approximate_seconds']:.0f}s), "
      f"and a real recursive scan of a populated `C:\\Program Files` is minutes, not seconds.")
    w("")
    w(f"**7. What false-assurance cases remain?**  After composite collection: "
      f"{rate(results['remaining_false_assurance_rate'])} of vulnerable fixtures. That number is "
      f"weaker than it looks. The composite claims completeness for nothing, so it *cannot* "
      f"produce a silent miss by construction - it converts them into abstentions instead. The "
      f"honest cost is "
      f"{frac(composite['unresolved_decisive_fact_rate'])} decisive facts left unresolved: two "
      f"unloaded user hives (unreachable without `reg load`, which is a write) and two application-"
      f"health facts (no Windows inventory channel models them).")
    w("")
    w("**8. Does the product need its own endpoint agent?**  On this analysis, it needs *a* "
      "second mechanism, not necessarily its own agent. Everything that made the difference here - "
      "reading both registry views, enumerating ProfileList, checking a file version - is ordinary "
      "PowerShell that any management platform can already run. What no existing inventory feed "
      "provides is the scope declaration, and that is a property of how the collector reports, not "
      "of who owns it.")
    w("")
    w("**9. Can the approach work through Intune / Defender / Tenable exports alone?**  The "
      "modelled answer is no, and the models are the weakest evidence here so treat it as a "
      "hypothesis. All four vendor exports claim a complete application inventory; all four are "
      "predicted to have silent misses "
      f"({vendor_silent_summary(per)}). None of them exposes a scope manifest an automated "
      "verifier could read, so even where "
      "coverage is good the *declaration* v2 showed to be load-bearing is absent.")
    w("")
    w("**10. Does v3 strengthen, narrow or falsify the startup thesis?**  It narrows it, sharply, "
      "and it does not confirm anything. See the thesis section.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Hypotheses")
    w("")
    w("No hypothesis below is supported or refuted, because none was tested against a real "
      "machine. Each is recorded with what the contract analysis predicts and what a lab run "
      "would have to show to falsify it.")
    w("")
    w("| ID | Hypothesis | Contract prediction | Status |")
    w("| --- | --- | --- | --- |")
    w(f"| H1 | Common Windows inventory sources contain material undeclared gaps for per-user, "
      f"side-by-side, portable and non-default-path installations | "
      f"{per['A_UNINSTALL_REGISTRY']['silent_misses']} and "
      f"{per['C_PACKAGE_PROVIDER']['silent_misses']} silent misses for the two channels that "
      f"claim inventory completeness, concentrated in exactly those families | **Untested** |")
    w(f"| H2 | An independent filesystem/version channel recovers a majority of decisive "
      f"package-inventory gaps | the file channel is the largest single rescuer, but overall "
      f"rescue is {pct(rescue['value'])} - a majority of *all* gaps, not of every kind | "
      f"**Untested; predicted partially true** |")
    w("| H3 | A composite active collector reduces decisive undeclared gaps by >=80% versus the "
      "best single passive collector | 100% against the ubiquitous script, undefined against a "
      "scope-honest one that already has zero | **Untested; the comparison is ill-posed** |")
    w("| H4 | Cross-collector disagreement is a useful trigger for INSUFFICIENT_EVIDENCE or active "
      "collection | the conflicting-evidence fixtures are resolvable only by noticing the "
      "disagreement; no single channel detects them | **Untested** |")
    w("| H5 | Reliable verification requires targeted collection rather than a full-fleet "
      "exhaustive scan | the composite settles 36 of 40 fixtures with three bounded widenings "
      "rather than a whole-volume scan | **Untested** |")
    w("")
    w("H3 deserves a note beyond its verdict. \"The best single passive collector\" turns out to "
      "be ambiguous in a way that decides the answer: judged by silent misses the best passive "
      "collector already scores zero, and judged by fixtures decided it settles 12 of 40. A "
      "hypothesis phrased as a percentage reduction cannot survive that ambiguity, and rephrasing "
      "it around absolute residual gaps - as the v3 brief itself insists - is the right fix.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Primary metrics")
    w("")
    w("| Metric | Numerator | Denominator |")
    w("| --- | --- | --- |")
    for name, definition in results["metric_definitions"].items():
        w(f"| `{name}` | {definition['numerator']} | {definition['denominator']} |")
    w("")
    w("| Collector | Decisive undeclared-gap rate | Silent misses | False coverage claims | "
      "Fixtures decided | Facts unresolved |")
    w("| --- | --- | --- | --- | --- | --- |")
    for cid in [c.collector_id for c in IMPLEMENTED_CONTRACTS] + OPTIONAL_IMPORT_COLLECTORS:
        entry = per[cid]
        w(f"| {SHORT[cid]} | {rate(entry['decisive_undeclared_gap_rate'])} | "
          f"{entry['silent_misses']} | {rate(entry['false_coverage_claim_rate'])} | "
          f"{frac(entry['verification_feasibility'])} | "
          f"{frac(entry['unresolved_decisive_fact_rate'])} |")
    w("")
    w(f"- **Fixture-level undeclared-gap rate (composite):** "
      f"{rate(composite['fixture_undeclared_gap_rate'])}")
    w(f"- **Cross-collector rescue rate:** {rate(rescue)}")
    w(f"- **Active-request success rate:** {rate(active)}")
    w(f"- **Remaining false-assurance rate after composite collection:** "
      f"{rate(results['remaining_false_assurance_rate'])}")
    w(f"- **Regression fixtures incorrectly blessed:** "
      f"{rate(results['harm_fixture_blessed_rate'])}")
    w("")
    w("Collection cost is a contract estimate in every row and is not a measurement: "
      + ", ".join(f"{SHORT[c]} ~{v['approximate_seconds']:.0f}s"
                  for c, v in results["collection_cost"]["per_collector"].items()
                  if c not in OPTIONAL_IMPORT_COLLECTORS) + ".")
    w("")

    # ------------------------------------------------------------------ #
    w("## Decision rule")
    w("")
    w(f"**{decision['classification']}.** {decision['classification_note']}")
    w("")
    w(f"Predicted classification if the contract analysis were confirmed: "
      f"**{decision['predicted_classification']}** "
      f"({decision['criteria_met']} of {decision['criteria_total']} criteria).")
    w("")
    w("| Criterion | Predicted | Detail |")
    w("| --- | --- | --- |")
    for key, label in DECISION_CRITERIA:
        entry = decision["criteria"][key]
        w(f"| {label} | {'yes' if entry['met'] else '**no**'} | {entry['detail']} |")
    w("")

    # ------------------------------------------------------------------ #
    w("## Counter-evidence")
    w("")
    w("**1. The headline result is a deduction from contracts I wrote.** The collector contracts "
      "encode documented Windows behaviour, and the PowerShell in `powershell/` implements them, "
      "but nothing here checks that the implementation matches the contract on a real machine. A "
      "contract analysis that predicts its own collectors do well is worth very little until it "
      "is falsified by a machine.")
    w("")
    w("**2. The composite's perfect silent-miss score is an artefact of a definitional choice.** "
      "It claims completeness for nothing, so it cannot produce a silent miss - by construction, "
      "not by capability. Any collector can achieve zero silent misses by declining to claim "
      "anything. The metric that resists this is unresolved decisive facts, where the composite "
      f"still leaves {frac(composite['unresolved_decisive_fact_rate'])}.")
    w("")
    w("**3. Cross-collector rescue came in at "
      f"{pct(rescue['value'])}, well below the 80% the decision rule asks for.** The reason is "
      "correlated failure: three of the five passive channels are registry enumerations that fail "
      "on the same fixtures. If real channel diversity is this shallow, multi-channel collection "
      "helps less than the phrase suggests.")
    w("")
    w("**4. Nothing detects a functional regression.** Two fixtures break a dependent application, "
      "and no collector - including the composite - models application health. They are scored as "
      "\"not blessed\" only because everyone abstains. A verification product that cannot tell you "
      "whether the fix broke the business is answering half the question.")
    w("")
    w("**5. The vendor adapters are unverified models.** Four of ten contracts describe published "
      "behaviour with no implementation behind them. Question 9's answer rests on them and should "
      "be treated as a hypothesis, not a finding.")
    w("")
    w("**6. Fixture prevalence is invented.** Twenty families in equal numbers is not a fleet. "
      "Real estates are mostly ordinary machine-wide 64-bit installs, which every channel handles. "
      "How often the awkward patterns actually occur is unmeasured, and that frequency - not the "
      "gap rate - decides whether any of this is worth building.")
    w("")
    w("**7. The friendly-metadata assumption.** Fixtures use copies of one Microsoft binary with "
      "clean, consistent version metadata. Real vendor executables carry inconsistent "
      "`FileVersion`/`ProductVersion` fields, sometimes none, and marketing versions that disagree "
      "with advisory versions. The file-version channel is the linchpin of the recovery story and "
      "it is being tested under the friendliest possible conditions.")
    w("")

    # ------------------------------------------------------------------ #
    w("## Startup thesis")
    w("")
    w("v1: execution status is a poor proxy for remediation success. v2: scope-aware verification "
      "defends completely against declared gaps and not at all against undeclared ones, which "
      "located the value in the collector rather than the verifier. v3 was meant to measure "
      "whether real collectors produce undeclared gaps. It did not, so the thesis has not moved "
      "on evidence - but the analysis narrows what a positive result could even look like.")
    w("")
    w("**What narrowed.** If the contract analysis is right, the difference between a collector "
      "that produces silent misses and one that does not is about ten lines of PowerShell - "
      "enumerate both registry views, walk loaded HKU, cross-reference ProfileList, and report the "
      "profiles you could not read. That is not a product. It is a patch to a script, and any "
      "management vendor can ship it in a sprint. The defensible position cannot be \"we know to "
      "read both registry views\".")
    w("")
    w("**What might still be defensible.** Three things survive the narrowing, and all three are "
      "unproven. First, the *reconciliation* layer: noticing that a package record and a file "
      "version disagree, and knowing which one decides. Second, the *bounded active request*: "
      "deciding which single additional query is worth its cost, which the v2 result showed is "
      "what makes fail-closed verification usable rather than merely safe. Third, the *audit "
      "artefact*: a per-fact record of what was checked, what was not, and why - which is a "
      "compliance deliverable rather than a technical one.")
    w("")
    w("**What weakened.** The correlated-failure result. If a second evidence channel has to be a "
      "genuinely different mechanism to help, then \"we aggregate your existing inventory feeds\" "
      "is not a product either - aggregating three registry-derived inventories yields one "
      "registry-derived inventory. The value would have to come from running a filesystem channel, "
      "which means either an agent or a management platform willing to run your script. Both are "
      "harder businesses than an integration.")
    w("")
    w("**Net: unchanged and better specified.** No evidence was added in either direction. The "
      "experiment converted a vague question into a cheap, falsifiable one.")
    w("")

    # ------------------------------------------------------------------ #
    w("## What a lab run would settle")
    w("")
    w("The harness is complete and gated. On a disposable Windows VM the run is four commands and "
      "produces measured versions of every table above, plus a prediction-versus-measurement diff "
      "(`prediction_vs_measurement` in `artifacts/results.json`) naming every contract that was "
      "wrong. Procedure in `reports/safety-and-lab-procedure.md`.")
    w("")
    w("The single most valuable output would be the diff, not the metrics. The metrics describe a "
      "constructed corpus; the diff describes reality disagreeing with documentation, and that is "
      "the thing nobody has written down.")
    w("")
    w("Next after that, in order: measure the *prevalence* of awkward installation patterns across "
      "a real fleet, because gap rates without prevalence decide nothing; test the file-version "
      "channel against real vendor binaries rather than one clean Microsoft executable; and "
      "measure the true cost of a widened filesystem scan on a populated machine.")
    w("")
    w("---")
    w("")
    w(f"Fixture manifest SHA-256: `{manifest['manifest_sha256']}`")
    w(f"Fixture specifications SHA-256: `{manifest['full_specifications_sha256']}`")
    w(f"Collector contracts SHA-256: `{results['collector_contracts_sha256']}`")
    w(f"Provisioning plan SHA-256: `{results['provisioning_plan_sha256']}`")
    w(f"Classifications SHA-256: `{results['classifications_sha256']}`")
    w("")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(L) + "\n")
    return Path(path)
