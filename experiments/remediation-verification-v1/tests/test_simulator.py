"""Simulator determinism and op semantics."""
from __future__ import annotations

import json

from rvbench.adapters.simulated import SimulatedEndpointAdapter
from rvbench.cases import Scenario
from rvbench.simulator.engine import RemediationOpError, apply_ops, validate_ops
from rvbench.simulator.state import EndpointState, project_post_reboot, version_lt


def test_version_compare():
    assert version_lt("1.4.2", "1.4.5")
    assert not version_lt("1.4.5", "1.4.5")
    assert not version_lt("1.10.0", "1.4.5")
    assert version_lt("1.4", "1.4.5")


def test_apply_ops_is_deterministic(corpus):
    """Same scenario applied twice -> identical state fingerprints."""
    for entry in corpus:
        scenario = Scenario.from_dict(entry["scenario"])
        prints = []
        for _ in range(2):
            adapter = SimulatedEndpointAdapter(scenario)
            adapter.apply_remediation()
            prints.append([adapter._true_state(i).fingerprint() for i in range(adapter.device_count)])
        assert prints[0] == prints[1], entry["public"]["case_id"]


def test_corpus_build_is_reproducible():
    from rvbench.corpus.build import build
    a = json.dumps(build(), sort_keys=True)
    b = json.dumps(build(), sort_keys=True)
    assert a == b


def test_install_package_side_by_side_vs_replace():
    s = EndpointState(packages={"p": ["1.0.0"]})
    apply_ops(s, [{"op": "install_package", "package": "p", "version": "2.0.0", "remove_old": False}])
    assert s.packages["p"] == ["1.0.0", "2.0.0"]
    apply_ops(s, [{"op": "install_package", "package": "p", "version": "3.0.0", "remove_old": True}])
    assert s.packages["p"] == ["3.0.0"]


def test_patch_requiring_reboot_is_staged_not_installed():
    s = EndpointState()
    apply_ops(s, [{"op": "install_patch", "kb": "KB1", "requires_reboot": True}])
    assert s.patches["KB1"] == {"installed": False, "staged": True}
    assert s.reboot_pending is True
    after = project_post_reboot(s)
    assert after.patches["KB1"] == {"installed": True, "staged": False}
    assert after.reboot_pending is False


def test_automatic_service_restarts_on_reboot():
    s = EndpointState(services={"svc": {"status": "stopped", "startup_type": "automatic"}})
    assert project_post_reboot(s).services["svc"]["status"] == "running"


def test_disabled_service_stays_stopped_on_reboot():
    s = EndpointState(services={"svc": {"status": "running", "startup_type": "disabled"}})
    assert project_post_reboot(s).services["svc"]["status"] == "stopped"


def test_unsupported_op_rejected():
    try:
        validate_ops([{"op": "rm -rf /"}])
    except RemediationOpError:
        return
    raise AssertionError("unsupported op was accepted")


def test_adapter_refuses_double_apply(corpus):
    adapter = SimulatedEndpointAdapter(Scenario.from_dict(corpus[0]["scenario"]))
    adapter.apply_remediation()
    try:
        adapter.apply_remediation()
    except RuntimeError:
        return
    raise AssertionError("double apply_remediation should raise")
