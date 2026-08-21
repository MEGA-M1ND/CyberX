"""Phase-2 placeholder for an isolated Windows lab adapter.

NOT implemented in v1 and NOT a dependency of any result in this experiment.
It exists to pin down the safety contract before anyone writes the real thing:

  * requires ALLOW_REAL_WINDOWS_LAB=1 in the environment, default disabled
  * read-only signals only (inventory, registry, services, file versions, KB
    state, reboot state, event logs, benign application smoke tests)
  * no exploitation, no network scanning, no third-party systems, no tenant
    mutation

Constructing it without the flag raises.  Constructing it with the flag raises
NotImplementedError, so it cannot silently become a live code path.
"""
from __future__ import annotations

import os

SAFETY_FLAG = "ALLOW_REAL_WINDOWS_LAB"


class RealEndpointSafetyError(RuntimeError):
    pass


class WindowsLabAdapter:
    def __init__(self, *_args, **_kwargs) -> None:
        if os.environ.get(SAFETY_FLAG) != "1":
            raise RealEndpointSafetyError(
                f"{SAFETY_FLAG}=1 is required before any real-endpoint adapter may be constructed. "
                "v1 of this benchmark runs entirely in simulation."
            )
        raise NotImplementedError(
            "WindowsLabAdapter is a Phase-2 design placeholder; see reports/final-report.md "
            "section 'Next Experiment' for the proposed isolated-VM design."
        )
