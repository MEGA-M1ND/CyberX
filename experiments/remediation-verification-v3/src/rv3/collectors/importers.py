"""Offline vendor-export importers.

Import only.  These read a file the operator exported by hand and never open a
network connection, authenticate, or touch a live tenant.  If no export file is
supplied the adapter reports itself as not-run rather than inventing records.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..vocab import CollectorId

SUPPORTED = {
    CollectorId.X_INTUNE_EXPORT.value: "Intune discovered-apps export (CSV or JSON)",
    CollectorId.X_DEFENDER_EXPORT.value: "Defender Vulnerability Management software inventory",
    CollectorId.X_TENABLE_EXPORT.value: "Tenable credentialed-scan export",
    CollectorId.X_SCCM_EXPORT.value: "Configuration Manager inventory export",
}


def load_export(collector_id: str, path: Optional[Path]) -> Dict[str, Any]:
    if collector_id not in SUPPORTED:
        raise KeyError(collector_id)
    if path is None or not Path(path).exists():
        return {"collector_id": collector_id, "status": "NOT_SUPPLIED",
                "description": SUPPORTED[collector_id], "records": [],
                "note": "No offline export was provided, so this adapter contributed nothing. "
                        "Its contract is still reported, marked as an unverified model."}
    path = Path(path)
    if path.suffix.lower() == ".json":
        records: List[Dict[str, Any]] = json.loads(path.read_text())
    else:
        with path.open(newline="") as handle:
            records = list(csv.DictReader(handle))
    return {"collector_id": collector_id, "status": "IMPORTED",
            "description": SUPPORTED[collector_id], "records": records,
            "record_count": len(records), "source_file": path.name}
