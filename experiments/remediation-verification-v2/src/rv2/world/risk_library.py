"""Standing library of "did the remediation leave a new exposure?" predicates.

The same list is applied to every case, so its presence carries no information
about which scenario is being examined.  A verifier consults it through the
observation package; the oracle consults it against the latent world.
"""
from __future__ import annotations

from typing import Any, Dict, List

STANDING_RISKS: List[Dict[str, Any]] = [
    {"id": "HOST_FIREWALL_DISABLED", "op": "posture_flag_true", "flag": "host_firewall_disabled"},
    {"id": "REALTIME_PROTECTION_DISABLED", "op": "posture_flag_true", "flag": "realtime_protection_disabled"},
    {"id": "SMB1_ENABLED", "op": "posture_flag_true", "flag": "smb1_enabled"},
    {"id": "LEGACY_TLS_REENABLED", "op": "posture_flag_true", "flag": "tls10_enabled"},
    {"id": "UNRESTRICTED_SCRIPT_POLICY", "op": "posture_flag_true", "flag": "unrestricted_script_policy"},
    {"id": "WORLD_WRITABLE_SHARE", "op": "posture_flag_true", "flag": "world_writable_share"},
    {"id": "UNEXPECTED_LOCAL_ADMIN", "op": "posture_flag_true", "flag": "unexpected_local_admin"},
    {"id": "UNLIMITED_CREDENTIAL_CACHE", "op": "posture_flag_true", "flag": "cached_creds_unlimited"},
    {"id": "REMOTE_REGISTRY_EXPOSED", "op": "posture_flag_true", "flag": "remote_registry_exposed"},
]

RISK_FLAGS = [node["flag"] for node in STANDING_RISKS]
