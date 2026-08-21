"""Phase 2 (OPTIONAL) - AI-generated remediation actions.

Disabled by default.  Nothing in the reported v1 benchmark depends on it, and
the benchmark runs to completion with no API key and no network access.

Safety boundary: the model is asked for a JSON remediation *plan* expressed in
the simulator's own op schema.  The plan is schema-validated and then executed
ONLY by SimulatedEndpointAdapter.  No generated text is ever passed to a shell,
to PowerShell, or to any real endpoint.

Configuration (all via environment, no vendor hard-coded):
    RVBENCH_LLM_ENABLED=1                 opt in
    RVBENCH_LLM_BASE_URL=...              any OpenAI-compatible /v1 endpoint
    RVBENCH_LLM_API_KEY=...
    RVBENCH_LLM_MODEL=...                 defaults to a low-cost model
    RVBENCH_LLM_TIMEOUT=60
"""
from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..simulator.engine import SUPPORTED_OPS, RemediationOpError, validate_ops

DEFAULT_MODEL = "openai/gpt-4o-mini"
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

SYSTEM_PROMPT = (
    "You are a defensive endpoint remediation planner. You emit ONLY a JSON object of the form "
    '{"ops": [...]} describing a remediation plan for a simulated endpoint. '
    f"Each op must use one of these op names: {sorted(SUPPORTED_OPS)}. "
    "Never emit shell commands, scripts, exploit code, or free text. "
    "The plan is executed only against an in-memory simulator."
)


class LLMDisabled(RuntimeError):
    pass


@dataclass
class GeneratorConfig:
    enabled: bool = False
    base_url: str = DEFAULT_BASE_URL
    api_key: Optional[str] = None
    model: str = DEFAULT_MODEL
    timeout: int = 60

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "GeneratorConfig":
        e = dict(os.environ if env is None else env)
        return cls(
            enabled=e.get("RVBENCH_LLM_ENABLED") == "1",
            base_url=e.get("RVBENCH_LLM_BASE_URL", DEFAULT_BASE_URL),
            api_key=e.get("RVBENCH_LLM_API_KEY"),
            model=e.get("RVBENCH_LLM_MODEL", DEFAULT_MODEL),
            timeout=int(e.get("RVBENCH_LLM_TIMEOUT", "60")),
        )


class RemediationGenerator:
    """Turns a public case into a simulator remediation plan using an LLM."""

    def __init__(self, config: Optional[GeneratorConfig] = None) -> None:
        self.config = config or GeneratorConfig.from_env()

    @property
    def available(self) -> bool:
        return bool(self.config.enabled and self.config.api_key)

    def generate(self, case, observed_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.available:
            raise LLMDisabled(
                "LLM remediation generation is disabled. Set RVBENCH_LLM_ENABLED=1 and "
                "RVBENCH_LLM_API_KEY to opt in. The v1 benchmark does not require it."
            )
        prompt = json.dumps(
            {
                "vulnerability_predicate": case.vulnerability_predicate,
                "remediation_intent": case.remediation_intent.get("description", ""),
                "observed_state": observed_state,
            },
            sort_keys=True,
        )
        body = json.dumps(
            {
                "model": self.config.model,
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            }
        ).encode()
        req = urllib.request.Request(
            self.config.base_url.rstrip("/") + "/chat/completions",
            data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.config.api_key}"},
        )
        with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
            payload = json.loads(resp.read().decode())
        content = payload["choices"][0]["message"]["content"]
        return self.parse_plan(content)

    @staticmethod
    def parse_plan(content: str) -> List[Dict[str, Any]]:
        """Parse and schema-validate a model response.  Raises on anything odd."""
        text = content.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0]
        data = json.loads(text)
        ops = data.get("ops")
        if not isinstance(ops, list):
            raise RemediationOpError("model response did not contain an 'ops' list")
        for op in ops:
            if not isinstance(op, dict) or "op" not in op:
                raise RemediationOpError(f"malformed op: {op!r}")
        validate_ops(ops)
        return ops
