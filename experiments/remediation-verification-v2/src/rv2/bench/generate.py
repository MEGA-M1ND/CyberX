"""Deterministic case-condition generation.

A *case condition* is one latent scenario crossed with one evidence condition:

    family  x  coverage level  x  missingness mechanism  x  instance

Nothing is hand-labelled.  The latent world is built from a seed, the collector
damages it according to the condition, and the oracle reads whatever world
results.  That is what makes several hundred conditions tractable without the
author quietly deciding each answer.

Seeds come from SHA-256 of the condition's own identity, so they do not depend
on iteration order, dict ordering, or Python's hash randomisation, and a single
condition can be regenerated in isolation.

Two partitions:
    dev      used while building and debugging
    holdout  frozen before the reported run; the headline numbers come from here
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List

from ..collect.conditions import COVERAGE_LEVELS, MECHANISMS
from ..vocab import Mechanism
from ..world.scenarios import FAMILIES

MASTER_SEED = 20260821
INSTANCES_PER_CELL = 2
PARTITIONS = ("dev", "holdout")


def stable_seed(*parts: Any) -> int:
    payload = "|".join(str(p) for p in parts).encode()
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big") % (2 ** 31)


@dataclass(frozen=True)
class CaseCondition:
    condition_id: str
    partition: str
    family: str
    coverage: float
    mechanism: str
    instance: int
    world_seed: int
    condition_seed: int

    @property
    def opaque_id(self) -> str:
        """Public identifier for the observation package.

        The condition id spells out the scenario family, the coverage level and
        the missingness mechanism.  Putting that in front of a verifier would
        hand it the answer, so packages carry an opaque digest instead and the
        harness keeps the mapping.
        """
        return "obs-" + hashlib.sha256(self.condition_id.encode()).hexdigest()[:20]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "condition_id": self.condition_id,
            "opaque_id": self.opaque_id,
            "partition": self.partition,
            "family": self.family,
            "coverage": self.coverage,
            "mechanism": self.mechanism,
            "instance": self.instance,
            "world_seed": self.world_seed,
            "condition_seed": self.condition_seed,
        }


def generation_config() -> Dict[str, Any]:
    """Everything that determines the corpus.  Hashed into the manifest."""
    return {
        "master_seed": MASTER_SEED,
        "families": list(FAMILIES),
        "coverage_levels": list(COVERAGE_LEVELS),
        "mechanisms": list(MECHANISMS),
        "instances_per_cell": INSTANCES_PER_CELL,
        "partitions": list(PARTITIONS),
        "full_coverage_mechanism": Mechanism.NONE.value,
        "seed_rule": "sha256(partition|family|coverage|mechanism|instance|role) mod 2**31",
    }


def _cells() -> Iterator[Dict[str, Any]]:
    for family in FAMILIES:
        for coverage in COVERAGE_LEVELS:
            mechanisms = [Mechanism.NONE.value] if coverage >= 1.0 else list(MECHANISMS)
            for mechanism in mechanisms:
                for instance in range(INSTANCES_PER_CELL):
                    yield {"family": family, "coverage": coverage,
                           "mechanism": mechanism, "instance": instance}


def generate(partition: str) -> List[CaseCondition]:
    if partition not in PARTITIONS:
        raise ValueError(f"unknown partition {partition!r}")
    out: List[CaseCondition] = []
    for cell in _cells():
        cid = (f"{partition[0].upper()}:{cell['family']}:c{int(cell['coverage'] * 100):03d}:"
               f"{cell['mechanism']}:i{cell['instance']}")
        out.append(CaseCondition(
            condition_id=cid,
            partition=partition,
            family=cell["family"],
            coverage=cell["coverage"],
            mechanism=cell["mechanism"],
            instance=cell["instance"],
            world_seed=stable_seed(MASTER_SEED, partition, cell["family"], cell["coverage"],
                                   cell["mechanism"], cell["instance"], "world"),
            condition_seed=stable_seed(MASTER_SEED, partition, cell["family"], cell["coverage"],
                                       cell["mechanism"], cell["instance"], "condition"),
        ))
    return out


def counts() -> Dict[str, int]:
    per_partition = len(generate("dev"))
    return {
        "families": len(FAMILIES),
        "coverage_levels": len(COVERAGE_LEVELS),
        "mechanisms_below_full_coverage": len(MECHANISMS),
        "instances_per_cell": INSTANCES_PER_CELL,
        "conditions_per_partition": per_partition,
        "partitions": len(PARTITIONS),
        "total_conditions": per_partition * len(PARTITIONS),
    }
