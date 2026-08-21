"""Statistics: Wilson intervals, scenario-family cluster bootstrap, McNemar.

The Wilson interval assumes independent observations, and these are not: 58
conditions share each scenario family, and conditions within a family differ
only in how their evidence was damaged.  Both are reported, and the cluster
bootstrap - resampling *families*, not conditions - is the one to believe.
"""
from __future__ import annotations

import math
import random
from typing import Callable, Dict, List, Optional, Tuple

Z_95 = 1.959963984540054
BOOTSTRAP_DRAWS = 2000
BOOTSTRAP_SEED = 20260821


def wilson_interval(successes: int, n: int, z: float = Z_95) -> Tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)) / denom
    # Wilson brackets the point estimate analytically; the clamp removes
    # floating-point dust at p = 0 and p = 1.
    return (max(0.0, min(p, centre - half)), min(1.0, max(p, centre + half)))


def cluster_bootstrap(clusters: Dict[str, List[dict]],
                      statistic: Callable[[List[dict]], Optional[float]],
                      draws: int = BOOTSTRAP_DRAWS,
                      seed: int = BOOTSTRAP_SEED) -> Dict[str, Optional[float]]:
    """Percentile CI from resampling whole scenario families with replacement.

    Returns None bounds when the statistic is undefined on too many resamples -
    which happens legitimately, e.g. an arm that never says VERIFIED has no
    false-assurance rate to bound.
    """
    keys = sorted(clusters)
    if not keys:
        return {"lo": None, "hi": None, "point": None, "draws": 0, "defined_draws": 0}
    rng = random.Random(seed)
    values: List[float] = []
    for _ in range(draws):
        picked = [rng.choice(keys) for _ in keys]
        rows: List[dict] = []
        for key in picked:
            rows.extend(clusters[key])
        value = statistic(rows)
        if value is not None:
            values.append(value)
    point = statistic([r for key in keys for r in clusters[key]])
    if len(values) < max(20, draws // 10):
        return {"lo": None, "hi": None, "point": point, "draws": draws,
                "defined_draws": len(values)}
    values.sort()
    lo = values[int(0.025 * (len(values) - 1))]
    hi = values[int(0.975 * (len(values) - 1))]
    return {"lo": lo, "hi": hi, "point": point, "draws": draws, "defined_draws": len(values)}


def _chi2_sf_1df(x: float) -> float:
    return 1.0 if x <= 0 else math.erfc(math.sqrt(x / 2.0))


def mcnemar(b: int, c: int) -> Dict[str, object]:
    """Paired comparison. b = arm 1 errs and arm 2 does not; c = the reverse."""
    n = b + c
    if n == 0:
        return {"b": b, "c": c, "n_discordant": 0, "p_exact": 1.0, "chi2": 0.0,
                "p_chi2": 1.0, "odds_ratio": None, "risk_difference": 0.0}
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) * (0.5 ** n)
    chi2 = (abs(b - c) - 1) ** 2 / n
    return {
        "b": b, "c": c, "n_discordant": n,
        "p_exact": min(1.0, 2.0 * tail),
        "chi2": chi2,
        "p_chi2": _chi2_sf_1df(chi2),
        # Effect sizes for paired binary data: the discordant odds ratio and the
        # difference in error proportions.
        "odds_ratio": (b / c) if c else None,
        "risk_difference": (b - c) / n,
    }


def significance_label(p: float, n_discordant: int, alpha: float = 0.05) -> str:
    if n_discordant == 0:
        return "inconclusive"
    if p < alpha and n_discordant >= 10:
        return "statistically significant"
    if p < alpha:
        return "directional (few discordant pairs)"
    return "inconclusive"
