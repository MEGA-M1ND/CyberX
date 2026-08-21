"""Small, dependency-free statistics: Wilson intervals and McNemar's test."""
from __future__ import annotations

import math
from typing import Dict, Tuple

Z_95 = 1.959963984540054


def wilson_interval(successes: int, n: int, z: float = Z_95) -> Tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Chosen over the normal approximation because several arms sit near 0 or 1,
    where the Wald interval is badly behaved (and can leave [0, 1]).
    """
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)) / denom
    # The Wilson interval analytically brackets the point estimate; clamping to
    # p removes floating-point dust at p = 0 and p = 1 (where the exact bounds
    # are 0 and 1) without otherwise moving the bounds.
    lo = min(p, centre - half)
    hi = max(p, centre + half)
    return (max(0.0, lo), min(1.0, hi))


def _chi2_sf_1df(x: float) -> float:
    """Survival function of chi-square with 1 degree of freedom."""
    if x <= 0:
        return 1.0
    return math.erfc(math.sqrt(x / 2.0))


def mcnemar(b: int, c: int) -> Dict[str, object]:
    """Paired binary comparison.

    b = cases where arm 1 errs and arm 2 does not
    c = cases where arm 2 errs and arm 1 does not

    Reports the exact binomial p-value (valid at any n, which matters at
    n=48) alongside the continuity-corrected chi-square approximation.
    """
    n = b + c
    if n == 0:
        return {
            "b": b, "c": c, "n_discordant": 0,
            "p_exact": 1.0, "chi2": 0.0, "p_chi2": 1.0,
            "method": "no discordant pairs",
        }
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) * (0.5 ** n)
    p_exact = min(1.0, 2.0 * tail)
    chi2 = (abs(b - c) - 1) ** 2 / n if n > 0 else 0.0
    return {
        "b": b, "c": c, "n_discordant": n,
        "p_exact": p_exact,
        "chi2": chi2,
        "p_chi2": _chi2_sf_1df(chi2),
        "method": "exact binomial (primary); continuity-corrected chi-square (reference)",
    }


def significance_label(p: float, n_discordant: int, alpha: float = 0.05) -> str:
    """Deliberately conservative three-way classification."""
    if n_discordant == 0:
        return "inconclusive"
    if p < alpha and n_discordant >= 6:
        return "statistically significant"
    if p < alpha:
        return "directional (significant p-value on very few discordant pairs)"
    return "inconclusive"
