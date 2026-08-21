# Collection degradation

How each arm behaves as evidence coverage falls and as the *shape* of the
loss changes.  All figures are the holdout partition.

## Coverage curves (all mechanisms pooled at each level)

### Unsafe escape rate

| Coverage | A status | B target | C unaware | D scoped | E active |
| --- | --- | --- | --- | --- | --- |
| 100% | 100.0% | 81.8% | 0.0% | 0.0% | 0.0% |
| 90% | 100.0% | 57.8% | 35.1% | 7.1% | 7.1% |
| 80% | 100.0% | 55.2% | 34.4% | 3.9% | 3.9% |
| 60% | 100.0% | 42.2% | 26.6% | 1.3% | 1.3% |
| 40% | 100.0% | 34.4% | 22.7% | 0.0% | 0.0% |

### False assurance rate

| Coverage | A status | B target | C unaware | D scoped | E active |
| --- | --- | --- | --- | --- | --- |
| 100% | 92.3% | 90.9% | 0.0% | 0.0% | 0.0% |
| 90% | 92.3% | 94.5% | 83.1% | 78.6% | 52.4% |
| 80% | 92.3% | 95.0% | 84.0% | 85.7% | 42.9% |
| 60% | 92.3% | 92.9% | 79.7% | 100.0% | 33.3% |
| 40% | 92.3% | 90.5% | 80.4% | n/a | 0.0% |

### Abstention rate

| Coverage | A status | B target | C unaware | D scoped | E active |
| --- | --- | --- | --- | --- | --- |
| 100% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| 90% | 0.0% | 1.6% | 1.6% | 57.7% | 20.9% |
| 80% | 0.0% | 6.6% | 6.6% | 66.5% | 28.0% |
| 60% | 0.0% | 13.2% | 12.1% | 76.9% | 46.2% |
| 40% | 0.0% | 24.2% | 23.6% | 85.7% | 52.2% |

### Verified-remediation recall

| Coverage | A status | B target | C unaware | D scoped | E active |
| --- | --- | --- | --- | --- | --- |
| 100% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| 90% | 100.0% | 42.9% | 92.9% | 21.4% | 71.4% |
| 80% | 100.0% | 35.7% | 85.7% | 7.1% | 57.1% |
| 60% | 100.0% | 42.9% | 92.9% | 0.0% | 28.6% |
| 40% | 100.0% | 42.9% | 71.4% | 0.0% | 14.3% |

## Missingness mechanism (all coverage levels below 100% pooled)

### Unsafe escape rate

| Mechanism | A status | B target | C unaware | D scoped | E active |
| --- | --- | --- | --- | --- | --- |
| `NONE` | 100.0% | 81.8% | 0.0% | 0.0% | 0.0% |
| `RANDOM_MISSING` | 100.0% | 55.7% | 9.1% | 0.0% | 0.0% |
| `DECISIVE_FIELD_MISSING` | 100.0% | 37.5% | 48.9% | 0.0% | 0.0% |
| `REGRESSION_EVIDENCE_MISSING` | 100.0% | 68.2% | 6.8% | 0.0% | 0.0% |
| `STALE_EVIDENCE` | 100.0% | 38.6% | 48.9% | 0.0% | 0.0% |
| `CONTRADICTORY_EVIDENCE` | 100.0% | 56.8% | 0.0% | 0.0% | 0.0% |
| `SCOPE_MISMATCH` | 100.0% | 38.6% | 45.5% | 0.0% | 0.0% |
| `UNDECLARED_GAP` | 100.0% | 36.4% | 48.9% | 21.6% | 21.6% |

### Abstention rate

| Mechanism | A status | B target | C unaware | D scoped | E active |
| --- | --- | --- | --- | --- | --- |
| `NONE` | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| `RANDOM_MISSING` | 0.0% | 10.6% | 9.6% | 49.0% | 37.5% |
| `DECISIVE_FIELD_MISSING` | 0.0% | 20.2% | 21.2% | 95.2% | 39.4% |
| `REGRESSION_EVIDENCE_MISSING` | 0.0% | 8.7% | 6.7% | 33.7% | 25.0% |
| `STALE_EVIDENCE` | 0.0% | 0.0% | 0.0% | 94.2% | 14.4% |
| `CONTRADICTORY_EVIDENCE` | 0.0% | 0.0% | 0.0% | 84.6% | 51.0% |
| `SCOPE_MISMATCH` | 0.0% | 21.2% | 22.1% | 96.2% | 41.3% |
| `UNDECLARED_GAP` | 0.0% | 19.2% | 17.3% | 49.0% | 49.0% |

### Verified-remediation recall

| Mechanism | A status | B target | C unaware | D scoped | E active |
| --- | --- | --- | --- | --- | --- |
| `NONE` | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| `RANDOM_MISSING` | 100.0% | 87.5% | 100.0% | 12.5% | 25.0% |
| `DECISIVE_FIELD_MISSING` | 100.0% | 0.0% | 62.5% | 0.0% | 50.0% |
| `REGRESSION_EVIDENCE_MISSING` | 100.0% | 100.0% | 100.0% | 0.0% | 12.5% |
| `STALE_EVIDENCE` | 100.0% | 0.0% | 62.5% | 0.0% | 87.5% |
| `CONTRADICTORY_EVIDENCE` | 100.0% | 100.0% | 100.0% | 0.0% | 37.5% |
| `SCOPE_MISMATCH` | 100.0% | 0.0% | 87.5% | 0.0% | 50.0% |
| `UNDECLARED_GAP` | 100.0% | 0.0% | 87.5% | 37.5% | 37.5% |

### False assurance rate

| Mechanism | A status | B target | C unaware | D scoped | E active |
| --- | --- | --- | --- | --- | --- |
| `NONE` | 92.3% | 90.9% | 0.0% | 0.0% | 0.0% |
| `RANDOM_MISSING` | 92.3% | 88.9% | 55.6% | 0.0% | 0.0% |
| `DECISIVE_FIELD_MISSING` | 92.3% | 100.0% | 90.9% | n/a | 0.0% |
| `REGRESSION_EVIDENCE_MISSING` | 92.3% | 89.2% | 60.0% | n/a | 0.0% |
| `STALE_EVIDENCE` | 92.3% | 100.0% | 90.7% | n/a | 0.0% |
| `CONTRADICTORY_EVIDENCE` | 92.3% | 87.7% | 0.0% | n/a | 0.0% |
| `SCOPE_MISMATCH` | 92.3% | 100.0% | 87.0% | n/a | 0.0% |
| `UNDECLARED_GAP` | 92.3% | 100.0% | 87.9% | 86.4% | 86.4% |

## Scenario family

Coverage of the advantage across families, so a single template cannot be
driving the headline.  Unsafe escape rate, all conditions.

| Family | A status | B target | C unaware | D scoped | E active |
| --- | --- | --- | --- | --- | --- |
| GENUINE_REMEDIATION | n/a | n/a | n/a | n/a | n/a |
| EXIT_ZERO_NO_CHANGE | 100.0% | 0.0% | 36.2% | 5.2% | 5.2% |
| WRONG_REGISTRY_KEY | 100.0% | 69.0% | 0.0% | 0.0% | 0.0% |
| WRONG_PRODUCT_IDENTITY | 100.0% | 39.7% | 37.9% | 5.2% | 5.2% |
| SIDE_BY_SIDE_VULNERABLE | 100.0% | 63.8% | 34.5% | 5.2% | 5.2% |
| PARTIAL_MULTI_PREDICATE | 100.0% | 77.6% | 0.0% | 0.0% | 0.0% |
| SERVICE_RETURNS_AFTER_REBOOT | 100.0% | 34.5% | 50.0% | 5.2% | 5.2% |
| REBOOT_REQUIRED_NOT_PERFORMED | 100.0% | 32.8% | 0.0% | 0.0% | 0.0% |
| VULNERABLE_BINARY_ON_DISK | 100.0% | 74.1% | 50.0% | 5.2% | 5.2% |
| INVENTORY_UPDATED_BINARY_UNCHANGED | 100.0% | 70.7% | 58.6% | 6.9% | 6.9% |
| GROUP_PARTIAL_ROLLOUT | 100.0% | 1.7% | 0.0% | 0.0% | 0.0% |
| REGRESSION_INTRODUCED | n/a | n/a | n/a | n/a | n/a |
| NEW_EXPOSURE_INTRODUCED | 100.0% | 70.7% | 48.3% | 0.0% | 0.0% |

## Evidence requests (Arm E only)

| Coverage | Mechanism | requests/case | granted | decision-relevant | abstention |
| --- | --- | --- | --- | --- | --- |
| 100% | `NONE` | 0.00 | n/a | n/a | 0.0% |
| 90% | `CONTRADICTORY_EVIDENCE` | 0.81 | 47.6% | 47.6% | 38.5% |
| 90% | `DECISIVE_FIELD_MISSING` | 1.08 | 71.4% | 67.9% | 30.8% |
| 90% | `RANDOM_MISSING` | 0.08 | 0.0% | 0.0% | 7.7% |
| 90% | `REGRESSION_EVIDENCE_MISSING` | 0.46 | 58.3% | 58.3% | 19.2% |
| 90% | `SCOPE_MISMATCH` | 1.12 | 69.0% | 69.0% | 30.8% |
| 90% | `STALE_EVIDENCE` | 1.00 | 100.0% | 100.0% | 0.0% |
| 90% | `UNDECLARED_GAP` | 0.19 | 0.0% | 0.0% | 19.2% |
| 80% | `CONTRADICTORY_EVIDENCE` | 0.81 | 66.7% | 57.1% | 34.6% |
| 80% | `DECISIVE_FIELD_MISSING` | 1.23 | 81.2% | 65.6% | 34.6% |
| 80% | `RANDOM_MISSING` | 0.50 | 46.2% | 46.2% | 26.9% |
| 80% | `REGRESSION_EVIDENCE_MISSING` | 0.69 | 83.3% | 83.3% | 7.7% |
| 80% | `SCOPE_MISMATCH` | 1.23 | 71.9% | 62.5% | 34.6% |
| 80% | `STALE_EVIDENCE` | 1.19 | 87.1% | 83.9% | 19.2% |
| 80% | `UNDECLARED_GAP` | 0.54 | 0.0% | 0.0% | 38.5% |
| 60% | `CONTRADICTORY_EVIDENCE` | 1.12 | 37.9% | 20.7% | 73.1% |
| 60% | `DECISIVE_FIELD_MISSING` | 1.65 | 69.8% | 65.1% | 42.3% |
| 60% | `RANDOM_MISSING` | 1.00 | 42.3% | 42.3% | 50.0% |
| 60% | `REGRESSION_EVIDENCE_MISSING` | 1.23 | 68.8% | 68.8% | 34.6% |
| 60% | `SCOPE_MISMATCH` | 1.73 | 68.9% | 62.2% | 42.3% |
| 60% | `STALE_EVIDENCE` | 1.23 | 87.5% | 81.2% | 23.1% |
| 60% | `UNDECLARED_GAP` | 0.96 | 0.0% | 0.0% | 57.7% |
| 40% | `CONTRADICTORY_EVIDENCE` | 0.96 | 76.0% | 36.0% | 57.7% |
| 40% | `DECISIVE_FIELD_MISSING` | 2.00 | 80.8% | 69.2% | 50.0% |
| 40% | `RANDOM_MISSING` | 2.00 | 42.3% | 32.7% | 65.4% |
| 40% | `REGRESSION_EVIDENCE_MISSING` | 1.19 | 67.7% | 61.3% | 38.5% |
| 40% | `SCOPE_MISMATCH` | 2.15 | 67.9% | 57.1% | 57.7% |
| 40% | `STALE_EVIDENCE` | 1.62 | 97.6% | 90.5% | 15.4% |
| 40% | `UNDECLARED_GAP` | 1.92 | 0.0% | 0.0% | 80.8% |

