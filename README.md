# CyberX

Defensive security research. Each experiment is a self-contained, reproducible study with
a stated hypothesis, a frozen benchmark corpus, machine-readable results, and an honest
write-up — including results that argue against the thesis being tested.

**Safety boundary for the whole repository:** everything runs against simulators, unit
tests, or explicitly isolated local fixtures. No scanning of third-party systems, no
exploit code, no production or tenant changes. Any adapter that touches a real machine
must be gated behind an explicit opt-in environment flag and default to disabled.

Experiments live under `experiments/<slug>/`.
