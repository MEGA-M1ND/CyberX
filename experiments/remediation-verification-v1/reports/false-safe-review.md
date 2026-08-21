# Manual false-safe review

Every prediction of `VERIFIED_REMEDIATED` against a ground-truth label that is
not `VERIFIED_REMEDIATED`, one entry per (case, arm).  Generated from
`results/raw_results.jsonl` and the frozen case corpus.

Total false-safe predictions across all arms: **75**

## STATUS_ONLY - 38 false-safe predictions

| Case | Category | Ground truth | Why the arm said safe | Missing signal |
| --- | --- | --- | --- | --- |
| `B-01` | B_EXIT0_NO_CHANGE | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `B-02` | B_EXIT0_NO_CHANGE | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `B-03` | B_EXIT0_NO_CHANGE | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `B-04` | B_EXIT0_NO_CHANGE | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `C-01` | C_WRONG_TARGET | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `C-02` | C_WRONG_TARGET | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `C-03` | C_WRONG_TARGET | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `C-04` | C_WRONG_TARGET | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `D-01` | D_TEMPORARY | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `D-02` | D_TEMPORARY | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `D-03` | D_TEMPORARY | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `D-04` | D_TEMPORARY | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `E-01` | E_SIDE_BY_SIDE | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `E-02` | E_SIDE_BY_SIDE | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `E-03` | E_SIDE_BY_SIDE | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `E-04` | E_SIDE_BY_SIDE | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `F-01` | F_PARTIAL | PARTIALLY_REMEDIATED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `F-02` | F_PARTIAL | PARTIALLY_REMEDIATED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `G-01` | G_FLEET_PARTIAL | PARTIALLY_REMEDIATED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `G-02` | G_FLEET_PARTIAL | PARTIALLY_REMEDIATED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `G-03` | G_FLEET_PARTIAL | PARTIALLY_REMEDIATED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `G-04` | G_FLEET_PARTIAL | PARTIALLY_REMEDIATED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `H-01` | H_REGRESSION | REGRESSION_INTRODUCED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `H-02` | H_REGRESSION | REGRESSION_INTRODUCED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `H-03` | H_REGRESSION | REGRESSION_INTRODUCED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `H-04` | H_REGRESSION | REGRESSION_INTRODUCED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `I-01` | I_NEW_RISK | NEW_SECURITY_RISK | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `I-02` | I_NEW_RISK | NEW_SECURITY_RISK | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `I-03` | I_NEW_RISK | NEW_SECURITY_RISK | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `J-01` | J_REBOOT_REQUIRED | PARTIALLY_REMEDIATED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `J-02` | J_REBOOT_REQUIRED | PARTIALLY_REMEDIATED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `J-03` | J_REBOOT_REQUIRED | PARTIALLY_REMEDIATED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `K-01` | K_WRONG_VULN_MATCH | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `K-02` | K_WRONG_VULN_MATCH | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `K-03` | K_WRONG_VULN_MATCH | REMEDIATION_FAILED | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `L-01` | L_EVIDENCE_MISSING | INSUFFICIENT_EVIDENCE | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `L-02` | L_EVIDENCE_MISSING | INSUFFICIENT_EVIDENCE | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |
| `L-03` | L_EVIDENCE_MISSING | INSUFFICIENT_EVIDENCE | EXIT_CODE_ZERO, DEPLOYMENT_REPORTED_SUCCESS | any post-remediation security state at all; the arm only reads execution metadata |

## TARGET_STATE - 34 false-safe predictions

| Case | Category | Ground truth | Why the arm said safe | Missing signal |
| --- | --- | --- | --- | --- |
| `C-01` | C_WRONG_TARGET | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `C-02` | C_WRONG_TARGET | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `C-03` | C_WRONG_TARGET | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `C-04` | C_WRONG_TARGET | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `D-01` | D_TEMPORARY | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `D-02` | D_TEMPORARY | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `D-03` | D_TEMPORARY | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `D-04` | D_TEMPORARY | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `E-01` | E_SIDE_BY_SIDE | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `E-02` | E_SIDE_BY_SIDE | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `E-03` | E_SIDE_BY_SIDE | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `E-04` | E_SIDE_BY_SIDE | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `F-01` | F_PARTIAL | PARTIALLY_REMEDIATED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `F-02` | F_PARTIAL | PARTIALLY_REMEDIATED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `F-03` | F_PARTIAL | PARTIALLY_REMEDIATED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `F-04` | F_PARTIAL | PARTIALLY_REMEDIATED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `G-01` | G_FLEET_PARTIAL | PARTIALLY_REMEDIATED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `G-02` | G_FLEET_PARTIAL | PARTIALLY_REMEDIATED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `G-04` | G_FLEET_PARTIAL | PARTIALLY_REMEDIATED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `H-01` | H_REGRESSION | REGRESSION_INTRODUCED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `H-02` | H_REGRESSION | REGRESSION_INTRODUCED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `H-03` | H_REGRESSION | REGRESSION_INTRODUCED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `H-04` | H_REGRESSION | REGRESSION_INTRODUCED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `I-01` | I_NEW_RISK | NEW_SECURITY_RISK | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `I-02` | I_NEW_RISK | NEW_SECURITY_RISK | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `I-03` | I_NEW_RISK | NEW_SECURITY_RISK | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `J-01` | J_REBOOT_REQUIRED | PARTIALLY_REMEDIATED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `J-02` | J_REBOOT_REQUIRED | PARTIALLY_REMEDIATED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `J-03` | J_REBOOT_REQUIRED | PARTIALLY_REMEDIATED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `K-01` | K_WRONG_VULN_MATCH | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `K-02` | K_WRONG_VULN_MATCH | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `K-03` | K_WRONG_VULN_MATCH | REMEDIATION_FAILED | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `L-02` | L_EVIDENCE_MISSING | INSUFFICIENT_EVIDENCE | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |
| `L-03` | L_EVIDENCE_MISSING | INSUFFICIENT_EVIDENCE | TARGET_STATE_APPLIED | an independent vulnerability predicate; the arm only checks that the intended change landed |

## INDEPENDENT_VERIFIER - 3 false-safe predictions

| Case | Category | Ground truth | Why the arm said safe | Missing signal |
| --- | --- | --- | --- | --- |
| `E-04` | E_SIDE_BY_SIDE | REMEDIATION_FAILED | VULNERABILITY_PREDICATE_FALSE, PERSISTENT_ACROSS_REBOOT_PROJECTION, NO_REGRESSION_DETECTED, NO_NEW_RISK_DETECTED, ROLLOUT_COMPLETE, TARGET_STATE_APPLIED | inventory omits package versions {'AcmeReader': ['1.4.2']} (collector: inventory enumerates machine-scope ARP entries only) |
| `I-03` | I_NEW_RISK | NEW_SECURITY_RISK | VULNERABILITY_PREDICATE_FALSE, PERSISTENT_ACROSS_REBOOT_PROJECTION, NO_REGRESSION_DETECTED, NO_NEW_RISK_DETECTED, ROLLOUT_COMPLETE, TARGET_STATE_APPLIED | posture snapshot omits security flags ['unexpected_local_admin'] (collector: local group membership is not part of the collected posture snapshot) |
| `K-03` | K_WRONG_VULN_MATCH | REMEDIATION_FAILED | VULNERABILITY_PREDICATE_FALSE, PERSISTENT_ACROSS_REBOOT_PROJECTION, NO_REGRESSION_DETECTED, NO_NEW_RISK_DETECTED, ROLLOUT_COMPLETE, TARGET_STATE_APPLIED | registry collection scope omits ['HKLM\\SOFTWARE\\AcmeEnterprise\\LegacyAuthEnabled'] (collector: vendor hive is not in the configured registry collection scope) |

