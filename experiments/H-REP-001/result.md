# H-REP-001 Result

## Formal result

**INVALID**

The retained formal execution is reconstructable, but it violates two locked requirements:

- 50 M01 validation identities reuse another population's M00 identity; 60 unique identities were observed where 110 fresh operator/condition/seed identities were required.
- Every fixed heuristic's 60-second per-epoch allowance was recorded once per fixture, affecting 80 operator/run pairs and producing 300 seconds in epoch 0 and 240 seconds in epoch 1 instead of 60 seconds in each.

The preregistered rule gives audited invalidity priority over gate passes, gate failures, and undefined gate values. No threshold, mechanism, population, seed, exclusion, or retained output was changed after lock.

## Gate disposition

Diagnostic reconstruction of the unchanged gates found:

- gates 1 and 2 undefined in all five seeds because held-out correctness is undefined for two members of the locked 11-operator set;
- gates 3 and 6 below their locked thresholds;
- gates 4, 5, 7, 8, and 9 at or above their locked requirements;
- gate 10 not satisfied because gates 1-2 are undefined and gate 6 has coefficient of variation 0.859127, above 0.25.

These observations are not formal estimates from a valid experiment. Exact seed values and formulas are published in `assessment.md`.

## Baseline disposition

All required categories were retained and reported separately:

- **functional baseline:** productive validation operator;
- **mechanism control:** M00@1.0.0 record-only;
- **null model:** preregistered seeded random ranking;
- **trivial heuristics:** always-pass, always-fail, random-verdict, easy-job-only, majority-following, maximum-volume, perfect-abstainer, and historical-majority;
- **resource-matched competitor:** raw selected-training validation count on the same M01 traces;
- **adversarial strategies:** self-interested and explicitly-adversarial.

No category substitutes for another. The identity violation compromises the formal M00/M01 comparison, and the allowance violation compromises the fixed-heuristic records.

## Mechanism decision

**M01@1.0.0: awaiting another experiment.**

M01 is neither accepted, rejected, nor revised by H-REP-001. It is not revised in place. A later attempt must use a new preregistration lock, fresh per-condition identities, and correctly enforced per-epoch budgets.

## Claim

**H-REP-001 does not establish whether M01 reputation predicts future correctness under the locked software-fixture population, operator population, information access, learning rules, schedule, and resources, because the formal execution is invalid.**

No claim is made about Sybil resistance, human behavior, market sustainability, token necessity or economics, customer standing, challenge markets, or generalization beyond the tested software-validation setting.

Evidence: `assessment.md`, `audit-report.json` (SHA256 `ee1332888ae74849524a29fdb977bcc41ef84f8bd5903942f614bbedba8ced36`), `formal-execution.json`, `formal-artifact-manifest.json`, and the ten run directories named by `formal-execution.json`.
