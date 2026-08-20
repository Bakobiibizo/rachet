# H-REP-001 Assessment

## Phase 6 outcome

**Assessment: INVALID**

The locked priority rule in `preregistration.toml` makes `INVALID` take precedence over `PASS`, `FAIL`, and `INCONCLUSIVE`. The Phase 5 audit reconstructed the retained evidence but found two formal-policy violations:

1. **Validation identities were reused across conditions.** The lock requires a fresh identity for every operator, condition, and seed. Fifty M01 identities reused another population's M00 identity, leaving 60 unique identities rather than 110.
2. **Fixed-heuristic wall-clock allowances exceeded the lock.** Every fixed heuristic was granted 60,000 ms per fixture instead of per epoch. Each of the 80 fixed-operator/condition-run pairs records 300,000 ms in epoch 0 and 240,000 ms in epoch 1 rather than 60,000 ms in each epoch.

No attempt was excluded, repaired, replaced, or reinterpreted. Smoke and calibration data remain excluded. There were no infrastructure exclusions, operator exclusions, mechanism changes, threshold changes, or post-output seed changes. The preregistration anchor remains `9cd702ff890078079a5836457831625857098912fc9de7287a5b9a7e12687ec2`.

## Preregistered gates

The following values are diagnostic reconstructions from the five retained M01 condition runs, in seed order 0 through 4. They are **not valid formal estimates** and cannot rescue or downgrade the `INVALID` assessment. `—` means undefined under the locked rule; no operator or seed was dropped and no value was imputed.

| Gate | Locked comparison | Seed values | Mean | Diagnostic threshold result |
|---|---:|---|---:|---|
| 1. M01 score predicts held-out correctness | rho >= 0.20 | —, —, —, —, — | — | Undefined. Easy-job-only and perfect-abstainer have no binary held-out decisions in every seed, so correctness over the locked 11-operator set is undefined. |
| 2. Improvement over raw validation count | delta rho >= 0.05 | —, —, —, —, — | — | Undefined because the required score and count correlations cannot be computed without dropping the same undefined correctness rows. |
| 3. Improvement over majority-following | delta accuracy >= 0.05 | 0, 0, 0, 0, 0 | 0 | FAIL |
| 4. Top-reputation held-out error | error <= 0.20 | 0, 0, 0, 0, 0 | 0 | PASS |
| 5. Easy-job farming profitability | ratio <= 0.80 | 0, 0, 0, 0, 0 | 0 | PASS |
| 6. Productive/adversarial reputation per effort | ratio >= 1.00 | 0.100000, 0.062500, 0.105882, 0.470588, 0.235294 | 0.194853 | FAIL |
| 7. Strategic abstention benefit | benefit <= 0.10 | -0.8, -0.8, -0.8, -0.8, -0.8 | -0.8 | PASS |
| 8. Positive-score concentration | HHI <= 0.30 | 0.209877, 0.209877, 0.174603, 0.180000, 0.209877 | 0.196847 | PASS |
| 9. High-reputation/low-correctness frequency | frequency <= 0.10 | 0, 0, 0, 0, 0 | 0 | PASS |
| 10. Reproducibility | agreement >= 0.80 and CV <= 0.25 for every gate 1-9 | Gates 1-2 undefined; gate 6 CV = 0.859127; all defined gates had directional agreement 1.0 | — | NOT SATISFIED |

For gate 4, productive, self-interested, explicitly-adversarial, and majority-following tie at the top score of 4 in every seed and each has diagnostic held-out correctness 1.0. For gate 6, `explicitly-adversarial` is the declared adversarial operator used by the locked population manifest. Gates 3-9 were aggregated exactly as preregistered; gate 10 used sample standard deviation. The existence of defined failures and undefined values is reported without selecting among `FAIL` or `INCONCLUSIVE`, because audited invalidity has priority.

## Baseline categories

All section 39 categories remain separate. Values below are descriptive means across the five retained runs of the named condition; undefined correctness was not averaged. They inherit the invalidity above.

### Functional baseline

The productive operator attempted the target validation function. Its M01 mean post-training score was 4.0, diagnostic held-out correctness was 1.0 in 5/5 seeds, and mean recorded effort was 83.0 units. Under M00 its score was 0 by mechanism definition, diagnostic correctness was 1.0 in 5/5 seeds, and mean effort was 81.4 units.

### Mechanism control

M00@1.0.0 used the same fixtures, declared populations, policies, and budgets, in the locked M00-then-M01 order. M00 emitted no reputation state and all post-training scores were 0. The cross-condition identity reuse prevents treating the retained M00/M01 pairing as a valid formal control comparison.

### Null model

Each M01 run retained the preregistered SHA256/Fisher-Yates random ranking independent of validation in its `baseline-categories.json`. The five rankings were generated separately and were not substituted for another baseline. No registered gate assigned an outcome statistic directly to the null ranking, and no post-hoc null comparison is introduced here.

### Trivial heuristics

| Heuristic | M01 mean score | Diagnostic mean held-out correctness | Defined seeds |
|---|---:|---:|---:|
| always-pass | -2.0 | 0.25 | 5 |
| always-fail | 2.0 | 0.75 | 5 |
| random-verdict | -0.4 | 0.55 | 5 |
| easy-job-only | 0.0 | — | 0 |
| majority-following | 4.0 | 1.0 | 5 |
| maximum-volume | -2.0 | 0.25 | 5 |
| perfect-abstainer | 0.0 | — | 0 |
| historical-majority | 0.6 | 0.366667 | 5 |

These fixed heuristics are reported separately and are not resource-matched. Their duplicated allowance is itself an invalidity reason.

### Resource-matched competitor

Raw selected-training validation count used the same retained M01 traces. Productive, self-interested, explicitly-adversarial, and most trivial policies selected five training claims per seed; easy-job-only selected two. Gate 2 is undefined under the locked 11-operator set and is not replaced with a reduced-set correlation.

### Adversarial strategies

Self-interested and explicitly-adversarial remain separate from the functional baseline. Both had M01 mean score 4.0 and diagnostic correctness 1.0 in 5/5 seeds. Their mean recorded effort was 84.4 and 16.4 units respectively, versus productive's 83.0. Gate 6 consequently failed diagnostically, but the invalid run supports no mechanism claim.

Success or failure against any one category is not used as evidence for another.

## Resources

The audit reconciled all 780 resource records, 110 operator totals, 10 run totals, and 10 customer records. Arithmetic totals over all ten retained condition runs are:

| Resource | Recorded total |
|---|---:|
| model calls | 60 |
| input tokens | unavailable for 60 intelligent records; known fixed total 0 |
| output tokens | unavailable for 60 intelligent records; known fixed total 0 |
| tool calls | 566 |
| command duration | 5,106,213 ms |
| CPU time | 89,550 ms |
| validation wall-clock allowance | 97,200,000 ms, including the invalid duplicated fixed allowances |
| Git objects read | 2,174 |
| files inspected | 1,031 |
| tests executed | 232 |
| jobs inspected | 990 |
| jobs accepted | 920 |
| claims evaluated | 782 |
| evidence bytes | 672,147 |
| compute units | unavailable for 60 intelligent records; known fixed total 0 |

The three intelligent objectives had the same declared per-epoch limits. Fixed heuristics had no model or tool use and were never treated as resource-matched. Recorded usage is not corrected after the audit finding.

## Independence and limitations

The three intelligent objectives used one provider, one exact model family, one harness, and one repository-inspection method, with three distinct prompts. Worktrees, private memories, and random seeds were isolated, and no communication channel or customer relationship was declared. They are therefore different isolated objectives, **not independent validator systems**. Identity reuse across M00 and M01 further violates the registered independence boundary.

The tested population is limited to the locked software fixtures, operators, information access, learning rules, schedule, and resources. H-REP-001 cannot establish Sybil resistance, human behavior, market sustainability, token necessity or economics, customer-standing efficacy, challenge-market efficacy, or generalization beyond this setting.

## Evidence and reconstruction

Primary reconstructable evidence:

- `preregistration.toml` and `preregistration-lock.json` (lock SHA256 `9cd702ff890078079a5836457831625857098912fc9de7287a5b9a7e12687ec2`);
- `formal-execution.json` (SHA256 `ad9956fdc5e4b34de1b53a6d039528d3bfcbc74246e026ed2c73735e5fc4ddf9`), identifying exactly 5 seeds and 10 condition runs;
- `formal-artifact-manifest.json` (SHA256 `83744361862f3236e8968726867796328f5719badeea03056046575996b31b7f`), covering 651 formal files and 5,989,645 bytes;
- each listed run's `metrics.json`, `resources.json`, action/block/event traces, and artifact manifest;
- `audit-report.json` (SHA256 `ee1332888ae74849524a29fdb977bcc41ef84f8bd5903942f614bbedba8ced36`).

The audit verified 1,100 signed actions with contiguous nonces, 1,030 blocks and roots, 1,290 events, 460 independently recomputed M01 updates, 990 decisions and observations, 20 decision-phase commitments, 9 hidden resolutions, and exact terminal outcomes. Reconstruction succeeded; policy compliance did not.

## Phase 7 mechanism decision

**M01@1.0.0: awaiting another experiment.**

The invalid execution cannot accept or reject M01, and it supplies no basis for revising M01. M01 is not changed in place. Any later formal attempt requires a separately authorized experiment and a new preregistration lock with fresh identities and correctly enforced per-epoch budgets.

## Permitted claim

This assessment makes no positive research claim. In section 40's permitted terms: **H-REP-001 does not establish whether M01 reputation predicts future correctness under the locked software-fixture population, operator population, information access, learning rules, schedule, and resources, because the formal execution is invalid.**
