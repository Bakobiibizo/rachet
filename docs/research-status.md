# Research status

## What is established

The current repository establishes an engineering proof of mechanism for a
deterministic validation chain:

- exact canonical state transitions and replay;
- signed, bounded action ingress;
- a real four-node Commonware consensus/network path;
- persistence, restart recovery, and state convergence;
- isolated, schema-constrained agent/operator execution; and
- retained experiment inputs, traces, resources, manifests, and audits.

These claims are supported by the workspace tests and the four-node release
gate. They say that the apparatus works; they do not establish that a particular
agent economy or reputation mechanism works.

## H-REP-001 is invalid

The retained H-REP-001 formal execution has the locked disposition **INVALID**.
Two protocol violations take precedence over every diagnostic gate:

1. fifty M01 validation identities reused identities from another population's
   M00 condition, violating the required fresh identity per operator,
   condition, and seed;
2. fixed-policy wall-clock allowances were granted per fixture rather than per
   epoch, exceeding the preregistered budget.

No attempt was excluded, repaired, or reinterpreted. The evidence remains in the
repository so the invalidity can be reproduced and audited. Reconstructed gate
values are diagnostic only and cannot accept, reject, or revise M01.

The complete audited account is in
[`../experiments/H-REP-001/assessment.md`](../experiments/H-REP-001/assessment.md).

## Claims not established

Rachet currently provides no evidence for:

- Sybil resistance;
- robust reputation prediction across environments;
- human or open-market behavior;
- market sustainability or token necessity;
- generalization beyond the checked-in software fixtures;
- the superiority of M01 over simpler baselines; or
- an exploit-derived successor mechanism.

## Current decision boundary

The chain should remain stable while the next experimental regime is designed.
The successor should be a new preregistration and execution, not a repair of the
invalid run. At minimum it should:

1. generate and audit a unique identity for every operator × condition × seed;
2. enforce budgets at the same epoch boundary used by the preregistration;
3. preflight all fixtures and manifests before any formal run;
4. fail closed and retain partial evidence on protocol deviation;
5. distinguish engineering failure, protocol invalidity, inconclusive evidence,
   and a mechanism-level result;
6. compare M00/M01 against explicit null, trivial, resource-matched, and
   adversarial baselines; and
7. treat any observed exploit as a reproducible hypothesis for a new mechanism
   version, never as an in-place patch to M01.

The experimental regime is intentionally not frozen by this documentation. Its
design is the next research decision.
