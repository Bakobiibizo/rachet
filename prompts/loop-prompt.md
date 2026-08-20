# Rachet Core v1 LDGR Loop

Work through exactly one ready LDGR work item.

1. Run `ldgr status`; use `ldgr context` only when the brief status and work item are insufficient.
2. Select exactly one ready pending item with `ldgr next`, inspect it with `ldgr work show <slug>`, and read the referenced sections of `docs/spec`.
3. Start one run with `ldgr run start <slug> --command "<bounded action>"`.
4. Implement only that item. Respect its dependencies, acceptance criteria, `docs/spec` fixed decisions, and explicit deferrals. Do not substitute mocks on a release-critical Commonware path.
5. Run the item's tests/checks. Write `.ldgr/run_summary.json` with objective, changed files/surfaces, commands, metrics, outcome, artifact references, and any newly discovered next work.
6. Record only continuity-bearing observations, artifacts, validations, errors, and decisions; do not duplicate routine evidence across records. Use narrative reports only for claim changes, surprising failures, external-validity changes, or milestone synthesis.
7. Queue follow-up work only for genuinely newly discovered scope. Record accepted-operation failures before retrying, following `.ldgr/agent-errors.md`.
8. Close the run with an accurate terminal status before stopping. Then run `ldgr status` and report the next pending item.

One loop means one work item; never silently weaken an acceptance gate.
