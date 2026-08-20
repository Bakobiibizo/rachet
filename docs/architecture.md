# Architecture and trust boundaries

Rachet separates deterministic protocol semantics from every host capability.
The separation is both an audit aid and an experiment control: agent behavior
may vary, while admitted actions and state transitions remain reproducible.

## Component flow

```text
actor identity / agent process
             |
       signed ActionEnvelope
             |
  client transport and bounded RPC ingress
             |
    Commonware networking and consensus
             |
        canonical block proposal
             |
  rachet-core deterministic transition
             |
        roots, receipts, and events
             |
 persistence, query, replay, and experiment audit
```

## Deterministic Core

`crates/core` owns protocol types, canonical codecs, content identifiers,
actions, events, blocks, state roots, invariants, and transition rules. It has
only three direct normal dependencies: `bytes`, `commonware-codec`, and
`commonware-cryptography`.

Core must not access:

- files or environment variables;
- sockets or HTTP;
- subprocesses;
- wall or monotonic clocks;
- floating-point arithmetic in consensus or economic semantics; or
- nondeterministic host runtime facilities.

Workspace contract tests enforce these restrictions. IDs are domain-separated,
state/action roots are mutation-sensitive, nonces advance contiguously, genesis
mechanisms are fixed, and mechanism namespaces cannot write across boundaries.

## Chain layer

`crates/chain` integrates the deterministic application with Commonware
networking, consensus, storage, metrics, and HTTP RPC. The production release
gate uses four real nodes rather than a simulated or mocked consensus path.

RPC ingress performs bounded decoding and validation before an action is
admitted. Query responses expose finalized state and redact private material.
Health distinguishes finalized height from connected-peer readiness so clients
do not infer forwarding availability from consensus progress alone.

## Identity and authority

Actor identity and consensus identity are separate protocol types. Customers
can submit jobs and evidence, validators can attest or challenge, and resolution
actions require the configured experiment authority. Actor signatures are bound
to chain ID, protocol version, nonce, expiry height, and canonical action bytes.

## Operator isolation

`crates/operator` is a host-facing boundary, not part of consensus. It constructs
redacted observations, invokes a configured external agent process, validates a
strict decision schema, and translates accepted decisions into proposed signed
actions. Model output does not mutate chain state directly.

The boundary retains malformed, crashed, and timed-out executions as evidence;
charges declared resource budgets; uses isolated homes; and never exposes
private evaluator paths, hidden truth, raw secrets, or peer decisions in the
observation contract.

## Mechanisms

The genesis configuration fixes an ordered set of immutable mechanism versions.
Core v1 implements:

- M00@1.0.0: record only;
- M01@1.0.0: naive reputation.

M02-M12 are proposals in the catalog and have no implementation binding. A
research result may motivate a new version, but cannot silently change the
meaning of a mechanism already used in a retained trace.

## Evidence and replay

Evidence content remains external and is referenced by digest, locator, media
type, and manifest digest. The chain records canonical actions, blocks, events,
receipts, and roots. Replay reconstructs state from retained canonical inputs
and detects divergence rather than repairing it silently.

## Deliberately absent scope

Core v1 does not implement a currency, marketplace, billing system, governance,
general-purpose VM, plugin runtime, GitHub App, automatic merge authority, or
web application. Those surfaces would add authority and security assumptions
that are unnecessary for the current validation-economy research question.
