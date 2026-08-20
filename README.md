# Rachet

Rachet is an experimental validation chain for studying how independent agents
submit evidence, attest to claims, challenge one another, and resolve outcomes
under deterministic rules.

The repository and Rust crates use the `rachet` name; command-line programs use
the shorter `rcht-*` prefix.

Rachet combines:

- a deterministic, consensus-independent protocol core;
- a real four-node [Commonware](https://commonware.xyz/) consensus and network
  integration;
- signed action ingress, canonical state transitions, persistence, recovery,
  and exact replay;
- isolated operator tooling for bounded agent experiments; and
- a reproducible laboratory for comparing validation mechanisms and agent
  populations.

## Project status

The **engineering baseline works**. The current release gate starts four real
nodes, finalizes 1,000 blocks, forwards a signed action to all peers, restarts a
node across a 100-block gap, catches it up, reproduces state on all nodes,
verifies replay, and shuts the network down cleanly.

The **research question remains open**. The retained H-REP-001 execution is
formally **invalid** because validation identities were reused across conditions
and fixed-policy wall-clock budgets were applied incorrectly. Its reconstructed
numbers are diagnostic only and support no mechanism claim. See
[`docs/research-status.md`](docs/research-status.md) and the retained
[`assessment`](experiments/H-REP-001/assessment.md).

Rachet is research software, not a production blockchain, financial network,
or deployed market. It currently has no token, billing, marketplace,
governance, smart-contract VM, auto-merge path, or claim of Sybil resistance.

## Architecture

```text
signed clients / isolated operators
                |
          bounded RPC ingress
                |
       Commonware four-node chain
                |
   deterministic Rachet state machine
                |
 canonical blocks, events, evidence, roots
                |
       replay and experiment audit
```

The consensus-independent core cannot read files, environment variables,
clocks, networks, or subprocesses. Host I/O stays in the chain, client,
operator, laboratory, and binary layers. See
[`docs/architecture.md`](docs/architecture.md).

## Workspace

| Path | Purpose |
| --- | --- |
| `crates/core` | Canonical protocol types, codecs, invariants, and transitions |
| `crates/mechanisms` | Mechanism catalog plus implemented M00 and M01 mechanisms |
| `crates/chain` | Commonware application, networking, persistence, RPC, and observability |
| `crates/client` | Actor identity, signing, and transport |
| `crates/operator` | Isolated observation/decision boundary and agent process adapter |
| `crates/lab` | Deterministic simulation, experiments, comparison, audit, and replay |
| `crates/cli` | Shared CLI support |
| `bins/*` | `rcht-node`, `rchtctl`, `rcht-operator`, and `rcht-lab` |
| `experiments/H-REP-001` | Preregistration, retained evidence, audit, and invalid assessment |
| `docs/spec` | Authoritative Core v1 specification |

## Quick start

Rachet supports Linux. On Windows, use WSL2. Install Rust 1.93.0 with `rustfmt`
and `clippy`, then run:

```sh
git clone https://github.com/bakobiibizo/rachet.git
cd rachet
python3 tools/generate_hrep_fixtures.py
cargo build --workspace --bins
cargo test --workspace
```

The fixture generator reconstructs the small nested Git histories used by the
laboratory. They are generated locally rather than stored as broken gitlinks in
the outer repository.

Initialize a local node configuration and inspect the available commands:

```sh
cargo run -p rcht-node -- init --config rcht-node.json --node-index 0
cargo run -p rcht-node -- inspect-config --config rcht-node.json
cargo run -p rchtctl -- --help
cargo run -p rcht-lab -- --help
```

Detailed setup and command examples are in
[`docs/getting-started.md`](docs/getting-started.md).

## Validation

The required local gate is:

```sh
make check
```

Equivalent commands:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --release
```

The focused production-path gate is:

```sh
cargo test -p rachet-chain --test four_node_release_gate --release
```

## Mechanism scope

- **M00 — record only:** immutable recording without reputation updates.
- **M01 — naive reputation:** the implemented experimental reputation rule.
- **M02-M12:** catalogued proposals only; they have no execution binding.

Adding a mechanism requires a new immutable version and new experiment. Existing
mechanism semantics are not silently rewritten after results are observed.

## Documentation

- [`docs/getting-started.md`](docs/getting-started.md) — build, run, and CLI guide
- [`docs/architecture.md`](docs/architecture.md) — trust and component boundaries
- [`docs/research-status.md`](docs/research-status.md) — established results and open questions
- [`docs/spec`](docs/spec) — authoritative Core v1 specification
- [`docs/commonware-spike.md`](docs/commonware-spike.md) — Commonware integration investigation

## License

Rachet is licensed under the [MIT License](LICENSE).
