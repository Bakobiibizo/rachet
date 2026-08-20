# Getting started

## Requirements

- Linux, or WSL2 on a Windows host
- Rust 1.93.0 with `rustfmt` and `clippy`
- Git

The repository includes `rust-toolchain.toml`, so rustup selects the expected
toolchain automatically.

```sh
git clone https://github.com/bakobiibizo/rachet.git
cd rachet
python3 tools/generate_hrep_fixtures.py
cargo build --workspace --bins
```

The generator deterministically reconstructs the nested two-commit Git
repositories used by the experiment fixtures. `fixtures/repositories/` is local
generated state and is intentionally not committed to the outer repository.

## Validate the checkout

Run the complete local acceptance gate:

```sh
make check
```

This checks formatting, denies every Clippy warning, runs the complete debug
workspace, and repeats the workspace tests under the release profile with
overflow checks enabled.

For a faster first pass:

```sh
cargo test --workspace
```

For the real production-network path:

```sh
cargo test -p rachet-chain --test four_node_release_gate --release
```

That integration test creates four real Commonware nodes on loopback, finalizes
1,000 blocks, checks signed forwarding, restarts and catches up one node,
verifies state/replay agreement, and performs a clean shutdown.

## Command-line programs

All programs support `--json` for structured success and error output.

### Node

Create a local configuration:

```sh
cargo run -p rcht-node -- init --config rcht-node.json --node-index 0
cargo run -p rcht-node -- inspect-config --config rcht-node.json
```

Start it in the foreground:

```sh
cargo run -p rcht-node -- run --config rcht-node.json
```

In another terminal:

```sh
cargo run -p rcht-node -- status --config rcht-node.json
```

Generated configuration, actor keys, and runtime state are local material. Do
not commit them.

### Client

Inspect the full client surface:

```sh
cargo run -p rchtctl -- --help
```

The client supports actor identity, job creation and closure, evidence
registration, attestations, commitments and reveals, challenges, resolutions,
block/state inspection, and replay verification.

Create and inspect a local actor identity:

```sh
cargo run -p rchtctl -- identity create --key actor.key
cargo run -p rchtctl -- --json identity show --key actor.key
```

### Operator boundary

```sh
cargo run -p rcht-operator -- --help
```

The operator adapter creates isolated homes, renders bounded observations,
validates schema-constrained decisions, retains malformed output without acting
on it, accounts for resources, and supports explicit pause/resume boundaries.

### Laboratory

```sh
cargo run -p rcht-lab -- --help
```

The laboratory supports smoke and calibrated runs, exact replay, comparisons,
audits, and promotion of a retained run into an exploit reproducer. Do not treat
the checked-in H-REP-001 execution as a valid result; read
[`research-status.md`](research-status.md) before designing a successor.

## Environment variables

- `RCHT_NODE_CONFIG` supplies the node config path when `--config` is absent.
- `RCHT_ACTOR_KEY` supplies the actor key path when `--key` is absent.
- `RCHT_NODE_URL` supplies the client node URL when `--node-url` is absent.

Explicit command options take precedence. Process environment is captured at
startup in the host-facing binaries and is never read from deterministic Core.

## Source of truth

[`spec`](spec) is authoritative for Core v1. If this guide and the specification
conflict, follow the specification and open a documentation issue.
