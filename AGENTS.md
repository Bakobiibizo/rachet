# Agent Guide

## Authority and scope

- Treat `docs/spec` as authoritative and implement only the active LDGR work item.
- Work on Linux or WSL2. Do not add native-Windows-only paths.
- Preserve the small workspace in spec section 8. In particular, do not split
  `crates/core` into more crates without a concrete compile-time dependency
  problem and a recorded decision.
- Do not implement deferred mechanisms or features. The mechanism catalog does
  not authorize an implementation.

## Architecture boundaries

- `crates/core` remains deterministic and consensus-independent. It must not
  invoke models, Git, shells, the web, or Commonware consensus code.
- Consensus nodes and validation operators are distinct roles and must use
  distinct terminology, keys, configuration, and state.
- Release-critical Commonware paths use real components, never substitute mocks.
- Commands intended for agents produce machine-readable output.

## Dependencies

- Keep `Cargo.lock` committed.
- Commonware dependencies must use the exact release family required by spec
  section 3.8. Any unavoidable Git revision and API mismatch belongs in
  `docs/commonware-spike.md` with reproducible evidence.
- Dependency upgrades require their own work item and validation evidence.

## Required checks

Run these before completing Rust work:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --release
```

Debug, test, and release profiles keep overflow checks enabled. Never weaken a
check to make a work item pass. Record assumptions, failures, decisions, and
validation evidence through LDGR.
