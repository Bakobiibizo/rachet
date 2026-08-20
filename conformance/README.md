# Protocol conformance vectors

The checked-in vectors are compatibility artifacts, not snapshots to refresh
when a test fails.

- `crates/core/conformance.toml` locks canonical actions, block headers, events,
  receipts, state keys, genesis configuration, and mechanism-set identity.
- `crates/mechanisms/conformance.toml` locks the deterministic outputs of M00
  and M01.
- `m00_record_only.toml` and `m01_naive_reputation.toml` retain the readable
  mechanism vectors used to review individual cases.

Run the locked vectors with:

```sh
cargo test -p rachet-core --test conformance
cargo test -p rachet-mechanisms
```

A hash mismatch is protocol byte or behavior drift. Do not regenerate merely
to make CI pass. Before approving an intentional change, reviewers must:

1. review whether `CodecVersion` must be incremented;
2. require a migration or a new genesis when compatibility changes;
3. inspect and explicitly approve the vector diff; and
4. replay every retained exploit trace against the proposed encoding and
   mechanism outputs.

Only after those checks may the Commonware fixtures be regenerated:

```sh
RUSTFLAGS="--cfg generate_conformance_tests" cargo test -p rachet-core --test conformance
RUSTFLAGS="--cfg generate_conformance_tests" cargo test -p rachet-mechanisms
```

Commit the resulting TOML changes together with the compatibility decision and
retained-trace replay evidence.
