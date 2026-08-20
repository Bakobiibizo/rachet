# Commonware compatibility spike

**Milestone 0 status:** closed and passing on WSL2/Linux with Rust 1.93.0.

This report consolidates the compatibility evidence for the selected Commonware
release. Each probe still records its own scope; in particular, the Alto result
is only reference evidence and is not substituted for a Rachet gate.

The specification's `tests/commonware_smoke.rs` deliverable is located at
`crates/chain/tests/commonware_smoke.rs`, Cargo's integration-test location for
the `rachet-chain` package. Stateful fork and restart probes are kept in
`crates/chain/tests/stateful_qmdb.rs` and
`crates/chain/tests/restart_catchup.rs` so the smoke file remains bounded. All
three run in the normal workspace suite.

## Milestone 0 gate summary

| Acceptance gate | Result | Evidence |
| --- | --- | --- |
| Linux or WSL2 build | Pass | Rust 1.93.0 full workspace checks and unchanged Alto build |
| Four local nodes finalize at least 100 blocks | Pass | Four real Ed25519/RoundRobin Simplex engines finalize the same 100 consecutive blocks in `commonware_smoke.rs` |
| One node stops, restarts, and catches up | Pass | Validator 0 reopens height 31, backfills a 43-block gap, and joins the canonical chain through height 60 in `restart_catchup.rs` |
| Same-seed deterministic replay | Pass | Seed `0x524143484554` reproduces the seven-event trace and runtime audit in `commonware_smoke.rs` |
| Stateful + Deferred + one current QMDB | Pass | Competing forks commit the winner and prune the loser in `stateful_qmdb.rs` |
| Exact Commonware release recorded | Pass | Every locked Commonware package is registry release `2026.7.0`; `commonware_smoke.rs` enforces the complete package set |
| No validation-network economic code | Pass | Milestone 0 changes are dependency, chain-probe, report, and evidence surfaces; core and mechanism modules remain bootstrap boundaries only |

This closes the compatibility spike, not the section 46 production release
gate. The full live chain must still compose authenticated lookup with
broadcast, Simplex, marshal, Stateful, and QMDB in later chain work. Milestone 0
proves those selected boundaries with real Commonware components in bounded
probes; it does not authorize economic protocol implementation.

## Alto integration-reference probe

**Status:** pass on WSL2/Linux with Rust 1.93.0; Rust 1.90.0 is incompatible.

**Reference:** official [`commonwarexyz/alto`](https://github.com/commonwarexyz/alto)
tag `v2026.7.1`, commit
`b8805820b29b0b20cc00828b4602c597b0288003` (release commit dated
2026-07-24). Alto is used only to inspect and exercise integration wiring. No
Alto source is vendored or treated as Rachet protocol code.

### Environment

The successful probe used:

```text
Linux 6.6.114.1-microsoft-standard-WSL2 x86_64
rustc 1.93.0 (254b59607 2026-01-19)
cargo 1.93.0 (083ac5135 2025-12-15)
git 2.43.0
```

Alto CI selects the current stable Rust toolchain but the repository does not
pin a toolchain or declare `rust-version`. Use Rust 1.93.0 for the commands
below; the incompatibility with this machine's Rust 1.90.0 is recorded below.

### Reproducible build and run

Clone the immutable release tag and verify its commit:

```sh
rm -rf /tmp/alto-v2026.7.1

git clone --branch v2026.7.1 --depth 1 \
  https://github.com/commonwarexyz/alto.git /tmp/alto-v2026.7.1
cd /tmp/alto-v2026.7.1
test "$(git rev-parse HEAD)" = \
  b8805820b29b0b20cc00828b4602c597b0288003
```

Build the official workspace without changing its lockfile:

```sh
cargo +1.93.0 build --workspace --locked
```

Observed result: all eight Alto workspace packages built successfully, along
with the locked Commonware dependency set. The clean Rust 1.93.0 build took
about 61 seconds and exited 0.

Generate an official local four-validator configuration. A relative output path
is intentional; Alto's behavior with an absolute output path is noted below.

```sh
cargo +1.93.0 run --locked --bin deploy -- generate \
  --peers 4 \
  --bootstrappers 1 \
  --worker-threads 2 \
  --log-level info \
  --message-backlog 16384 \
  --mailbox-size 16384 \
  --deque-size 10 \
  --signature-threads 2 \
  --output alto-probe \
  local --start-port 34000
```

Run each generated validator from the Alto checkout (one process per generated
validator YAML, excluding `peers.yaml`):

```sh
mkdir -p /tmp/alto-logs
for cfg in alto-probe/*.yaml; do
  test "$(basename "$cfg")" = peers.yaml && continue
  name=$(basename "$cfg" .yaml)
  target/debug/validator \
    --peers="$PWD/alto-probe/peers.yaml" \
    --config="$PWD/$cfg" \
    >"/tmp/alto-logs/$name.log" 2>&1 &
done
```

Validate the live processes through the generated metrics endpoints:

```sh
for port in 34001 34003 34005 34007; do
  curl -fsS "http://127.0.0.1:$port/metrics" |
    awk '$1 == "engine_marshal_processed_height" { print $1, $2 }'
done
```

Observed result: all four authenticated validator processes started, initialized
Simplex and marshal, and reported `engine_marshal_processed_height 21`. Each
application log also reported finalized block height 21. The processes were
then terminated; no Alto process remained listening on ports 34000-34007.
This is evidence that the reference runs, not a substitute for Rachet's own
four-node and recovery gates.

### Version facts

Alto identifies every Alto package as `2026.7.1`. Its workspace requirements
name Commonware `2026.7.0`, and the committed Alto `Cargo.lock` resolves every
Commonware package in that checkout to `2026.7.0`, including actor, broadcast,
codec, codec-macros, coding, consensus, cryptography, deployer, formatting,
macros, macros-impl, math, p2p, parallel, resolver, runtime, runtime-macros,
storage, stream, and utils. No Commonware Git revision was needed.

Rachet's direct Commonware requirements are exact `=2026.7.0` pins. The
Stateful/QMDB probe additionally pins `commonware-parallel = "=2026.7.0"`
because the concrete current-database type must name `Sequential`; no suitable
re-export exists.

The compatibility gate aligns the **entire** locked Commonware graph, including
transitive support crates, to registry release `2026.7.0`. No Commonware Git
source or revision is present. The exact locked set is:

```text
commonware-actor              2026.7.0
commonware-broadcast          2026.7.0
commonware-codec              2026.7.0
commonware-codec-macros       2026.7.0
commonware-coding             2026.7.0
commonware-conformance        2026.7.0
commonware-conformance-macros 2026.7.0
commonware-consensus          2026.7.0
commonware-cryptography       2026.7.0
commonware-formatting         2026.7.0
commonware-glue               2026.7.0
commonware-invariants         2026.7.0
commonware-macros             2026.7.0
commonware-macros-impl        2026.7.0
commonware-math               2026.7.0
commonware-p2p                2026.7.0
commonware-parallel           2026.7.0
commonware-resolver           2026.7.0
commonware-runtime            2026.7.0
commonware-runtime-macros     2026.7.0
commonware-storage            2026.7.0
commonware-stream             2026.7.0
commonware-utils              2026.7.0
```

`locked_commonware_graph_matches_compatibility_baseline` checks the package
names, versions, and crates.io source from `Cargo.lock`. Any upgrade or Git
revision must deliberately update that test and perform the separate evidence
required by section 3.8.

### Observed APIs and wiring

The release source confirms these concrete APIs:

- Production execution is configured with `commonware_runtime::tokio::Config`
  and started with `tokio::Runner::new(...).start(...)`.
- The validator uses `commonware_p2p::authenticated::discovery`, constructs an
  `authenticated::Network`, authorizes the epoch participant set through
  `oracle.track(...)`, and registers distinct pending, recovered, resolver,
  broadcast, and marshal channels.
- `commonware_broadcast::buffered::Engine::new` supplies the block buffer and
  mailbox.
- Two `commonware_storage::archive::immutable::Archive` instances store
  finalizations-by-height and finalized blocks.
- Marshal is initialized through `marshal::core::Actor::init`. Its application
  adapter type is
  `marshal::standard::Deferred<E, Scheme, Application, Block, FixedEpocher>`;
  that clone is passed as both the Simplex automaton and relay.
- Missing marshal data uses `marshal::resolver::p2p::init` and the
  `commonware_resolver::TargetedResolver` boundary.
- The application implements `commonware_consensus::Application` with mutable
  asynchronous `propose` and `verify` methods over an `Ancestry<Block>` stream.
  Finalized `marshal::Update<Block>` values arrive through `Reporter::report`,
  and the application acknowledges delivered blocks.
- Startup order is buffered broadcast, marshal, optional indexer consumer, then
  Simplex consensus. The components are joined as runtime actor handles.

These source observations are from `chain/src/engine.rs`,
`chain/src/application.rs`, and `validator/src/main.rs` at the commit above.

### Incompatibilities and reference limits

1. **Rust 1.90.0 does not build the pinned release.**
   `cargo build --workspace --locked` fails with four `E0658` errors because
   `commonware-p2p 2026.7.0` uses `std::time::Duration::from_hours`, which is
   unstable on Rust 1.90.0. The unchanged source and lockfile build with Rust
   1.93.0. This is a toolchain requirement, not grounds to change the pinned
   Commonware family.
2. **Absolute deploy output is treated as relative.** Passing
   `--output /tmp/rachet-alto-local` while in `/tmp/alto-v2026.7.1` created
   `/tmp/alto-v2026.7.1/tmp/rachet-alto-local` and emitted doubled paths.
   Relative output paths work and are used in the reproducible command above.
3. **Alto's networking policy is not Rachet's fixed mapping.** Alto uses
   `authenticated::discovery`, while the specification selects
   `authenticated::lookup` for Rachet. Alto also uses a BLS12-381 threshold
   Simplex scheme, while Rachet selects the attributable Ed25519 Simplex
   scheme. These are reference differences, not decisions to copy Alto.
4. **Alto does not prove Rachet state integration.** The observed chain wires
   `Deferred` directly around Alto's stateless application and immutable
   archives. It does not exercise `commonware_glue::stateful::Stateful` or a
   QMDB current database. Those remain separate Milestone 0 probes.

### Reconciliation of observed differences

| Observation | Reconciliation with the specification |
| --- | --- |
| Rust 1.90.0 cannot compile `commonware-p2p 2026.7.0` because it uses `Duration::from_hours`. | Use Rust 1.93.0 on the specified Linux/WSL2 platform. The Commonware selection remains `2026.7.0`; no dependency decision changed. |
| Alto's deploy command treats an absolute `--output` as relative. | This is an Alto CLI quirk only. Reproduction uses a relative path; Rachet neither vendors Alto nor inherits this CLI. |
| Alto uses authenticated discovery and BLS threshold Simplex. | Alto remains a wiring reference. Rachet probes directly prove the fixed `authenticated::lookup` and Ed25519/RoundRobin choices from sections 4 and 19. |
| Cargo initially selected five transitive Commonware support crates at `2026.7.1`. | The final lock explicitly resolves those crates to `2026.7.0`, matching Alto's locked Commonware graph. The smoke test prevents silent drift. |
| `RoundRobin`'s hasher is not inferred from `SimplexConfig`. | The concrete configuration spells `RoundRobin::<Sha256>`. This is a type-annotation requirement, not a leader-election change. |
| `Recipients::One` feedback reports local queue submission even when a key has no live authenticated path. | Unknown-peer rejection is tested through outsider `Recipients::All` established-path feedback and authenticated receives. No authorization claim is inferred from local submission feedback. |
| Current QMDB requires the concrete `Location<mmr::Family>`, public `merkle::full::Config` path, and direct `commonware_parallel::Sequential`; several methods are trait-provided. | The probes use those concrete release APIs and import the required codec, cryptography, runtime, database, supervisor, and certificate-verifier traits. Sections 18 and 19 describe behavior rather than conflicting concrete Rust signatures, so no fixed decision changes. |
| Actor feedback exposes `accepted()`, not `is_accepted()`. | Tests use `Feedback::accepted()`; the specification does not prescribe the method name. |
| Runtime `Supervisor::stop` is runtime-global; the public simulation lifecycle stops one validator by aborting its root `Handle`. | Global authenticated-network teardown proves bounded graceful actor/socket shutdown. The restart probe exercises the stricter abrupt node-stop boundary, reuses persisted storage without repair, and catches up through marshal/Stateful/QMDB. “Clean shutdown and restart” is therefore covered across the two public API boundaries rather than by a nonexistent subtree supervisor. |
| The manifests enable Commonware `mocks`/`test-utils` features. | These features expose deterministic keys and the public simulation harness. The tested consensus, lookup/simulated P2P, broadcast, marshal, resolver, Stateful, and QMDB actors are real Commonware components; no substitute implementation is used. |
| The spec names a workspace-level `tests/commonware_smoke.rs`. | Rust workspace roots do not discover integration tests. The deliverable is placed at `crates/chain/tests/commonware_smoke.rs`, where `cargo test --workspace` executes it. |

The initial Prometheus HELP-line match, formatting failures, missing trait imports,
and a Rust borrow error were probe-implementation defects, not Commonware/spec
mismatches. They were corrected before evidence was accepted; retained artifacts
contain the failed and successful commands.

### Evidence

Durable command output is stored under `.ldgr/artifacts/`:

- `spike-001-alto-build.txt` — expected Rust 1.90.0 failure;
- `spike-001-alto-build-rust-1.93.txt` — successful locked workspace build;
- `spike-001-alto-generate.txt` — actual four-validator generation command;
- `spike-001-alto-four-node-run.txt` — corrected live validation transcript;
- `spike-001-alto-metrics-run2-34001.txt`, `-34003.txt`, `-34005.txt`, and
  `-34007.txt` — final Prometheus snapshots;
- `spike-001-alto-validator-logs-run2/` — one runtime log per validator.

## Deterministic-runtime actor replay probe

**Status:** pass on WSL2/Linux with Commonware `2026.7.0` and Rust 1.93.0.

The normal workspace suite now runs
`crates/chain/tests/commonware_smoke.rs`. The test uses the real
`commonware_runtime::deterministic::Runner` and a bounded
`commonware_actor::mailbox`; it does not substitute a runtime or actor mock.
Two producer tasks submit events to one mailbox-driven actor under declared seed
`0x524143484554`. Two independent runners must produce the same explicit event
trace and Commonware runtime audit, and both are locked to these observed values:

```text
event_actor:alpha:0
event_actor:beta:0
event_actor:beta:1
event_actor:alpha:1
event_actor:alpha:2
event_actor:beta:2
event_actor:stop
runtime_audit=10f5d4043127419f2beb59158c7817998de636824d9ecc33f07cfa2694a1978e
```

This confirms the selected release's seeded task scheduling, simulated clock,
actor mailbox, and runtime auditor replay consistently for the bounded
Milestone 0 probe. No Commonware API mismatch was found. Validation output is
stored in `.ldgr/artifacts/spike-002-validation.txt`.

## Authenticated lookup P2P probe

**Status:** pass on WSL2/Linux with Commonware `2026.7.0` and Rust 1.93.0.

The `authenticated_lookup_four_peer_exchange_rejects_unknown_and_stops_cleanly`
test in `crates/chain/tests/commonware_smoke.rs` runs five real
`commonware_p2p::authenticated::lookup::Network` instances over the Tokio
runtime's loopback TCP transport. Four deterministic Ed25519 identities form the
fixed committee at peer-set index 0. Their loopback addresses are allocated once
before startup and supplied directly to every committee oracle; no discovery or
simulated P2P implementation is used.

Each committee member sends its identity payload on channel 7 to the other
three members. Connection retries are capped at 100 per peer, receives have a
10-second deadline, the channel backlog is 512 messages, and payloads are capped
at 1 KiB. Every receiver must observe all three distinct authorized senders and
must match each authenticated sender key to the payload.

A fifth validly signed Ed25519 identity knows the committee addresses but is
absent from every committee directory. Across 30 bounded attempts its
`Recipients::All` submissions have no established recipient, demonstrating
that the committee rejects the unknown identity during authenticated lookup
connection establishment.

Shutdown uses the Commonware supervisor signal with a five-second bound. All
five lookup network handles must return cleanly, the runtime reports zero tasks
under the lookup-peer supervision prefix, and every listen address must be
immediately bindable again after the runner exits. No lookup API difference
from sections 4 and 19.6 was found. The previously recorded Rust 1.93.0
requirement still applies because `lookup::Config::local` reaches the pinned
P2P crate's `Duration::from_hours` use.

## Empty Simplex chain probe

**Status:** pass on WSL2/Linux with Commonware `2026.7.0` and Rust 1.93.0.

The `four_node_ed25519_round_robin_simplex_finalizes_matching_empty_chain` test
in `crates/chain/tests/commonware_smoke.rs` starts four real Simplex engines in
one deterministic runtime. Each engine owns a deterministic Ed25519 private key
and constructs
`commonware_consensus::simplex::scheme::ed25519::Scheme` from the same ordered
four-member committee. Leader selection is explicitly
`commonware_consensus::simplex::elector::RoundRobin<Sha256>`; the probe performs
no DKG, threshold-signature, or BLS setup.

The four engines exchange pending votes, recovered certificates, and resolver
traffic over `commonware_p2p::simulated`, with a fully connected 5 ms link
matrix and no message loss. This is Commonware's real deterministic laboratory
network component, not a consensus or P2P mock. The preceding authenticated
lookup probe separately covers the fixed live-network transport boundary.

The minimal application has no block body. Its SHA-256 payload commits to an
empty-block namespace and the Simplex consensus context, so every node can
independently verify the proposal without a block-distribution side channel.
Certification always uses the `CertifiableAutomaton` default. A custom reporter
records only real Simplex finalization certificates. The test waits until all
four reporters contain at least 100 finalizations, compares the first 100
`(view, parent, payload)` entries exactly, and checks that every parent is the
previous finalized view. The observed run finalized 100 matching, gap-free
empty blocks on all four nodes.

No Commonware API mismatch from sections 19.1-19.2 was found. Rust required an
explicit `RoundRobin::<Sha256>` spelling at the configuration site because the
default generic hasher was not inferred from the surrounding `SimplexConfig`.
Targeted validation output is stored in
`.ldgr/artifacts/spike-004-targeted-validation.txt`.

## Stateful, Deferred, and current-QMDB fork probe

**Status:** pass on WSL2/Linux with Commonware `2026.7.0` and Rust 1.93.0.

The
`stateful_deferred_commits_winner_and_prunes_dead_current_qmdb_fork` test in
`crates/chain/tests/stateful_qmdb.rs` wires one real
`commonware_storage::qmdb::current::unordered::fixed::Db` into
`commonware_glue::stateful::Stateful`. It uses the MMR family, SHA-256 keys and
fixed values, a 32-byte current-state bitmap chunk, `TwoCap`, and
`commonware_parallel::Sequential`. `Stateful::init` creates the database from a
`current::FixedConfig`; no in-memory database or storage mock substitutes for
QMDB.

The test also initializes the real standard marshal actor with immutable
archives, its P2P resolver over Commonware's simulated network, and a real
Ed25519 Simplex scheme. `SyncPlan::init` and `SyncPlan::marshal_start` give
marshal and Stateful the same genesis decision. A real QMDB standard resolver
is attached through `stateful::db::p2p::standard::Actor`. The integration shape
is then:

```text
marshal::standard::Deferred::new(
    deterministic context,
    Stateful mailbox,
    marshal mailbox,
    FixedEpocher,
)
```

The application implements `commonware_glue::stateful::Application` over one
`Arc<TracedAsyncRwLock<CurrentQmdb>>`. Its `propose` and `verify` methods mutate
an unmerkleized batch, call `stateful::db::Unmerkleized::merkleize`, and commit
both the resulting canonical current-state root and the QMDB replay-sync target
(`ops_root` plus the range from `sync_boundary` to `bounds.total_size`).
`sync_targets` returns that target, and `apply` deterministically replays the
same mutation.

Two height-one siblings write distinct values to the same key and produce
distinct canonical roots. A child is successfully built from the losing
sibling before finalization, proving Stateful retained branch-local speculative
batches rather than mutating committed QMDB state. Both siblings pass the
actual `Deferred::verify` optimistic stage and `Deferred::certify` application
gate after marshal persists them with `Mailbox::verified`.

Finalization is delivered through `Deferred`'s `Reporter` implementation as
`marshal::Update::Block` with an `acknowledgement::Exact`. Stateful acknowledges
only after applying the winning merkleized batch. The attached current QMDB
then contains the winning value and its canonical root exactly matches the
winning block. A proposal against the persisted losing parent succeeds before
finalization but returns `None` after finalization. Because marshal can still
supply that parent, this rejection is specifically the observable consequence
of Stateful removing the dead branch's pending batch at finalization rather
than a missing-block artifact. The losing value never reaches committed QMDB
state.

No API mismatch from spec sections 18 or 19.3 was found. The concrete release
APIs exercised are `SyncPlan::{init, marshal_start}`, `Stateful::init`,
`Mailbox::{propose, subscribe_databases}`, `Deferred::{new, verify, certify}`,
`Reporter::report(Update::Block)`, `DatabaseSet::initial_sync_targets`,
`Unmerkleized::merkleize`, `CurrentMerkleized::{root, ops_root,
sync_boundary}`, and current QMDB `get`/`root`. Validation output is stored in
`.ldgr/artifacts/spike-005-targeted-validation.txt` and
`.ldgr/artifacts/spike-005-validation.txt`.

## Shutdown, restart, and missing-ancestry catch-up probe

**Status:** pass on WSL2/Linux with Commonware `2026.7.0` and Rust 1.93.0.

The
`stopped_node_reopens_persisted_storage_and_backfills_missing_ancestry` test in
`crates/chain/tests/restart_catchup.rs` runs four real Ed25519/RoundRobin
Simplex validators through the public `commonware_glue::simulate` lifecycle.
The harness is enabled only as a test utility; the node definition itself uses
real simulated P2P channels, buffered broadcast, Simplex, standard marshal with
`Deferred`, the P2P marshal resolver, `Stateful`, the standard QMDB resolver,
and one current QMDB database per validator. It contains no mock consensus,
marshal, Stateful, resolver, or storage component.

At deterministic time 1.5 seconds the schedule stops validator 0 while the
other three validators retain quorum and continue finalizing. At 5 seconds it
restarts the same identity and stable partition names. On the recorded seed,
marshal reopened an application-acknowledged persisted frontier at height 31
while the live peers had reached height 74. The 43-block gap exceeds the
buffered broadcaster's deliberately bounded two-block cache, so the restarted
marshal cannot catch up from current broadcasts alone: it resolves the missing
finalized blocks over its real targeted P2P backfill channel. `Stateful` then
replays the recovered blocks through `Application::apply`, commits and
acknowledges the current-QMDB batches, and advances marshal's processed height.
All four validators processed at least height 60 after restart and the harness
observed one block digest at that height.

The reused `SyncPlan`, marshal archives, cache/stream partitions, Simplex
journal, and current-QMDB partitions are opened without deletion, copying, or
manual repair. Recovering persisted height 31 proves that the stopped node's
acknowledged storage remained reusable; reaching the common post-restart height
proves that missing ancestry and QMDB application replay completed before the
exit gate passed.

The pinned runtime exposes `Supervisor::stop` at runtime scope, not as a
validator-subtree graceful-stop token. Commonware's public simulation lifecycle
therefore implements node-scoped stop/restart by aborting the validator's root
`Handle` and preserving deterministic-runtime storage. This probe exercises
that stricter abrupt-stop boundary; the authenticated lookup probe above
separately exercises the runtime-global graceful supervisor signal and confirms
that all actor handles and sockets close within a bound. This API shape is an
observed terminology difference from the specification's “clean shutdown,” not
a substitution of a mock path.

Targeted validation output, including the persisted and peer heights, is stored
in `.ldgr/artifacts/spike-006-targeted-validation.txt`.

## Deterministic simulated-P2P fault controls

**Status:** pass on WSL2/Linux with Commonware `2026.7.0` and Rust 1.93.0.

The laboratory surface in `crates/lab/src/simulator/p2p.rs` runs declared fault
and traffic schedules directly through `commonware_p2p::simulated` inside a
seeded `commonware_runtime::deterministic::Runner`. Directed link replacement
controls latency, jitter, and drop probability. Topology reconciliation removes
and restores real Commonware links for disconnect/reconnect and bipartition/heal
actions. Same-seed submissions, authenticated deliveries, delivery times, and
the settled runtime audit replay exactly in the integration tests.

The pinned simulated network supports a corrupted peer sending arbitrary bytes
under that peer's authenticated identity. It does **not** expose identity
spoofing, unauthenticated injection, or in-flight payload mutation. The lab
therefore exposes the supported arbitrary-payload action and a machine-readable
`UNSUPPORTED_CORRUPTION_MODES` list; it does not emulate the unavailable modes
with a second transport or silently relabel ordinary sends as those faults.

The six tests in `crates/lab/tests/simulated_p2p_faults.rs` cover deterministic
latency replay, seeded jitter, full message drop, disconnect/reconnect,
partition/heal, and attributed arbitrary corrupted-peer payloads. Full debug and
release workspace evidence is stored in
`.ldgr/artifacts/lab-007-validation.txt`.

## Ordered-variable QMDB resolver codec mismatch

**Status:** adapted locally for the exact Commonware `2026.7.0` release family.

The packaged `commonware_glue::stateful::db::p2p::{standard,compact}` actors
require the QMDB operation type to implement `commonware_codec::Codec<Cfg =
()>`. Rachet's section 17 schema uses
`qmdb::current::ordered::variable`, whose operation codec correctly requires
bounded key/value `RangeCfg` values and therefore cannot satisfy that equality.
This is a compile-time API mismatch, not a missing package or version mismatch;
the exact dependency pins and `Cargo.lock` remain unchanged.

`crates/chain/src/engine/variable_resolver.rs` is the narrow adapter. It carries
the real ordered-variable QMDB operations and Merkle proofs over the dedicated
authenticated committee channel, decodes them with the same explicit non-empty
key and bounded value configuration used by QMDB, and implements Commonware's
`qmdb::sync::resolver::Resolver` and Stateful `AttachableResolver` interfaces.
Marshal block repair continues to use
`commonware_resolver::TargetedResolver` directly. No mock or alternate storage
component is selected on the live path.
