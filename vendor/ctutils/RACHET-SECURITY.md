# Rachet security backport

This directory contains the published `ctutils` 0.3.2 source from
RustCrypto/utils. Rachet changes one dependency requirement:

- `cmov = "=0.5.0-pre.0"` becomes `cmov = "=0.5.4"`.

The change removes versions affected by
[GHSA-3rjw-m598-pq24](https://github.com/advisories/GHSA-3rjw-m598-pq24), an
AArch64 correctness vulnerability in `Cmov` and `CmovEq`. `ctutils` 0.3.2 was
already migrated to the `cmov` 0.5 API, so no Rust source changes are needed.

The patch remains necessary while Commonware 2026.7.x requires `ctutils`
0.3.x. Remove it once the exact Commonware compatibility boundary advances to
a release that resolves `ctutils` 0.4.x and `cmov` 0.5.4 or newer directly.

Upstream source: <https://crates.io/crates/ctutils/0.3.2>

Upstream revision: `a357620b8a109753daffd53a2f5bec193cc7547d`

License: Apache-2.0 OR MIT (upstream license files are preserved here).
