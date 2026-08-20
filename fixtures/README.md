# H-REP-001 validation fixtures

The corpus has three independently integrity-bound partitions:

- `jobs-public/{smoke,calibration,formal}` contains the only fixture data exposed to validation operators. Each `manifest.json` hashes its public fixture definitions and every definition hashes its specification, public artifacts, and real Git commit pair.
- `repositories/<fixture-id>` contains one real Git repository per case, checked out at its candidate commit.
- `ground-truth-private/{smoke,calibration,formal}` contains evaluator-only labels and reproduction evidence. Its exact `manifest.json` hash is published as `jobs-public/<set>/private-manifest.sha256` without exposing truth.

Operator processes must receive capabilities only for the selected public partition and `repositories`; they must never receive the workspace root or `ground-truth-private`. The public loader API cannot name or enumerate the private root. The experiment evaluator receives the private root separately after operator decisions close.

Calibration and formal fixture IDs, repositories, base commits, and candidate commits are disjoint. Each partition contains all nine section 35 fixture classes. The formal partition is held out: do not expose it during smoke or calibration.

Rebuild the deterministic corpus with:

```sh
python3 tools/generate_hrep_fixtures.py
```
