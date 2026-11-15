# golden-gate-shared-cache-catalog

The B+catalog image of the shared-cache fold-in: [golden-gate-shared-cache](../golden-gate-shared-cache/README.md)'s
fold, unchanged, with the family built with runtime-perf's catalog of 320 Swift records instead of family B. Only
`pipeline/sets/dev-bs-test-fold-catalog.txt` has it, in the place golden-gate-shared-cache has in dev-bs-test-fold.
It exists because a set picks recipes, and a recipe names its rows: the two families need two rows.

## Input

`rebuilt_cache_catalog` (`pipeline/inputs/25G342/`): rebuilt-cache-fold-in-catalog-26B131-20261114-86dd72e (cache
UUID b3c88154), from the same generator commit, System view, roots and provider bytes as family B.

## How it works

`make.sh` stages golden-gate-shared-cache's `src/fold.py` and `src/providers.txt` as `build/fold`, and runs that
recipe's own `make.sh` into `build/fold/build` (golden-gate-userspace's code). `src/kc-hook.sh` runs
`build/fold/fold.py install` on `inputs/rebuilt_cache_catalog`. Every step, gate and record is golden-gate-shared-cache's.
A change to that recipe's code reaches this one at the next build without a revision here.

## Verify

- `python3.14 -I -B -m unittest discover -s patches/golden-gate-shared-cache-catalog/tests`: the hook and its row; the
  staged fold is golden-gate-shared-cache's byte for byte and finds its staged userspace.
- The base recipe's suite reads this row's artifact too.
- Build log and image: as golden-gate-shared-cache, with this row's artifact.

## Validation

NEEDS VALIDATION: not built or booted. Host tests only. The set waits on row `hao_runtime_fold`; whether this
family's cache UUID needs its own payload is open (see the B recipe's Validation).

## Revisions
- r1 2026-11-15 New: golden-gate-shared-cache's fold on the B+catalog family (row rebuilt_cache_catalog), for set dev-bs-test-fold-catalog.
