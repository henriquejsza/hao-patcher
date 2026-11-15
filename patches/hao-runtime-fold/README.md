# hao-runtime-fold

[hao-runtime](../hao-runtime/README.md)'s installation for the shared-cache fold-in sets (`dev-bs-test-fold`,
`dev-bs-test-fold-catalog`), in hao-runtime's place. The rebuilt cache family has its own cache UUID, and hao's
generated data names the UUID it was made for, so these images take a payload built for that family (runtime builds
it from research's generated lock for the family). The row is separate because `hao_runtime` is the payload of every
other set (and `pipeline/latest`, `swaps.py` and release-cut read that row by name).

## Input

`hao_runtime_fold` (`pipeline/inputs/25G342/` or `golden/26B131/`): a hao-runtime payload folder, as `hao_runtime`.
Not there yet, so `status` is `unfinished`; the row commit makes it `experiment`.

## How it works

`src/kc-hook.sh` runs the payload's own `hao-install.py` exactly as hao-runtime's hook does, on `inputs/hao_runtime_fold`.
What it installs is hao-runtime's `files` list; it is not declared again here (the fold sets are dev images).

## Verify

- `python3.14 -I -B -m unittest discover -s patches/hao-runtime-fold/tests`: the hook is hao-runtime's on this row, and
  only the two fold sets use it, in hao-runtime's place.
- On the image: `usr/lib/hao/install.json` and the payload's `build.json` name the fold family's cache UUID.

## Validation

NEEDS VALIDATION: the row does not exist yet.

## Revisions
- r1 2026-11-15 New: hao-runtime's installation on row hao_runtime_fold (the payload for the fold-in family), for the two fold sets.
