# hao-runtime-fold

[hao-runtime](../hao-runtime/README.md)'s installation for the shared-cache fold-in sets (`dev-bs-test-fold`,
`dev-bs-test-fold-catalog`), in hao-runtime's place. The rebuilt cache family has its own cache UUID, and hao's
generated data names the UUID it was made for, so these images take a payload built for that family (runtime builds
it from research's generated lock for the family). The row is separate because `hao_runtime` is the payload of every
other set (and `pipeline/latest`, `swaps.py` and release-cut read that row by name).

## Input

`hao_runtime_fold` (`pipeline/inputs/golden/26B131/`): hao-runtime-26B131-20261115-96870dd3f441-B2, a payload folder as
`hao_runtime` (payload-manifest sha256 checked by the row). One payload serves both fold families: their images have
the same UUIDs. libhao and libhao_identity are `hao_runtime`'s c66997a bytes; what differs is the units (the four
libraries the fold replaces lose theirs; research's re-export-aware units for MetalOld, CoreWiFiTahoe and
IO80211Old are added) and the cache UUID in its records.

## How it works

`src/kc-hook.sh` runs the payload's own `hao-install.py` exactly as hao-runtime's hook does, on `inputs/hao_runtime_fold`.
What it installs is hao-runtime's `files` list; it is not declared again here (the fold sets are dev images).

## Verify

- `python3.14 -I -B -m unittest discover -s patches/hao-runtime-fold/tests`: the hook is hao-runtime's on this row, and
  only the two fold sets use it, in hao-runtime's place.
- On the image: `usr/lib/hao/install.json` and the payload's `build.json` name the fold family's cache UUID.

## Validation

NEEDS VALIDATION: not built or booted. The payload's own checks (in its README): units 1895/1895 matched on both
caches, 963 embedded, 965 of 969 AOT caches; one CoreWiFi record bridges without a unit and 21 Swift helper records
have no definer on B (runtime's known limits).

## Revisions
- r3 2026-11-15 Row `hao_runtime_fold`: the units set 2 payload (-B2: same hao-runtime 96870dd and libhao; 16 more B records typed). No recipe change.
- r2 2026-11-15 Row `hao_runtime_fold`: hao-runtime-26B131-20261115-96870dd3f441-B (hao-runtime 96870dd, both fold families); status experiment.
- r1 2026-11-15 New: hao-runtime's installation on row hao_runtime_fold (the payload for the fold-in family), for the two fold sets.
