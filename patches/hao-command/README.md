# hao-command

Installs the `hao` command on the Mac: `/usr/local/bin/hao`, which runs the release's `tools/hao` with a bundled
x86_64 CPython 3.12. macOS 27 has no working `python3`, so `hao` brings its own (owner, 2026-11-16: "Bundle it.").

## What it installs (Data volume)

| Path | What |
|---|---|
| `usr/local/bin/hao` | A two-line launcher: `exec /usr/local/lib/hao/python/bin/python3.12 -I /usr/local/lib/hao/hao/tools/hao/hao "$@"` |
| `usr/local/lib/hao/python/` | Input row `python_x86_64` (python-build-standalone install_only), unpacked |
| `usr/local/lib/hao/hao/` | `tools/hao` of this release without its tests, with `tools/hao/vendor` (Rich, MIT) and the notices; `make.sh` stages it |

Everything is on the Data volume, root:wheel, not writable by others, so `hao update` can replace it without
touching the sealed System.

## Verify

On the installed Mac: `hao`, `hao status`, `hao --help`.

## Validation

NEEDS VALIDATION: not yet run in an image build, a QEMU install or on a laptop.

## Revisions
- r5 2026-11-17 Declares its pack (base): recipe layout format pass; its pack decides the machines (applies.models dropped); nothing it installs changes.

- r4 2026-11-16 no du in apply.sh (the Recovery has none); in the dev, release and metal27 sets too
- r3 2026-11-16 make.sh stages from a release archive too (no .git): files on disk, VERSION from pipeline/SOURCE_COMMIT
- r2 2026-11-16 make.sh writes tools/hao/VERSION (the staged commit) for hao's version on a dev image
- r1 2026-11-16 first recipe: CPython row and tools/hao under /usr/local/lib/hao, launcher at /usr/local/bin/hao
