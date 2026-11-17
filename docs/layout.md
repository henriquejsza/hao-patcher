# Recipe layout: OS layer, platform packs, dev

Every recipe belongs to one pack, every pack to one layer, and an image's patch list is generated from one build
order and a profile. A new Mac or GPU adds a pack and its recipes; no hand-made list is edited.

## Layers

| Layer | Holds | Selected by |
|---|---|---|
| **os** | what any Intel Mac running this macOS build needs: the Darwin 27 kernel and its repairs, the hao runtime and the `hao` command, the userspace cryptex, dyld, launchd, identities, the per-build caches and seeds (pack `base`; opt-in pack `os-extras`; the installer's Recovery: pack `recovery`) | always for that build (`base`), or by name in a profile (opt-in packs) |
| **platform** | one hardware family each, with a `kind`: GPU (`intel-hd4000`, `metal-3802`), Wi-Fi (`wifi-broadcom-modern`), audio (`audio-modern`), CPU, model (`mbp92`: OpenCore config, board, early kexts), the model's Recovery drivers (`recovery-mbp92`) | the pack's `detect` (OCLP patch sets, board id) on the target, as `hao detect` reads it |
| **dev** | test-image-only recipes (SSH, measurement, no sleep) | by name only |

## Declarations

- `patches/NAME/patch.json` has `"pack": PACK`, exactly one. A recipe's machine scope is its pack's detection;
  `applies` names only the macOS builds it is written for (`"builds"`) or `"any"`.
- `packs/PACK.json` has `"layer"` (`os`, `platform`, `dev`); a platform pack also `"kind"` and `"platform"`
  (`apple-intel`). A pack lists no recipes: `pipeline/patches.py` collects them from the recipes' `pack`.
- A variant recipe has `"variant": NAME` and may have `"replaces": RECIPE` of the same pack (e.g. `hao-runtime-fold`
  replaces `hao-runtime` in variant `cache-fold`).
- `patches/` stays flat: the layer is declared, not encoded in the path.

## Sets are generated

- `pipeline/order.txt` lists every image recipe once, in build order, each with the reason for its position.
- `pipeline/profiles/NAME.json` says what an image is: `target` (a `pipeline/targets/*.json`), opt-in `packs` and
  single opt-in `recipes` by name, and `variants`.
- The set = `order.txt` filtered to the packs the target detects, the profile's named packs and recipes, and its
  variants (each replacing the recipe it names). `pipeline/patches.py set PROFILE` prints it. golden-run,
  `hao build-image`, release-cut and `patches.py plan` take a set name and read its profile when there is one; the
  hand sets that remain (`pipeline/sets/`: the legacy runner sets, the bootstrap and 26A428 sets) are read as files.
- Each profile generates exactly its former set file (`pipeline/tests/test_layout.py`).

## Checks

`pipeline/patches.py check` refuses a recipe without a pack, a pack without a layer (a platform pack without its kind
and platform), a pack that lists recipes, an image recipe missing from `order.txt` or listed twice, a variant that
replaces a recipe of another pack, and a profile that does not generate. `patches/TRACKER.md` and `docs/PATCHES.md`
are regenerated from the declarations.

## What a new Mac or GPU adds

- **Another Intel Mac with a supported GPU**: `pipeline/targets/NAME.json`, its OCLP hardware profile
  (`tools/oclp-hardware/profiles/NAME.json`) and a model pack (`packs/NAME.json`, kind `model`: board id, its OpenCore
  config recipe, early kexts). The OS layer comes unchanged; GPU, Wi-Fi and audio packs come from detection.
- **Another GPU**: a platform pack of kind `gpu` with its `detect` and its recipes, each with `"pack"` and a line in
  `order.txt`.
- **Another macOS build**: rows under `pipeline/inputs/golden/BUILD`, `applies.builds` widened on the recipes that
  carry over, and the per-build data (caches, seeds, metallib repairs) remade as rows.
