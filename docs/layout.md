# Recipe layout: OS layer, platform packs, dev

Proposal (not in effect yet). Goal: a recipe says which layer it belongs to, an image's patch list is generated from
the OS layer plus the packs a Mac is detected to need, and a new Mac or GPU adds a pack instead of editing hand-made
lists.

## Layers

| Layer | Holds | Scope | Selected by |
|---|---|---|---|
| **OS** | what any Intel Mac running this macOS build needs: the Darwin 27 kernel, its repairs, the hao runtime, the userspace cryptex, dyld, launchd, identities, the per-build caches and seeds | macOS build(s) (`26B131`) | always, for that build |
| **platform** | one hardware family each: GPU (`intel-hd4000`, `metal-3802`), Wi-Fi (`wifi-broadcom-modern`), audio (`audio-modern`), input, model (`mbp92`: OpenCore config, board, early kexts) | the pack's `detect` (OCLP patch sets, board id) | detection on the Mac, as `hao detect` does today |
| **dev** | test-image-only recipes (SSH, measurement, no sleep) | any | by name only (`opt_in`) |

The Recovery is a second OS (Tahoe's), with the same split: its `rec-*` recipes take the same layer fields.

## Where recipes live

`patches/NAME/` stays flat. Moving folders would break every input row, ledger line and recipe history that names a
path, for no gain the planner needs. The layer is declared, not encoded in the path:

- `patch.json` gets `"pack": NAME`, exactly one, naming a `packs/NAME.json`. It replaces both `applies.models` and the
  `recipes` lists in `packs/*.json` (one place, read by the planner, the manifest and the catalog).
- `packs/NAME.json` gets `"layer": "os" | "platform" | "dev"` and, for platform packs, `"kind": "gpu" | "wifi" |
  "audio" | "input" | "model"`. `detect`, `phase`, `oclp_patchsets` and `proven_on` stay as they are.
- `applies.builds` stays: it is the OS scope (which macOS builds a recipe is written for), on every layer.
- `pipeline/patches.py check` refuses a recipe without `pack`, a pack without `layer`, an OS-layer recipe that names a
  model, and a platform recipe without a build scope. `docs/PATCHES.md` and `patches/TRACKER.md` group by layer.

## Sets are generated

Today a set (`pipeline/sets/*.txt`) is a hand-ordered list per image. Proposed:

- **One order**, `pipeline/order.txt`: every recipe once, in build order, each line with the reason for its position
  (the comments today's sets carry: "after hao-runtime (its dyld)", "before golden-gate-native-identities"). Order is a
  property of the recipes, not of an image.
- **A profile** names what an image is: macOS build, model target, extra packs by name (dev, trials) and variants (the
  folded cache family). `hao build-image --model M` already detects packs; the profile adds the rest.
- **The set** = `order.txt` filtered to the OS layer for that build, the detected platform packs, and the named
  packs. A variant is a recipe that declares `"replaces": OTHER` (e.g. `hao-runtime-fold` replaces `hao-runtime`).
  `patches.py set PROFILE` prints it; golden-run and build-image take a profile where they take a set file now.
- The hand sets stay readable as profiles: `dev-beta-candidate-fold` = 26B131, MacBookPro9,2, `+dev-access`,
  variant `cache-fold`. The format pass is proven by generating each current set and requiring the identical list,
  then building the beta candidate from the generated set and comparing the image byte for byte.

## Recipes that mix layers

From patcher's classification of all 47 recipes (15 OS, 8 mixed, the rest one platform pack, dev or Recovery). A mixed
recipe is split into one recipe per layer before it gets a `pack`; data that varies per OS build stays a row:

| Recipe | Split |
|---|---|
| golden-gate-userspace | OS (cryptexes, dyld, code identity) / Wi-Fi (IO80211, WiFiPeerToPeer, CoreWiFi compat) / GPU (display state shim) / model (Tahoe donors) |
| hao-opencore | model (OpenCore config, ACPI, SMBIOS) / OS (kernel repairs, commpage ABI, HaoExec) |
| darwin27-kernel | OS (the kernel) / model (the kernel collections' contents) |
| golden-gate-live-text-service | OS (service start) / model (the OpenCore token) |
| golden-gate-metal-libraries, golden-gate-shader-caches | GPU recipes, with one row per OS build |
| golden-gate-shared-cache (and -catalog) | OS recipe; its row is built per platform set (it folds in the platform recipes' libraries) |

Splits and moves come in one pass with the format change, agreed with patcher (and metal for the Metal recipes), each
with an image byte-identical to the one before.

## What a new Mac adds

- **Another Intel Mac with a supported GPU** (e.g. MacBookPro10,1): `pipeline/targets/NAME.json`, its OCLP hardware
  profile (`tools/oclp-hardware/profiles/NAME.json`), a model pack (`packs/mbp101.json`: board id, OpenCore config
  recipe, early kexts). The OS layer comes unchanged; GPU, Wi-Fi and audio packs come from detection when they exist.
- **Another GPU**: a platform pack with its `detect` (the OCLP patch set name) and its recipes, each with
  `"pack"` and a line in `order.txt`. The check lists which OS-layer recipes it must not touch.
- **Another macOS build**: new rows under `pipeline/inputs/golden/BUILD`, `applies.builds` widened on the recipes that
  carry over, and the per-build data (caches, seeds, metallib repairs) remade as rows.
