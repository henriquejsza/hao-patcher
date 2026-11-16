# Building an image

The base is macOS 27.2.1 (26B131), with Tahoe 25G342 as the donor; the 27.0 (26A428) assembly
`mbp92-golden-first.json` is older and no longer maintained. Tahoe supplies only the donor files
the inputs list.

## Requirements

- Apple silicon Mac, Xcode command-line tools, Python 3.14. The image is 80 GiB and the
  workspace 160 GiB, both sparse.
- Builder VM: [`tools/ssdvm`](../tools/ssdvm/README.md), `pipeline/vm/`. All formatting, APFS
  writes and kernel-collection builds run in it, never on the host. Build the launcher with
  `tools/ssdvm/build.sh store/vm/bin`; each build runs in an APFS clone of the VM at `store/vm/base`
  (made with `ssdvm install`, see its README; `pipeline/vm/clones.py` provisions each clone). Provisioning drives the
  clone's screen with `pipeline/vm/vmctl`, which needs Pillow and cryptography in `store/cache/vmctl-venv`
  (`python3.14 -m venv store/cache/vmctl-venv && store/cache/vmctl-venv/bin/python3 -m pip install pillow cryptography`;
  `VMCTL_PYTHON` names another).
- Inputs from [Build inputs](inputs.md).

## 1. Prepare the inputs

1. Download the [archives](inputs.md#downloads) and check their SHA256.
2. Build the [prepared inputs](inputs.md#prepared-inputs) with their tools (e.g.
   [`tahoe-donors`](../tools/tahoe-donors/README.md),
   [`oclp-hardware`](../tools/oclp-hardware/README.md)).
3. Point the rows in `pipeline/inputs/` at them ([Input rows](inputs.md#input-rows)).

### From a release

A release (`release.json` on [hao-assets](https://github.com/lythka/hao-assets/releases)) pins every input:

```sh
python3.14 -I tools/hao/hao fetch release.json --cache FETCH      # downloads and assets, each by size and sha256
python3.14 -I pipeline/place release.json FETCH                     # into store/, each row checked
python3.14 -I tools/hao/hao build-image REPO --model MacBookPro9,2 --assembly ASSEMBLY   # release.json "assembly"
```

`place` lists what is still missing: the rows in `made_on_mac` (made from Apple's files by their producers; the
ones that read the IPSW cannot run from a release yet) and the harvested caches (optional, skipped). Pass the
release's `assembly`: without it build-image takes the target's default assembly.

`plan` prints a set's run order and every input it needs:

```sh
python3.14 -I pipeline/patches.py plan pipeline/sets/golden-gate-26B131.txt pipeline/targets/mbp92.json 25G342 \
  --locks pipeline/inputs/golden/26B131:pipeline/inputs/25G342:pipeline/inputs/common   # 26B131, as golden-run looks up rows
```

### Optional cache recipes

`golden-gate-shader-caches`, `golden-gate-icon-caches`, `golden-gate-font-registry` and
`golden-gate-user-template` install caches and templates made by [`cache/seeds`](../cache/seeds/README.md) from a
harvest of a running laptop; `golden-gate-user-seed` copies their per-user parts into new accounts. Their patch.json has
`"optional": "caches"`. Without these files the image still builds; first boot and each new
account's first login are slower.

- A cache recipe whose input row is missing, or whose `store/` path is not there, is skipped
  with one line naming the recipe and the row. A row that is there but fails its SHA256 stops
  the build.
- `golden-gate-user-seed` (`"needs_any": "caches"`) is skipped when no cache recipe runs.
- To leave them out even when the files exist: `golden-run --skip-optional caches`, or
  `"skip_optional": ["caches"]` in the assembly.
- `store/runs/<job>/optional.json` (and `optional` in `build.json`) lists which ran and which
  were skipped, and why.

## 2. Build

```sh
python3.14 -I pipeline/golden-run pipeline/assemblies/mbp92-26B131.json --repo /path/to/image-repository
```

The [assembly](../pipeline/assemblies/mbp92-26B131.json) selects target, OS and donor
builds, image sizes, donor rows and the patch set.

Before writing anything, `golden-run`, `hao build-image --here`, `tools/qemu-vm` and the builder VM's start check the
free disk space (`pipeline/diskguard.py`): a build needs about 175 GB (staged inputs ~82 GB, the workspace ~66 GB, the
image commit ~23 GB; an assembly can say more with `disk_need_gb`), a kit alone 90 GB, a QEMU run the size of the disks
it boots, and each refuses when it would leave less than 150 GB free (`HAO_DISK_FLOOR_GB`). `HAO_DISK_CHECK=COMMAND`
hands the decision to a host-wide guard (`COMMAND check --need GB --who NAME --what TEXT`, exit 3 = refused).

`golden-run` (also with `--stage-kit`, which the stick's kit comes from) and `release-cut --write` refuse to start
while a live swap proven on a laptop has no resolution. The swapper records the proof when a bench pass or the owner
shows the swap works: `python3.14 -I pipeline/swaps.py proven LAPTOP-PATH --evidence "bench ITEM"` (or
`"owner: THEIR WORDS"`), which adds a `proven` line to the swap ledger. The refusal names each path, its sha256, who
swapped it and who proved it. It is resolved by a line in `pipeline/live-swaps.tsv` (`recipe NAME`, `row NAME`, or
`dropped: WHY`); there is no override. `swaps.py status` lists every swap (`OPEN`, `PROVEN-OPEN`, `resolved`).

The VM runs the same `pipeline/stages/golden-assemble.sh` that `hao install` runs in the target's Recovery.
That Recovery (Tahoe 25G342) has fewer commands than a full macOS. The ones it has are listed in
`pipeline/stages/recovery-commands-25G342.txt`. `install`, `shasum`, `cmp` and `readlink` are missing, and the
kit's `recovery-tools.py` stands in for them. `rsync` is missing too, so the assembly uses `ditto`.
`pipeline/tests/test_recovery_commands.py` checks every command the install path runs against that list.
`golden-run --recovery-commands` builds in the VM with only those commands on PATH, as the stick's install does.
The assembly also holds a sleep assertion for its whole run (`caffeinate`, or `recovery-tools.py awake`).
Copies onto the FAT ESP carry data only (`FAT_COPY` in `golden-image.py`: `ditto --norsrc --noextattr --noacl`):
the Recovery runs no `doubleagentd`, which keeps a FAT volume's extended attributes, so a copy with attributes fails
there. `pipeline/tests/test_fat_esp.py` runs those copies on a real FAT32 disk image, with only the Recovery's
commands on PATH (`HAO_TEST_KIT=KIT` adds a staged kit's ESP).

The Recovery cannot link the kernel collections: its `kmutil` links a kernel-only collection for the target volume
(it reads none of its kexts). So a builder VM build stores the Boot and System collections it linked in
`store/cache/kc/KEY/` ([`prelinked_kc.py`](../pipeline/prelinked_kc.py): KEY covers the input rows and sources that
shape System up to `darwin27-kernel`). `golden-run --stage-kit` copies the entry with the kit's key into the kit's
`darwin27-kernel` hook folder (`prelinked/`), and the hook checks each file's sha256 and installs them instead of
linking. `hao create-installer` refuses a kit without them: build the image once in the VM first. Producing them
without the VM is open (see the VM-free build plan).

The Recovery mounts the stick's HAO volume `noowners`, so every file the install copies from the kit arrives owned
by `_unknown` (99:99). `golden-image.py` gives such files root:wheel after the base layers, the recipes and the
posts, and records the counts in `build.json` `owners_fixed`. kmutil refuses kexts with those owners, which is why
the Recovery linked a kernel-only collection before. In the builder VM there are none.

A failed assembly can continue at its failed step, on the same disk, when that step can run again over what the
failed attempt left (`RESUMABLE` in `golden-image.py`: `boot-and-esp` and `hardware`):
`golden-image.py CONFIG --resume WORK`, `golden-assemble.sh ... --resume WORK`, or
`hao install /dev/diskN --resume /Volumes/HAO/hao-install-DATE` (confirmed with RESUME, not ERASE). It finds the
volumes again by their UUIDs, refuses a kit whose configuration differs (set, target, inputs; the files a
kit carries are not compared), and skips nothing that did not complete. The record's `resumed`
names the run it continued.

### Layer order

Defined by `LAYERS` in [`golden-image.py`](../pipeline/stages/golden-image.py). Each layer goes
on top of the previous ones. Layers 1–6 are the same for every set.

| # | Layer | Adds | Why |
|---|---|---|---|
| 1 | `layout` | Raw image, GPT, APFS container, System volume | |
| 2 | `golden-system` | macOS 27 System from `filesystem.dmg` | Copied while System is the only volume, so APFS keeps its identity |
| 3 | `group-volumes` | Data, Preboot, Recovery, VM; ESP mounted | |
| 4 | `golden-finalize` | 27's Data template and firmlinks; Tahoe and KDK Intel kexts; Darwin 27 x86_64 kernel; Tahoe native roots | 27 has no Intel kexts and lacks some x86_64 code. Later layers read the kernel |
| 5 | `boot-and-esp` | Tahoe Intel Preboot/Recovery files; OpenCore ESP (`build-efi.py`) | 27 has no Intel boot files |
| 6 | `hardware` | OCLP overlay: HD 4000 Metal/OpenGL, wireless, audio | Checks the kernel's Darwin version |
| 7 | `recipes` | Each `oclp-hook` entry's `src/kc-hook.sh` (or, with `--from-overlays`, its files from the overlays), in set order, System writable | |
| 8 | `snapshot` | Preboot update, bless, System snapshot | |
| 9 | `posts` | Each `post` entry's `apply.sh`, in set order, System read-only | |
| 10 | `efi-bundle` | Final ESP and manifest | |

The donor artifact decides which frameworks the Tahoe native roots replace. The 26B131 one
keeps 27's Metal, OpenCL, AppleGVA(Core), GPUCompiler, MTLCompiler, IO80211 and
WiFiPeerToPeer. The 26A428 one installs Tahoe's.

In layer 7, `darwin27-kernel` links the Boot and System KCs (the record keeps the BootKC);
`golden-gate-userspace` builds the OS cryptex (with the code identity carrier in the x86_64 cache's
Security.framework) and installs the Wi-Fi compat libraries and the display shim;
`golden-gate-native-identities` runs last, after every recipe that re-signs a program ad hoc, and
lists those programs with their Apple originals for the carrier. Recipes get `TAHOE_DRIVERKIT_ARTIFACT`,
`TAHOE_DONOR_TOOL` and `TAHOE_NATIVE_ARTIFACT` from the runner. Each set entry has a comment saying
what it adds and why.

The sealed OS and App cryptex images are kept between builds in `store/cache/cryptex` (the two newest, about 13 GB
each). Their key covers the rows they are made from, the code that makes them and the builder's APFS tools
([golden-gate-userspace](../patches/golden-gate-userspace/README.md), "Cryptex cache"); a build with the same key
copies them (sha256-checked) instead of rebuilding. `build.json` `cryptex_cache` says `hit`, `miss` or `stored`;
`--no-cryptex-cache` always builds them.

`golden-run` refuses a set unless:
- the first two entries are `darwin27-kernel`, then `golden-gate-userspace` (later recipes
  edit their output);
- no recipe uses `src/hook.sh`;
- no `oclp-hook` entry follows a `post` entry.

### Installing from the overlays (opt-in)

```sh
python3.14 -I pipeline/golden-run pipeline/assemblies/dev-26B131.json --repo /path/to/image-repository \
  --from-overlays --overlay-system /path/to/golden-gate-fs
```

`--overlay-system` is the build's Golden Gate file system (its `filesystem.dmg` attached read-only): the edits
start from its files. Before the VM starts, the host materialises the set
([`materialize.py`](../pipeline/materialize.py); the edit-engine store is kept in `store/cache/edit-engine-store`,
`--overlay-store` to change it) and [`overlays.py`](../pipeline/overlays.py) plans, in set order, which recipes
install their files from the overlays instead of running their hook or `apply.sh`: those whose every declared
file was made on the host. A recipe with anything made on the target (kernel collections, the cryptex, HaoExec's
stamp, `kc.bind`, generated records, native-identities), without declarations, or writing a file before such a
recipe edits it, runs its hook as before. `--overlay-hook NAME` keeps one more on its hook. The guest installs
each recipe's files at its turn ([`golden-overlays.py`](../pipeline/stages/golden-overlays.py)): staged sha256
checked, the file an edit starts from checked, mode, owner and flags (and a tar member's mtime) as the manifest
says. The build record keeps `overlay-plan.json`, `overlay-report.json` and the timings (`build.json`
`overlays`). Without the flag nothing changes.

Before trusting such a build, compare it with a hook build of the same commit (`pipeline/overlays.py tree` on
each image's volumes, mounted read-only, then `overlays.py compare`): only signature-only differences (files
signed on the host have other CDHashes), native-identities' observed CDHashes, and what differs between two hook
builds anyway may remain.

### Output

The guest detaches the image. The host mounts the stopped VM's workspace read-only and commits
the image with [`ssdimg`](../tools/ssdimg), with no copy through the shared folder.

With `hao-opencore` in the set, `boot-efi.zip` sits beside `image.json`. It holds the final ESP,
a manifest of model, OS build, KC and every EFI file, and the OpenCorePkg and OCLP license texts
(`LICENSES/`). Install it after restoring the matching image. Don't regenerate a stock OCLP EFI instead: it drops the OpenCore additions.

If export was interrupted, resume with `golden-run --capture-record RECORD`. This needs a
successful assembly record and a stopped VM.

| Location | Contents |
|---|---|
| `--repo` | Image repository |
| `store/runs/` | Build record: inputs, plan, optional recipes run/skipped, source identities, logs |
| `store/tmp/` | Workspace and intermediate disks |

Boot the image in [QEMU](../tools/qemu-vm/README.md) before installing it on hardware.

## Recovery

`pipeline/recovery TARGET BUILD recovery` builds the offline Recovery from the Tahoe BaseSystem
and a root-patched System; the `rec-*` recipes add hardware support and the installer. The
System comes from a `stock` image, which only the legacy Tahoe-first runner `pipeline/run`
builds. That is the only reason the legacy runner is kept.

## Tests

The host tests use fixtures and start no VM:

```sh
python3.14 -I -B -m unittest discover -s pipeline/tests
python3.14 -I -B -m unittest discover -s tools/tahoe-donors/tests
python3.14 -I -B -m unittest discover -s tools/oclp-hardware/tests
```

Other suites: [CONTRIBUTING.md](../CONTRIBUTING.md).
