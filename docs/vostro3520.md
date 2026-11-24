# Dell Vostro 3520 (Intel Alder Lake + Iris Xe)

Experimental bare-metal target for running **macOS 27.2.1 (Golden Gate, `26B131`)** on a
**Dell Vostro 3520** (12th Gen Intel Core i5-1235U, Intel Iris Xe Graphics `8086:46a8`, 80 EU)
by combining `hao-patcher`'s Darwin 27 OS layer with the Vostro 3520 OpenCore and Iris Xe Metal 2
stack from [VostroXe](https://github.com/henriquejsza/VostroXe).

## Architecture

Unlike `MacBookPro9,2` (Ivy Bridge + HD 4000), the Vostro 3520 uses:

| Layer | Source | Why |
|---|---|---|
| OS layer (`pack: base`) | Golden Gate `26B131` + Tahoe `25G342` donors + `hao-runtime` | Same Darwin 27 x86_64 kernel, OS/App/Rosetta cryptexes, shims, and ARM64 translation |
| Model pack (`packs/vostro3520.json`) | `patches/opencore-vostro3520` (from `VostroXe`) | SMBIOS `MacBookPro16,2`, Alder Lake `Cpuid1Data`/`Cpuid1Mask` emulation, ACPI SSDTs, `VirtualSMC`, `CryptexFixup` + `-crypt_force_avx`, input/network/audio kexts |
| GPU pack (`packs/intel-xe.json`) | `patches/golden-gate-intel-xe` (from `VostroXe` / `NootedGreen`) | Tiger Lake 16.0.32 driver bundles, `HookCase.kext`, patched `AppleIntelTGLGraphicsMTLDriver` (`MTL17` + `libxedrv`), and `xe.bundle` shader compiler |
| Kernel & BootKC binding | `patches/hao-opencore` + `tools/kc-binder` | Darwin 27 early-VM patches, `IntelCommpage.kext`, `HaoExec.kext`, `amfi_dyld`, `auxKCAtBoot=false` |

### Why Iris Xe kexts move to `/System/Library/Extensions` on macOS 27

On macOS 26 (Tahoe), `VostroXe` installs `AppleIntelTGLGraphics.kext`,
`AppleIntelTGLGraphicsFramebuffer.kext`, and `HookCase.kext` into `/Library/Extensions` and
registers them in the Auxiliary Kernel Collection via `kmutil load`.

On macOS 27 (Golden Gate), `kmutil` cannot build an x86_64 Auxiliary Kernel Collection
(`unsupported arch: x86_64`, so `hao-opencore` sets `auxKCAtBoot=false`). Therefore,
`golden-gate-intel-xe` (r2) places those three kexts into `/System/Library/Extensions` and
re-links **only** `SystemKernelExtensions.kc` via Tahoe's `libKernelCollectionBuilder.dylib`
while keeping `BootKernelExtensions.kc` byte-identical for `IntelCommpage.kext`, `HaoExec.kext`,
and `kc-binder`.

## Building on an x86_64 macOS 15 (Sequoia) VM

When assembling on a macOS 15.8.1 (`x86_64`) KVM builder VM without an Apple Silicon Mac:

- **`kmutil` + Tahoe `libKernelCollectionBuilder.dylib`**: Tahoe `25G342`'s `/usr/bin/kmutil`
  links against macOS 26's `/usr/lib/swift/libswift_DarwinFoundation1.dylib`, which macOS 15
  lacks. Pairing the Sequoia host's `/usr/bin/kmutil` with Tahoe `25G342`'s extracted
  `libKernelCollectionBuilder.dylib` (which links only `libc++.1` and `libSystem.B`) via
  `kmutil_builder.py` links both Darwin 27 `BootKernelExtensions.kc` and
  `SystemKernelExtensions.kc` cleanly.
- **Apple clang 17 `idlist.o` relocation**: Apple clang 17's relative lookup table pass emits
  `X86_64_RELOC_SUBTRACTOR` (`extern=1`) paired with `X86_64_RELOC_UNSIGNED` (`extern=0`) for
  `_names.rel` in `hao-runtime`'s `idlist.o`, storing the raw target section VM address `T` in
  the 32-bit field (rather than `T - S`). Handling `extern and not extern2` as
  `address_of(obj_index, field) - sub_address` resolves it cleanly for the `26B131` shared cache.
- **No bytecode inside `hao-runtime` payload**: Ensure `sys.dont_write_bytecode = True` on the
  staging Python before `golden-gate-userspace` imports `hao-install.py`, otherwise `hao-runtime`
  refuses `__pycache__/*.pyc` files not listed in `payload-manifest.json`.

## Safe-first bare-metal bring-up

`tools/vostro3520/build-usb-efi.py` writes three OpenCore configs onto the boot USB ESP:

- `config-safe.plist` (default `config.plist`): Darwin 27 verbose boot with `NootedGreen.kext`
  disabled and no `9A49` GPU spoof, to prove Darwin 27 kernel + userspace + `hao-runtime` boot
  first.
- `config-accel.plist`: enables `NootedGreen.kext`, the `9A49` Tiger Lake PCI spoof, and the
  Iris Xe Metal 2 boot arguments (`-ngreentglwithgfx`, `ngreen-dmc=adlp`, `ngreen-eu=80`, etc.).
- `config-recovery.plist`: boots the Tahoe Recovery `BaseSystem.dmg` without Darwin 27 kexts or
  kernel patches.

### Standalone APFS EFI Driver & GlobalConnect

Freshly sliced APFS containers lack an embedded JumpStart driver in the container superblock
(`OCJS: Missing JumpStart - Unsupported`). Real Macs contain `apfs.efi` in motherboard ROM; PC
firmware (Dell Vostro 3520) does not. Therefore, `build-usb-efi.py` installs Apple's standalone
`apfs.efi` into `EFI/OC/Drivers/`, enables it in `UEFI.Drivers`, and sets `UEFI.APFS.GlobalConnect: true`
so OpenCore discovers the APFS container and preboot volumes across NVMe controllers.

### Post-boot steps on the Vostro 3520

1. Press **F12** at power-on → boot the USB stick (`OPENCORE`) → pick **`macOS Golden Gate`** (not Option 3 / Tahoe Recovery).
2. Complete Setup Assistant in safe graphics mode (`config-safe.plist`).
3. Pre-compile ARM64 AOT caches for fast app launches: `sudo /usr/libexec/hao --aot`.
4. To enable **Intel Iris Xe Metal 2**, swap `EFI/OC/config-accel.plist` → `EFI/OC/config.plist`
   on the USB ESP and reboot (if anything hangs, swap `config-safe.plist` back from Linux).

## Dual-boot APFS deployment

To keep an existing Linux installation untouched on the internal NVMe drive:

1. Assemble the Golden Gate `26B131` disk image inside the macOS builder VM (sparse raw image).
2. Shrink the Linux root partition online (`btrfs filesystem resize` + `sfdisk`/`parted`) and
   create a GPT partition of type Apple APFS (`7c3457ef-0000-11aa-aa11-00306543ecac`).
3. Flash only the APFS container slice (`s2`) into the new partition with
   `tools/vostro3520/flash-apfs-partition.sh` (which verifies the partition is unmounted and has
   the Apple APFS GUID before writing).
4. Write the bound OpenCore EFI onto the USB stick's FAT32 ESP with
   `tools/vostro3520/build-usb-efi.py`.

### Bare-metal & QEMU Bring-Up Findings

- **Never enable OpenCore serial logging (`Target` bit `0x02`) on the Vostro 3520**: the laptop
  has no legacy `0x3F8` COM1 UART, so `Target = 67` stalls ~284 ms per debug line (~3 min
  before reaching the picker). `build-usb-efi.py` pins `Target = 65` (file log only).
- **Bare-metal Darwin 27.2.0 kernel & userspace confirmed**: `macOS Golden Gate` (`26B131`)
  booted bare-metal on the i5-1235U to userspace (PID 543+): all 5 Darwin 27 kernel/AMFI
  patches, `CryptexFixup`, `IntelCommpage`, `HaoExec`, OS/App cryptex grafts, `CS8409HDA`,
  `VoodooI2C` touchpad, `VoodooPS2` keyboard, `WindowServer`, `loginwindow`, and `hao-runtime`
  ran with zero kernel panics.
- **Display takeover (`config-safe` vs `config-accel`)**: on bare-metal `config-safe` (without
  `NootedGreen.kext` and without `-igfxvesa`), the Alder Lake GOP framebuffer relocated above
  4 GiB (`0x4000000000`) and `WindowServer` stayed at `gIOScreenLockState 3` (`llk 1`), while
  booting the exact same NVMe APFS partition read-only in QEMU KVM transitioned `llk 1 -> 0`,
  enabled `windowserver-filter`, and launched `mbsystemadministration` + `Language Chooser`.
  `config-safe.plist` now appends `-igfxvesa`, and `config-accel.plist` (`--default-accel`)
  activates `NootedGreen.kext` + the linked Tiger Lake Metal 2 stack for bare-metal GUI bring-up.

## Status

Experimental (`validated: false`). Host CI checks, recipe unit tests, full Golden Gate `26B131`
image assembly, dual-boot APFS deployment, QEMU COW verification (`WindowServer` +
`windowserver-filter` + `mbsystemadministration` + `Language Chooser`), and bare-metal Darwin
27.2.0 kernel + userspace boot on the Dell Vostro 3520 are complete. Bare-metal Iris Xe Metal 2
display takeover (`config-accel.plist`) is next to test.
