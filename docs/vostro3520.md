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
`golden-gate-intel-xe` places those three kexts into `/System/Library/Extensions` so Tahoe's
`kmutil` links them directly into `SystemKernelExtensions.kc` during image assembly.

## Safe-first bare-metal bring-up

`tools/vostro3520/build-usb-efi.py` writes three OpenCore configs onto the boot USB ESP:

- `config-safe.plist` (default `config.plist`): Darwin 27 verbose boot with `NootedGreen.kext`
  disabled and no `9A49` GPU spoof, to prove Darwin 27 kernel + userspace + `hao-runtime` boot
  first.
- `config-accel.plist`: enables `NootedGreen.kext`, the `9A49` Tiger Lake PCI spoof, and the
  Iris Xe Metal 2 boot arguments (`-ngreentglwithgfx`, `ngreen-dmc=adlp`, `ngreen-eu=80`, etc.).
- `config-recovery.plist`: boots the Tahoe Recovery `BaseSystem.dmg` without Darwin 27 kexts or
  kernel patches.

## Dual-boot APFS deployment

To keep an existing Linux installation untouched on the internal NVMe drive:

1. Assemble the Golden Gate `26B131` disk image inside the macOS builder VM (sparse raw image).
2. Shrink the Linux root partition online and create a GPT partition of type Apple APFS
   (`7c3457ef-0000-11aa-aa11-00306543ecac`).
3. Flash only the APFS container slice (`s2`) into the new partition with
   `tools/vostro3520/flash-apfs-partition.sh` (which verifies the partition is unmounted and has
   the Apple APFS GUID before writing).
4. Write the bound OpenCore EFI onto the USB stick's FAT32 ESP with
   `tools/vostro3520/build-usb-efi.py`.

## Status

Experimental (`validated: false`). Host CI checks, recipe unit tests, macOS shim builds, Tahoe
`25G342` KDK donor extraction, and the `VostroXe` Iris Xe Metal 2 bundle build pass. Bare-metal
Golden Gate `26B131` image assembly and hardware boot validation on the Vostro 3520 are in progress.
