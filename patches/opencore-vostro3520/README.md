# opencore-vostro3520

Dell Vostro 3520 (12th Gen Intel Core i5-1235U, Intel Iris Xe `8086:46A8`) model OpenCore configuration
(pack `vostro3520`), adapted from `VostroXe` for Golden Gate (macOS 27.2.1, `26B131`).

## How it works

`apply.sh` runs `src/vostro3520.py` on the ESP right before [hao-opencore](../hao-opencore/README.md):

- Copies the Dell Vostro 3520 ACPI SSDTs (`SSDT-PLUG-ALT`, `SSDT-EC`, `SSDT-USBX`, `SSDT-PNLF`, `SSDT-XOSI`, etc.),
  kexts (`VirtualSMC`, `NootedGreen`, `NVMeFix`, `RestrictEvents`, `USBToolBox`, `UTBMap`, `VoodooI2C`, `VoodooPS2`,
  `RealtekRTL8111`, `HoRNDIS`, `CS8409HDA`, `BrightnessKeys`, `WhateverGreen`) and resources from the VostroXe EFI.
- Keeps the Alder Lake CPUID emulation (`Cpuid1Data`/`Cpuid1Mask`) and `MacBookPro16,2` SMBIOS.
- Adds `CryptexFixup.kext` (1.0.5) right after `Lilu.kext` and appends `-crypt_force_avx` to `boot-args`, which is
  required on AVX2 CPUs so Golden Gate's modified OS cryptex grafts.
- Writes both `config-safe.plist` (VESA/no GPU spoof, `NootedGreen` disabled, verbose) and `config-accel.plist`
  (Iris Xe `9A49` spoof + `NootedGreen` Metal 2), defaulting `config.plist` to `config-safe.plist` until Darwin 27
  bare-metal boot is proven.

`hao-opencore` then appends the Darwin 27 kernel repairs, `IntelCommpage.kext`, `HaoExec.kext`, and Golden Gate boot
arguments.

## Verify

- `python3.14 -I -B -m unittest discover -s patches/opencore-vostro3520/tests`
- On the ESP: `plutil -lint EFI/OC/config.plist`, `CryptexFixup.kext` loaded immediately after `Lilu.kext`,
  `-crypt_force_avx` present in `boot-args`, and both `config-safe.plist` and `config-accel.plist` present.

## Validation

NEEDS VALIDATION: host unit tests only; bare-metal boot on Dell Vostro 3520 with Darwin 27 (`26B131`) is in progress.

## Revisions
- r1 2026-11-23 Initial Dell Vostro 3520 OpenCore recipe adapted from VostroXe with CryptexFixup and `-crypt_force_avx`.
