# golden-gate-intel-xe

Installs the Intel Iris Xe (Gen12 / Alder Lake `8086:46A8`) Metal 2 acceleration stack adapted from
`VostroXe` / `NootedGreen` onto macOS 27 (Golden Gate, `26B131`).

## How it works

`src/kc-hook.sh` runs during the `oclp-hook` stage on the writable System volume when `VOSTROXE_BUNDLE`
points to a built VostroXe graphics payload (Apple's 16.0.32 Tiger Lake bundles, `HookCase.kext`, patched
`AppleIntelTGLGraphicsMTLDriver.bundle`, `libxedrv`, shader compiler and `xe.bundle`).

Because macOS 27's `kmutil` cannot build an x86_64 Auxiliary Kernel Collection (`auxKCAtBoot=false`),
`AppleIntelTGLGraphics.kext`, `AppleIntelTGLGraphicsFramebuffer.kext`, and `HookCase.kext` are placed
in `/System/Library/Extensions` (rather than `/Library/Extensions`) so Tahoe's `kmutil` links them into
`SystemKernelExtensions.kc`. When `VOSTROXE_BUNDLE` is unset, the recipe is a clean no-op so an initial
Darwin 27 bare-metal boot can be verified in safe graphics mode first.

## Verify

- `python3.14 -I -B -m unittest discover -s patches/golden-gate-intel-xe/tests`
- On the installed Vostro 3520 after booting `config-accel.plist`: `kmutil showloaded | grep NootedGreen` and
  `system_profiler SPDisplaysDataType | grep Metal` (Metal 2, 1536 MB).

## Validation

NEEDS VALIDATION: host tests only; bare-metal Darwin 27 (`26B131`) validation on Dell Vostro 3520 is in progress.

## Revisions
- r1 2026-11-23 Initial Intel Iris Xe acceleration hook for Golden Gate 27.2.1 (`26B131`).
