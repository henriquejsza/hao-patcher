# opencore-generic

The generic model's part of the image's OpenCore (pack `generic`): the image for **virtual machines and non-Apple PCs**,
with graphics in software, a baseline others can use for their own testing. **It is not for Mac hardware:** its
VirtualSMC conflicts with a real Mac's SMC. A Mac uses its own model pack (MacBookPro9,2: `mbp92`).

## How it works

`apply.sh` runs `src/generic.py` on the EFI partition that `pipeline/stages/build-efi.py` made for the generic target,
right before [hao-opencore](../hao-opencore/README.md). From the row `qemu_reference_efi` (the OpenCore tree tested on
OVMF, the base of `tools/kernel-foundation vm_esp.py`) it takes:

| Setting | Why |
|---|---|
| SMBIOS iMac20,1, created (`UpdateSMBIOSMode` Create) | Non-Apple firmware has no Mac SMBIOS. iMac20,1 is an Intel model Tahoe supports natively, so the Tahoe donors and OCLP's base config fit it and OCLP adds no model patches. |
| Serial, MLB, system UUID, ROM: generated per image | Made the first time the recipe runs, kept after. Random, not Apple-issued: Apple services that check them (iMessage, FaceTime) need the user's own valid values. |
| VirtualSMC.kext (Acidanthera 1.3.8), right after Lilu | macOS needs an SMC; non-Apple firmware has none. Byte-identical to the release (hao-opencore `src/kext-provenance.json`). |
| Lilu.kext replaced by OCLP's 1.7.2 RELEASE payload | The reference carries another Lilu build; hao-opencore's provenance check accepts only the pinned bytes, and both images then load the same Lilu. VirtualSMC from the reference already equals its pin (Acidanthera 1.3.8). |
| CryptexFixup.kext (Acidanthera 1.0.5), right after Lilu | Without it APFS requires the root hash of the image's modified OS cryptex, the graft fails (graftdmg 80) and the boot stops before userspace (QEMU, 2026-11-17: the 9,2 config without it failed there, with it passed). Taken from OCLP's RELEASE payload in the row `oclp_source`, byte-identical to hao-opencore's pinned copy. |
| The reference's Booter, Kernel and UEFI quirks | What non-Apple firmware needs: runtime-services memory map, KASLR slide, write protection, Apple EFI image loading, CFG Lock, VT-d tables, power-state timeouts, CPU info on a hypervisor. Each one's reason is in hao-opencore's `src/config-reasons.json`, marked "generic image only". |

No GPU, Wi-Fi or model kexts are added. hao-opencore then adds the Darwin 27 kernel repairs, IntelCommpage, HaoExec
and the boot-args. Its reasons check refuses any element without a reason, and any "generic image only" element in
a config that isn't this one (SMBIOS iMac20,1, created).

## Verify

- `python3.14 -I -B -m unittest discover -s patches/opencore-generic/tests` (with the store, the real reference's
  quirks: every element it adds has a reason).
- Build log: `opencore-generic: SMBIOS iMac20,1 (new identity), VirtualSMC after Lilu, quirks set: ...`.
- QEMU boot of the generic image (builder's GEN2): the desktop in software graphics; `sysctl hw.model` is iMac20,1;
  `kextstat | grep -i smc` shows VirtualSMC.

## Validation

NEEDS VALIDATION: host tests only; no generic image is built or booted yet.

## Revisions
- r3 2026-11-17 Lilu is OCLP's pinned 1.7.2 RELEASE (from row oclp_source), not the reference's build: the provenance check refused the reference's.
- r2 2026-11-17 Adds CryptexFixup (from OCLP's payload in row oclp_source, the pinned bytes): the modified OS cryptex does not graft without it.
- r1 2026-11-17 New (GEN1): SMBIOS iMac20,1 with a per-image identity, VirtualSMC, and the QEMU reference's firmware quirks, for VMs and non-Apple PCs.
