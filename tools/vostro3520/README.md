# tools/vostro3520

Host and macOS-builder helpers for bringing up **macOS 27.2.1 (Golden Gate, `26B131`)** on the
**Dell Vostro 3520** (Alder Lake i5-1235U, Intel Iris Xe `8086:46a8`). See
[docs/vostro3520.md](../../docs/vostro3520.md) for the full bring-up architecture.

## Tools

| File | Purpose |
|---|---|
| `build-shims-macos.sh` | Compiles and ad-hoc signs the open-source `hao-patcher` tools (`fl`, `hmeta`, `autool`, `ripatch`) and x86_64 userspace shims (`codeid_carrier`, `dss_shim`, `corewifi_compat`, `corespotlight_compat`, `windowserver_filter`) on an x86_64 macOS builder (macOS 15+ CLT). |
| `build-usb-efi.py` | Merges a `VostroXe` OpenCore EFI with `hao-opencore`'s Darwin 27 kexts and bound `Kernel.Patch` entries, emitting `config-safe.plist`, `config-accel.plist`, `config-recovery.plist`, and `config.plist`. |
| `flash-apfs-partition.sh` | Extracts the Apple APFS container slice (`s2`) from a built raw Golden Gate image and writes it to an existing unmounted GPT Apple APFS partition (`7c3457ef-0000-11aa-aa11-00306543ecac`) without modifying other partitions. |

## Verify

```sh
python3 -I -B -m unittest discover -s tools/vostro3520/tests
python3 -I -B -m unittest discover -s patches/opencore-vostro3520/tests
python3 -I -B -m unittest discover -s patches/golden-gate-intel-xe/tests
```
