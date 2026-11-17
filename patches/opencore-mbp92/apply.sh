#!/bin/sh
# opencore-mbp92 (post, right before hao-opencore): the MacBookPro9,2's early Tahoe display and wired-network kexts in
# OpenCore's Kernel.Add, for any that neither kernel collection links (none on any recorded build), and the codeless
# kext that puts the Bluetooth HID-proxy devices on the kernel HID driver.
set -eu
# The kit's Python for the Mac the assembly runs on (golden-image.py sets OCLP_PYTHON); the builder VM's share copy
# for the legacy runner.
PY=${OCLP_PYTHON:-/private/var/ssdshare/py/bin/python3.12}
"$PY" -I "$P/src/early_kexts.py" "$SYS" "$ESP" "$P/src/early-kexts.txt"
# The Bluetooth controller's HID-proxy devices go to the kernel HID driver, so they finish terminating when Bluetooth
# switches to HCI mode and the EHCI controller can power off (wake panic, src/hid_proxy.py).
"$PY" -I "$P/src/hid_proxy.py" "$ESP" "$P/src/HIDProxyKernelMatch-Info.plist"
plutil -lint "$ESP/EFI/OC/config.plist"
