#!/bin/sh
# opencore-vostro3520 (post, right before hao-opencore; pack vostro3520): overlays the Dell Vostro 3520
# OpenCore configuration (VostroXe) onto the image ESP, adding CryptexFixup + -crypt_force_avx so Golden Gate's
# modified OS cryptex grafts on the AVX2 Alder Lake CPU. hao-opencore runs next for Darwin 27 kernel repairs.
set -eu
PY=${OCLP_PYTHON:-/private/var/ssdshare/py/bin/python3.12}
VOSTROXE_EFI=${VOSTROXE_EFI:-$P/inputs/vostroxe_efi}
"$PY" -I "$P/src/vostro3520.py" "$ESP" "$VOSTROXE_EFI" "$P/inputs/oclp_source"
plutil -lint "$ESP/EFI/OC/config.plist"
