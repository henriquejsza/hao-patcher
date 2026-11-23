#!/usr/bin/env bash
# Safely flash the APFS container slice (s2) from a built Golden Gate raw disk image
# onto an existing GPT Apple APFS partition (e.g. /dev/nvme0n1p3) without touching any
# other partition on the drive.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: sudo $0 TARGET_RAW_IMG TARGET_APFS_PARTITION" >&2
    echo "Example: sudo $0 store/vm/target-gg27.img /dev/nvme0n1p3" >&2
    exit 2
fi

IMG=$1
PART=$2
APFS_GUID="7c3457ef-0000-11aa-aa11-00306543ecac"

[ -f "$IMG" ] || { echo "error: image not found: $IMG" >&2; exit 1; }
[ -b "$PART" ] || { echo "error: block device not found: $PART" >&2; exit 1; }

if findmnt -n "$PART" >/dev/null 2>&1; then
    echo "error: $PART is mounted; refusing to overwrite" >&2
    exit 1
fi

PARTTYPE=$(lsblk -no PARTTYPE "$PART" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
if [ "$PARTTYPE" != "$APFS_GUID" ]; then
    echo "error: $PART has PARTTYPE '$PARTTYPE', expected Apple APFS ($APFS_GUID); refusing" >&2
    exit 1
fi

# Locate slice 2 (APFS container) offset & size in IMG via Python GPT parser (512-byte sectors)
read -r OFFSET_BYTES SIZE_BYTES < <(python3 - "$IMG" <<'PY'
import struct, sys, uuid
img = sys.argv[1]
with open(img, 'rb') as f:
    f.seek(512)
    hdr = f.read(92)
    if hdr[:8] != b'EFI PART':
        raise SystemExit('no GPT header in image')
    part_lba, num_entries, entry_size = struct.unpack_from('<QII', hdr, 72)
    f.seek(part_lba * 512)
    apfs = uuid.UUID('7c3457ef-0000-11aa-aa11-00306543ecac').bytes_le
    for _ in range(num_entries):
        ent = f.read(entry_size)
        if ent[:16] == apfs:
            first_lba, last_lba = struct.unpack_from('<QQ', ent, 32)
            print(first_lba * 512, (last_lba - first_lba + 1) * 512)
            sys.exit(0)
raise SystemExit('no Apple APFS partition found in image GPT')
PY
)

PART_BYTES=$(blockdev --getsize64 "$PART")
if [ "$SIZE_BYTES" -gt "$PART_BYTES" ]; then
    echo "error: APFS slice ($SIZE_BYTES bytes) is larger than $PART ($PART_BYTES bytes)" >&2
    exit 1
fi

echo "Flashing APFS slice from $IMG (offset=$OFFSET_BYTES, size=$SIZE_BYTES) -> $PART (size=$PART_BYTES)..."
dd if="$IMG" of="$PART" bs=4M iflag=skip_bytes,count_bytes,fullblock skip="$OFFSET_BYTES" count="$SIZE_BYTES" status=progress conv=fsync
echo "Done: APFS container written to $PART."
