# hao-command: the hao command on the installed Mac (owner 2026-11-16, Q5 "Bundle it."): the kit's x86_64 CPython under
# usr/local/lib/hao/python, tools/hao under usr/local/lib/hao/hao, and usr/local/bin/hao, which starts one with the
# other. All on the Data volume, so a later hao update can replace them without touching the sealed System.
L="$DATA/usr/local/lib/hao"
B="$DATA/usr/local/bin"
install -d -o root -g wheel -m 755 "$DATA/usr/local" "$DATA/usr/local/lib" "$L" "$B"
rm -rf "$L/python" "$L/hao"
tar -xzf "$P/inputs/python_x86_64" -C "$L"
[ -x "$L/python/bin/python3.12" ] || { echo "hao-command: the CPython archive has no python/bin/python3.12" >&2; exit 1; }
(cd "$P/build" && tar -cf - hao) | (cd "$L" && tar -xf -)
[ -f "$L/hao/tools/hao/hao" ] || { echo "hao-command: the staged tools/hao is missing" >&2; exit 1; }
printf '#!/bin/sh\nexec /usr/local/lib/hao/python/bin/python3.12 -I /usr/local/lib/hao/hao/tools/hao/hao "$@"\n' > "$B/hao"
chown -R root:wheel "$L" "$B/hao"
chmod 755 "$B/hao"
chmod -R go-w "$L"
echo "hao-command: $(du -sk "$L" | cut -f1) KB under /usr/local/lib/hao; /usr/local/bin/hao"
