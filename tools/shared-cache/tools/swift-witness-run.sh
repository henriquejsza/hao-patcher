#!/bin/sh
# Temporary own-process probes only. No application or session changes.
set -eu
cd "$(dirname "$0")"
./bind-runtime-probes witness.d "$1" > bound.d
for case in native v4 v5; do
    if [ "$case" = native ]; then
        dtrace -s bound.d -c './witness-probe native' > "$case.trace" 2> "$case.err"
    else
        # The helper selects its own debug library after DTrace attaches.
        dtrace -s bound.d -c "./witness-probe ./$case.dylib" > "$case.trace" 2> "$case.err"
    fi
done
