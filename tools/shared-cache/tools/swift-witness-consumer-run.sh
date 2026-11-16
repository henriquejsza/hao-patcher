#!/bin/sh
# Each phase gets a fresh runtime: preparation must not warm the consumer cache.
set -eu
bundle=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=$1
mkdir "$out"
cp "$bundle/build.json" "$out/build.json"
for mode in produce native export implementation; do
    "$bundle/witness-consumer" "$mode" "$out/fixture.tsv" > "$out/$mode.jsonl" 2> "$out/$mode.stderr"
done
