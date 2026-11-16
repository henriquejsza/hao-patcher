#!/bin/sh
set -eu
mkdir -p "$1"
cp "$(dirname "$0")"/edits/*.json "$1"/
