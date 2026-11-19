#!/bin/zsh
# Build ssdpush-agent for the target Mac's macOS Recovery (x86_64, SSSE3 BLAKE2b) and for this Mac (local tests).
# usage: build.sh [zstd-1.5.x source dir [output dir]]   (default: store/cache/zstd/zstd-1.5.7, this folder).
# HOST_ONLY=1 builds only this Mac's ssdpush-agent-macos (what the ssdimg tests build into a temporary folder).
# Outputs stay untracked.
set -e
H=${0:A:h}; Z=${1:-${H:h:h}/store/cache/zstd/zstd-1.5.7}; O=${2:-$H}
SRC=($H/agent.c $Z/lib/common/{entropy_common,error_private,fse_decompress,xxhash,zstd_common,debug}.c
     $Z/lib/decompress/{huf_decompress,zstd_ddict,zstd_decompress,zstd_decompress_block}.c
     $Z/lib/compress/{fse_compress,hist,huf_compress,zstd_compress,zstd_compress_literals,zstd_compress_sequences,zstd_compress_superblock,zstd_double_fast,zstd_fast,zstd_lazy,zstd_ldm,zstd_opt,zstd_preSplit}.c)
FLAGS=(-O2 -I$H -I$Z/lib -I$Z/lib/common -DZSTD_DISABLE_ASM -pthread)
[[ -n $HOST_ONLY ]] || clang -arch x86_64 -mmacosx-version-min=26.0 $FLAGS -mssse3 $SRC $H/blake2b_ssse3.c -framework CoreFoundation -framework IOKit -o $O/ssdpush-agent-macos-x86_64
clang $FLAGS $SRC $H/blake2b.c -framework CoreFoundation -framework IOKit -o $O/ssdpush-agent-macos
ls -la $O/ssdpush-agent-*
