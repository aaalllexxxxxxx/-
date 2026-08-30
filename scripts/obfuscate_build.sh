#!/bin/bash
# obfuscate_build.sh - 用 OLLVM 混淆编译加固 dylib（更强防护）
#
# 依赖: obfuscator-llvm 工具链 (https://github.com/obfuscator-llvm/obfuscator)
# 用法: OLLVM_HOME=/path/to/ollvm ./obfuscate_build.sh [out_dir]
set -euo pipefail

OLLVM_HOME="${OLLVM_HOME:?please set OLLVM_HOME to your obfuscator-llvm build dir}"
OUT_DIR="${1:-build_obf}"
mkdir -p "$OUT_DIR"

KEY=$(python3 -c "import random; print(random.randint(0x21, 0x7E))")

"$OLLVM_HOME/bin/clang" \
  -target arm64-apple-ios12.0 \
  -isysroot "$(xcrun -sdk iphoneos --show-sdk-path)" \
  -dynamiclib \
  -install_name "@executable_path/Frameworks/libguard.dylib" \
  -O2 -fvisibility=hidden \
  -DGUARD_STR_KEY=$KEY \
  `# OLLVM 混淆选项` \
  -mllvm -sub -mllvm -sub_loop=3 \
  -mllvm -bcf -mllvm -bcf_prob=60 -mllvm -bcf_loop=2 \
  -mllvm -fla \
  -mllvm -split -mllvm -split_num=3 \
  src/guard.c \
  -o "$OUT_DIR/libguard.dylib"

shasum -a 256 "$OUT_DIR/libguard.dylib" > "$OUT_DIR/libguard.sha256"
echo "[+] obfuscated dylib: $OUT_DIR/libguard.dylib"
