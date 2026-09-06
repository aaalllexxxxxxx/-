#!/bin/bash
# obfuscate_build.sh - 用 O-MVLL (https://obfuscator.re/omvll) 混淆编译加固 dylib
#
# O-MVLL 是基于 LLVM New Pass Manager 的混淆插件,直接挂载到 Apple clang,
# 无需替换工具链;但插件版本必须与 Xcode 版本严格匹配(见 harden.yml)。
#
# 依赖: O-MVLL macOS 发行包 (omvll-xcode.dylib + Python-3.10.7/Lib) + omvll_config.py
# 用法: OMVLL_HOME=/path/to/omvll ./obfuscate_build.sh [out_dir]
set -euo pipefail

OMVLL_HOME="${OMVLL_HOME:?please set OMVLL_HOME to your o-mvll dir}"
OUT_DIR="${1:-build}"
mkdir -p "$OUT_DIR"

# 每次构建随机化字符串加密密钥、JS salt 与密文 magic(与 build_guard.sh 一致)
KEY=$(python3 -c "import random; print(random.randint(0x21, 0x7E))")
SALT=$(python3 -c "import random; print('0x%016x' % random.getrandbits(64))")
MAGIC=$(python3 -c "import random; print('0x%016x' % random.getrandbits(64))")
echo "$SALT" > "$OUT_DIR/salt.txt"
echo "$MAGIC" > "$OUT_DIR/magic.txt"
echo "[*] guard string key: $KEY, js salt: $SALT, js magic: $MAGIC"

OMVLL_DYLIB="$OMVLL_HOME/omvll-xcode.dylib"
[ -f "$OMVLL_DYLIB" ] || { echo "::error::omvll-xcode.dylib not found in $OMVLL_HOME"; exit 1; }
OMVLL_PYHOME=$(find "$OMVLL_HOME" -maxdepth 1 -type d -name "Python-*" | head -1)
[ -n "$OMVLL_PYHOME" ] || { echo "::error::bundled Python-3.10.* dir not found in $OMVLL_HOME"; exit 1; }
export OMVLL_PYTHONPATH="$OMVLL_PYHOME/Lib"
export OMVLL_CONFIG="$PWD/omvll_config.py"
[ -f "$OMVLL_CONFIG" ] || { echo "::error::$OMVLL_CONFIG missing"; exit 1; }

# 与 build_guard.sh 保持一致: 存在 AuthDylib 源码时合并编译为单一 dylib (bridge mode)
SRCS="src/guard.c"
EXTRA_FLAGS=""
EXTRA_LDFLAGS=""
if ls src/auth/*.mm >/dev/null 2>&1; then
  echo "[*] AuthDylib detected, merging into single dylib (bridge mode)"
  SRCS="$SRCS src/guard_bridge.mm src/auth/*.mm"
  EXTRA_FLAGS="-fobjc-arc -DGUARD_AUTH_BRIDGE=1 -Isrc"
  EXTRA_LDFLAGS="-lc++ -framework UIKit -framework Security -framework CoreGraphics"
fi

xcrun -sdk iphoneos clang \
  -arch arm64 \
  -fpass-plugin="$OMVLL_DYLIB" \
  -dynamiclib \
  -install_name "@executable_path/Frameworks/libguard.dylib" \
  -framework Foundation \
  -fvisibility=hidden \
  -O2 \
  -DGUARD_STR_KEY=$KEY \
  -DGUARD_JS_SALT=${SALT}ULL \
  -DGUARD_JS_MAGIC=${MAGIC}ULL \
  -mios-version-min=13.0 \
  $EXTRA_FLAGS \
  $SRCS \
  $EXTRA_LDFLAGS \
  -o "$OUT_DIR/libguard.dylib"

shasum -a 256 "$OUT_DIR/libguard.dylib" > "$OUT_DIR/libguard.sha256"
echo "[+] obfuscated dylib: $OUT_DIR/libguard.dylib"
