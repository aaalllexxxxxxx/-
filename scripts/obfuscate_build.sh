#!/bin/bash
# obfuscate_build.sh - 用 O-MVLL (https://obfuscator.re/omvll) 混淆编译加固 dylib
#
# O-MVLL 是基于 LLVM New Pass Manager 的混淆插件,直接挂载到 Apple clang,
# 无需替换工具链;但插件版本必须与 Xcode 版本严格匹配(见 harden.yml)。
#
# 编译与链接分开执行:混淆 pass 只在 -c 阶段运行;
# Xcode 26 的新版 ld 链接混淆后的目标文件可能段错误,故链接按
# 默认 linker -> -ld_classic -> Xcode 26.6 linker 依次回退。
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

# A2-universal: per-build 随机 32 字节 JS 解密密钥
python3 -c "
import os
k = os.urandom(32)
open('$OUT_DIR/guard_js_key.inc','w').write('static const unsigned char g_js_key[32] = {' + ','.join('0x%02x'%x for x in k) + '};
')
open('$OUT_DIR/js_key.bin','wb').write(k)
"
echo "[*] js key injected -> $OUT_DIR/guard_js_key.inc"

OMVLL_DYLIB="$OMVLL_HOME/omvll-xcode.dylib"
[ -f "$OMVLL_DYLIB" ] || { echo "::error::omvll-xcode.dylib not found in $OMVLL_HOME"; exit 1; }
OMVLL_PYHOME=$(find "$OMVLL_HOME" -maxdepth 1 -type d -name "Python-*" | head -1)
[ -n "$OMVLL_PYHOME" ] || { echo "::error::bundled Python-3.10.* dir not found in $OMVLL_HOME"; exit 1; }
export OMVLL_PYTHONPATH="$OMVLL_PYHOME/Lib"
export OMVLL_CONFIG="$PWD/omvll_config.py"
[ -f "$OMVLL_CONFIG" ] || { echo "::error::$OMVLL_CONFIG missing"; exit 1; }

# 与 build_guard.sh 保持一致: 存在 AuthDylib 源码时合并编译为单一 dylib (bridge mode)
SRCS="src/guard.c"
EXTRA_CFLAGS=""
EXTRA_LDFLAGS=""
if ls src/auth/*.mm >/dev/null 2>&1; then
  echo "[*] AuthDylib detected, merging into single dylib (bridge mode)"
  SRCS="$SRCS src/guard_bridge.mm src/auth/*.mm"
  EXTRA_CFLAGS="-fobjc-arc -DGUARD_AUTH_BRIDGE=1 -Isrc -I$OUT_DIR -include $OUT_DIR/guard_js_key.inc"
  EXTRA_LDFLAGS="-lc++ -framework UIKit -framework Security -framework CoreGraphics"
fi

COMMON_FLAGS="-arch arm64 -fvisibility=hidden -O2 -DGUARD_STR_KEY=$KEY \
-DGUARD_JS_SALT=${SALT}ULL -DGUARD_JS_MAGIC=${MAGIC}ULL -mios-version-min=13.0 \
$EXTRA_CFLAGS"

# ---------- 编译:混淆 pass 在此阶段执行 ----------
OBJS=""
for SRC in $SRCS; do
  OBJ="$OUT_DIR/$(basename "$SRC" | sed 's/\.[^.]*$//' | tr -c 'A-Za-z0-9_' '_').o"
  echo "[*] compiling (obfuscated): $SRC"
  xcrun -sdk iphoneos clang $COMMON_FLAGS -fpass-plugin="$OMVLL_DYLIB" -c "$SRC" -o "$OBJ"
  OBJS="$OBJS $OBJ"
done

# ---------- 链接:不带混淆插件,依次回退 linker ----------
LDFLAGS="-dynamiclib -install_name @executable_path/Frameworks/libguard.dylib \
-framework Foundation $EXTRA_LDFLAGS"

try_link() {
  # $1 = 额外 linker 参数(可为空),其余环境:DEVELOPER_DIR 可覆盖工具链
  # shellcheck disable=SC2086
  xcrun -sdk iphoneos clang -arch arm64 $LDFLAGS $1 $OBJS -o "$OUT_DIR/libguard.dylib"
}

LINKED=0
for TRY in "" "-Wl,-ld_classic" "XCODE_26_6"; do
  if [ "$TRY" = "XCODE_26_6" ]; then
    [ -d /Applications/Xcode_26.6.app ] || continue
    echo "[*] linking with Xcode 26.6 linker"
    if DEVELOPER_DIR=/Applications/Xcode_26.6.app xcrun -sdk iphoneos clang \
         -arch arm64 $LDFLAGS $OBJS -o "$OUT_DIR/libguard.dylib"; then
      LINKED=1; break
    fi
  else
    [ -z "$TRY" ] && echo "[*] linking with default linker" || echo "[*] linking with: $TRY"
    if try_link "$TRY"; then LINKED=1; break; fi
  fi
  echo "::warning::linker failed ($TRY), trying next fallback"
done
[ "$LINKED" = "1" ] || { echo "::error::all linker fallbacks failed"; exit 1; }

rm -f $OBJS
shasum -a 256 "$OUT_DIR/libguard.dylib" > "$OUT_DIR/libguard.sha256"
echo "[+] obfuscated dylib: $OUT_DIR/libguard.dylib"
