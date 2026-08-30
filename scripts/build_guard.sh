#!/bin/bash
# build_guard.sh - 编译加固 dylib（需在 macOS + Xcode 环境执行）
set -euo pipefail

OUT_DIR="${1:-build}"
mkdir -p "$OUT_DIR"

# 每次构建随机化字符串加密密钥、JS salt 与密文 magic，对抗特征匹配
KEY=$(python3 -c "import random; print(random.randint(0x21, 0x7E))")
SALT=$(python3 -c "import random; print('0x%016x' % random.getrandbits(64))")
MAGIC=$(python3 -c "import random; print('0x%016x' % random.getrandbits(64))")
echo "$SALT" > "$OUT_DIR/salt.txt"
echo "$MAGIC" > "$OUT_DIR/magic.txt"
echo "[*] guard string key: $KEY, js salt: $SALT, js magic: $MAGIC"

# 若存在 src/auth/*.mm（AuthDylib 卡密验证），与 guard.c + guard_bridge.mm
# 合并编译为单一 dylib，并启用桥接模式（JS 加载由卡密状态控制）
SRCS="src/guard.c"
EXTRA_FLAGS=""
EXTRA_LDFLAGS=""
if ls src/auth/*.mm >/dev/null 2>&1; then
  echo "[*] AuthDylib detected, merging into single dylib (bridge mode)"
  SRCS="$SRCS src/guard_bridge.mm src/auth/*.mm"
  EXTRA_FLAGS="-fobjc-arc -DGUARD_AUTH_BRIDGE=1 -Isrc"
  EXTRA_LDFLAGS="-lc++ -framework UIKit -framework Security -framework CoreGraphics"
fi

for ARCH in arm64; do
  xcrun -sdk iphoneos clang \
    -arch $ARCH \
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
    -o "$OUT_DIR/libguard_$ARCH.dylib"
done

lipo -create "$OUT_DIR"/libguard_*.dylib -output "$OUT_DIR/libguard.dylib"
rm -f "$OUT_DIR"/libguard_*.dylib

# 生成构建期指纹，供宿主侧硬编码比对（可选的增强互锁）
shasum -a 256 "$OUT_DIR/libguard.dylib" > "$OUT_DIR/libguard.sha256"
echo "[+] built: $OUT_DIR/libguard.dylib"
