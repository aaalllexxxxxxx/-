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

# 若存在 src/card_auth.m，与 guard.c 合并编译为单一 dylib：
# card_auth constructor(101) 先执行卡密校验，失败 exit(0)，guard 的 JS 加载不会执行
SRCS="src/guard.c"
EXTRA_FRAMEWORKS=""
if [ -f src/card_auth.m ]; then
  echo "[*] card_auth.m detected, merging into single dylib"
  SRCS="$SRCS src/card_auth.m"
  EXTRA_FRAMEWORKS="-framework UIKit -framework Security"
fi

for ARCH in arm64; do
  xcrun -sdk iphoneos clang \
    -arch $ARCH \
    -dynamiclib \
    -install_name "@executable_path/Frameworks/libguard.dylib" \
    -framework Foundation \
    $EXTRA_FRAMEWORKS \
    -fvisibility=hidden \
    -O2 \
    -DGUARD_STR_KEY=$KEY \
    -DGUARD_JS_SALT=${SALT}ULL \
    -DGUARD_JS_MAGIC=${MAGIC}ULL \
    -mios-version-min=12.0 \
    $SRCS \
    -o "$OUT_DIR/libguard_$ARCH.dylib"
done

lipo -create "$OUT_DIR"/libguard_*.dylib -output "$OUT_DIR/libguard.dylib"
rm -f "$OUT_DIR"/libguard_*.dylib

# 生成构建期指纹，供宿主侧硬编码比对（可选的增强互锁）
shasum -a 256 "$OUT_DIR/libguard.dylib" > "$OUT_DIR/libguard.sha256"
echo "[+] built: $OUT_DIR/libguard.dylib"
