#!/bin/bash
# build_guard.sh - 编译加固 dylib（需在 macOS + Xcode 环境执行）
set -euo pipefail
# 读取功能开关(camouflage.conf)
CONF="$(dirname "$0")/../camouflage.conf"
[ -f "$CONF" ] && . "$CONF"

OUT_DIR="${1:-build}"
mkdir -p "$OUT_DIR"

# 每次构建随机化字符串加密密钥、JS salt 与密文 magic，对抗特征匹配
KEY=$(python3 -c "import random; print(random.randint(0x21, 0x7E))")
SALT=$(python3 -c "import random; print('0x%016x' % random.getrandbits(64))")
MAGIC=$(python3 -c "import random; print('0x%016x' % random.getrandbits(64))")
echo "$SALT" > "$OUT_DIR/salt.txt"
echo "$MAGIC" > "$OUT_DIR/magic.txt"
echo "[*] guard string key: $KEY, js salt: $SALT, js magic: $MAGIC"

# A2-universal: per-build 随机 32 字节 JS 解密密钥(注入 guard.c 并供 embed_js.sh 使用)
python3 -c "
import os
k = os.urandom(32)
open('$OUT_DIR/guard_js_key.inc','w').write('static const unsigned char g_js_key[32] = {' + ','.join('0x%02x'%x for x in k) + '};' + chr(10))
open('$OUT_DIR/js_key.bin','wb').write(k)
"
echo "[*] js key injected -> $OUT_DIR/guard_js_key.inc"

# 若存在 src/auth/*.mm（AuthDylib 卡密验证），与 guard.c + guard_bridge.mm
# 合并编译为单一 dylib，并启用桥接模式（JS 加载由卡密状态控制）
SRCS="src/guard.c"
EXTRA_FLAGS=""
EXTRA_LDFLAGS=""
if [ "$EMBED_AUTH_DYLIB" != "false" ] && ls src/auth/*.mm >/dev/null 2>&1; then
  echo "[*] AuthDylib detected, merging into single dylib (bridge mode)"
  SRCS="$SRCS src/guard_bridge.mm src/auth/*.mm"
  EXTRA_FLAGS="-fobjc-arc -DGUARD_AUTH_BRIDGE=1 -Isrc -I$OUT_DIR -include $OUT_DIR/guard_js_key.inc"
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
