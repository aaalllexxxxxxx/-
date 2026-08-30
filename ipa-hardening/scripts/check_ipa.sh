#!/bin/bash
# check_ipa.sh - 加固前的 ipa 兼容性检查
set -euo pipefail

IPA="$1"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

unzip -q "$IPA" -d "$WORK"
APP_DIR=$(find "$WORK" -maxdepth 3 -name "*.app" | head -1)
[ -n "$APP_DIR" ] || { echo "[FAIL] no .app found in ipa"; exit 1; }
APP_NAME=$(basename "$APP_DIR" .app)
BIN="$APP_DIR/$APP_NAME"
[ -f "$BIN" ] || { echo "[FAIL] main binary $APP_NAME not found"; exit 1; }

FAIL=0

# 1. 必须是 Mach-O
if ! file "$BIN" | grep -q "Mach-O"; then
  echo "[FAIL] main binary is not Mach-O"; FAIL=1
else
  echo "[OK] Mach-O binary"
fi

# 2. 必须包含 arm64（真机）
if lipo -info "$BIN" 2>/dev/null | grep -q "arm64"; then
  echo "[OK] arm64 slice present"
else
  echo "[FAIL] no arm64 slice"; FAIL=1
fi

# 3. 必须无壳（FairPlay 加密检测：cryptid 应为 0）
CRYPTID=$(otool -arch arm64 -l "$BIN" 2>/dev/null | grep -A4 LC_ENCRYPTION_INFO | awk '/cryptid/{print $2; exit}')
if [ "${CRYPTID:-0}" != "0" ]; then
  echo "[FAIL] binary is FairPlay-encrypted (cryptid=$CRYPTID), need decrypted ipa"; FAIL=1
else
  echo "[OK] not encrypted (cryptid=0)"
fi

# 4. entitlements：内嵌在 Mach-O 里即可，ldid -e 能 dump 就算通过
if ldid -e "$BIN" 2>/dev/null | grep -q "plist"; then
  echo "[OK] entitlements embedded in Mach-O"
else
  echo "[WARN] no entitlements found, will inject empty dict (TrollStore requires it)"
fi

# 5. load command 头部空间：insert_dylib 需要空间添加 LC_LOAD_DYLIB
#    （insert_dylib 自带 --inplace 处理，一般 OK，此处仅提示）
echo "[INFO] load commands: $(otool -arch arm64 -l "$BIN" | grep -c 'cmd LC_')"

# 6. 已有 libguard 注入记录（避免重复注入）
if otool -L "$BIN" | grep -q "libguard.dylib"; then
  echo "[FAIL] libguard.dylib already injected"; FAIL=1
fi

[ "$FAIL" = "0" ] && echo "==> ipa is compatible" || { echo "==> ipa incompatible"; exit 1; }
