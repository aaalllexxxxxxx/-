#!/bin/bash
# inject_ipa.sh - 将加固 dylib 注入 ipa 并重签名
#
# 用法: ./inject_ipa.sh <input.ipa> <libguard.dylib> <mobileprovision> <sign_identity> [output.ipa]
# 依赖: insert_dylib (https://github.com/Tyilo/insert_dylib), ldid 或 codesign, macOS 环境
set -euo pipefail

IPA="$1"; DYLIB="$2"; PROV="$3"; IDENTITY="$4"
OUT="$(cd "$(dirname "${5:-output_hardened.ipa}")" && pwd)/$(basename "${5:-output_hardened.ipa}")"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "[*] unpacking $IPA"
unzip -q "$IPA" -d "$WORK/Payload-root"
APP_DIR=$(find "$WORK/Payload-root" -maxdepth 2 -name "*.app" | head -1)
APP_NAME=$(basename "$APP_DIR" .app)
BIN="$APP_DIR/$APP_NAME"
[ -f "$BIN" ] || { echo "[!] cannot locate app binary"; exit 1; }

echo "[*] stripping old signature"
find "$APP_DIR" -name "_CodeSignature" -exec rm -rf {} + 2>/dev/null || true
ldid -r "$BIN" 2>/dev/null || codesign --remove-signature "$BIN" 2>/dev/null || true

echo "[*] embedding guard dylib"
mkdir -p "$APP_DIR/Frameworks"
cp "$DYLIB" "$APP_DIR/Frameworks/libguard.dylib"

echo "[*] injecting LC_LOAD into $APP_NAME"
insert_dylib --inplace --strip-codesig --all-yes \
  "@executable_path/Frameworks/libguard.dylib" "$BIN"
# insert_dylib 会备份原文件为 ${BIN}_patched 原样保留，确保最终二进制生效
[ -f "${BIN}_patched" ] && mv -f "${BIN}_patched" "$BIN"

echo "[*] embedding provisioning profile"
cp "$PROV" "$APP_DIR/embedded.mobileprovision"

# 从描述文件提取 entitlements
security cms -D -i "$PROV" > "$WORK/prov.plist"
/usr/libexec/PlistBuddy -x -c "Print :Entitlements" "$WORK/prov.plist" > "$WORK/ent.plist"

echo "[*] re-signing (frameworks first, then app)"
find "$APP_DIR/Frameworks" -name "*.dylib" | while read -r f; do
  codesign -fs "$IDENTITY" "$f"
done
codesign -fs "$IDENTITY" --entitlements "$WORK/ent.plist" "$APP_DIR"

echo "[*] repacking -> $OUT"
cd "$WORK/Payload-root"
mkdir -p Payload && mv "$APP_DIR" Payload/
zip -qr "$OUT" Payload
echo "[+] done: $OUT"
