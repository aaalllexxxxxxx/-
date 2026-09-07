#!/bin/bash
# inject_ipa_ldid.sh - 越狱/TrollStore 场景：注入 dylib 并用 ldid 伪签名
#
# 用法: ./inject_ipa_ldid.sh <input.ipa> <libguard.dylib> [output.ipa] [extra_entitlements_csv]
# extra_entitlements_csv: 逗号分隔的布尔型 entitlements，如 task_for_pid-allow,get-task-allow
set -euo pipefail

IPA="$1"; DYLIB="$2"
OUT="$(cd "$(dirname "${3:-output_hardened.ipa}")" && pwd)/$(basename "${3:-output_hardened.ipa}")"
EXTRA_ENTS="${4:-}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "[*] unpacking $IPA"
unzip -q "$IPA" -d "$WORK/root"
APP_DIR=$(find "$WORK/root" -maxdepth 3 -name "*.app" | head -1)
APP_NAME=$(basename "$APP_DIR" .app)
BIN="$APP_DIR/$APP_NAME"
[ -f "$BIN" ] || { echo "[!] cannot locate app binary"; exit 1; }

# TrollStore 要求 ipa 结构为 Payload/xxx.app，记录并还原原始结构
TOP_DIR=$(dirname "$APP_DIR" | sed "s|$WORK/root/||")

echo "[*] dumping original entitlements"
ldid -e "$BIN" > "$WORK/ent.plist" 2>/dev/null || true
if [ ! -s "$WORK/ent.plist" ]; then
  echo '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict></dict></plist>' \
    > "$WORK/ent.plist"
fi

# 合并额外 entitlements（布尔 true）
if [ -n "$EXTRA_ENTS" ]; then
  IFS=',' read -ra ENTS <<< "$EXTRA_ENTS"
  for ent in "${ENTS[@]}"; do
    echo "[*] adding entitlement: $ent"
    /usr/libexec/PlistBuddy -c "Add :$ent bool true" "$WORK/ent.plist" 2>/dev/null \
      || /usr/libexec/PlistBuddy -c "Set :$ent true" "$WORK/ent.plist"
  done
fi

echo "[*] removing old signature"
find "$APP_DIR" -name "_CodeSignature" -exec rm -rf {} + 2>/dev/null || true

# 加载伪装命名配置（可定义在仓库根目录 camouflage.conf）
GUARD_NAME="libguard.dylib"
GADGET_NAME="FridaGadget.dylib"
JS_BLOB_NAME="agent.js.enc"
JS_DOC_NAME=".agent_cache.js"
CONF="$(dirname "$0")/../camouflage.conf"
[ -f "$CONF" ] && . "$CONF"
# JS 调试弹窗开关(由 camouflage.conf 控制,供 embed_js.sh -> gen_loader.py)
[ "$JS_DEBUG_ALERTS" = "true" ] && export GEN_LOADER_DEBUG=1 || true
echo "[*] camouflage: guard->$GUARD_NAME gadget->$GADGET_NAME blob->$JS_BLOB_NAME js->$JS_DOC_NAME"
export GADGET_NAME JS_BLOB_NAME JS_DOC_NAME   # 供 embed_js.sh 使用

echo "[*] embedding guard dylib as $GUARD_NAME"
mkdir -p "$APP_DIR/Frameworks"
cp "$DYLIB" "$APP_DIR/Frameworks/$GUARD_NAME"

# A2: 先把 Gadget 放进 Frameworks（必须在 LC_LOAD 注入之前）
if [ -n "${AGENT_JS:-}" ] && [ -f "${AGENT_JS:-}" ]; then
  "$(dirname "$0")/embed_js.sh" gadget "$APP_DIR"
fi

# 改写 dylib 自身 install_name 为伪装路径（伪装后宿主/dyld 均以新名引用）
install_name_tool -id "@executable_path/Frameworks/$GUARD_NAME" \
  "$APP_DIR/Frameworks/$GUARD_NAME" 2>/dev/null \
  || echo "[warn] install_name_tool -id failed (no header pad); LC_LOAD path still works"

echo "[*] injecting LC_LOAD into $APP_NAME"
insert_dylib --inplace --strip-codesig --all-yes \
  "@executable_path/Frameworks/$GUARD_NAME" "$BIN"
[ -f "${BIN}_patched" ] && mv -f "${BIN}_patched" "$BIN"

# Gadget 直接经 LC_LOAD 加载（稳妥模式）；guard 的运行时 JS 装载器找不到密文时为无害 no-op
if [ -n "${AGENT_JS:-}" ] && [ -f "${AGENT_JS:-}" ]; then
  echo "[*] injecting Gadget LC_LOAD ($GADGET_NAME)"
  insert_dylib --inplace --strip-codesig --all-yes \
    "@executable_path/Frameworks/$GADGET_NAME" "$BIN"
  [ -f "${BIN}_patched" ] && mv -f "${BIN}_patched" "$BIN"
fi

echo "[*] fake-signing with ldid (dylib first, then app binary)"
ldid -S"$WORK/ent.plist" "$APP_DIR/Frameworks/$GUARD_NAME"
# 应用内已有的其他 dylib/framework 一并签
find "$APP_DIR/Frameworks" \( -name "*.dylib" -o -name "*.framework" -prune \) | while read -r f; do
  [ "$f" = "$APP_DIR/Frameworks/$GUARD_NAME" ] && continue
  ldid -S "$f" 2>/dev/null || true
done
ldid -S"$WORK/ent.plist" "$BIN"

# A2-universal: 用 guard 密钥加密的业务 JS + loader 壳 + config（签名之后执行）
if [ -n "${AGENT_JS:-}" ] && [ -f "${AGENT_JS:-}" ]; then
  JS_KEY="$(dirname "$DYLIB")/js_key.bin"
  "$(dirname "$0")/embed_js.sh" payload "$APP_DIR" "$JS_KEY" "$AGENT_JS"
fi

echo "[*] repacking -> $OUT"
cd "$WORK/root"
# 保持原始目录结构（通常是 Payload/xxx.app）
if [ "$TOP_DIR" = "." ]; then
  mkdir -p Payload && mv "$APP_DIR" Payload/
fi
zip -qr "$OUT" .
echo "[+] done: $OUT"
