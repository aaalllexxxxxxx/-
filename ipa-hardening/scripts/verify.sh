#!/bin/bash
# verify.sh - 注入后自检：确认 LC_LOAD 存在、签名有效
set -euo pipefail

APP_DIR="$1"
APP_NAME=$(basename "$APP_DIR" .app)
BIN="$APP_DIR/$APP_NAME"

echo "[*] checking LC_LOAD commands"
otool -L "$BIN" | grep -q "libguard.dylib" \
  && echo "[+] libguard.dylib load command present" \
  || { echo "[!] injection missing"; exit 1; }

echo "[*] checking signature"
codesign -v --deep "$APP_DIR" && echo "[+] signature valid"

echo "[*] guard dylib symbols"
nm -gU "$APP_DIR/Frameworks/libguard.dylib" | grep -E "guard_(query_page|tick)" \
  && echo "[+] guard interface exported"
