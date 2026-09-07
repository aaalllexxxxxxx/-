#!/bin/bash
# embed_js.sh - JS 静态嵌入（guard 密钥绑定版，A2-universal）
#
# 用法:
#   embed_js.sh gadget  <app_dir>                          -- LC_LOAD 注入之前
#   embed_js.sh payload <app_dir> <js_key.bin> <agent.js>  -- ldid 签名之后
#
# 密钥（构建期与运行期一致）:
#   key         = guard 构建期生成的随机 32 字节（build/js_key.bin）
#   keystream_i = SHA256(key || salt(8) || counter(u32,LE))   每块 32 字节
#   明文        = magic(4, 构建期随机) || 业务 JS
# 运行期 loader 通过 Module.getExportByName(null,'guard_js_key') 调 guard 导出符号
# 取同一密钥。不依赖宿主二进制 → 适用于任意 IPA，不受安装对二进制改动影响。
# guard 被移除 → loader 取不到符号 → JS 不加载（互锁）。
# 禁止使用 atob/btoa（frida 的 QuickJS 不提供）。
set -euo pipefail

CMD="${1:-}"
case "$CMD" in
  gadget)
    APP_DIR="$2"
    GADGET_NAME="${GADGET_NAME:-FridaGadget.dylib}"
    FRIDA_VERSION="${FRIDA_VERSION:-16.5.9}"
    echo "[*] fetching FridaGadget $FRIDA_VERSION -> $GADGET_NAME"
    curl -fL --retry 3 -o /tmp/gadget.gz \
      "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-ios-universal.dylib.gz"
    gunzip -c /tmp/gadget.gz > "$APP_DIR/Frameworks/$GADGET_NAME"
    chmod 755 "$APP_DIR/Frameworks/$GADGET_NAME"
    install_name_tool -id "@executable_path/Frameworks/$GADGET_NAME" \
      "$APP_DIR/Frameworks/$GADGET_NAME" 2>/dev/null || true
    ;;
  payload)
    APP_DIR="$2"; JS_KEY="$3"; JS="$4"
    GADGET_NAME="${GADGET_NAME:-FridaGadget.dylib}"
    JS_DOC_NAME="${JS_DOC_NAME:-.agent_cache.js}"
    [ -f "$JS_KEY" ] || { echo "::error::js_key.bin not found at $JS_KEY"; exit 1; }

    OBF_DIR=$(mktemp -d)
    JS_INPUT="$JS"
    if command -v npx >/dev/null 2>&1; then
      echo "[*] obfuscating agent.js (javascript-obfuscator)"
      if npx --yes javascript-obfuscator "$JS" --output "$OBF_DIR/agent_obf.js" \
          --compact true \
          --control-flow-flattening true --control-flow-flattening-threshold 0.75 \
          --string-array true --string-array-threshold 0.75 \
          --string-array-encoding base64 \
          --identifier-names-generator hexadecimal \
          --unicode-escape-sequence false \
          --self-defending false \
          >/dev/null 2>&1 \
         && ! grep -q "atob(" "$OBF_DIR/agent_obf.js"; then
        JS_INPUT="$OBF_DIR/agent_obf.js"
        echo "[+] obfuscated: $(wc -c < "$JS_INPUT") bytes"
      else
        echo "::warning::javascript-obfuscator unavailable/failed, embedding plain agent.js"
      fi
    else
      echo "::warning::npx not found, embedding plain agent.js"
    fi

    echo "[*] encrypting payload with guard key"
    python3 "$(dirname "$0")/gen_loader.py" "$JS_KEY" "$JS_INPUT"       "$APP_DIR/Frameworks/$JS_DOC_NAME" "$APP_DIR/Frameworks/${GADGET_NAME%.*}.config"
    ;;
  *)
    echo "usage: $0 {gadget <app_dir> | payload <app_dir> <js_key.bin> <js>}" >&2
    exit 1
    ;;
esac
