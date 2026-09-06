#!/bin/bash
# embed_js.sh - 静态嵌入 FridaGadget 与 loader JS（稳妥模式）
#
# 放弃"运行时解密落盘"方案（AES 密文 + host digest 绑定 + Documents 落盘），
# 该链路任一环节失败都是静默的且无法在真机上定位。稳妥模式：
#   - Gadget 由 dyld 经 LC_LOAD 直接加载（inject_ipa_ldid.sh 注入）
#   - loader 壳 JS（XOR+base64 包装业务代码，明文逻辑不上盘）静态放
#     Frameworks/<JS_DOC_NAME>；frida-core 对相对路径的解析顺序为
#     数据容器 Documents -> Gadget 所在 Frameworks 目录（gadget.vala
#     resolve_script_path/resolve_asset_path），Frameworks 静态文件命中回退分支
#   - config 构建期预置，运行期零写入
# 代价：密文与宿主绑定失效，loader 可被剥壳（以稳妥换安全）。
#
# 用法: GADGET_NAME=xxx.dylib JS_DOC_NAME=.yyy.js ./embed_js.sh <app_dir> <agent.js>
set -euo pipefail

APP_DIR="$1"; JS="$2"
GADGET_NAME="${GADGET_NAME:-FridaGadget.dylib}"
JS_DOC_NAME="${JS_DOC_NAME:-.agent_cache.js}"
FRIDA_VERSION="${FRIDA_VERSION:-16.5.9}"

echo "[*] fetching FridaGadget $FRIDA_VERSION -> $GADGET_NAME"
curl -fL --retry 3 -o /tmp/gadget.gz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-ios-universal.dylib.gz"
gunzip -c /tmp/gadget.gz > "$APP_DIR/Frameworks/$GADGET_NAME"
chmod 755 "$APP_DIR/Frameworks/$GADGET_NAME"
# 抹去 Gadget install_name 中的 frida 特征
install_name_tool -id "@executable_path/Frameworks/$GADGET_NAME" \
  "$APP_DIR/Frameworks/$GADGET_NAME" 2>/dev/null || true

echo "[*] wrapping agent.js with self-decrypting loader (XOR+base64, plaintext never hits disk)"
python3 - "$JS" "$APP_DIR/Frameworks/$JS_DOC_NAME" <<'PYEOF'
import sys, os, base64

src, dst = sys.argv[1], sys.argv[2]
with open(src, 'rb') as f:
    raw = f.read()

# 业务代码 XOR+base64，loader 在 JS 引擎内存里解码 eval。
# 磁盘上只有 loader 壳，明文业务逻辑只存在于内存。
xor_key = os.urandom(32)
enc = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(raw))
b64 = base64.b64encode(enc).decode()
key_hex = xor_key.hex()

loader = (
    "const __k='" + key_hex + "';const __d='" + b64 + "';"
    "(function(){var kb=[];for(var i=0;i<__k.length;i+=2)kb.push(parseInt(__k.substr(i,2),16));"
    "var db=atob(__d),bs=[];for(var j=0;j<db.length;j++)bs.push(String.fromCharCode(db.charCodeAt(j)^kb[j%kb.length]));"
    "var s=bs.join('');"
    "try{s=decodeURIComponent(escape(s));}catch(e){}"
    "(0,eval)(s);})();"
)

with open(dst, 'w') as f:
    f.write(loader)
print(f"[+] loader -> {dst} ({len(loader)} bytes)")
PYEOF

# 预置 Gadget config：相对路径由 Gadget 在 Frameworks（其所在目录）回退解析
GADGET_STEM="${GADGET_NAME%.*}"
echo "[*] writing Gadget config -> $GADGET_STEM.config (script path: $JS_DOC_NAME)"
printf '{"interaction":{"type":"script","path":"%s","on_change":"ignore"}}\n' \
  "$JS_DOC_NAME" > "$APP_DIR/Frameworks/$GADGET_STEM.config"
