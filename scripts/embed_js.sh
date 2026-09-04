#!/bin/bash
# embed_js.sh - 下载 FridaGadget、AES-256-GCM 加密 JS、伪装命名嵌入 app
#               （必须在 inject 之后执行，密钥与注入后的宿主二进制绑定）
#
# 用法: GADGET_NAME=xxx.dylib JS_BLOB_NAME=yyy.bin ./embed_js.sh <app_dir> <agent.js> <salt_hex> <magic_hex>
# 密文格式: magic(8) || nonce(12) || ciphertext || tag(16)
# key = SHA-256( host_digest(8,LE) || salt(8,LE) || plain_len(8,LE) )
set -euo pipefail

APP_DIR="$1"; JS="$2"; SALT="$3"; MAGIC="${4:-0x474d414749433031}"
GADGET_NAME="${GADGET_NAME:-FridaGadget.dylib}"
JS_BLOB_NAME="${JS_BLOB_NAME:-agent.js.enc}"
JS_DOC_NAME="${JS_DOC_NAME:-.agent_cache.js}"
APP_NAME=$(basename "$APP_DIR" .app)
BIN="$APP_DIR/$APP_NAME"
FRIDA_VERSION="${FRIDA_VERSION:-16.5.9}"

echo "[*] fetching FridaGadget $FRIDA_VERSION -> $GADGET_NAME"
curl -fL --retry 3 -o /tmp/gadget.gz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-ios-universal.dylib.gz"
gunzip -c /tmp/gadget.gz > "$APP_DIR/Frameworks/$GADGET_NAME"
chmod 755 "$APP_DIR/Frameworks/$GADGET_NAME"
# 抹去 Gadget install_name 中的 frida 特征（可选：伪装成普通自引用库）
install_name_tool -id "@executable_path/Frameworks/$GADGET_NAME" \
  "$APP_DIR/Frameworks/$GADGET_NAME" 2>/dev/null || true

echo "[*] computing host digest (FNV-1a over first 4096 bytes, seed 'HOST')"
DIGEST=$(python3 - "$BIN" <<'EOF'
import sys
with open(sys.argv[1], 'rb') as f:
    data = f.read(4096)
h = 1469598103934665603 ^ 0x484F5354
for b in data:
    h ^= b
    h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
print(h)
EOF
)

echo "[*] wrapping agent.js with self-decrypting loader (XOR+base64, plaintext never hits disk)"
python3 - "$JS" "$APP_DIR/Frameworks/$JS_BLOB_NAME" "$DIGEST" "$SALT" "$MAGIC" <<'EOF'
import sys, hashlib, os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

src, dst, digest, salt, magic = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4], 16), int(sys.argv[5], 16)

with open(src, 'rb') as f:
    raw = f.read()

# 第一层：业务代码 XOR+base64，loader 在 JS 引擎内存里解码 eval。
# 明文业务逻辑只存在于内存，磁盘上（config path 指向的脚本文件）只有 loader 壳。
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

plain = loader.encode()

# KDF: key = SHA-256( digest || salt || plain_len )，与 guard.c 完全一致
key = hashlib.sha256(
    digest.to_bytes(8, 'little')
    + salt.to_bytes(8, 'little')
    + len(plain).to_bytes(8, 'little')
).digest()

nonce = os.urandom(12)
ct_with_tag = AESGCM(key).encrypt(nonce, plain, None)
ct, tag = ct_with_tag[:-16], ct_with_tag[-16:]

# 头部写入 magic，供 guard 运行时在任意伪装文件名中识别密文
with open(dst, 'wb') as f:
    f.write(magic.to_bytes(8, 'little') + nonce + ct + tag)
print(f"[+] encrypted -> {dst} ({8 + 12 + len(ct) + 16} bytes, loader-wrapped {len(plain)} bytes)")
EOF

# 预置 Gadget config（构建期写入，运行期只读即可）。
# iOS 上 script 相对路径会先在 app Documents 目录查找（frida-core 16.x 行为），
# guard 运行时把解密后的 JS 写到 Documents/<JS_DOC_NAME>，Gadget 据此加载。
GADGET_STEM="${GADGET_NAME%.*}"
echo "[*] writing Gadget config -> $GADGET_STEM.config (script path: $JS_DOC_NAME)"
printf '{"interaction":{"type":"script","path":"%s","on_change":"ignore"}}\n' \
  "$JS_DOC_NAME" > "$APP_DIR/Frameworks/$GADGET_STEM.config"

echo "[*] fake-signing gadget"
ldid -S "$APP_DIR/Frameworks/$GADGET_NAME"
