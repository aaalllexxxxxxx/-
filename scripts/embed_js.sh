#!/bin/bash
# embed_js.sh - JS 静态嵌入（宿主绑定加密版，A2 方案）
#
# 用法:
#   embed_js.sh gadget  <app_dir>                     -- 在 LC_LOAD 注入之前调用
#   embed_js.sh payload <app_dir> <host_bin> <js>     -- 在 ldid 签名完成之后调用
#
# 架构:
#   - Gadget 经 LC_LOAD 由 dyld 直接加载（inject_ipa_ldid.sh 注入）
#   - loader 壳为静态文件（Frameworks/<JS_DOC_NAME>，后缀/文件名可任意伪装，
#     Gadget 只按字节内容识别源码），config 由本脚本预置
#   - 业务 JS 先过 javascript-obfuscator（可选，失败则回退原文），再加密
#
# 密钥派生（构建期与运行期 loader 完全一致）:
#   digest     = SHA256(宿主主二进制 __TEXT 内偏移 0x4000 起的 4096 字节)
#   ← 不能绑定文件头(前 4096 字节)：TrollStore 安装时 ldid 重签会改写头部
#     load command 区(LC_CODE_SIGNATURE size)，实测导致安装后 digest 失配。
#     0x4000 窗口位于 __TEXT 代码区，重签不触碰，安装后仍稳定；
#     而 patch 业务代码仍会导致失配，互锁保持。
#   keystream_i = SHA256(digest || salt(8,LE) || counter(u32,LE))   每块 32 字节
#   明文       = magic(4, 构建期随机) || 业务 JS
# 剥壳/移植到其他 App/patch 宿主二进制 → digest 变 → 解密结果 magic 校验不过 → 拒绝 eval。
# 运行期 loader 用 NativeFunction 调系统 CC_SHA256，无任何第三方依赖；
# 禁止使用 atob/btoa（frida 的 QuickJS 不提供，已核实 gadget 16.5.9 符号）。
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
    # 抹去 Gadget install_name 中的 frida 特征
    install_name_tool -id "@executable_path/Frameworks/$GADGET_NAME" \
      "$APP_DIR/Frameworks/$GADGET_NAME" 2>/dev/null || true
    ;;

  payload)
    APP_DIR="$2"; HOST_BIN="$3"; JS="$4"
    GADGET_NAME="${GADGET_NAME:-FridaGadget.dylib}"
    JS_DOC_NAME="${JS_DOC_NAME:-.agent_cache.js}"

    # ---- C: 业务 JS 混淆（失败回退原文；产物若含 atob 也回退）----
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

    # ---- A2: 宿主绑定加密 + 生成随机化 loader 壳 ----
    echo "[*] computing host digest from signed binary"
    python3 - "$HOST_BIN" "$JS_INPUT" "$APP_DIR/Frameworks/$JS_DOC_NAME" \
      "$APP_DIR/Frameworks/${GADGET_NAME%.*}.config" <<'PYEOF'
import hashlib, os, sys

host_bin, js_path, loader_path, config_path = sys.argv[1:5]

WIN_OFF, WIN_LEN = 0x4000, 4096
with open(host_bin, 'rb') as f:
    f.seek(WIN_OFF)
    window = f.read(WIN_LEN)
if len(window) < WIN_LEN:
    raise SystemExit(f"::error::host binary smaller than {WIN_OFF + WIN_LEN:#x}, adjust WIN_OFF")
digest = hashlib.sha256(window).digest()
with open(js_path, 'rb') as f:
    raw = f.read()

salt = os.urandom(8)
magic = os.urandom(4)
plain = magic + raw

# keystream: SHA256(digest || salt || counter_u32le), 每块 32 字节
blocks = (len(plain) + 31) // 32
ks = bytearray()
for i in range(blocks):
    ks.extend(hashlib.sha256(digest + salt + i.to_bytes(4, 'little')).digest())
ct = bytes(p ^ k for p, k in zip(plain, ks))

# 随机化 loader 标识符（对抗通用特征剥壳脚本）
def rid():
    return 'v' + os.urandom(6).hex()
v = {name: rid() for name in
     ('S','D','gm','cc','ib','ob','ib2','h2b','dg','sl','ctb','ks','rp',
      'nb','i1','i2','inp','blk','ptb','mg','sv')}

L = []
A = L.append
A("const " + v['S'] + "='" + salt.hex() + "'," + v['D'] + "='" + ct.hex() + "';")
A("(function(){")
# 真机可见上报:console + UIAlertView(调试期保留,稳定后可移除)
A("function " + v['rp'] + "(m){console.log('[pipeline] '+m);"
  "try{ObjC.schedule(ObjC.mainQueue,function(){"
  "ObjC.classes.UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_('pipeline',m,NULL,'ok',NULL).show();"
  "});}catch(e){}}")
# 每阶段独立 try/catch,失败即上报并中止
A("try{")
A("var " + v['gm'] + "=Process.enumerateModules()[0];"
  "if(!" + v['gm'] + ")throw new Error('no modules');")
A("var " + v['cc'] + "=new NativeFunction(Module.getExportByName(null,'CC_SHA256'),'pointer',['pointer','uint32','pointer']);")
A("var " + v['ib'] + "=Memory.alloc(4096)," + v['ob'] + "=Memory.alloc(64)," + v['ib2'] + "=Memory.alloc(64);")
A("var " + v['h2b'] + "=function(h){var r=[],i;for(i=0;i<h.length;i+=2)r.push(parseInt(h.substr(i,2),16));return r;};")
A("Memory.copy(" + v['ib'] + "," + v['gm'] + ".base.add(0x4000),4096);")
A(v['cc'] + "(" + v['ib'] + ",4096," + v['ob'] + ");")
A("var " + v['dg'] + "=new Uint8Array(Memory.readByteArray(" + v['ob'] + ",32));")
A(v['rp'] + "('stage1 digest='+Array.prototype.map.call(" + v['dg'] + ",function(x){return ('0'+x.toString(16)).slice(-2);}).join('').slice(0,16));")
A("}catch(e){" + v['rp'] + "('stage1 failed: '+e);return;}")
A("var " + v['sl'] + "=" + v['h2b'] + "('" + salt.hex() + "');")
A("var " + v['ctb'] + "=" + v['h2b'] + "('" + ct.hex() + "');")
A("try{")
A("var " + v['ks'] + "=[],nb=Math.ceil(" + v['ctb'] + ".length/32)," + v['i1'] + "," + v['i2'] + "," + v['inp'] + "," + v['blk'] + ";")
A("for(" + v['i1'] + "=0;" + v['i1'] + "<nb;" + v['i1'] + "++){")
A(v['inp'] + "=new Uint8Array(44);")
A(v['inp'] + ".set(" + v['dg'] + ",0);" + v['inp'] + ".set(" + v['sl'] + ",32);")
A(v['inp'] + "[40]=(" + v['i1'] + "&255);" + v['inp'] + "[41]=(" + v['i1'] + ">>>8)&255;")
A(v['inp'] + "[42]=(" + v['i1'] + ">>>16)&255;" + v['inp'] + "[43]=(" + v['i1'] + ">>>24)&255;")
A("Memory.writeByteArray(" + v['ib2'] + ",Array.prototype.slice.call(" + v['inp'] + "));")
A(v['cc'] + "(" + v['ib2'] + ",44," + v['ob'] + ");")
A(v['blk'] + "=new Uint8Array(Memory.readByteArray(" + v['ob'] + ",32));")
A("for(" + v['i2'] + "=0;" + v['i2'] + "<32;" + v['i2'] + "++)" + v['ks'] + ".push(" + v['blk'] + "[" + v['i2'] + "]);")
A("}" + v['rp'] + "('stage2 ks ok');")
A("}catch(e){" + v['rp'] + "('stage2 failed: '+e);return;}")
A("try{")
A("var " + v['ptb'] + "=new Uint8Array(" + v['ctb'] + ".length);")
A("for(" + v['i1'] + "=0;" + v['i1'] + "<" + v['ctb'] + ".length;" + v['i1'] + "++)" + v['ptb'] + "[" + v['i1'] + "]=" + v['ctb'] + "[" + v['i1'] + "]^" + v['ks'] + "[" + v['i1'] + "];")
A("var " + v['mg'] + "=[" + ','.join(str(b) for b in magic) + "];")
A("for(" + v['i1'] + "=0;" + v['i1'] + "<4;" + v['i1'] + "++)if(" + v['ptb'] + "[" + v['i1'] + "]!==" + v['mg'] + "[" + v['i1'] + "]){" + v['rp'] + "('stage3 key mismatch (host changed?)');return;}")
A("var " + v['sv'] + "='';")
A("for(" + v['i1'] + "=4;" + v['i1'] + "<" + v['ptb'] + ".length;" + v['i1'] + "+=4096)" + v['sv'] + "+=String.fromCharCode.apply(null," + v['ptb'] + ".subarray(" + v['i1'] + ",Math.min(" + v['i1'] + "+4096," + v['ptb'] + ".length)));")
A("try{" + v['sv'] + "=decodeURIComponent(escape(" + v['sv'] + "));}catch(e){}")
A("try{(0,eval)(" + v['sv'] + ");" + v['rp'] + "('loaded OK');}catch(e){" + v['rp'] + "('stage4 eval failed: '+e);}")
A("}catch(e){" + v['rp'] + "('stage3/4 failed: '+e);}")
A("})();")
loader = "".join(L)

with open(loader_path, 'w') as f:
    f.write(loader)

# Gadget config：相对路径由 Gadget 在 Frameworks（其所在目录）回退解析
with open(config_path, 'w') as f:
    f.write('{"interaction":{"type":"script","path":"%s","on_change":"ignore"}}\n' % os.path.basename(loader_path))

print(f"[+] host-bound payload -> {loader_path} ({len(loader)} bytes, "
      f"plain {len(raw)} bytes, {blocks} keystream blocks)")
print(f"[+] build-side window digest (0x{WIN_OFF:x}+{WIN_LEN}): {digest.hex()}")
PYEOF
    ;;

  *)
    echo "usage: $0 {gadget <app_dir> | payload <app_dir> <host_bin> <js>}" >&2
    exit 1
    ;;
esac
