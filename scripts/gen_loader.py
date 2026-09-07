#!/usr/bin/env python3
"""生成宿主无关、guard 密钥绑定的 loader 壳 + Gadget config。

用法: gen_loader.py <js_key.bin> <agent.js> <loader_path> <config_path>

密钥(构建期与运行期一致):
  key         = guard 构建期生成的随机 32 字节
  keystream_i = SHA256(key || salt(8) || counter(u32,LE))   每块 32 字节
  明文        = magic(4, 构建期随机) || 业务 JS
运行期 loader 通过 Module.getExportByName(null,'guard_js_key') 调 guard
导出符号取同一密钥。guard 被移除 -> loader 取不到符号 -> JS 不加载(互锁)。
不依赖宿主二进制 -> 适用于任意 IPA,不受安装对二进制改动影响。
禁止使用 atob/btoa(frida QuickJS 不提供)。
"""
import hashlib, os, sys


def main():
    js_key_path, js_path, loader_path, config_path = sys.argv[1:5]
    with open(js_key_path, "rb") as f:
        key = f.read()
    assert len(key) == 32, "js_key must be 32 bytes, got " + str(len(key))
    with open(js_path, "rb") as f:
        raw = f.read()

    salt = os.urandom(8)
    magic = os.urandom(4)
    plain = magic + raw
    blocks = (len(plain) + 31) // 32
    ks = bytearray()
    for i in range(blocks):
        ks.extend(hashlib.sha256(key + salt + i.to_bytes(4, "little")).digest())
    ct = bytes(p ^ k for p, k in zip(plain, ks))

    def rid():
        return "v" + os.urandom(6).hex()

    names = ("S", "D", "kp", "cc", "sha", "ib", "ob", "h2b", "dg", "sl", "ctb",
             "ks", "rp", "i1", "i2", "inp", "blk", "ptb", "mg", "sv")
    v = {n: rid() for n in names}
    S, D = v["S"], v["D"]
    KP, CC, SHA = v["kp"], v["cc"], v["sha"]
    IB, OB, H2B = v["ib"], v["ob"], v["h2b"]
    DG, SL, CTB, KS = v["dg"], v["sl"], v["ctb"], v["ks"]
    RP, I1, I2, INP, BLK = v["rp"], v["i1"], v["i2"], v["inp"], v["blk"]
    PTB, MG, SV = v["ptb"], v["mg"], v["sv"]
    salt_hex = salt.hex()
    ct_hex = ct.hex()
    mg_csv = ",".join(str(b) for b in magic)

    L = []

    def A(s):
        L.append(s)

    A("const " + S + "='" + salt_hex + "'," + D + "='" + ct_hex + "';")
    A("(function(){")
    A("function " + RP + "(m){console.log('[pipeline] '+m);"
      "try{ObjC.schedule(ObjC.mainQueue,function(){"
      "ObjC.classes.UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_('pipeline',m,NULL,'ok',NULL).show();"
      "});}catch(e){}}")
    A("try{")
    A("var " + KP + "=Module.getExportByName(null,'guard_js_key');"
      "if(!" + KP + ")throw new Error('guard not present');")
    A("var " + CC + "=new NativeFunction(" + KP + ",'pointer',[]);")
    A("var " + SHA + "=new NativeFunction(Module.getExportByName(null,'CC_SHA256'),'pointer',['pointer','uint32','pointer']);")
    A("var " + IB + "=Memory.alloc(64)," + OB + "=Memory.alloc(64);")
    A("var " + H2B + "=function(h){var r=[],i;for(i=0;i<h.length;i+=2)r.push(parseInt(h.substr(i,2),16));return r;};")
    A("var " + KP + "_ptr=" + CC + "();")
    A("var " + DG + "=new Uint8Array(Memory.readByteArray(" + KP + "_ptr,32));")
    A("var " + SL + "=" + H2B + "('" + salt_hex + "');")
    A("var " + CTB + "=" + H2B + "('" + ct_hex + "');")
    A("}catch(e){" + RP + "('stage1 key fetch failed: '+e);return;}")
    A("try{")
    A("var " + KS + "=[],nb=Math.ceil(" + CTB + ".length/32)," + I1 + "," + I2 + "," + INP + "," + BLK + ";")
    A("for(" + I1 + "=0;" + I1 + "<nb;" + I1 + "++){")
    A(INP + "=new Uint8Array(44);")
    A(INP + ".set(" + DG + ",0);" + INP + ".set(" + SL + ",32);")
    A(INP + "[40]=(" + I1 + "&255);" + INP + "[41]=(" + I1 + ">>>8)&255;")
    A(INP + "[42]=(" + I1 + ">>>16)&255;" + INP + "[43]=(" + I1 + ">>>24)&255;")
    A("Memory.writeByteArray(" + IB + ",Array.prototype.slice.call(" + INP + "));")
    A(SHA + "(" + IB + ",44," + OB + ");")
    A(BLK + "=new Uint8Array(Memory.readByteArray(" + OB + ",32));")
    A("for(" + I2 + "=0;" + I2 + "<32;" + I2 + "++)" + KS + ".push(" + BLK + "[" + I2 + "]);")
    A("}" + RP + "('stage2 ks ok');")
    A("}catch(e){" + RP + "('stage2 failed: '+e);return;}")
    A("try{")
    A("var " + PTB + "=new Uint8Array(" + CTB + ".length);")
    A("for(" + I1 + "=0;" + I1 + "<" + CTB + ".length;" + I1 + "++)" + PTB + "[" + I1 + "]=" + CTB + "[" + I1 + "]^" + KS + "[" + I1 + "];")
    A("var " + MG + "=[" + mg_csv + "];")
    A("for(" + I1 + "=0;" + I1 + "<4;" + I1 + "++)if(" + PTB + "[" + I1 + "]!==" + MG + "[" + I1 + "]){" + RP + "('stage3 key mismatch');return;}")
    A("var " + SV + "='';")
    A("for(" + I1 + "=4;" + I1 + "<" + PTB + ".length;" + I1 + "+=4096)" + SV + "+=String.fromCharCode.apply(null," + PTB + ".subarray(" + I1 + ",Math.min(" + I1 + "+4096," + PTB + ".length)));")
    A("try{" + SV + "=decodeURIComponent(escape(" + SV + "));}catch(e){}")
    A("try{(0,eval)(" + SV + ");" + RP + "('loaded OK');}catch(e){" + RP + "('stage4 eval failed: '+e);}")
    A("}catch(e){" + RP + "('stage3/4 failed: '+e);}")
    A("})();")

    loader = "".join(L)
    with open(loader_path, "w") as f:
        f.write(loader)
    with open(config_path, "w") as f:
        f.write('{"interaction":{"type":"script","path":"%s","on_change":"ignore"}}\n'
                % os.path.basename(loader_path))
    print("[+] guard-key payload -> " + loader_path + " ("
          + str(len(loader)) + " bytes, plain " + str(len(raw))
          + " bytes, " + str(blocks) + " keystream blocks)")


if __name__ == "__main__":
    main()
