#!/usr/bin/env python3
# verify_blob.py - 工作流自检：解密 JS 密文，验证 loader 包装与业务代码一致性
#
# 用法: verify_blob.py <blob> <app_binary> <agent.js> <salt_hex> <magic_hex>
# 校验:
#   1. AES-256-GCM 解密成功（密钥与注入后宿主绑定，KDF 与 guard.c 一致）
#   2. 明文以 loader 壳开头（业务代码已经 XOR+base64 包装，磁盘无业务明文）
#   3. loader 载荷还原后与原始 agent.js 逐字节一致
import base64
import hashlib
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC_LEN, NONCE_LEN, TAG_LEN = 8, 12, 16


def host_digest(path: str) -> int:
    h = 1469598103934665603 ^ 0x484F5354
    with open(path, 'rb') as f:
        for b in f.read(4096):
            h ^= b
            h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def main() -> int:
    blob_path, bin_path, js_path, salt_hex, magic_hex = sys.argv[1:6]
    salt, magic = int(salt_hex, 16), int(magic_hex, 16)

    with open(blob_path, 'rb') as f:
        blob = f.read()
    if blob[:MAGIC_LEN] != magic.to_bytes(MAGIC_LEN, 'little'):
        print('FAIL: magic mismatch')
        return 1

    nonce = blob[MAGIC_LEN:MAGIC_LEN + NONCE_LEN]
    ct, tag = blob[MAGIC_LEN + NONCE_LEN:-TAG_LEN], blob[-TAG_LEN:]

    key = hashlib.sha256(
        host_digest(bin_path).to_bytes(8, 'little')
        + salt.to_bytes(8, 'little')
        + len(ct).to_bytes(8, 'little')
    ).digest()
    try:
        plain = AESGCM(key).decrypt(nonce, ct + tag, None)
    except Exception as e:
        print(f'FAIL: GCM auth failed: {e}')
        return 1

    if not plain.startswith(b"const __k='"):
        print('FAIL: loader wrapper missing (raw plaintext on disk)')
        return 1
    if b"__test" in plain[:64]:
        pass  # placeholder guard

    # 从 loader 壳提取载荷并还原，比对原始 agent.js
    k_start = plain.index(b"const __k='") + len(b"const __k='")
    k_end = plain.index(b"'", k_start)
    d_start = plain.index(b";const __d='", k_end) + len(b";const __d='")
    d_end = plain.index(b"'", d_start)
    xor_key = bytes.fromhex(plain[k_start:k_end].decode())
    enc = base64.b64decode(plain[d_start:d_end])
    restored = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(enc))

    with open(js_path, 'rb') as f:
        original = f.read()
    if restored != original:
        print('FAIL: restored payload != original agent.js')
        return 1

    print(f'[ok] blob verified: GCM auth pass, loader-wrapped, '
          f'restored sha256={hashlib.sha256(restored).hexdigest()[:16]} '
          f'({len(original)} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
