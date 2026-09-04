/*
 * guard.c - 注入型加固 dylib 核心
 *
 * 防护能力：
 *  1. 反调试（PT_DENY_ATTACH + sysctl 轮询检测）
 *  2. 完整性校验（对宿主 Mach-O 关键段做哈希，dylib 被移除时宿主侧校验失败）
 *  3. 反 hook（检查关键函数前导指令是否被改写、__DATA 段绑定是否被重绑）
 *  4. 环境检测（越狱特征、Frida/Cycript/Substitute 等注入框架）
 *  5. 字符串加密（编译期 XOR，运行期按需解密，对抗静态分析）
 *
 * 与宿主应用的互锁协议：
 *  - 启动时 dylib 计算宿主 Mach-O 的校验值，写入共享内存页并投递通知
 *  - 宿主侧 guard_host.m 周期性地校验 dylib 是否仍在内存、共享页内容是否合法
 *  - 任一侧校验失败 -> 调用 abort() 终止进程（配合崩溃混淆，避免被轻易 patch）
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <limits.h>
#include <CommonCrypto/CommonCrypto.h>
#include <TargetConditionals.h>

/* ============ 编译期字符串混淆 ============ */

/* 密钥建议每次构建由脚本随机生成并注入 */
#ifndef GUARD_STR_KEY
#define GUARD_STR_KEY 0x5A
#endif

/* 用脚本生成 ENC(...) 数组；运行期解密到栈上 */
#define ENC_DECL(name, ...) static const unsigned char name[] = { __VA_ARGS__, 0 ^ GUARD_STR_KEY }
static void dec(const unsigned char *enc, char *out, size_t n) {
    for (size_t i = 0; i < n; i++) out[i] = (char)(enc[i] ^ GUARD_STR_KEY);
    out[n] = 0;
}

/* "frida" / "cycript" / "substrate" / "substitute" 等特征串，构建脚本中生成 */
ENC_DECL(k_str_frida,    'f'^GUARD_STR_KEY,'r'^GUARD_STR_KEY,'i'^GUARD_STR_KEY,'d'^GUARD_STR_KEY,'a'^GUARD_STR_KEY);
ENC_DECL(k_str_cycript,  'c'^GUARD_STR_KEY,'y'^GUARD_STR_KEY,'c'^GUARD_STR_KEY,'r'^GUARD_STR_KEY,'i'^GUARD_STR_KEY,'p'^GUARD_STR_KEY,'t'^GUARD_STR_KEY);
ENC_DECL(k_str_substrate,'s'^GUARD_STR_KEY,'u'^GUARD_STR_KEY,'b'^GUARD_STR_KEY,'s'^GUARD_STR_KEY,'t'^GUARD_STR_KEY,'r'^GUARD_STR_KEY,'a'^GUARD_STR_KEY,'t'^GUARD_STR_KEY,'e'^GUARD_STR_KEY);
ENC_DECL(k_str_substitute,'s'^GUARD_STR_KEY,'u'^GUARD_STR_KEY,'b'^GUARD_STR_KEY,'s'^GUARD_STR_KEY,'t'^GUARD_STR_KEY,'i'^GUARD_STR_KEY,'t'^GUARD_STR_KEY,'u'^GUARD_STR_KEY,'t'^GUARD_STR_KEY,'e'^GUARD_STR_KEY);
ENC_DECL(k_str_guardpage, "guard.shared.v1"[0]^GUARD_STR_KEY, 'g'^GUARD_STR_KEY,'u'^GUARD_STR_KEY,'a'^GUARD_STR_KEY,'r'^GUARD_STR_KEY,'d'^GUARD_STR_KEY,'.'^GUARD_STR_KEY,'s'^GUARD_STR_KEY,'h'^GUARD_STR_KEY,'a'^GUARD_STR_KEY,'r'^GUARD_STR_KEY,'e'^GUARD_STR_KEY,'d'^GUARD_STR_KEY,'.'^GUARD_STR_KEY,'v'^GUARD_STR_KEY,'1'^GUARD_STR_KEY);

/* ============ 轻量哈希（FNV-1a 64，避免引入外部依赖） ============ */

static uint64_t fnv1a(const void *data, size_t len, uint64_t seed) {
    const unsigned char *p = (const unsigned char *)data;
    uint64_t h = 1469598103934665603ULL ^ seed;
    for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

/* ============ 共享校验页：dylib 与宿主之间的互锁通道 ============ */

typedef struct {
    uint64_t magic;          /* 0x4755415244303031 "GUARD001" */
    uint64_t host_digest;    /* 宿主 __TEXT 关键段哈希 */
    uint64_t self_digest;    /* dylib 自身在内存中的哈希 */
    uint64_t heartbeat;      /* 心跳计数，宿主侧校验它持续增长 */
    uint64_t flags;          /* 检测到的风险位 */
} guard_page_t;

#define GUARD_MAGIC 0x4755415244303031ULL

static guard_page_t *g_page;
static volatile int g_abort_flag = 0;

/* ============ 反调试 ============ */

static void deny_attach(void) {
#if !TARGET_OS_SIMULATOR
    /* PT_DENY_ATTACH = 31 */
    typedef int (*ptrace_t)(int, pid_t, caddr_t, int);
    void *h = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    ptrace_t pt = (ptrace_t)dlsym(h, "ptrace");
    if (pt) pt(31, 0, 0, 0);
#endif
}

static int debugger_attached(void) {
    struct kinfo_proc info;
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    size_t sz = sizeof(info);
    if (sysctl(mib, 4, &info, &sz, NULL, 0) != 0) return 0;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

/* ============ 注入框架 / 越狱环境检测 ============ */

static int injected_framework_present(void) {
    uint32_t n = _dyld_image_count();
    char buf[16];
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        dec(k_str_frida, buf, 5);       if (strstr(name, buf)) return 1;
        dec(k_str_cycript, buf, 7);     if (strstr(name, buf)) return 1;
        dec(k_str_substrate, buf, 9);   if (strstr(name, buf)) return 1;
        dec(k_str_substitute, buf, 10); if (strstr(name, buf)) return 1;
    }
    return 0;
}

static int jailbreak_artifacts_present(void) {
    const char *paths[] = {
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/sbin/frida-server",
        "/private/var/lib/apt",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        /* 用 open 而非 access，部分越狱检测绕过工具只钩 access/stat */
        int fd = open(paths[i], O_RDONLY);
        if (fd >= 0) { close(fd); return 1; }
    }
    return 0;
}

/* ============ 反 hook：校验关键函数前导指令 ============ */

/*
 * 对进程内关键系统函数取样，检查前 16 字节是否为正常指令流。
 * 被 inline hook 时开头通常被改写为绝对跳转（如 ldr x16/br x16 或 bl 跳板）。
 */
static int prologue_tampered(void) {
    const char *syms[] = { "open", "read", "stat", "dlopen", "sysctl" };
    for (int i = 0; i < 5; i++) {
        void *p = dlsym(RTLD_DEFAULT, syms[i]);
        if (!p) continue;
        uint32_t *ins = (uint32_t *)p;
        /* AArch64: 检测常见的 trampoline 模式
         *  LDR X16, #8 ; BR X16  =>  0x58000050, 0xD61F0200
         *  B #imm (相对跳转覆盖) => 高 6 位为 000101
         */
        if (ins[0] == 0x58000050 && ins[1] == 0xD61F0200) return 1;
        if ((ins[0] & 0xFC000000) == 0x14000000) {
            /* 正常函数极少以无条件 B 开头（除了 PLT），结合目标距离判断 */
            int64_t off = ((int64_t)(ins[0] & 0x03FFFFFF) << 2);
            if (off < -(1 << 24) || off > (1 << 24)) return 1;
        }
    }
    return 0;
}

/* ============ 完整性校验 ============ */

static uint64_t digest_host_text(void) {
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!mh) return 0;
    /* 对 __TEXT 段头 + 前 N 字节取样哈希；全量哈希可用脚本在构建期固化期望值 */
    return fnv1a(mh, 4096, 0x484F5354ULL /* "HOST" */);
}

static uint64_t digest_self(void) {
    Dl_info info;
    if (!dladdr((void *)digest_self, &info)) return 0;
    return fnv1a(info.dli_fbase, 4096, 0x53454C46ULL /* "SELF" */);
}

/* ============ 生产级终止策略 ============ */

/*
 * 不直接 abort：随机延迟 0-30s 后，通过空指针写入崩溃，
 * 崩溃点远离检测点，增加攻击者用断点/日志定位检测逻辑的成本。
 */
static void guard_die(void);

/* 导出给 guard_bridge.mm：卡密被服务端拒绝时终止进程 */
__attribute__((visibility("default")))
void guard_request_die(void) {
    guard_die();
}

static void guard_die(void) {
    if (g_page) g_page->flags |= 1ULL << 63;   /* 留痕：宿主侧可见 */
    unsigned jitter = arc4random_uniform(30000);
    usleep(jitter * 1000);
    volatile uint64_t *p = (volatile uint64_t *)((uintptr_t)g_page ^ (uintptr_t)-1);
    *p = 0xDEAD;   /* 无效地址写入 -> SIGSEGV */
    abort();       /* 兜底 */
}

/* ============ 后台守护线程 ============ */

/* 解密后的 JS 明文临时文件路径（延迟清理，见 guard_loop） */
static char g_tmp_js_path[PATH_MAX];
static volatile int g_tmp_js_pending = 0;
static unsigned g_tmp_js_ticks = 0;

static void *guard_loop(void *arg) {
    (void)arg;
    for (;;) {
        uint64_t risk = 0;
        if (debugger_attached())          risk |= 1 << 0;
        if (injected_framework_present()) risk |= 1 << 1;
        if (prologue_tampered())          risk |= 1 << 2;
        if (jailbreak_artifacts_present())risk |= 1 << 3;

        if (g_page) {
            g_page->flags = risk;
            g_page->heartbeat++;
        }

        if (risk & ((1 << 0) | (1 << 1) | (1 << 2))) {
            g_abort_flag = 1;
            guard_die();
        }

        /* 兜底清理 JS 明文：dlopen 成功后已在主流程立即删除（Gadget constructor
         * 阻塞至脚本 init 完成，返回时脚本已读入内存），这里仅防极端时序，3s 即删 */
        if (g_tmp_js_pending && ++g_tmp_js_ticks >= 6) {
            g_tmp_js_ticks = 0;
            g_tmp_js_pending = 0;
            unlink(g_tmp_js_path);
        }
        usleep(500000); /* 500ms 轮询 */
    }
    return NULL;
}

/* ============ Frida JS 安全加载 ============ */

/*
 * JS 脚本加密存储在 app 内（Frameworks/agent.js.enc）。
 * 解密密钥派生自：宿主 Mach-O digest + 构建期嵌入的 salt + 设备进程特征。
 * 验证 dylib 被移除 -> 无人 dlopen FridaGadget，JS 永远是密文；
 * 验证 dylib 被 patch -> host_digest 变化 -> 密钥错误 -> 解密出垃圾 -> Gadget 拒绝加载。
 */

#ifndef GUARD_JS_SALT
#define GUARD_JS_SALT 0x1122334455667788ULL
#endif

/* 编译期注入的密文识别 magic（8 字节，每次构建随机，脚本同步用于加密打包）。
 * guard 不记任何固定文件名，靠 magic 扫描发现密文，文件名可任意伪装。 */
#ifndef GUARD_JS_MAGIC
#define GUARD_JS_MAGIC 0x474D414749433031ULL
#endif

/*
 * 密文格式: magic(8) || nonce(12) || ciphertext || tag(16)，AES-256-GCM。
 * key = SHA-256( host_digest(8, LE) || salt(8, LE) || plain_len(8, LE) )
 * 绑定宿主完整性 + 构建期 salt + 明文长度上下文。
 * GCM 认证标签使任何对密文/密钥的篡改都导致解密失败。
 */
#define GCM_MAGIC_LEN 8
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN   16

#include <dirent.h>
#include <sys/stat.h>

/* 在 dir 中查找带 GUARD_JS_MAGIC 头的文件（密文），返回 0 表示找到 */
static int find_blob_by_magic(const char *dir, char *out, size_t out_sz) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    uint64_t want = GUARD_JS_MAGIC;
    struct dirent *ent;
    int found = -1;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        uint64_t magic = 0;
        if (read(fd, &magic, 8) == 8 && magic == want) {
            strlcpy(out, path, out_sz);
            found = 0;
        }
        close(fd);
        if (found == 0) break;
    }
    closedir(d);
    return found;
}

/* 在 dir 中找体积最大的 dylib（FridaGadget 30MB+，业务库远小于它） */
static int find_gadget_by_size(const char *dir, const char *self_path,
                               char *out, size_t out_sz) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *ent;
    off_t best = 8 * 1024 * 1024;   /* 至少 8MB 才考虑，过滤普通业务库 */
    int found = -1;
    while ((ent = readdir(d)) != NULL) {
        size_t n = strlen(ent->d_name);
        if (n < 7 || strcmp(ent->d_name + n - 6, ".dylib") != 0) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (self_path && strstr(path, self_path)) continue;   /* 排除自身 */
        struct stat st;
        if (stat(path, &st) == 0 && st.st_size > best) {
            best = st.st_size;
            strlcpy(out, path, out_sz);
            found = 0;
        }
    }
    closedir(d);
    return found;
}

static void derive_js_key(uint8_t out[CC_SHA256_DIGEST_LENGTH],
                          uint64_t host_digest, uint64_t plain_len) {
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    uint64_t d = host_digest, s = GUARD_JS_SALT, l = plain_len;
    CC_SHA256_Update(&ctx, &d, 8);
    CC_SHA256_Update(&ctx, &s, 8);
    CC_SHA256_Update(&ctx, &l, 8);
    CC_SHA256_Final(out, &ctx);
}

/* ===== 手写 AES-256-GCM 解密（NIST SP 800-38D）=====
 * iOS SDK 公开 CommonCrypto 头文件未导出 GCM 接口（kCCModeGCM 等），
 * 故按标准手写：AES-ECB 单块 + CTR 异或 + GHASH 认证。
 * 与 embed_js.sh 中 Python cryptography 的 AESGCM（格式 nonce||ct||tag）互通。 */

/* AES-256 单块 ECB 加密（公开 API，GCM 构件） */
static void aes_ecb_encrypt_block(const uint8_t key[kCCKeySizeAES256],
                                  const uint8_t in[16], uint8_t out[16]) {
    size_t moved = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode,
            key, kCCKeySizeAES256, NULL, in, kCCBlockSizeAES128,
            out, kCCBlockSizeAES128, &moved);
}

/* GF(2^128) 乘法（MSB-first），结果覆盖 X */
static void gf128_mul(uint8_t X[16], const uint8_t H[16]) {
    uint8_t Z[16] = {0}, V[16];
    memcpy(V, H, 16);
    for (int i = 0; i < 16; i++) {
        for (int b = 7; b >= 0; b--) {
            if ((X[i] >> b) & 1)
                for (int k = 0; k < 16; k++) Z[k] ^= V[k];
            uint8_t lsb = V[15] & 1;
            for (int k = 15; k > 0; k--)
                V[k] = (uint8_t)((V[k] >> 1) | (V[k - 1] << 7));
            V[0] >>= 1;
            if (lsb) V[0] ^= 0xE1;
        }
    }
    memcpy(X, Z, 16);
}

/* GCM 解密：in 格式 nonce(12) || ct || tag(16)，空 AAD。
 * 认证失败返回 -1，成功返回 0，明文写入 plain（长度 = ct_len）。 */
static int gcm_decrypt(const uint8_t key[kCCKeySizeAES256],
                       const uint8_t *nonce_ct_tag, size_t total_len,
                       unsigned char *plain) {
    if (total_len <= GCM_NONCE_LEN + GCM_TAG_LEN) return -1;
    size_t ct_len = total_len - GCM_NONCE_LEN - GCM_TAG_LEN;
    const uint8_t *nonce = nonce_ct_tag;
    const uint8_t *ct    = nonce_ct_tag + GCM_NONCE_LEN;
    const uint8_t *tag   = nonce_ct_tag + GCM_NONCE_LEN + ct_len;

    uint8_t H[16], J0[16];
    static const uint8_t zero16[16] = {0};
    aes_ecb_encrypt_block(key, zero16, H);
    memcpy(J0, nonce, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    /* CTR：计数器从 inc32(J0) 起 */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    for (size_t off = 0; off < ct_len; off += 16) {
        for (int i = 15; i >= 12; i--) { if (++ctr[i]) break; }
        uint8_t ks[16];
        aes_ecb_encrypt_block(key, ctr, ks);
        size_t n = ct_len - off < 16 ? ct_len - off : 16;
        for (size_t i = 0; i < n; i++) plain[off + i] = ct[off + i] ^ ks[i];
    }

    /* GHASH（空 AAD || ct || 长度块） */
    uint8_t Y[16] = {0}, blk[16];
    for (size_t off = 0; off < ct_len; off += 16) {
        memset(blk, 0, 16);
        size_t n = ct_len - off < 16 ? ct_len - off : 16;
        memcpy(blk, ct + off, n);
        for (int i = 0; i < 16; i++) Y[i] ^= blk[i];
        gf128_mul(Y, H);
    }
    memset(blk, 0, 16);  /* AAD bitlen = 0 */
    uint64_t ctBits = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; i++) blk[8 + i] = (uint8_t)(ctBits >> ((7 - i) * 8));
    for (int i = 0; i < 16; i++) Y[i] ^= blk[i];
    gf128_mul(Y, H);

    /* tag = E_K(J0) XOR GHASH */
    uint8_t expect[16];
    aes_ecb_encrypt_block(key, J0, expect);
    for (int i = 0; i < 16; i++) expect[i] ^= Y[i];
    return memcmp(expect, tag, 16) == 0 ? 0 : -1;
}

/* 导出给 guard_bridge.mm 调用（卡密联动）；独立使用时由 constructor 直接调用 */
__attribute__((visibility("default")))
int guard_load_frida_agent(void) {
    char base[PATH_MAX];
    uint32_t sz = sizeof(base);
    if (_NSGetExecutablePath(base, &sz) != 0) return -1;
    char *slash = strrchr(base, '/');
    if (!slash) return -1;
    *slash = 0;

    char fw_dir[PATH_MAX];
    snprintf(fw_dir, sizeof(fw_dir), "%s/Frameworks", base);

    /* 1. 按 magic 扫描发现密文（文件名任意伪装） */
    char enc_path[PATH_MAX];
    if (find_blob_by_magic(fw_dir, enc_path, sizeof(enc_path)) != 0) return -1;

    int fd = open(enc_path, O_RDONLY);
    if (fd < 0) return -1;
    off_t total = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (total <= (off_t)(GCM_MAGIC_LEN + GCM_NONCE_LEN + GCM_TAG_LEN)) { close(fd); return -1; }
    unsigned char *blob = malloc(total);
    if (!blob || read(fd, blob, total) != total) { close(fd); free(blob); return -1; }
    close(fd);

    const unsigned char *nonce = blob + GCM_MAGIC_LEN;
    const unsigned char *ct    = blob + GCM_MAGIC_LEN + GCM_NONCE_LEN;
    size_t ct_len = (size_t)total - GCM_MAGIC_LEN - GCM_NONCE_LEN - GCM_TAG_LEN;
    const unsigned char *tag   = blob + GCM_MAGIC_LEN + GCM_NONCE_LEN + ct_len;

    /* 2. 派生密钥并解密（AES-256-GCM，认证失败即返回错误） */
    uint8_t key[CC_SHA256_DIGEST_LENGTH];
    derive_js_key(key, digest_host_text(), (uint64_t)ct_len);

    unsigned char *plain = malloc(ct_len);
    if (!plain) { free(blob); return -1; }

    if (gcm_decrypt(key, nonce, GCM_NONCE_LEN + ct_len + GCM_TAG_LEN, plain) != 0) {
        memset(key, 0, sizeof(key));
        free(plain);
        free(blob);
        return -1;
    }
    memset(key, 0, sizeof(key));
    free(blob);

    /* 3. 先解密到 TMPDIR 临时文件（rename 原子化落地用，延迟清理见 guard_loop） */
    char tmp[PATH_MAX];
    const char *td = getenv("TMPDIR");
    snprintf(tmp, sizeof(tmp), "%s/gXXXXXX.js", td ? td : "/tmp");
    int tfd = mkstemps(tmp, 3);
    if (tfd < 0) { memset(plain, 0, ct_len); free(plain); return -1; }
    size_t off = 0;
    while (off < ct_len) {
        ssize_t n = write(tfd, plain + off, ct_len - off);
        if (n <= 0) break;
        off += (size_t)n;
    }
    close(tfd);
    if (off != ct_len) { memset(plain, 0, ct_len); free(plain); unlink(tmp); return -1; }
    memset(plain, 0, ct_len);
    free(plain);

    /* 4. 发现 Gadget 并读取其嵌入 config（构建期由 embed_js.sh 预置到 Frameworks），
     *    从中解析 script 相对路径名 —— Gadget 会在 Documents 下优先查找该名字 */
    char gadget_path[PATH_MAX];
    Dl_info self_info;
    const char *self_name = NULL;
    if (dladdr((void *)guard_load_frida_agent, &self_info) && self_info.dli_fname)
        self_name = strrchr(self_info.dli_fname, '/');
    if (find_gadget_by_size(fw_dir, self_name, gadget_path, sizeof(gadget_path)) != 0) {
        unlink(tmp);
        return -1;
    }
    char cfg_path[PATH_MAX];
    strlcpy(cfg_path, gadget_path, sizeof(cfg_path));
    char *dot = strrchr(cfg_path, '.');
    if (dot) *dot = 0;
    strlcat(cfg_path, ".config", sizeof(cfg_path));
    char cfg_data[2048];
    {
        int cfd = open(cfg_path, O_RDONLY);
        if (cfd < 0) { unlink(tmp); return -1; }
        ssize_t n = read(cfd, cfg_data, sizeof(cfg_data) - 1);
        close(cfd);
        if (n <= 0) { unlink(tmp); return -1; }
        cfg_data[n] = 0;
    }
    const char *pk = strstr(cfg_data, "\"path\":\"");
    if (!pk) { unlink(tmp); return -1; }
    pk += strlen("\"path\":\"");
    const char *pe = strchr(pk, '"');
    if (!pe || pe == pk || (size_t)(pe - pk) >= PATH_MAX) { unlink(tmp); return -1; }
    char js_name[PATH_MAX];
    memcpy(js_name, pk, (size_t)(pe - pk));
    js_name[pe - pk] = 0;
    if (js_name[0] == '/') { unlink(tmp); return -1; } /* 仅支持相对路径（Documents 解析） */

    /* 5. 把明文 JS rename 到 Documents/<js_name>（可写沙盒目录，Gadget 相对路径优先在此查找） */
    char doc_dir[PATH_MAX];
    snprintf(doc_dir, sizeof(doc_dir), "%s/Documents", base);
    mkdir(doc_dir, 0755); /* 已存在则忽略 */
    char doc_js[PATH_MAX];
    snprintf(doc_js, sizeof(doc_js), "%s/%s", doc_dir, js_name);
    if (rename(tmp, doc_js) != 0) { unlink(tmp); return -1; }

    void *g = dlopen(gadget_path, RTLD_NOW);
    if (!g) { unlink(doc_js); return -1; }
    /* Gadget constructor 阻塞至脚本 init 完成（script 模式下等 init 返回才 resume），
     * dlopen 返回即明文已无用，立即删除；guard_loop 3s 兜底防极端时序 */
    unlink(doc_js);
    strlcpy(g_tmp_js_path, doc_js, sizeof(g_tmp_js_path));
    g_tmp_js_pending = 1;
    g_tmp_js_ticks = 0;
    return 0;
}

/* ============ 入口 ============ */

__attribute__((constructor))
static void guard_init(void) {
    deny_attach();

    /* 建立共享校验页（用 mmap 匿名页，宿主侧通过已导出符号取地址） */
    g_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_ANON | MAP_PRIVATE, -1, 0);
    if (g_page == MAP_FAILED) { g_page = NULL; abort(); }

    g_page->magic       = GUARD_MAGIC;
    g_page->host_digest = digest_host_text();
    g_page->self_digest = digest_self();
    g_page->heartbeat   = 1;
    g_page->flags       = 0;

#ifndef GUARD_AUTH_BRIDGE
    /* 独立模式（无卡密模块）：先做一轮快速环境检查，通过即加载 Frida JS。
     * 桥接模式（-DGUARD_AUTH_BRIDGE）：JS 加载由 guard_bridge.mm 按卡密状态控制 */
    if (!debugger_attached() && !injected_framework_present() && !prologue_tampered()) {
        guard_load_frida_agent();
    }
#endif

    pthread_t t;
    pthread_create(&t, NULL, guard_loop, NULL);
    pthread_detach(t);
}

/* 导出给宿主侧调用的校验接口（符号名由构建脚本随机化） */
__attribute__((visibility("default")))
const guard_page_t *guard_query_page(void) {
    return g_page;
}

/* 宿主心跳确认：宿主定期调用，若 dylib 被 unload/移除则调用直接崩溃 */
__attribute__((visibility("default")))
uint64_t guard_tick(uint64_t v) {
    if (!g_page || g_page->magic != GUARD_MAGIC) abort();
    return fnv1a(&v, sizeof(v), g_page->heartbeat);
}
