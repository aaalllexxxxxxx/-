/*
 * card_auth.m — TrollStore-R 本地卡密校验 Dylib (短卡密 v2)
 * Target: arm64-apple-ios
 * Dependencies: UIKit, Security.framework, Foundation, CommonCrypto
 * Constructor Priority: __attribute__((constructor(101)))
 *
 * 新版 16 位短卡密 (大小写字母 + 数字, 共 62 种字符, 不含分隔符):
 *   [档位2位][载荷7位][校验3位][尾码4位]
 *     S3/M1/H1/H3/D1/W7/M3/M9/Y1/Y0 共 10 个档位
 *     载荷  : Base62( 32bit 到期Unix时间戳 XOR 密钥派生流 )
 *     校验  : Base62( CRC16_XMODEM(档位+载荷) XOR 混淆常量 (低16位) + 高2位混淆 )
 *     尾码  : G=HMAC(KEY, "G:"+档位+载荷+校验)[0:20bit]
 *             B=HMAC(KEY, "B:"+设备ID+档位+载荷+校验)[0:20bit]
 *
 * 编译: clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
 *       -framework UIKit -framework Security -framework Foundation \
 *       -dynamiclib card_auth.m -o card_auth.dylib
 *
 * 编译后使用 ldid 签名: ldid -S card_auth.dylib
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonHMAC.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>

/* =========================================================
 *  硬性编码约束
 *  - 密钥使用 uint8_t 字节数组, 禁止明文
 *  - 全部授权数据存放 Keychain, 禁止沙盒文件
 *  - 失败场景调用 exit(0)
 *  - UI / 剪贴板操作全部 dispatch_async 到主线程
 * ========================================================= */

/* ---- 卡密主密钥: 32 字节, 必须与 gen_card.py 中 CARD_KEY_BYTES 完全一致 ---- */
static const uint8_t g_card_key[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

/* ---- Base62 字符表 ---- */
static const char g_b62_chars[63] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* ---- CRC 混淆常量 ---- */
#define CRC_OBFUSCATOR      0x2A5F37u

/* ---- 全局状态 ---- */
static bool g_is_activated = false;

/* ---- Keychain Service 标识 ---- */
#define KC_SERVICE            "com.nbxy.app.cardauth"
#define KC_ACTIVE_CARD        "active_card"          /* 当前激活的完整 16 位卡密 */
#define KC_USED_CARD_LIST     "used_card_list"       /* 本机黑名单 */
#define KC_TIME_CHECK_REC     "time_check_record"    /* 时间篡改记录 */
#define KC_LOCAL_DEVICE_ID    "local_device_id"      /* 设备 ID 缓存 */

/* ---- 前缀 → 秒数映射 (新两位档位码) ---- */
typedef struct {
    const char *prefix;
    int64_t seconds;
} duration_entry_t;

static const duration_entry_t g_duration_table[] = {
    { "S3",  30LL         },
    { "M1",  60LL         },
    { "H1",  3600LL       },
    { "H3",  10800LL      },
    { "D1",  86400LL      },
    { "W7",  604800LL     },
    { "M3",  2592000LL    },
    { "M9",  7776000LL    },
    { "Y1",  31536000LL   },
    { "Y0",  315360000LL  },
};
static const int g_duration_table_count =
    (int)(sizeof(g_duration_table) / sizeof(g_duration_table[0]));

/* ---- 时间篡改阈值: 2 天 = 172800 秒 ---- */
#define TIME_TAMPER_THRESHOLD 172800

/* =========================================================
 *  工具子模块
 * ========================================================= */

/* --- 1. Keychain 字符串读写 --- */
static NSString *kc_get_string(NSString *key) {
    NSDictionary *query = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: [NSString stringWithUTF8String:KC_SERVICE],
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData:  @YES,
        (__bridge id)kSecMatchLimit:  (__bridge id)kSecMatchLimitOne
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) return nil;
    NSData *data = (__bridge_transfer NSData *)result;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static bool kc_set_string(NSString *key, NSString *value) {
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *query = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: [NSString stringWithUTF8String:KC_SERVICE],
        (__bridge id)kSecAttrAccount: key
    };
    NSDictionary *attrs = @{
        (__bridge id)kSecValueData: data
    };
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query,
                                     (__bridge CFDictionaryRef)attrs);
    if (status == errSecItemNotFound) {
        NSMutableDictionary *add = [query mutableCopy];
        [add setObject:data forKey:(__bridge id)kSecValueData];
        status = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    }
    return (status == errSecSuccess);
}

/* --- 2. Keychain 数组读写（used_card_list 黑名单）--- */
static NSArray *kc_get_array(NSString *key) {
    NSString *json = kc_get_string(key);
    if (!json) return @[];
    NSData *d = [json dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *arr = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    return arr ?: @[];
}

static bool kc_set_array(NSString *key, NSArray *array) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:array options:0 error:nil];
    if (!d) return false;
    NSString *json = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    return kc_set_string(key, json);
}

/* --- 3. boottime 获取: sysctl KERN_BOOTTIME --- */
static struct timeval get_boottime(void) {
    struct timeval boot = {0, 0};
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    size_t size = sizeof(boot);
    if (sysctl(mib, 2, &boot, &size, NULL, 0) != 0) {
        /* 失败返回零值 */
    }
    return boot;
}

/* --- 4. 获取并缓存 identifierForVendor --- */
static NSString *get_local_device_id(void) {
    NSString *cached = kc_get_string(@(KC_LOCAL_DEVICE_ID));
    if (cached && cached.length > 0) return cached;

    __block NSString *idf = nil;
    if ([NSThread isMainThread]) {
        idf = [UIDevice currentDevice].identifierForVendor.UUIDString;
    } else {
        dispatch_sync(dispatch_get_main_queue(), ^{
            idf = [UIDevice currentDevice].identifierForVendor.UUIDString;
        });
    }
    if (idf) {
        kc_set_string(@(KC_LOCAL_DEVICE_ID), idf);
    }
    return idf ?: @"";
}

/* --- 5. 剪贴板工具 --- */
static void copy_to_clipboard(NSString *text) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [UIPasteboard generalPasteboard].string = text;
    });
}

/* =========================================================
 *  卡密校验核心模块 (替换 Fernet)
 * ========================================================= */

/* Base62 字符 -> 数字 (0-61), 非法返回 -1 */
static int b62_char_ord(char c) {
    if (c >= '0' && c <= '9') return (int)(c - '0');                     /* 0-9: 0~9   */
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A') + 10;                /* A-Z: 10~35 */
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 36;                /* a-z: 36~61 */
    return -1;
}

/* Base62 字符串解码为 uint64, 成功返回 true, out=结果 */
static bool b62_decode(const char *s, int len, uint64_t *out) {
    uint64_t val = 0;
    for (int i = 0; i < len; i++) {
        int d = b62_char_ord(s[i]);
        if (d < 0) return false;
        val = val * 62ULL + (uint64_t)d;
    }
    *out = val;
    return true;
}

/* CRC-16-XMODEM: poly 0x1021, init 0x0000, no reflection, no final xor */
static uint16_t crc16_xmodem(const uint8_t *data, size_t len) {
    uint16_t crc = 0x0000;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)((uint16_t)data[i] << 8);
        for (int b = 0; b < 8; b++) {
            if (crc & 0x8000u) {
                crc = (uint16_t)((crc << 1) ^ 0x1021u);
            } else {
                crc = (uint16_t)(crc << 1);
            }
        }
    }
    return crc;
}

/*
 * HMAC-SHA256 便捷封装.
 * digest_out: 至少 CC_SHA256_DIGEST_LENGTH (32) 字节
 */
static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t *digest_out) {
    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA256, key, key_len);
    CCHmacUpdate(&ctx, msg, msg_len);
    CCHmacFinal(&ctx, digest_out);
}

/* 解析档位前缀秒数, 未找到返回 0 */
static int64_t lookup_duration(const char *prefix2) {
    for (int i = 0; i < g_duration_table_count; i++) {
        if (prefix2[0] == g_duration_table[i].prefix[0] &&
            prefix2[1] == g_duration_table[i].prefix[1]) {
            return g_duration_table[i].seconds;
        }
    }
    return 0;
}

/*
 * 派生 XOR 密钥流 (4 字节).
 * 算法: HMAC-SHA256(g_card_key, "XOR:"+prefix2+":"+type+":"+device_id_or_empty)[0:4]
 * type: "G" or "B"
 */
static void derive_xor_keystream(const char *prefix2, const char *type,
                                 NSString *device_id,
                                 uint8_t ks_out[4]) {
    NSMutableData *msg = [NSMutableData data];
    [msg appendBytes:"XOR:" length:4];
    [msg appendBytes:prefix2 length:2];
    [msg appendBytes:":" length:1];
    [msg appendBytes:type length:1];
    [msg appendBytes:":" length:1];
    if (device_id && device_id.length > 0) {
        NSData *d = [device_id dataUsingEncoding:NSUTF8StringEncoding];
        if (d) [msg appendData:d];
    }
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    hmac_sha256(g_card_key, sizeof(g_card_key),
                (const uint8_t *)msg.bytes, msg.length, digest);
    memcpy(ks_out, digest, 4);
}

/*
 * 派生 20bit 尾码.
 * device_id=nil 代表 G 类型, 非 nil 代表 B 类型.
 * 返回值 0 ~ 1048575 (< 62^4)
 */
static uint32_t derive_20bit_tail(const char *prefix2,
                                  const char *cipher7,
                                  const char *crc3,
                                  NSString *device_id) {
    NSMutableData *msg = [NSMutableData data];
    if (device_id && device_id.length > 0) {
        /* B: "B:" + device_id + prefix2 + cipher7 + crc3 */
        [msg appendBytes:"B:" length:2];
        NSData *d = [device_id dataUsingEncoding:NSUTF8StringEncoding];
        if (d) [msg appendData:d];
    } else {
        /* G: "G:" + prefix2 + cipher7 + crc3 */
        [msg appendBytes:"G:" length:2];
    }
    [msg appendBytes:prefix2 length:2];
    [msg appendBytes:cipher7  length:7];
    [msg appendBytes:crc3     length:3];

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    hmac_sha256(g_card_key, sizeof(g_card_key),
                (const uint8_t *)msg.bytes, msg.length, digest);
    /* 前 3 字节 24bit, 取高 20bit */
    uint32_t v = ((uint32_t)digest[0] << 16) |
                 ((uint32_t)digest[1] << 8)  |
                  (uint32_t)digest[2];
    return v >> 4;
}

/* 校验返回原因码 (UI 用它区分"无效"/"过期"/"位数不够") */
enum {
    CAR_OK          = 0,
    CAR_ERR_GENERIC = 1,
    CAR_ERR_EXPIRED = 2,
};

/*
 * 完整版校验: 返回 true 表示通过.
 *   expire_out: 成功时赋值到期 Unix 时间戳 (秒)
 *   type_out  : 成功时赋值为 'G' 或 'B' (可传 NULL)
 *   reason_out: 失败时赋值为 CAR_ERR_* (可传 NULL)
 */
static bool validate_card_ex(NSString *card_str,
                              int64_t *expire_out,
                              char *type_out,
                              int *reason_out) {
    if (expire_out) *expire_out = 0;
    if (type_out)   *type_out   = 0;
    if (reason_out) *reason_out = CAR_ERR_GENERIC;

    if (!card_str || card_str.length != 16) {
        NSLog(@"[card_auth] invalid card length (expect 16)");
        return false;
    }
    const char *cstr = card_str.UTF8String;
    if (!cstr) return false;
    if (strlen(cstr) != 16) return false;

    /* 1. 校验所有字符都是合法 base62 */
    for (int i = 0; i < 16; i++) {
        if (b62_char_ord(cstr[i]) < 0) {
            NSLog(@"[card_auth] invalid char at pos %d: '%c'", i, cstr[i]);
            return false;
        }
    }

    /* 2. 切片 */
    const char *prefix2 = cstr;       /* [0,2) */
    const char *cipher7 = cstr + 2;   /* [2,9) */
    const char *crc3    = cstr + 9;   /* [9,12) */
    const char *tail4   = cstr + 12;  /* [12,16) */

    /* 3. 查档位合法性 */
    int64_t dur = lookup_duration(prefix2);
    if (dur <= 0) {
        NSLog(@"[card_auth] unknown prefix: %.2s", prefix2);
        return false;
    }

    /* 4. CRC16 公开校验 */
    uint8_t crc_src_buf[9];
    memcpy(crc_src_buf, prefix2, 2);
    memcpy(crc_src_buf + 2, cipher7, 7);
    uint16_t expected_crc = crc16_xmodem(crc_src_buf, sizeof(crc_src_buf));

    uint64_t crc_18 = 0;
    if (!b62_decode(crc3, 3, &crc_18)) return false;
    uint16_t restored = (uint16_t)((uint32_t)crc_18 & 0xFFFFu) ^
                        (uint16_t)(CRC_OBFUSCATOR & 0xFFFFu);
    if (restored != expected_crc) {
        NSLog(@"[card_auth] crc mismatch: expected %04X, got %04X",
              expected_crc, restored);
        return false;
    }

    /* 5. 解载荷 7字符 -> 32bit 整数 (4字节) */
    uint64_t cipher_int = 0;
    if (!b62_decode(cipher7, 7, &cipher_int)) return false;
    if (cipher_int >= 0x100000000ULL) {
        NSLog(@"[card_auth] cipher_int overflow 32bit");
        return false;
    }
    uint8_t cipher_bytes[4];
    cipher_bytes[0] = (uint8_t)((cipher_int >> 24) & 0xFFu);
    cipher_bytes[1] = (uint8_t)((cipher_int >> 16) & 0xFFu);
    cipher_bytes[2] = (uint8_t)((cipher_int >> 8)  & 0xFFu);
    cipher_bytes[3] = (uint8_t)( cipher_int        & 0xFFu);

    /* 6. 解尾码 4字符 -> 20bit */
    uint64_t actual_tail = 0;
    if (!b62_decode(tail4, 4, &actual_tail)) return false;
    if (actual_tail > 1048575ULL) return false; /* 20bit 上限 */

    /* 7. 优先尝试 B (绑定, 如果本地有 device_id), 再尝试 G (通用).
     *    两种类型独立派生 XOR 密钥流和尾码, 互不干扰. */
    NSString *dev_id = get_local_device_id();
    char match_type = 0;
    int64_t expire_ts = 0;

    const char *types[2] = { NULL, NULL };
    NSString *devs[2]   = { nil, nil };
    int try_count = 0;
    if (dev_id && dev_id.length > 0) {
        types[try_count] = "B"; devs[try_count] = dev_id; try_count++;
    }
    types[try_count] = "G"; devs[try_count] = nil; try_count++;

    for (int k = 0; k < try_count; k++) {
        uint8_t ks[4];
        derive_xor_keystream(prefix2, types[k], devs[k], ks);
        uint8_t plain_bytes[4];
        for (int i = 0; i < 4; i++) plain_bytes[i] = cipher_bytes[i] ^ ks[i];
        uint32_t ts = ((uint32_t)plain_bytes[0] << 24) |
                      ((uint32_t)plain_bytes[1] << 16) |
                      ((uint32_t)plain_bytes[2] << 8)  |
                       (uint32_t)plain_bytes[3];

        uint32_t exp_tail = derive_20bit_tail(prefix2, cipher7, crc3, devs[k]);
        if (exp_tail == (uint32_t)actual_tail) {
            match_type = types[k][0];
            expire_ts = (int64_t)ts;
            break;
        }
    }

    if (match_type == 0) {
        NSLog(@"[card_auth] tail mismatch (wrong key/type/device)");
        return false;
    }

    /* 8. 有效期检查: 过期单独返回原因码, UI 提示"使用期限已到" */
    int64_t now = (int64_t)[[NSDate date] timeIntervalSince1970];
    if (expire_ts <= now) {
        NSLog(@"[card_auth] card already expired at %lld (now=%lld)", expire_ts, now);
        if (reason_out) *reason_out = CAR_ERR_EXPIRED;
        return false;
    }

    if (expire_out) *expire_out = expire_ts;
    if (type_out)   *type_out   = match_type;
    if (reason_out) *reason_out = CAR_OK;
    return true;
}

/* 兼容旧签名: 成功返回到期时间戳, 失败返回 0. (启动校验路径复用) */
static int64_t validate_card(NSString *card_str, char *out_type) {
    int64_t ts = 0;
    validate_card_ex(card_str, &ts, out_type, NULL);
    return ts;
}

/* =========================================================
 *  UI 弹窗模块 (模块 C) — 全部主线程
 * ========================================================= */

@class CardAuthWindow;
@protocol CardAuthWindowProto
@end

@interface CardAuthWindow : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UITextField *inputField;
@property (nonatomic, strong) UILabel *hintLabel;
@property (nonatomic, strong) UILabel *stickyInfoLabel;
- (void)showToast:(NSString *)msg;
- (void)showStickyInfo:(NSString *)title detail:(NSString *)detail;
- (void)showErrorAlert:(NSString *)title message:(NSString *)msg;
- (void)dismissWindow;
@end

static CardAuthWindow *g_auth_window = nil;

@implementation CardAuthWindow

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.1 green:0.1 blue:0.12 alpha:1.0];
    self.view.alpha = 1.0;

    CGFloat sw = self.view.bounds.size.width;

    /* 0. 顶部状态条 (到期 / 异常时显示, 初始隐藏) */
    self.stickyInfoLabel = [[UILabel alloc] init];
    self.stickyInfoLabel.numberOfLines = 0;
    self.stickyInfoLabel.font = [UIFont boldSystemFontOfSize:13];
    self.stickyInfoLabel.textColor = [UIColor colorWithRed:1.0 green:0.85 blue:0.3 alpha:1.0];
    self.stickyInfoLabel.backgroundColor = [UIColor colorWithRed:0.25 green:0.15 blue:0.05 alpha:0.95];
    self.stickyInfoLabel.textAlignment = NSTextAlignmentCenter;
    self.stickyInfoLabel.layer.cornerRadius = 8;
    self.stickyInfoLabel.layer.masksToBounds = YES;
    self.stickyInfoLabel.hidden = YES;
    self.stickyInfoLabel.frame = CGRectMake(16, 18, sw - 32, 36);
    [self.view addSubview:self.stickyInfoLabel];

    /* 1. 提示标签 */
    self.hintLabel = [[UILabel alloc] init];
    self.hintLabel.text = @"欢迎使用，请输入激活码";
    self.hintLabel.numberOfLines = 0;
    self.hintLabel.font = [UIFont systemFontOfSize:14];
    self.hintLabel.textColor = [UIColor whiteColor];
    self.hintLabel.textAlignment = NSTextAlignmentCenter;
    self.hintLabel.frame = CGRectMake(20, 66, sw - 40, 50);
    [self.view addSubview:self.hintLabel];

    /* 2. 激活码输入框 */
    self.inputField = [[UITextField alloc] init];
    self.inputField.placeholder = @"请输入激活码";
    self.inputField.borderStyle = UITextBorderStyleRoundedRect;
    self.inputField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.inputField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.inputField.spellCheckingType = UITextSpellCheckingTypeNo;
    self.inputField.smartQuotesType = UITextSmartQuotesTypeNo;
    self.inputField.smartDashesType = UITextSmartDashesTypeNo;
    self.inputField.delegate = self;
    self.inputField.frame = CGRectMake(20, 130, sw - 40, 44);
    [self.view addSubview:self.inputField];

    CGFloat btnY = 188;
    CGFloat btnW = (sw - 50) / 2.0;

    /* 3. 复制设备信息按钮 */
    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [copyBtn setTitle:@"复制本机码" forState:UIControlStateNormal];
    [copyBtn.titleLabel setFont:[UIFont systemFontOfSize:15]];
    copyBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.5 blue:0.2 alpha:1.0];
    [copyBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    copyBtn.layer.cornerRadius = 8;
    copyBtn.frame = CGRectMake(20, btnY, btnW, 40);
    [copyBtn addTarget:self action:@selector(copyDeviceID:)
      forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:copyBtn];

    /* 4. 激活按钮 */
    UIButton *activateBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [activateBtn setTitle:@"立即激活" forState:UIControlStateNormal];
    [activateBtn.titleLabel setFont:[UIFont systemFontOfSize:15]];
    activateBtn.backgroundColor = [UIColor colorWithRed:0.1 green:0.4 blue:0.8 alpha:1.0];
    [activateBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    activateBtn.layer.cornerRadius = 8;
    activateBtn.frame = CGRectMake(30 + btnW, btnY, btnW, 40);
    [activateBtn addTarget:self action:@selector(activatePressed:)
      forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:activateBtn];

    /* 5. 退出按钮 */
    UIButton *exitBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [exitBtn setTitle:@"关闭软件" forState:UIControlStateNormal];
    [exitBtn.titleLabel setFont:[UIFont systemFontOfSize:15]];
    exitBtn.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.2 alpha:1.0];
    [exitBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    exitBtn.layer.cornerRadius = 8;
    exitBtn.frame = CGRectMake(20, 243, sw - 40, 40);
    [exitBtn addTarget:self action:@selector(exitPressed:)
      forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:exitBtn];
}

- (void)showStickyInfo:(NSString *)title detail:(NSString *)detail {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self.stickyInfoLabel) return;
        NSString *text;
        if (detail && detail.length > 0) {
            text = [NSString stringWithFormat:@"%@\n%@", title, detail];
        } else {
            text = title;
        }
        self.stickyInfoLabel.text = text;
        self.stickyInfoLabel.hidden = NO;
        /* 根据内容动态调整高度 */
        CGFloat sw = self.view.bounds.size.width;
        CGRect r = self.stickyInfoLabel.frame;
        r.size.height = [text boundingRectWithSize:CGSizeMake(sw - 32, CGFLOAT_MAX)
                                            options:NSStringDrawingUsesLineFragmentOrigin
                                         attributes:@{NSFontAttributeName:self.stickyInfoLabel.font}
                                            context:nil].size.height + 18;
        r.origin.x = 16; r.size.width = sw - 32; r.origin.y = 18;
        self.stickyInfoLabel.frame = r;
    });
}

- (void)copyDeviceID:(UIButton *)sender {
    NSString *devID = get_local_device_id();
    if (devID.length == 0) {
        [self showToast:@"获取失败，请重试"];
        return;
    }
    [UIPasteboard generalPasteboard].string = devID;
    [self showToast:@"本机码已复制，发给客服即可"];
}

- (void)activatePressed:(UIButton *)sender {
    NSString *card = self.inputField.text;
    if (card.length == 0) {
        [self showToast:@"请输入激活码"];
        return;
    }
    /* 清理输入: 去空格换行 (支持用户 4+4+4+4 分组粘贴) */
    card = [card stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    card = [card stringByReplacingOccurrencesOfString:@" " withString:@""];
    card = [card stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    card = [card stringByReplacingOccurrencesOfString:@"\r" withString:@""];

    char ctype = 0;
    int64_t expire_ts = 0;
    int car = CAR_ERR_GENERIC;
    BOOL ok = validate_card_ex(card, &expire_ts, &ctype, &car);
    if (!ok) {
        NSLog(@"[card_auth] user input card invalid (reason=%d)", car);
        if (car == CAR_ERR_EXPIRED) {
            [self showToast:@"使用期限已到，请联系客服换一个"];
        } else if (card.length < 16) {
            [self showToast:@"激活码位数不够"];
        } else {
            [self showToast:@"激活码无效"];
        }
        return;
    }

    /* 本机黑名单: 用过的卡密即便还在有效期也不允许第二次激活 */
    NSArray *used = kc_get_array(@(KC_USED_CARD_LIST));
    if ([used containsObject:card]) {
        [self showToast:@"激活码已使用过"];
        return;
    }

    /* 所有校验通过 -> 写入 Keychain, 激活 */
    kc_set_string(@(KC_ACTIVE_CARD), card);

    NSMutableArray *new_used = [used mutableCopy];
    [new_used addObject:card];
    kc_set_array(@(KC_USED_CARD_LIST), new_used);

    struct timeval boot = get_boottime();
    int64_t now = (int64_t)[[NSDate date] timeIntervalSince1970];
    NSDictionary *rec = @{
        @"last_check_time": @(now),
        @"last_boottime":   @((int64_t)boot.tv_sec)
    };
    NSData *rec_data = [NSJSONSerialization dataWithJSONObject:rec options:0 error:nil];
    NSString *rec_json = [[NSString alloc] initWithData:rec_data
                                                encoding:NSUTF8StringEncoding];
    kc_set_string(@(KC_TIME_CHECK_REC), rec_json);

    g_is_activated = true;
    [self dismissWindow];
}

- (void)exitPressed:(UIButton *)sender {
    exit(0);
}

- (void)showToast:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        UILabel *toast = [[UILabel alloc] init];
        toast.text = msg;
        toast.font = [UIFont systemFontOfSize:14];
        toast.textColor = [UIColor whiteColor];
        toast.backgroundColor = [UIColor colorWithWhite:0 alpha:0.7];
        toast.textAlignment = NSTextAlignmentCenter;
        toast.numberOfLines = 0;
        toast.alpha = 0;
        CGFloat y = self.view.bounds.size.height - 110;
        if (y < 280) y = 280;
        toast.frame = CGRectMake(20, y, self.view.bounds.size.width - 40, 44);
        toast.layer.cornerRadius = 8;
        toast.layer.masksToBounds = YES;
        [self.view addSubview:toast];

        [UIView animateWithDuration:0.3 animations:^{
            toast.alpha = 1.0;
        } completion:^(BOOL finished) {
            [UIView animateWithDuration:0.3 delay:1.5 options:0 animations:^{
                toast.alpha = 0;
            } completion:^(BOOL finished) {
                [toast removeFromSuperview];
            }];
        }];
    });
}

- (void)showErrorAlert:(NSString *)title message:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:title
                             message:msg
                      preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *ok = [UIAlertAction
            actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil];
        [alert addAction:ok];
        [self presentViewController:alert animated:YES completion:nil];
    });
}

- (void)dismissWindow {
    [UIView animateWithDuration:0.25 animations:^{
        self.view.alpha = 0;
    } completion:^(BOOL finished) {
        [self.view removeFromSuperview];
        self.window.hidden = YES;
        g_auth_window = nil;
    }];
}

@end

/* =========================================================
 *  弹窗辅助函数
 * ========================================================= */

static void show_auth_window_on_main(void) {
    if (g_auth_window) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        g_auth_window = [[CardAuthWindow alloc] init];
        UIWindow *win = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        win.windowLevel = UIWindowLevelAlert + 100;
        win.rootViewController = g_auth_window;
        g_auth_window.window = win;
        win.hidden = NO;
        [win makeKeyAndVisible];

        /* 启动时自动读取剪贴板内容, 如果像卡密就填入输入框 */
        NSString *pasteboard = [UIPasteboard generalPasteboard].string;
        if (pasteboard && pasteboard.length > 0) {
            NSString *clean = [pasteboard
                stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            clean = [clean stringByReplacingOccurrencesOfString:@" " withString:@""];
            clean = [clean stringByReplacingOccurrencesOfString:@"\n" withString:@""];
            clean = [clean stringByReplacingOccurrencesOfString:@"\r" withString:@""];
            if (clean.length == 16) {
                bool all_ok = true;
                const char *s = clean.UTF8String;
                for (int i = 0; i < 16; i++) {
                    if (b62_char_ord(s[i]) < 0) { all_ok = false; break; }
                }
                if (all_ok) {
                    g_auth_window.inputField.text = clean;
                    [g_auth_window showToast:@"检测到剪贴板有激活码，已自动填入"];
                }
            }
        }
    });
}

static void show_fatal_alert_on_main(NSString *title, NSString *detail) {
    dispatch_async(dispatch_get_main_queue(), ^{
        /* 致命场景: 先清掉旧激活记录, 弹出激活窗口并在顶部提示.
         * 注意: 此处绝对不能调用 exit(0), 也不能弹 UIAlert(易闪退).
         *       正确做法是把用户留在激活窗口, g_is_activated 保持 false,
         *       sendEvent 会继续拦截触摸, 用户无法进入主界面. */
        kc_set_string(@(KC_ACTIVE_CARD), @"");
        kc_set_string(@(KC_TIME_CHECK_REC), @"");

        if (!g_auth_window) {
            g_auth_window = [[CardAuthWindow alloc] init];
            UIWindow *win = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            win.windowLevel = UIWindowLevelAlert + 100;
            win.rootViewController = g_auth_window;
            g_auth_window.window = win;
            win.hidden = NO;
            [win makeKeyAndVisible];
        }
        /* 在激活窗口顶部显示原因 */
        [g_auth_window showStickyInfo:title detail:detail];
    });
}


/* =========================================================
 *  模块 B: 授权状态校验主逻辑
 * ========================================================= */

static void check_authorization(void) {
    /* 1. 读 Keychain: 当前激活卡密 */
    NSString *active_card = kc_get_string(@(KC_ACTIVE_CARD));
    if (!active_card || active_card.length == 0) {
        g_is_activated = false;
        show_auth_window_on_main();
        return;
    }

    /* 2. 重新校验激活码有效性 (解出到期时间) */
    char ctype = 0;
    int64_t expire_ts = validate_card(active_card, &ctype);
    if (expire_ts <= 0) {
        g_is_activated = false;
        show_fatal_alert_on_main(@"激活失效", @"请重新输入激活码");
        return;
    }

    /* 3. 获取当前系统时间、boottime */
    int64_t now = (int64_t)[[NSDate date] timeIntervalSince1970];
    struct timeval boot = get_boottime();
    int64_t boot_sec = (int64_t)boot.tv_sec;

    /* 4. 读取上一次校验记录 */
    NSString *rec_json = kc_get_string(@(KC_TIME_CHECK_REC));
    int64_t last_check_time = 0;
    int64_t last_boottime = 0;
    if (rec_json) {
        NSData *d = [rec_json dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *rec = [NSJSONSerialization JSONObjectWithData:d
                                                              options:0 error:nil];
        if (rec) {
            last_check_time = [rec[@"last_check_time"] longLongValue];
            last_boottime   = [rec[@"last_boottime"]   longLongValue];
        }
    }

    /* 5. 时间校验 */
    if (last_check_time > 0 && last_boottime > 0) {
        int64_t wall_delta = now - last_check_time;
        int64_t boot_delta = boot_sec - last_boottime;
        int64_t diff = wall_delta - boot_delta;
        if (diff < 0) diff = -diff;
        if (diff > TIME_TAMPER_THRESHOLD) {
            g_is_activated = false;
            show_fatal_alert_on_main(@"系统时间异常", @"请确认手机时间正确后重试");
            return;
        }
    }

    /* 6. 过期检测 */
    if (now > expire_ts) {
        g_is_activated = false;
        show_fatal_alert_on_main(@"使用期限已到", @"请联系客服获取新的激活码");
        return;
    }

    /* 7. 全部校验通过: 激活 */
    g_is_activated = true;

    /* 回写时间记录 */
    NSDictionary *new_rec = @{
        @"last_check_time": @(now),
        @"last_boottime":   @(boot_sec)
    };
    NSData *new_rec_data = [NSJSONSerialization dataWithJSONObject:new_rec
                                                              options:0 error:nil];
    NSString *new_rec_json = [[NSString alloc] initWithData:new_rec_data
                                                  encoding:NSUTF8StringEncoding];
    kc_set_string(@(KC_TIME_CHECK_REC), new_rec_json);
}

/* =========================================================
 *  模块 E: 全局触摸事件拦截 (sendEvent hook)
 * ========================================================= */

static void (*orig_sendEvent)(id, SEL, UIEvent *) = NULL;

static void hook_sendEvent(id self, SEL _cmd, UIEvent *event) {
    if (!g_is_activated) {
        if (g_auth_window) {
            if (orig_sendEvent) orig_sendEvent(self, _cmd, event);
            return;
        }
        return; /* 丢弃 */
    }
    if (orig_sendEvent) orig_sendEvent(self, _cmd, event);
}

static void install_sendEvent_hook(void) {
    Class cls = objc_getClass("UIApplication");
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, @selector(sendEvent:));
    if (!m) return;
    orig_sendEvent = (void (*)(id, SEL, UIEvent *))method_getImplementation(m);
    method_setImplementation(m, (IMP)hook_sendEvent);
}

/* =========================================================
 *  模块 A: 高优先级入口 pre-main constructor
 * ========================================================= */

__attribute__((constructor(101)))
static void card_auth_init(void) {
    g_is_activated = false;
    install_sendEvent_hook();
    dispatch_async(dispatch_get_main_queue(), ^{
        get_local_device_id();
        check_authorization();
    });
}

/*
 * 失败场景调用 exit(0):
 *   check_authorization:
 *     - 本地授权数据无法验证 -> 致命弹窗 -> exit
 *     - 已过期               -> 致命弹窗 -> exit
 *     - 时间篡改             -> 致命弹窗 -> exit
 *   用户交互:
 *     - 点击退出按钮         -> exit
 *
 *   parseAndValidateCard (用户输入时失败): 只 toast, 允许重新输入
 */
