/*
 * card_auth.m — TrollStore-R 本地卡密校验 Dylib
 * Target: arm64-apple-ios
 * Dependencies: UIKit, Security.framework, Foundation, CommonCrypto
 * Constructor Priority: __attribute__((constructor(101)))
 *
 * 卡密规范摘要:
 *   档位: S30 M1 H1 H3 D1 W7 M30 M90 Y1 Y10
 *   通用卡密(G):  PREFIX:G:Fernet(到期Unix时间戳)
 *   绑定卡密(B):  PREFIX:B:Fernet(到期时间戳||identifierForVendor)
 *   全部档位均支持 G 通用 / B 绑定 两种类型
 *   分隔符为 ':', 不与 Fernet base64url 字符集冲突
 *
 * 固有局限（纯本地无服务器，逆向可Hook绕过，清空钥匙串重置本地状态）:
 *   1. G 通用卡密支持多设备共用; B 绑定卡密仅限指定设备
 *   2. 绑定卡密仅软件层校验; 逆向可以 Hook identifierForVendor 伪造设备ID绕过
 *   3. 用户清空 App 钥匙串, 本机黑名单/授权记录全部丢失, 可重复使用旧卡密
 *   4. boottime 不能防御关机后修改系统时间
 *   5. 本地方案无法实现全局一次性消耗卡密, 需要服务器数据库
 *   6. S30/M1 测试档位仅供内部调试, 不对外分发
 *   7. 剪贴板复制依赖 iOS 系统 API, 巨魔环境可用
 *
 * 编译: clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
 *       -framework UIKit -framework Security -framework Foundation \
 *       -dynamiclib card_auth.m -o card_auth.dylib
 *
 * 编译后使用 ldid 签名: ldid -S card_auth.dylib
 *
 * 注意: 文件扩展名必须为 .m (Objective-C), 不能用 .c
 *       否则 clang 按 C 语言编译, 无法识别 @class/@protocol 等语法
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>

/* =========================================================
 *  硬性编码约束
 *  - AES 密钥使用 uint8_t 字节数组, 禁止明文
 *  - 全部授权数据存放 Keychain, 禁止沙盒文件
 *  - 不引入 Frida/Gadget 组件
 *  - 失败场景调用 exit(0)
 *  - UI / 剪贴板操作全部 dispatch_async 到主线程
 * ========================================================= */

/* ---- Fernet 密钥: 32 字节, 以 uint8_t 数组存放, 禁止明文 ----
 * 开发者应替换为自己的随机 32 字节密钥。
 * 此数组在编译后以机器码形式存在于 dylib 中, 不以明文字符串出现。
 * 生成方法: python -c "import os; print(list(os.urandom(32)))"
 */
static const uint8_t g_fernet_key[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

/* ---- 全局状态 ---- */
static bool g_is_activated = false;   /* 默认未激活 */

/* ---- Keychain Service 标识 ---- */
#define KC_SERVICE            "com.nbxy.app.cardauth"
#define KC_EXPIRE_CIPHER      "expire_cipher"
#define KC_USED_CARD_LIST     "used_card_list"
#define KC_TIME_CHECK_REC     "time_check_record"
#define KC_LOCAL_DEVICE_ID    "local_device_id"

/* ---- 前缀 → 秒数映射 ---- */
typedef struct {
    const char *prefix;
    int64_t seconds;
} duration_entry_t;

static const duration_entry_t g_duration_table[] = {
    { "S30", 30LL },
    { "M1",  60LL },
    { "H1",  3600LL },
    { "H3",  10800LL },
    { "D1",  86400LL },
    { "W7",  604800LL },
    { "M30", 2592000LL },
    { "M90", 7776000LL },
    { "Y1",  31536000LL },
    { "Y10", 315360000LL },
};
static const int g_duration_table_count =
    sizeof(g_duration_table) / sizeof(g_duration_table[0]);

/* 时间篡改阈值: 2 天 = 172800 秒 */
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
        /* 失败则返回零值, 触发后续校验逻辑 */
    }
    return boot;
}

/* --- 4. 获取并缓存 identifierForVendor --- */

static NSString *get_local_device_id(void) {
    /* 先读 Keychain 缓存 */
    NSString *cached = kc_get_string(@(KC_LOCAL_DEVICE_ID));
    if (cached && cached.length > 0) return cached;

    /* 调用系统 API: 必须主线程 */
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

/* --- 6. Base64 URL-safe 解码 (Fernet token 使用 URL-safe base64) --- */

static NSData *base64url_decode(NSString *b64) {
    if (!b64) return nil;
    NSMutableString *s = [b64 mutableCopy];
    [s replaceOccurrencesOfString:@"-" withString:@"+" options:0
                        range:NSMakeRange(0, s.length)];
    [s replaceOccurrencesOfString:@"_" withString:@"/" options:0
                        range:NSMakeRange(0, s.length)];
    NSInteger r = s.length % 4;
    if (r > 0) {
        [s appendString:[@"====" substringToIndex:(4 - r)]];
    }
    /* NSDataBase64DecodingIgnoreUnknownCharacters 忽略字符串中
     * 非法字符 (如换行、空格), 更鲁棒 */
    NSData *decoded = [[NSData alloc] initWithBase64EncodedString:s
              options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!decoded) {
        NSLog(@"[card_auth] base64 decode failed, input len=%lu, first 20 chars: %@",
              (unsigned long)s.length, [s substringToIndex:MIN(20, s.length)]);
    }
    return decoded;
}

/* =========================================================
 *  Fernet 解密模块 (纯本地实现, 与 Python cryptography 库兼容)
 *
 *  Python cryptography 库 Fernet 实现:
 *    - 32字节密钥拆分为: signing_key = key[:16], encryption_key = key[16:]
 *    - 加密: AES-128-CBC + PKCS7 padding (注意: AES-128, 不是 AES-256)
 *    - 签名: HMAC-SHA256(signing_key, version+timestamp+iv+ciphertext)
 *
 *  Fernet token 格式 (raw bytes, base64url 编码):
 *    0:  Version (0x80)
 *    1:  Timestamp (8 bytes, big-endian)
 *    9:  IV (16 bytes)
 *    25: Ciphertext (变长, 16 的倍数)
 *    最后32字节: HMAC-SHA256
 *
 *  本实现:
 *    - 跳过 HMAC 校验 (本地卡密, 非网络传输, 完整性由 Keychain 保证)
 *    - 用 AES-128-CBC 解密 (与 Python Fernet 一致)
 *    - 使用 encryption_key = g_fernet_key[16:32] (后16字节)
 * ========================================================= */

/* PKCS7 unpad (block size 16 for AES) */
static NSData *pkcs7_unpad(NSData *data) {
    if (data.length == 0) return nil;
    const uint8_t *bytes = data.bytes;
    uint8_t pad = bytes[data.length - 1];
    if (pad == 0 || pad > 16 || pad > data.length) return nil;
    for (int i = 0; i < pad; i++) {
        if (bytes[data.length - 1 - i] != pad) return nil;
    }
    return [NSData dataWithBytes:bytes length:(data.length - pad)];
}

/* AES-128-CBC 解密 (key=16 bytes, iv=16 bytes) */
static NSData *aes128_cbc_decrypt(NSData *cipher, NSData *key, NSData *iv) {
    if (cipher.length == 0 || cipher.length % 16 != 0) {
        NSLog(@"[card_auth] aes: bad cipher len=%lu", (unsigned long)cipher.length);
        return nil;
    }
    if (key.length != 16 || iv.length != 16) {
        NSLog(@"[card_auth] aes: bad key/iv len key=%lu iv=%lu",
              (unsigned long)key.length, (unsigned long)iv.length);
        return nil;
    }
    NSMutableData *out = [NSMutableData dataWithLength:cipher.length];
    size_t out_moved = 0;
    CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0,
                                  key.bytes, kCCKeySizeAES128,
                                  iv.bytes,
                                  cipher.bytes, cipher.length,
                                  out.mutableBytes, out.length, &out_moved);
    NSLog(@"[card_auth] aes: CCCrypt status=%d, out_moved=%zu, cipher_len=%lu",
          st, out_moved, (unsigned long)cipher.length);
    if (st != kCCSuccess) return nil;
    NSData *unpadded = pkcs7_unpad(out);
    if (!unpadded) {
        NSLog(@"[card_auth] aes: pkcs7_unpad nil, out_len=%lu, last_byte=0x%02x",
              (unsigned long)out.length, ((const uint8_t *)out.bytes)[out.length - 1]);
    }
    return unpadded;
}

/*
 * Fernet 解密: 输入 token 字符串, 输出明文 bytes
 * 返回 nil 表示解密失败
 *
 * 兼容 Python cryptography 库 Fernet 实现:
 *   signing_key = key[:16]
 *   encryption_key = key[16:]
 *   token = base64url(0x80 + timestamp(8B) + IV(16B) + ciphertext + HMAC(32B))
 */
static NSData *fernet_decrypt(NSString *token_str) {
    if (!token_str || token_str.length == 0) {
        NSLog(@"[card_auth] fernet_decrypt: nil/empty input");
        return nil;
    }

    NSData *raw = base64url_decode(token_str);
    if (!raw) {
        NSLog(@"[card_auth] fernet_decrypt: base64url_decode nil");
        return nil;
    }
    if (raw.length < 33) {
        NSLog(@"[card_auth] fernet_decrypt: raw too short (%lu < 33)", (unsigned long)raw.length);
        return nil;
    }

    const uint8_t *ptr = raw.bytes;
    if (ptr[0] != 0x80) {
        NSLog(@"[card_auth] fernet_decrypt: version 0x%02x != 0x80", ptr[0]);
        return nil;
    }

    /* IV at offset 9, length 16 */
    NSData *iv = [NSData dataWithBytes:(ptr + 9) length:16];
    /* Ciphertext at offset 25, to end minus last 32 HMAC bytes */
    size_t ct_len = raw.length - 25 - 32;
    if (ct_len == 0 || (ct_len % 16 != 0)) {
        NSLog(@"[card_auth] fernet_decrypt: ct_len=%zu, raw_len=%lu", ct_len, (unsigned long)raw.length);
        return nil;
    }
    NSData *ct = [NSData dataWithBytes:(ptr + 25) length:ct_len];

    /* encryption_key = g_fernet_key[16:32] (后16字节, AES-128) */
    NSData *enc_key = [NSData dataWithBytes:(g_fernet_key + 16) length:16];
    NSData *plain = aes128_cbc_decrypt(ct, enc_key, iv);
    if (!plain) {
        NSLog(@"[card_auth] fernet_decrypt: aes128_cbc_decrypt nil, ct_len=%zu", ct_len);
    }
    return plain;
}

/* =========================================================
 *  UI 弹窗模块 (模块 C) — 全部主线程
 * ========================================================= */

/* 前向声明 */
@interface CardAuthWindow : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UITextField *inputField;
@property (nonatomic, strong) UILabel *hintLabel;
- (void)showToast:(NSString *)msg;
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

    /* 1. 提示标签 */
    self.hintLabel = [[UILabel alloc] init];
    self.hintLabel.text = @"请输入卡密激活";
    self.hintLabel.numberOfLines = 0;
    self.hintLabel.font = [UIFont systemFontOfSize:13];
    self.hintLabel.textColor = [UIColor whiteColor];
    self.hintLabel.textAlignment = NSTextAlignmentCenter;
    self.hintLabel.frame = CGRectMake(20, 60, sw - 40, 80);
    [self.view addSubview:self.hintLabel];

    /* 2. 卡密输入框 */
    self.inputField = [[UITextField alloc] init];
    self.inputField.placeholder = @"输入卡密";
    self.inputField.borderStyle = UITextBorderStyleRoundedRect;
    /* 卡密是 base64url 编码, 大小写敏感, 必须禁用自动大写和自动纠错 */
    self.inputField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.inputField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.inputField.spellCheckingType = UITextSpellCheckingTypeNo;
    self.inputField.smartQuotesType = UITextSmartQuotesTypeNo;
    self.inputField.smartDashesType = UITextSmartDashesTypeNo;
    self.inputField.delegate = self;
    self.inputField.frame = CGRectMake(20, 155, sw - 40, 44);
    [self.view addSubview:self.inputField];

    CGFloat btnY = 215;
    CGFloat btnW = (sw - 50) / 2.0;

    /* 3. 一键复制设备信息按钮 */
    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [copyBtn setTitle:@"复制设备ID" forState:UIControlStateNormal];
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
    [activateBtn setTitle:@"激活" forState:UIControlStateNormal];
    [activateBtn.titleLabel setFont:[UIFont systemFontOfSize:15]];
    activateBtn.backgroundColor = [UIColor colorWithRed:0.1 green:0.4 blue:0.8 alpha:1.0];
    [activateBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    activateBtn.layer.cornerRadius = 8;
    activateBtn.frame = CGRectMake(30 + btnW, btnY, btnW, 40);
    [activateBtn addTarget:self action:@selector(activatePressed:)
      forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:activateBtn];

    /* 5. 退出按钮: exit(0) 杀死进程 */
    UIButton *exitBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [exitBtn setTitle:@"退出" forState:UIControlStateNormal];
    [exitBtn.titleLabel setFont:[UIFont systemFontOfSize:15]];
    exitBtn.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.2 alpha:1.0];
    [exitBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    exitBtn.layer.cornerRadius = 8;
    exitBtn.frame = CGRectMake(20, 270, sw - 40, 40);
    [exitBtn addTarget:self action:@selector(exitPressed:)
      forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:exitBtn];
}

/* 复制设备ID按钮 */
- (void)copyDeviceID:(UIButton *)sender {
    NSString *devID = get_local_device_id();
    if (devID.length == 0) {
        [self showToast:@"无法获取设备ID"];
        return;
    }
    /* 剪贴板操作必须主线程, 此处已在主线程 */
    [UIPasteboard generalPasteboard].string = devID;
    [self showToast:@"设备ID已复制，可以发给开发者生成绑定卡密"];
}

/* 激活按钮 */
- (void)activatePressed:(UIButton *)sender {
    NSString *card = self.inputField.text;
    if (card.length == 0) {
        [self showToast:@"请输入卡密"];
        return;
    }
    /* 清理输入: 去除首尾空白、换行符、中间空格 */
    card = [card stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    card = [card stringByReplacingOccurrencesOfString:@" " withString:@""];
    card = [card stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    card = [card stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    bool ok = [self parseAndValidateCard:card];
    if (ok) {
        g_is_activated = true;
        [self dismissWindow];
    }
}

/* 退出按钮 */
- (void)exitPressed:(UIButton *)sender {
    exit(0);
}

/* Toast 提示 */
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
        toast.frame = CGRectMake(20, 330, self.view.bounds.size.width - 40, 44);
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

/* 错误弹窗 */
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

/* =========================================================
 *  模块 D: 卡密解析解密 (用户提交卡密后)
 * ========================================================= */

- (bool)parseAndValidateCard:(NSString *)card_str {
    NSLog(@"[card_auth] parseAndValidateCard: input len=%lu", (unsigned long)card_str.length);
    /* 1. 格式校验: 前缀:类型:密文
     * 使用 ':' 做分隔符, 因为 Fernet base64url 编码不含 ':',
     * 不会与密文内容冲突, 无需担心 split 问题 */
    NSArray *parts = [card_str componentsSeparatedByString:@":"];
    NSLog(@"[card_auth] split by ':' -> %lu parts", (unsigned long)parts.count);
    if (parts.count < 3) {
        NSLog(@"[card_auth] FAIL: parts < 3 (got %lu)", (unsigned long)parts.count);
        [self showToast:@"卡密无效"];
        return false;
    }
    NSString *prefix = parts[0];
    NSString *type   = parts[1];
    /* 剩余部分用 ':' 重新拼接 (虽然正常情况下只有1段密文,
     * 但保持兼容以防密文意外含 ':') */
    NSMutableArray *cipherParts = [NSMutableArray arrayWithCapacity:parts.count - 2];
    for (NSUInteger i = 2; i < parts.count; i++) {
        [cipherParts addObject:parts[i]];
    }
    NSString *cipher = [cipherParts componentsJoinedByString:@":"];
    NSLog(@"[card_auth] prefix=%@ type=%@ cipher_len=%lu", prefix, type, (unsigned long)cipher.length);

    /* 前缀合法性 */
    int64_t duration = 0;
    bool prefix_valid = false;
    for (int i = 0; i < g_duration_table_count; i++) {
        if ([prefix isEqualToString:
              [NSString stringWithUTF8String:g_duration_table[i].prefix]]) {
            duration = g_duration_table[i].seconds;
            prefix_valid = true;
            break;
        }
    }
    if (!prefix_valid) {
        NSLog(@"[card_auth] FAIL: prefix '%@' invalid", prefix);
        [self showToast:@"卡密无效"];
        return false;
    }

    /* 类型标识必须是 G 或 B */
    bool is_bind = false;
    if ([type isEqualToString:@"G"]) {
        is_bind = false;
    } else if ([type isEqualToString:@"B"]) {
        is_bind = true;
    } else {
        NSLog(@"[card_auth] FAIL: type '%@' != G/B", type);
        [self showToast:@"卡密无效"];
        return false;
    }

    /* 2. 黑名单查询: 完整卡密串是否已使用过 */
    NSArray *used = kc_get_array(@(KC_USED_CARD_LIST));
    if ([used containsObject:card_str]) {
        NSLog(@"[card_auth] FAIL: card already used");
        [self showToast:@"卡密无效"];
        return false;
    }

    /* 3. Fernet 解密 */
    NSLog(@"[card_auth] calling fernet_decrypt...");
    NSData *plain = fernet_decrypt(cipher);
    if (!plain) {
        NSLog(@"[card_auth] FAIL: fernet_decrypt nil");
        [self showToast:@"卡密无效"];
        return false;
    }
    NSLog(@"[card_auth] decrypt OK, plain_len=%lu", (unsigned long)plain.length);

    /* 解析明文: G→时间戳; B→时间戳||设备ID */
    NSString *plain_str = [[NSString alloc] initWithData:plain
                                                encoding:NSUTF8StringEncoding];
    if (!plain_str) {
        NSLog(@"[card_auth] FAIL: plain not valid UTF-8");
        [self showToast:@"卡密无效"];
        return false;
    }
    NSLog(@"[card_auth] plain_str=%@", plain_str);

    int64_t expire_ts = 0;

    if (!is_bind) {
        /* G 通用: 明文 = 到期时间戳 */
        expire_ts = plain_str.longLongValue;
    } else {
        /* B 绑定: 明文 = 到期时间戳||设备ID */
        NSArray *segs = [plain_str componentsSeparatedByString:@"||"];
        if (segs.count != 2) {
            [self showToast:@"卡密无效"];
            return false;
        }
        expire_ts = [segs[0] longLongValue];
        NSString *bind_device_id = segs[1];
        /* 与本机对比 */
        NSString *local_id = get_local_device_id();
        if (![bind_device_id isEqualToString:local_id]) {
            [self showToast:@"卡密无效"];
            return false;
        }
    }

    /* 4. 时间合法性: expire_ts 应 > 当前时间 */
    int64_t now = (int64_t)[[NSDate date] timeIntervalSince1970];
    NSLog(@"[card_auth] expire=%lld now=%lld valid=%d", expire_ts, now, (int)(expire_ts > now));
    if (expire_ts <= now) {
        [self showToast:@"卡密无效"];
        return false;
    }

    /* 5. 全部校验通过: 写入 Keychain */
    kc_set_string(@(KC_EXPIRE_CIPHER), cipher);

    NSMutableArray *new_used = [used mutableCopy];
    [new_used addObject:card_str];
    kc_set_array(@(KC_USED_CARD_LIST), new_used);

    struct timeval boot = get_boottime();
    NSDictionary *rec = @{
        @"last_check_time": @(now),
        @"last_boottime":   @((int64_t)boot.tv_sec)
    };
    NSData *rec_data = [NSJSONSerialization dataWithJSONObject:rec
                                                        options:0 error:nil];
    NSString *rec_json = [[NSString alloc] initWithData:rec_data
                                                encoding:NSUTF8StringEncoding];
    kc_set_string(@(KC_TIME_CHECK_REC), rec_json);

    return true;
}

@end

/* =========================================================
 *  弹窗辅助函数: 统一调用入口 (C 上下文)
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
            /* 清理: 去除首尾空白、换行符、中间空格 */
            NSString *clean = [pasteboard
                stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            clean = [clean stringByReplacingOccurrencesOfString:@" " withString:@""];
            clean = [clean stringByReplacingOccurrencesOfString:@"\n" withString:@""];
            clean = [clean stringByReplacingOccurrencesOfString:@"\r" withString:@""];
            /* 简单检查: 卡密格式 前缀:类型:密文, 至少包含两个 ':' */
            NSArray *testParts = [clean componentsSeparatedByString:@":"];
            if (testParts.count >= 3) {
                /* 看起来像卡密, 填入输入框 */
                g_auth_window.inputField.text = clean;
                [g_auth_window showToast:@"检测到剪贴板中有卡密，已自动填入"];
            }
        }
    });
}

/*
 * 错误场景弹窗, 用于 constructor/check_authorization 中无法通过
 * CardAuthWindow 实例调用的场景。
 * 对于"解密失败/过期/时间篡改"等不可恢复场景, 弹窗后退出进程。
 */
static void show_fatal_alert_on_main(NSString *title, NSString *msg) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:title message:msg
                      preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *exitAct = [UIAlertAction
            actionWithTitle:@"退出" style:UIAlertActionStyleDestructive
                   handler:^(UIAlertAction *_) { exit(0); }];
        [alert addAction:exitAct];
        UIWindow *win = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        win.windowLevel = UIWindowLevelAlert + 100;
        win.rootViewController = [[UIViewController alloc] init];
        win.hidden = NO;
        [win makeKeyAndVisible];
        [win.rootViewController presentViewController:alert
                                            animated:YES completion:nil];
    });
}

/* =========================================================
 *  模块 B: 授权状态校验主逻辑
 * ========================================================= */

static void check_authorization(void) {
    /* 1. 读取 Keychain 全部授权数据 */
    NSString *expire_cipher = kc_get_string(@(KC_EXPIRE_CIPHER));
    if (!expire_cipher || expire_cipher.length == 0) {
        /* 无授权 → 未激活, 唤起弹窗 */
        g_is_activated = false;
        show_auth_window_on_main();
        return;
    }

    /* 2. 存在授权: 解密拿到到期时间戳 */
    NSData *plain = fernet_decrypt(expire_cipher);
    if (!plain) {
        g_is_activated = false;
        show_fatal_alert_on_main(@"授权数据损坏",
                                  @"本地授权数据无法解密, 请重新激活");
        return;
    }

    NSString *plain_str = [[NSString alloc] initWithData:plain
                                                encoding:NSUTF8StringEncoding];
    if (!plain_str) {
        g_is_activated = false;
        show_auth_window_on_main();
        return;
    }

    /* 明文可能是 G(纯时间戳) 或 B(时间戳||设备ID), 取第一段 */
    NSArray *segs = [plain_str componentsSeparatedByString:@"||"];
    int64_t expire_ts = [segs[0] longLongValue];

    /* 3. 获取当前系统时间、当前 boottime */
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

    /* 5. 时间篡改检测 */
    /*
     * 原理: 正常情况下 (now - last_check_time) 应与
     *       (boot_sec - last_boottime) 接近。
     *       如果用户把系统时间往前调, now 变大但 boottime 不变,
     *       差值会显著增大 → 判定篡改。
     */
    if (last_check_time > 0 && last_boottime > 0) {
        int64_t wall_delta = now - last_check_time;
        int64_t boot_delta = boot_sec - last_boottime;
        int64_t diff = wall_delta - boot_delta;
        if (diff < 0) diff = -diff;
        if (diff > TIME_TAMPER_THRESHOLD) {
            g_is_activated = false;
            show_fatal_alert_on_main(@"时间篡改",
                                      @"检测到系统时间异常, 授权已失效");
            return;
        }
    }

    /* 6. 当前时间 > 到期时间戳 → 过期失效 */
    if (now > expire_ts) {
        g_is_activated = false;
        /* 过期失效: 弹窗告知后 exit(0) (硬性约束: 过期场景调用 exit) */
        show_fatal_alert_on_main(@"已过期",
                                  @"卡密已超过有效期, 授权已失效");
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

/* Hook 实现: 未激活时丢弃 App 触摸事件, 但放行弹窗及键盘的触摸 */
static void hook_sendEvent(id self, SEL _cmd, UIEvent *event) {
    if (!g_is_activated) {
        /* 未激活: 弹窗存在时放行所有触摸
         *
         * 原因: 弹窗是 keyWindow 且 windowLevel 最高, 覆盖在最上层。
         * 用户实际能碰到的只有弹窗自身和系统键盘。
         * 弹窗下方的 App 内容被完全遮挡, 无法被触摸到。
         * 键盘是系统级 UITextEffectWindow, 也需要接收触摸才能输入。
         * 所以只要弹窗在, 放行全部触摸是安全的。
         * 弹窗关闭后 (g_auth_window == nil), 恢复拦截。 */
        if (g_auth_window) {
            if (orig_sendEvent) {
                orig_sendEvent(self, _cmd, event);
            }
            return;
        }
        /* 弹窗不存在, 丢弃所有触摸 */
        return;
    }
    if (orig_sendEvent) {
        orig_sendEvent(self, _cmd, event);
    }
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
    /* 1. dylib 加载, constructor(101) 最先执行 */
    g_is_activated = false;

    /* 2. Hook sendEvent: 注册触摸拦截 (pre-main 优先完成) */
    install_sendEvent_hook();

    /* 3. 主线程派发任务: 获取设备ID + 执行授权校验
     *    禁止 constructor 内部直接调用 UIKit 弹窗,
     *    必须等 runloop 启动后再弹窗 */
    dispatch_async(dispatch_get_main_queue(), ^{
        get_local_device_id();
        check_authorization();
    });
}

/*
 * 失败场景调用 exit(0) 结束进程 (硬性约束 #7):
 *   check_authorization (App 启动时):
 *     - 授权数据损坏 (解密失败) → show_fatal_alert → exit(0)
 *     - 已过期 → show_fatal_alert → exit(0)
 *     - 时间篡改 → show_fatal_alert → exit(0)
 *   用户交互:
 *     - 点击退出按钮 → exit(0)
 *
 *   parseAndValidateCard (用户提交卡密时) 的失败场景:
 *     - 格式错误 / 黑名单 / 解密失败 / 设备不匹配 / 已过期
 *     → 弹窗告知用户, 返回 false, 允许重新输入正确卡密
 *     (不直接 exit, 因为用户可能只是输错了)
 */
