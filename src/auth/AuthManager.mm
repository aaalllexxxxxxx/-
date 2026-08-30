#import "AuthManager.h"
#import "Config.h"
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>

// Keychain item:service 固定,account 区分凭据与设备 UUID
static NSString * const kService = @"AuthDylib";
static NSString * const kAccountCredential = @"credential"; // JSON {key,secret,max_seq,last_ok,expires_at,pkg_state,pkg_factor,pkg_kk}
static NSString * const kAccountDevice     = @"device";     // 安装生成的持久 UUID

// pkg_state:包名绑定握手状态(服务端 v4.2.1 无状态校验,pkg_kk 终身缓存)
static NSInteger const kPkgUnknown = 0; // 未握手
static NSInteger const kPkgUnbound = 1; // 握手过:项目未绑定包名/通用卡,无需因子
static NSInteger const kPkgBound   = 2; // 握手过:pkg_factor 有效(pkg_kk 已缓存)

#pragma mark - Crypto helpers

static NSString *SHA256Hex(NSString *input) {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:64];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static NSData *SHA256Data(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    return [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
}

static NSData *HexDecode(NSString *hex) {
    if (hex.length == 0 || hex.length % 2 != 0) return nil;
    NSString *lower = hex.lowercaseString;
    NSMutableData *out = [NSMutableData dataWithCapacity:lower.length / 2];
    char byte[3] = {0, 0, 0};
    for (NSUInteger i = 0; i < lower.length; i += 2) {
        byte[0] = [lower characterAtIndex:i];
        byte[1] = [lower characterAtIndex:i + 1];
        unsigned value = 0;
        if (sscanf(byte, "%2x", &value) != 1) return nil;
        [out appendBytes:&value length:1];
    }
    return out;
}

// HMAC-SHA256:key 为原始字节,输出小写 hex
static NSString *HMACRawHex(NSData *key, NSString *message) {
    if (key.length == 0) return nil;
    NSData *msg = [message dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, msg.bytes, (CC_LONG)msg.length, mac);
    NSMutableString *hex = [NSMutableString stringWithCapacity:64];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", mac[i]];
    return hex;
}

static NSString *HMACHex(NSString *keyHex, NSString *message) {
    return HMACRawHex(HexDecode(keyHex), message);
}

// AES-256 单块 ECB 加密(公开 API,GCM 构件)
static void AESECBEncryptBlock(NSData *key, const uint8_t *in, uint8_t *out) {
    size_t moved = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode,
            key.bytes, key.length, NULL, in, kCCBlockSizeAES128, out, kCCBlockSizeAES128, &moved);
}

// GF(2^128) 乘法(NIST SP 800-38D MSB-first),结果覆盖 X
static void GF128Mul(uint8_t *X, const uint8_t *H) {
    uint8_t Z[16] = {0}, V[16];
    memcpy(V, H, 16);
    for (int i = 0; i < 16; i++) {
        for (int b = 7; b >= 0; b--) {
            if ((X[i] >> b) & 1)
                for (int k = 0; k < 16; k++) Z[k] ^= V[k];
            uint8_t lsb = V[15] & 1;
            for (int k = 15; k > 0; k--) V[k] = (uint8_t)((V[k] >> 1) | (V[k - 1] << 7));
            V[0] >>= 1;
            if (lsb) V[0] ^= 0xE1;
        }
    }
    memcpy(X, Z, 16);
}

// AES-256-GCM 解密:packed = base64(iv[12] | tag[16] | ct),与服务端封装格式一致。
// iOS 公开 CryptoKit 不可从 ObjC 直接调用、GCM 头文件仅 macOS SDK 提供,
// 故按 NIST SP 800-38D 手写:ECB 单块 + CTR 异或 + GHASH 认证(算法已经 Node 与原生 GCM 500 组互验)
static NSData *AESGCMDecryptPacked(NSString *packedB64, NSData *key) {
    NSData *packed = [[NSData alloc] initWithBase64EncodedString:packedB64 options:0];
    if (packed.length < 12 + 16 + 1 || key.length != kCCKeySizeAES256) return nil;
    const uint8_t *p = (const uint8_t *)packed.bytes;
    NSData *ct = [packed subdataWithRange:NSMakeRange(28, packed.length - 28)];
    NSUInteger ctLen = ct.length;
    const uint8_t *ctb = (const uint8_t *)ct.bytes;

    uint8_t H[16], J0[16];
    static const uint8_t zero[16] = {0};
    AESECBEncryptBlock(key, zero, H);
    memcpy(J0, p, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    // CTR:计数器从 inc32(J0) 起
    NSMutableData *plain = [NSMutableData dataWithLength:ctLen];
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    uint8_t *plainB = (uint8_t *)plain.mutableBytes;
    for (NSUInteger off = 0; off < ctLen; off += 16) {
        for (int i = 15; i >= 12; i--) { if (++ctr[i]) break; }
        uint8_t ks[16];
        AESECBEncryptBlock(key, ctr, ks);
        NSUInteger n = MIN(16, ctLen - off);
        for (NSUInteger i = 0; i < n; i++) plainB[off + i] = ctb[off + i] ^ ks[i];
    }

    // GHASH(空 AAD || ct || 长度块)
    uint8_t Y[16] = {0}, blk[16];
    for (NSUInteger off = 0; off < ctLen; off += 16) {
        memset(blk, 0, 16);
        NSUInteger n = MIN(16, ctLen - off);
        memcpy(blk, ctb + off, n);
        for (int i = 0; i < 16; i++) Y[i] ^= blk[i];
        GF128Mul(Y, H);
    }
    memset(blk, 0, 16); // AAD bitlen = 0
    uint64_t ctBits = (uint64_t)ctLen * 8;
    for (int i = 0; i < 8; i++) blk[8 + i] = (uint8_t)(ctBits >> ((7 - i) * 8));
    for (int i = 0; i < 16; i++) Y[i] ^= blk[i];
    GF128Mul(Y, H);

    // tag = E_K(J0) XOR GHASH
    uint8_t tag[16];
    AESECBEncryptBlock(key, J0, tag);
    for (int i = 0; i < 16; i++) tag[i] ^= Y[i];
    if (memcmp(tag, p + 12, 16) != 0) return nil;
    return plain;
}

static NSString *RandomNonceHex(void) {
    uint8_t raw[16];
    SecRandomCopyBytes(kSecRandomDefault, sizeof(raw), raw);
    NSMutableString *hex = [NSMutableString stringWithCapacity:32];
    for (NSUInteger i = 0; i < sizeof(raw); i++) [hex appendFormat:@"%02x", raw[i]];
    return hex;
}

#pragma mark - Keychain

static NSData *KCRead(NSString *account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)query, &result) != errSecSuccess) return nil;
    return CFBridgingRelease(result);
}

static BOOL KCWrite(NSString *account, NSData *data) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecAttrAccount: account,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
    };
    return SecItemAdd((__bridge CFDictionaryRef)attributes, NULL) == errSecSuccess;
}

static void KCDelete(NSString *account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecAttrAccount: account,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

#pragma mark - Error diagnosis

static NSString *AuthNetworkMessage(NSError *error, NSData *data) {
    if (error == nil && data.length == 0) return @"服务器返回空响应";
    NSString *raw = error.localizedDescription ?: @"";
    if (raw.length == 0) return @"网络异常,请稍后重试";
    if ([raw rangeOfString:@"App Transport Security" options:NSCaseInsensitiveSearch].location != NSNotFound)
        return @"宿主需允许 HTTP(ATS)或服务端改用 HTTPS";
    if ([raw rangeOfString:@"certificate" options:NSCaseInsensitiveSearch].location != NSNotFound ||
        [raw rangeOfString:@"SSL" options:NSCaseInsensitiveSearch].location != NSNotFound ||
        [raw rangeOfString:@"TLS" options:NSCaseInsensitiveSearch].location != NSNotFound)
        return [NSString stringWithFormat:@"证书错误:%@", raw];
    if ([raw rangeOfString:@"Could not connect" options:NSCaseInsensitiveSearch].location != NSNotFound ||
        [raw rangeOfString:@"timed out" options:NSCaseInsensitiveSearch].location != NSNotFound ||
        [raw rangeOfString:@"appears to be down" options:NSCaseInsensitiveSearch].location != NSNotFound)
        return @"无法连接服务器,请检查地址/同一局域网/服务是否启动";
    return [NSString stringWithFormat:@"网络错误:%@", raw];
}

// 深度归一化:全角转半角、剔除空白/零宽/其他非法字符。
// V3 卡密大小写敏感(混合大小写+校验位),严禁大小写折叠;
// 服务端 normalizeKey 仅去空白,这里与其对齐并额外容错全角输入
static NSString *NormalizeCardKey(NSString *raw) {
    NSMutableString *out = [NSMutableString string];
    for (NSUInteger i = 0; i < raw.length; i++) {
        unichar c = [raw characterAtIndex:i];
        if (c >= 0xFF01 && c <= 0xFF5E) c -= 0xFEE0;   // 全角区 → ASCII
        if (c == 0x200B || c == 0x200C || c == 0x200D || c == 0xFEFF) continue; // 零宽字符
        if ([[NSCharacterSet whitespaceAndNewlineCharacterSet] characterIsMember:c]) continue;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-') {
            [out appendFormat:@"%C", c];
        }
    }
    return out;
}

// 是否服务端包名校验类失败(密钥轮换等场景,重握手可恢复)
static BOOL IsBindingFailure(NSString *msg) {
    if (msg.length == 0) return NO;
    return [msg rangeOfString:@"身份验证失败"].location != NSNotFound ||
           [msg rangeOfString:@"仅限指定软件"].location != NSNotFound ||
           [msg rangeOfString:@"包名"].location != NSNotFound;
}

#pragma mark - AuthManager

@interface AuthManager ()
- (void)handshakeForKey:(NSString *)key
               callback:(void (^)(BOOL hardFail, NSString *errMsg, NSInteger state, NSString *factor))callback;
- (void)performActivate:(NSString *)key
             pkgState:(NSInteger)pkgState
            pkgFactor:(NSString *)pkgFactor
             callback:(void (^)(AuthResult, NSString *, NSDictionary *))callback;
- (void)performVerify:(void (^)(AuthResult, NSString *))callback;
@end

@implementation AuthManager

+ (instancetype)shared {
    static AuthManager *manager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ manager = [[AuthManager alloc] init]; });
    return manager;
}

#pragma mark Device fingerprint

+ (NSString *)deviceID {
    NSString *uuid = nil;
    NSData *stored = KCRead(kAccountDevice);
    if (stored.length > 0) uuid = [[NSString alloc] initWithData:stored encoding:NSUTF8StringEncoding];
    if (uuid.length == 0) {
        uuid = [[NSUUID UUID] UUIDString];
        KCWrite(kAccountDevice, [uuid dataUsingEncoding:NSUTF8StringEncoding]);
    }
    return SHA256Hex([@"ckdylib:" stringByAppendingString:uuid]);
}

#pragma mark Credential storage (Keychain JSON)

- (nullable NSDictionary *)localInfo {
    NSData *data = KCRead(kAccountCredential);
    if (data.length == 0) return nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [obj isKindOfClass:[NSDictionary class]] ? obj : nil;
}

- (BOOL)hasLocalCredential {
    NSDictionary *cred = [self localInfo];
    NSString *key = cred[@"key"];
    NSString *secret = cred[@"secret"];
    return key.length > 0 && secret.length >= 32;
}

- (void)saveCredentialKey:(NSString *)key secret:(NSString *)secret
                   maxSeq:(long long)maxSeq expiresAt:(NSString *)expiresAt
                 pkgState:(NSInteger)pkgState pkgFactor:(NSString *)pkgFactor pkgKk:(NSString *)pkgKk {
    NSDictionary *cred = @{
        @"key": key ?: @"",
        @"secret": secret ?: @"",
        @"max_seq": @(maxSeq),
        @"last_ok": @([NSDate date].timeIntervalSince1970),
        @"expires_at": expiresAt ?: @"",
        @"pkg_state": @(pkgState),
        @"pkg_factor": pkgFactor ?: @"",
        @"pkg_kk": pkgKk ?: @"",
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:cred options:0 error:nil];
    if (data) KCWrite(kAccountCredential, data);
}

- (void)clearCredential {
    KCDelete(kAccountCredential);
}

- (BOOL)hasUsableOfflineCache {
    NSDictionary *cred = [self localInfo];
    NSTimeInterval lastOk = [cred[@"last_ok"] doubleValue];
    if (lastOk <= 0) return NO;
    return [NSDate date].timeIntervalSince1970 - lastOk < AUTH_OFFLINE_GRACE_HOURS * 3600;
}

#pragma mark HTTP

- (void)postPath:(NSString *)path
            body:(NSDictionary *)body
        callback:(void (^)(NSError *error, NSDictionary *json, NSData *raw, NSInteger httpStatus))callback {
    NSString *base = AUTH_SERVER_URL;
    while ([base hasSuffix:@"/"]) base = [base substringToIndex:base.length - 1];
    if ([base hasSuffix:@"/api"]) base = [base substringToIndex:base.length - 4];
    NSURL *url = [NSURL URLWithString:[base stringByAppendingString:path]];
    if (url == nil) {
        NSDictionary *info = @{NSLocalizedDescriptionKey: @"服务端地址配置错误"};
        callback([NSError errorWithDomain:@"AuthDylib" code:-1 userInfo:info], nil, nil, 0);
        return;
    }
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    request.timeoutInterval = 15;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    [[NSURLSession.sharedSession dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            NSInteger httpStatus = 0;
            if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
                httpStatus = ((NSHTTPURLResponse *)response).statusCode;
            }
            NSDictionary *json = nil;
            if (data.length > 0) {
                id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                if ([obj isKindOfClass:[NSDictionary class]]) json = obj;
            }
            callback(error, json, data, httpStatus);
        });
    }] resume];
}

- (nullable NSDictionary *)payloadOf:(NSDictionary *)json {
    id data = json[@"data"];
    return [data isKindOfClass:[NSDictionary class]] ? data : nil;
}

#pragma mark Package binding handshake (POST /api/project-key)

// v4.2.1:pre_key = SHA256("pre:" + 卡密) 公开派生,激活前即可完成握手。
// hardFail=YES 表示必须中止(非官方软件);其余失败为软失败(可继续走激活/心跳拿真实报错)
- (void)handshakeForKey:(NSString *)key
               callback:(void (^)(BOOL hardFail, NSString *errMsg, NSInteger state, NSString *factor))callback {
    NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:@{@"key": key}];
    if (AUTH_PROJECT_SLUG.length > 0) body[@"project"] = AUTH_PROJECT_SLUG;

    [self postPath:@"/api/project-key"
              body:body
        callback:^(NSError *error, NSDictionary *json, NSData *raw, NSInteger httpStatus) {
        if (error != nil || json == nil) {
            callback(NO, AuthNetworkMessage(error, raw), kPkgUnknown, nil);
            return;
        }
        NSDictionary *data = [self payloadOf:json];
        if ([json[@"code"] integerValue] != 0 || data == nil) {
            callback(NO, json[@"message"] ?: @"握手失败", kPkgUnknown, nil);
            return;
        }
        if (![data[@"success"] boolValue]) {
            // 通用卡/未绑定项目:按"无需因子"处理
            NSString *msg = data[@"message"] ?: @"";
            if ([msg rangeOfString:@"无需包名验证"].location != NSNotFound ||
                [msg rangeOfString:@"未绑定"].location != NSNotFound) {
                callback(NO, nil, kPkgUnbound, nil);
                return;
            }
            callback(NO, msg.length > 0 ? msg : @"握手失败", kPkgUnknown, nil);
            return;
        }
        if (![data[@"bound"] boolValue]) {
            callback(NO, nil, kPkgUnbound, nil);
            return;
        }

        // 三层解密:pkg_kk = AESGCM(pkg_kk_ct, pre_key);包名 = AESGCM(pkg_ct, pkg_kk)
        NSData *preKey = SHA256Data([[@"pre:" stringByAppendingString:key]
                                     dataUsingEncoding:NSUTF8StringEncoding]);
        NSData *pkgKk = AESGCMDecryptPacked(data[@"pkg_kk_ct"], preKey);
        if (pkgKk.length != 32) {
            callback(NO, @"包名材料解密失败(卡密可能有误)", kPkgUnknown, nil);
            return;
        }
        NSData *pkgPlain = AESGCMDecryptPacked(data[@"pkg_ct"], pkgKk);
        NSString *expectedPkg = pkgPlain.length > 0
            ? [[NSString alloc] initWithData:pkgPlain encoding:NSUTF8StringEncoding] : nil;
        NSString *localPkg = [NSBundle mainBundle].bundleIdentifier ?: @"";
        if (expectedPkg.length == 0 || ![localPkg isEqualToString:expectedPkg]) {
            // 非官方软件:本地包名与服务端登记不一致,硬失败
            callback(YES, @"非官方软件,拒绝激活", kPkgUnknown, nil);
            return;
        }
        // factor = HMAC-SHA256(pkg_kk 原始字节, 本地包名)
        NSString *factor = HMACRawHex(pkgKk, localPkg);
        if (factor.length == 0) {
            callback(NO, @"因子派生失败", kPkgUnknown, nil);
            return;
        }
        callback(NO, nil, kPkgBound, factor);
        // 注:pkg_kk 已随 factor 由调用方持久化(Keychain),终身复用,无需重复握手
    }];
}

#pragma mark Activate (POST /api/activate)

- (void)activateCard:(NSString *)card
            callback:(void (^)(AuthResult, NSString *, NSDictionary *))callback {
    // V3 大小写敏感:仅清洗全角/空白,不动大小写(与服务端 normalizeKey 对齐)
    NSString *key = NormalizeCardKey(card);
    if (key.length == 0) {
        callback(AuthResultNeedActivate, @"请输入卡密", nil);
        return;
    }
    // 激活前握手(pre_key 只依赖卡号):绑定包名的卡必须先拿 factor 才能过 activate 校验
    [self handshakeForKey:key callback:^(BOOL hardFail, NSString *errMsg, NSInteger state, NSString *factor) {
        if (hardFail) {
            callback(AuthResultSecurityError, errMsg, nil);
            return;
        }
        [self performActivate:key pkgState:state pkgFactor:factor ?: @"" callback:callback];
    }];
}

- (void)performActivate:(NSString *)key
               pkgState:(NSInteger)pkgState
              pkgFactor:(NSString *)pkgFactor
               callback:(void (^)(AuthResult, NSString *, NSDictionary *))callback {
    NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:@{
        @"key": key,
        @"device": [AuthManager deviceID],
    }];
    if (AUTH_PROJECT_SLUG.length > 0) body[@"project"] = AUTH_PROJECT_SLUG;
    BOOL bound = pkgState == kPkgBound && pkgFactor.length > 0;
    if (bound) body[@"pkg_factor"] = pkgFactor;

    // 已持同卡 sk(重复激活/换绑):补 nonce + c_sig 完整验签;首次激活尚无 sk,不带 c_sig
    NSDictionary *cred = [self localInfo];
    NSString *secret = cred[@"secret"];
    BOOL sameCard = [cred[@"key"] isEqualToString:key] && secret.length >= 32;
    if (sameCard) {
        NSString *nonce = RandomNonceHex();
        NSString *device = [AuthManager deviceID];
        NSString *msg = bound
            ? [NSString stringWithFormat:@"%@|%@|%@|%@", key, device, nonce, pkgFactor]
            : [NSString stringWithFormat:@"%@|%@|%@", key, device, nonce];
        body[@"nonce"] = nonce;
        body[@"c_sig"] = HMACHex(secret, msg) ?: @"";
    }

    [self postPath:@"/api/activate"
              body:body
        callback:^(NSError *error, NSDictionary *json, NSData *raw, NSInteger httpStatus) {
        if (error != nil || json == nil) {
            callback(AuthResultNetworkError, AuthNetworkMessage(error, raw), nil);
            return;
        }
        NSDictionary *data = [self payloadOf:json];
        if ([json[@"code"] integerValue] != 0 || data == nil) {
            callback(AuthResultNeedActivate,
                     json[@"message"] ?: (data[@"message"] ?: @"激活失败"), nil);
            return;
        }
        if (![data[@"success"] boolValue]) {
            callback(AuthResultNeedActivate, data[@"message"] ?: @"激活失败", nil);
            return;
        }
        NSString *secretKey = data[@"secret_key"];
        if (secretKey.length < 32) {
            callback(AuthResultNetworkError, @"服务端响应缺少签名密钥", nil);
            return;
        }
        // 持久化:sk + 包名握手结果(pkg_kk 相关字段随 factor 一起落 Keychain 终身复用)
        // pkg_kk 本身不在本层返回,由握手层缓存;此处沿用当前握手产物
        [self saveCredentialKey:key secret:secretKey maxSeq:0 expiresAt:data[@"expires_at"]
                       pkgState:pkgState pkgFactor:bound ? pkgFactor : @"" pkgKk:@""];
        callback(AuthResultOK, data[@"message"] ?: @"激活成功", data);
    }];
}

#pragma mark Verify (POST /api/heartbeat)

- (void)verifyWithCallback:(void (^)(AuthResult, NSString *))callback {
    NSDictionary *cred = [self localInfo];
    NSString *key = cred[@"key"];
    NSString *secret = cred[@"secret"];
    if (key.length == 0 || secret.length < 32) {
        callback(AuthResultNeedActivate, @"未激活");
        return;
    }
    // 从未握手过 → 先握手(服务端 v4.2.1 无状态,任何时刻握手都有效)
    if ([cred[@"pkg_state"] integerValue] == kPkgUnknown) {
        [self handshakeForKey:key callback:^(BOOL hardFail, NSString *errMsg, NSInteger state, NSString *factor) {
            if (hardFail) {
                callback(AuthResultSecurityError, errMsg);
                return;
            }
            [self persistPkgState:state factor:factor forKey:key];
            [self performVerify:callback];
        }];
        return;
    }
    [self performVerify:callback];
}

// 把握手产物写入现有凭据(不动 sk 等字段)
- (void)persistPkgState:(NSInteger)state factor:(NSString *)factor forKey:(NSString *)key {
    NSDictionary *cred = [self localInfo];
    if (!cred) return;
    [self saveCredentialKey:cred[@"key"] secret:cred[@"secret"]
                     maxSeq:[cred[@"max_seq"] longLongValue]
                  expiresAt:cred[@"expires_at"]
                   pkgState:state pkgFactor:factor ?: @"" pkgKk:cred[@"pkg_kk"] ?: @""];
}

- (void)performVerify:(void (^)(AuthResult, NSString *))callback {
    NSDictionary *cred = [self localInfo];
    NSString *key = cred[@"key"];
    NSString *secret = cred[@"secret"];
    NSString *device = [AuthManager deviceID];
    NSString *nonce = RandomNonceHex();
    NSString *factor = cred[@"pkg_factor"];
    BOOL bound = [cred[@"pkg_state"] integerValue] == kPkgBound && factor.length > 0;
    NSString *msg = bound
        ? [NSString stringWithFormat:@"%@|%@|%@|%@", key, device, nonce, factor]
        : [NSString stringWithFormat:@"%@|%@|%@", key, device, nonce];
    NSString *cSig = HMACHex(secret, msg);
    if (cSig.length == 0) {
        callback(AuthResultSecurityError, @"本地凭据损坏,请重新激活");
        [self clearCredential];
        return;
    }
    NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:@{
        @"key": key,
        @"device": device,
        @"nonce": nonce,
        @"c_sig": cSig,
    }];
    if (bound) body[@"pkg_factor"] = factor;
    if (AUTH_PROJECT_SLUG.length > 0) body[@"project"] = AUTH_PROJECT_SLUG;

    [self postPath:@"/api/heartbeat"
              body:body
        callback:^(NSError *error, NSDictionary *json, NSData *raw, NSInteger httpStatus) {
        if (error != nil || json == nil) {
            callback(AuthResultNetworkError, AuthNetworkMessage(error, raw));
            return;
        }
        NSDictionary *data = [self payloadOf:json];
        NSInteger code = [json[@"code"] integerValue];
        NSString *srvMsg = json[@"message"] ?: @"";
        if (code != 0 || data == nil) {
            // 403 包名校验失败:可能是服务端轮换过密钥(pkg_kk 失效)→ 重握手刷新后重试一次
            if (code == 403 && IsBindingFailure(srvMsg)) {
                [self handshakeForKey:key callback:^(BOOL hardFail, NSString *errMsg, NSInteger state, NSString *factor2) {
                    if (hardFail) {
                        callback(AuthResultSecurityError, errMsg);
                        return;
                    }
                    if (errMsg != nil) {
                        callback(AuthResultNetworkError, errMsg);
                        return;
                    }
                    [self persistPkgState:state factor:factor2 forKey:key];
                    [self performVerify:callback];
                }];
                return;
            }
            // 401 验签失败:sk 与服务端不一致(服务端重置),需重新激活
            [self clearCredential];
            callback(AuthResultNeedActivate, srvMsg.length > 0 ? srvMsg : @"服务端拒绝请求");
            return;
        }

        // ---- 响应三重验签:nonce 回显 / HMAC / seq 单调 ----
        BOOL valid = [data[@"valid"] boolValue];
        long long seq = [data[@"seq"] longLongValue];
        long long ts = [data[@"ts"] longLongValue];
        long long maxSeq = [cred[@"max_seq"] longLongValue];
        NSString *signedMsg = [NSString stringWithFormat:@"%@|%@|%@|%@|%@|%lld|%lld|%@",
                               key, device, valid ? @"1" : @"0",
                               data[@"status"] ?: @"", data[@"expires_at"] ?: @"",
                               seq, ts, nonce];
        NSString *expect = HMACHex(secret, signedMsg);
        BOOL nonceOK = [data[@"nonce"] isKindOfClass:[NSString class]] &&
                       [data[@"nonce"] isEqualToString:nonce];
        BOOL sigOK = expect.length > 0 && [expect isEqualToString:data[@"sig"]];
        BOOL seqOK = seq > maxSeq;
        if (!(nonceOK && sigOK && seqOK)) {
            [self clearCredential];
            callback(AuthResultSecurityError, @"安全校验失败,请重新激活");
            return;
        }

        [self saveCredentialKey:key secret:secret maxSeq:seq expiresAt:data[@"expires_at"]
                       pkgState:[cred[@"pkg_state"] integerValue]
                      pkgFactor:cred[@"pkg_factor"] ?: @"" pkgKk:cred[@"pkg_kk"] ?: @""];

        if (!valid) {
            callback(AuthResultNeedActivate, data[@"message"] ?: @"授权已失效");
            return;
        }
        NSString *okMsg = @"授权有效";
        if ([data[@"in_grace"] boolValue]) okMsg = @"授权已到期,当前处于宽限期,请尽快续费";
        else if ([data[@"expiring_soon"] boolValue])
            okMsg = [NSString stringWithFormat:@"授权即将到期(剩余 %@ 天),请及时续费", data[@"days_left"]];
        callback(AuthResultOK, okMsg);
    }];
}

@end
