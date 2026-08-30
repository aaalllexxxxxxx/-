#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, AuthResult) {
    AuthResultOK = 0,        // 授权有效
    AuthResultNeedActivate,  // 未激活 / 卡密无效 / 设备不匹配 / 已过期禁用,需要(重新)激活
    AuthResultNetworkError,  // 网络异常(可容忍,不应打断已授权用户)
    AuthResultSecurityError, // 响应验签失败(疑似伪造服务器/重放),凭据已清除
};

@interface AuthManager : NSObject

+ (instancetype)shared;

/// 设备指纹:Keychain 持久 UUID 的 SHA256(卸载重装不变,换设备必变)
+ (NSString *)deviceID;

/// Keychain 中是否已有激活凭据(secret_key)
- (BOOL)hasLocalCredential;

/// 激活卡密并绑定本机(POST /api/activate),回调回主线程
- (void)activateCard:(NSString *)card
            callback:(void (^)(AuthResult result, NSString *msg, NSDictionary *info))callback;

/// 心跳校验(POST /api/heartbeat):上行 c_sig + 响应 nonce/seq/sig 三重验签
- (void)verifyWithCallback:(void (^)(AuthResult result, NSString *msg))callback;

/// 本地缓存(离线放行判定与展示用):key / expires_at / last_ok
- (nullable NSDictionary *)localInfo;

/// 离线容忍判定:最后一次心跳成功距今是否仍在宽限窗口内
- (BOOL)hasUsableOfflineCache;

@end
