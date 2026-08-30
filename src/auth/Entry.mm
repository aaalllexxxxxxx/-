#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "Config.h"
#import "AuthManager.h"
#import "AuthUI.h"

// dylib 入口:被加载后等主窗口就绪,再决定放行还是弹激活面板
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static dispatch_source_t _heartbeatTimer;

static void AuthDylibCheck(NSInteger attempt);
static void StartHeartbeat(void);

__attribute__((constructor))
static void AuthDylibEntry(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        // 激活面板成功后收到通知 → 启动心跳保活
        [[NSNotificationCenter defaultCenter]
            addObserverForName:AuthUIActivatedNotification object:nil
            queue:[NSOperationQueue mainQueue]
            usingBlock:^(NSNotification *note) {
            StartHeartbeat();
        }];
        AuthDylibCheck(0);
    });
}

static UIWindow *AuthDylibKeyWindow(void) {
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if ([scene isKindOfClass:[UIWindowScene class]] &&
            scene.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *window in ((UIWindowScene *)scene).windows) {
                if (window.isKeyWindow) return window;
            }
        }
    }
    return [UIApplication sharedApplication].keyWindow;
}

static void ShowPanel(void) {
    UIWindow *window = AuthDylibKeyWindow();
    if (window) [AuthUI showOnHostWindow:window];
}

// 每 AUTH_HEARTBEAT_SECONDS 心跳;服务端明确拒绝(禁用/解绑/重置)才弹面板,
// 网络抖动不打断已授权用户(离线容忍由 hasUsableOfflineCache 在下次启动兜底)
static void StartHeartbeat(void) {
    if (_heartbeatTimer != nil) return;
    int64_t interval = (int64_t)AUTH_HEARTBEAT_SECONDS * NSEC_PER_SEC;
    _heartbeatTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                             dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(_heartbeatTimer, dispatch_walltime(NULL, interval), interval, 5 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(_heartbeatTimer, ^{
        [[AuthManager shared] verifyWithCallback:^(AuthResult result, NSString *msg) {
            if (result == AuthResultNeedActivate || result == AuthResultSecurityError) {
                dispatch_source_cancel(_heartbeatTimer);
                _heartbeatTimer = nil;
                dispatch_async(dispatch_get_main_queue(), ^{ ShowPanel(); });
            }
            // 网络错误:静默,等待下一轮
        }];
    });
    dispatch_resume(_heartbeatTimer);
}

static void AuthDylibCheck(NSInteger attempt) {
    UIWindow *window = AuthDylibKeyWindow();
    // constructor 先于 main() 执行,主窗口可能尚未创建,每 0.5s 重试最多 30s
    if (!window) {
        if (attempt >= 60) return;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ AuthDylibCheck(attempt + 1); });
        return;
    }

    AuthManager *auth = [AuthManager shared];
    if (![auth hasLocalCredential]) {
        ShowPanel();
        return;
    }

    [auth verifyWithCallback:^(AuthResult result, NSString *msg) {
        switch (result) {
            case AuthResultOK:
                StartHeartbeat();
                return;
            case AuthResultNetworkError:
                // 离线容忍:最后一次成功心跳仍在宽限窗口内 → 放行并继续心跳
                if ([auth hasUsableOfflineCache]) { StartHeartbeat(); return; }
                ShowPanel();
                return;
            default:
                // 未激活 / 服务端明确拒绝 / 验签失败(凭据已清) → 弹面板重新激活
                ShowPanel();
                return;
        }
    }];
}

#pragma clang diagnostic pop
