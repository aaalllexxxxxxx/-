#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "AuthManager.h"
#import "AuthUI.h"

// dylib 入口:App 进入活跃态时,无凭据则弹激活面板。
// 改为事件驱动(UIApplicationDidBecomeActiveNotification),不靠 constructor
// 轮询 key window —— Gadget 经 LC_LOAD 在 dyld init 阻塞主线程跑 agent.js,
// 主队列轮询时序不可靠;事件触发时 window/scene 必然已就绪。
// 巡检(guard_bridge.mm)发现凭据失效时也会弹面板,双保险。
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static void AuthDylibCheck(void);

__attribute__((constructor))
static void AuthDylibEntry(void) {
    // constructor 先于 main() 执行,此时注册通知;App 进活跃态后回调触发
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidBecomeActiveNotification object:nil
        queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
            AuthDylibCheck();
        }];
    // 兜底:也走一次旧的轮询,防某些 scene 早期已 active 但通知已错过的情形
    dispatch_async(dispatch_get_main_queue(), ^{ AuthDylibCheck(); });
}

static UIWindow *AuthDylibKeyWindow(void) {
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) continue;
        // 放宽:只要 window 存在即可,不强制 ForegroundActive
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window) return window;
        }
    }
    return [UIApplication sharedApplication].keyWindow;
}

static void ShowPanel(void) {
    UIWindow *window = AuthDylibKeyWindow();
    if (window) [AuthUI showOnHostWindow:window];
}

static void AuthDylibCheck(void) {
    // 无本地凭据 -> 弹激活面板(有凭据则不弹,由巡检周期校验)
    if (![[AuthManager shared] hasLocalCredential]) {
        ShowPanel();
    }
}

#pragma clang diagnostic pop
