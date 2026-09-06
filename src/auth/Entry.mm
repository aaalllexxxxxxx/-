#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "AuthManager.h"
#import "AuthUI.h"

// dylib 入口:被加载后等主窗口就绪,无凭据时弹激活面板
// 卡密周期巡检与 JS 加载由 guard_bridge.mm 统一调度,
// 本文件仅负责启动引导与面板 UI,避免与巡检产生心跳并发
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static void AuthDylibCheck(NSInteger attempt);

__attribute__((constructor))
static void AuthDylibEntry(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
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

static void AuthDylibCheck(NSInteger attempt) {
    UIWindow *window = AuthDylibKeyWindow();
    // constructor 先于 main() 执行,主窗口可能尚未创建,每 0.5s 重试最多 30s
    if (!window) {
        if (attempt >= 60) return;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ AuthDylibCheck(attempt + 1); });
        return;
    }

    // 仅负责面板展示:巡检(guard_bridge.mm)发现未通过会终止进程,
    // 存活期间无凭据时持续引导激活;验证调度全部由巡检负责
    if (![[AuthManager shared] hasLocalCredential]) {
        ShowPanel();
    }
}

#pragma clang diagnostic pop
