/*
 * guard_bridge.mm - guard.c 与 AuthDylib 卡密验证的联动桥接
 *
 * 联动策略（满足"验证被破解后 JS 不再加载"）：
 *  1. 启动时：本地有激活凭据且在离线宽限窗口内 -> 延迟加载 JS
 *     （无凭据 -> 卡密面板弹出，JS 不加载）
 *  2. 激活成功通知（AuthUIActivatedNotification）-> 立即加载 JS
 *  3. 心跳判定为 NeedActivate / SecurityError（被禁用/解绑/验签失败）
 *     -> guard_die() 终止进程，JS 随进程死亡
 *  4. 卡密逻辑被整体 patch 移除 -> guard.c 的反 hook/反调试检测命中
 *     -> 随机延迟崩溃
 *
 * 编译时由 build_guard.sh 传入 -DGUARD_AUTH_BRIDGE=1，
 * 此时 guard.c 的 constructor 不再自动加载 JS，改由本文件控制。
 */

#import <Foundation/Foundation.h>
#import "auth/AuthManager.h"
#import "auth/AuthUI.h"
#import <dlfcn.h>

/* guard.c 导出 */
extern "C" {
    int guard_load_frida_agent(void);
    void guard_request_die(void);
}

static bool g_js_loaded = false;

static void LoadJsOnce(void) {
    if (g_js_loaded) return;
    if (guard_load_frida_agent() == 0) {
        g_js_loaded = true;
        NSLog(@"[guard] agent loaded after auth ok");
    }
}

__attribute__((constructor))
static void GuardAuthBridge(void) {
    /* 1. 激活成功 -> 加载 JS */
    [[NSNotificationCenter defaultCenter]
        addObserverForName:AuthUIActivatedNotification object:nil
        queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
        LoadJsOnce();
    }];

    /* 2. 已有本地凭据（老用户）-> 心跳确认授权有效后加载 JS；
     *    离线宽限期内网络异常也放行（与 AuthDylib 的离线容忍策略一致） */
    AuthManager *am = [AuthManager shared];
    if ([am hasLocalCredential]) {
        if ([am hasUsableOfflineCache]) {
            /* 宽限期内先加载，后台心跳再做最终确认 */
            LoadJsOnce();
        }
        [am verifyWithCallback:^(AuthResult result, NSString *msg) {
            if (result == AuthResultOK) {
                LoadJsOnce();
            } else if (result == AuthResultNeedActivate ||
                       result == AuthResultSecurityError) {
                /* 服务端明确拒绝：凭据已被清除，面板会弹出；
                 * 若 JS 已加载，终止进程让其随之失效 */
                if (g_js_loaded) guard_request_die();
            }
            /* NetworkError: 容忍，不处理 */
        }];
    }
    /* 无凭据：什么都不做。卡密面板弹出，JS 保持不加载 */
}
