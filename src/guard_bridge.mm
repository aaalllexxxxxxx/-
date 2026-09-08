/*
 * guard_bridge.mm - guard.c 与 AuthDylib 卡密验证的联动桥接
 *
 * 联动策略（"JS 先行生效 + 周期巡检闪退"）：
 *  1. 启动时：constructor 立即加载 JS，与卡密状态解耦
 *     （失败按 1s/3s/9s 退避重试，至多 3 次）
 *  2. 巡检：以 [AUTH_PATROL_MIN_SECONDS, AUTH_PATROL_MAX_SECONDS]
 *     区间随机间隔调用 verifyWithCallback（本地凭据 + 服务端心跳双检），
 *     NeedActivate / SecurityError → 清凭据 + 弹激活面板(当场重新激活,不闪退);
 *     NetworkError → 闪退(断网不容忍)
 *  3. 判定与崩溃点分离：guard_die() 随机延迟 0-30s 后 SIGSEGV
 *  4. 卡密逻辑被整体 patch 移除 -> guard.c 反 hook/反调试检测命中 -> 随机延迟崩溃
 *
 * 巡检调度唯一性：本文件是全仓库唯一的 verifyWithCallback 周期调度方，
 * Entry.mm 已移除心跳逻辑，避免心跳 seq 单调校验的并发冲突误杀。
 *
 * 编译时由 build_guard.sh 传入 -DGUARD_AUTH_BRIDGE=1，
 * 此时 guard.c 的 constructor 由本文件控制 JS 加载。
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "auth/AuthUI.h"
#import "auth/AuthManager.h"
#import "auth/Config.h"
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
        NSLog(@"[guard] agent loaded at startup");
    }
}

/* JS 立即生效：失败退避重试 1s/3s/9s，共 3 次 */
static void LoadJsWithRetry(NSInteger attempt) {
    if (g_js_loaded) return;
    LoadJsOnce();
    if (g_js_loaded || attempt >= 3) return;
    static const int delays[] = {1, 3, 9};
    int64_t delay = (int64_t)delays[attempt] * NSEC_PER_SEC;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delay),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        LoadJsWithRetry(attempt + 1);
    });
}

/* ============ 周期巡检 ============ */

static dispatch_source_t g_patrol_timer;

static uint64_t NextPatrolIntervalNs(void) {
    /* [MIN, MAX] 闭区间随机，ns */
    int lo = AUTH_PATROL_MIN_SECONDS;
    int hi = AUTH_PATROL_MAX_SECONDS;
    if (hi < lo) { int t = lo; lo = hi; hi = t; }
    int span = hi - lo + 1;
    int sec = lo + (int)arc4random_uniform((uint32_t)span);
    return (uint64_t)sec * NSEC_PER_SEC;
}

static void PatrolTick(void) {
    [[AuthManager shared] verifyWithCallback:^(AuthResult result, NSString *msg) {
        switch (result) {
            case AuthResultOK:
                return; /* 下一轮巡检继续 */
            case AuthResultNeedActivate:   /* 未激活/无效/过期/设备不匹配 */
            case AuthResultSecurityError:  /* 响应验签失败,疑似伪造 */
                /* 凭据失效:清凭据并弹激活面板,让用户当场重新激活
                 * (而非直接闪退——直接 die 不清凭据会导致下次启动 hasLocalCredential
                 * 仍为真、不弹面板,反复闪退直到凭据被某次清掉,体验差且像没卡密) */
                NSLog(@"[guard] patrol reject (%ld), clear cred + show panel", (long)result);
                [[AuthManager shared] clearCredential];
                dispatch_async(dispatch_get_main_queue(), ^{
                    UIWindow *win = nil;
                    for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
                        if (![sc isKindOfClass:[UIWindowScene class]]) continue;
                        for (UIWindow *w in ((UIWindowScene *)sc).windows) {
                            if (w.isKeyWindow) { win = w; break; }
                        }
                        if (win) break;
                    }
                    if (win) [AuthUI showOnHostWindow:win];
                });
                return; /* 不 die:面板阻塞,等用户重新激活;激活成功后巡检自然恢复 */
            case AuthResultNetworkError:   /* 断网:离线容忍由 hasUsableOfflineCache 兜底 */
            default:
                NSLog(@"[guard] patrol reject (%ld)", (long)result);
                guard_request_die();
                return;
        }
    }];
}

static void StartPatrol(void) {
    if (g_patrol_timer != nil) return;
    g_patrol_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    uint64_t first = NextPatrolIntervalNs();
    dispatch_source_set_timer(g_patrol_timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)first),
                              (int64_t)AUTH_PATROL_MAX_SECONDS * NSEC_PER_SEC,
                              (int64_t)AUTH_PATROL_MAX_SECONDS * NSEC_PER_SEC);
    dispatch_source_set_event_handler(g_patrol_timer, ^{
        PatrolTick();
        /* 每轮 tick 后重设下一轮随机间隔，消除固定周期特征 */
        uint64_t next = NextPatrolIntervalNs();
        dispatch_source_set_timer(g_patrol_timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)next),
                                  (int64_t)AUTH_PATROL_MAX_SECONDS * NSEC_PER_SEC,
                                  (int64_t)AUTH_PATROL_MAX_SECONDS * NSEC_PER_SEC);
    });
    dispatch_resume(g_patrol_timer);
}

__attribute__((constructor))
static void GuardAuthBridge(void) {
    /* 1. JS 启动即生效，与卡密状态解耦 */
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        LoadJsWithRetry(0);
    });

    /* 2. 周期巡检：本地凭据 + 服务端心跳双检，任一未通过即闪退 */
    StartPatrol();
}
