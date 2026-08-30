/*
 * guard_host.m - 宿主 App 侧互锁代码
 *
 * 这段代码需要合并进你的 App 源码（对重签名场景，可通过注入一个
 * category +load 方法由 guard dylib 附带，或打补丁进现有二进制）。
 *
 * 功能：
 *  1. 启动时 dlopen 失败 / 找不到 guard dylib -> 拒绝启动
 *  2. 周期性调用 guard_tick 并校验共享页 magic 与心跳递增
 *  3. 校验失败立即终止进程
 */

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <signal.h>

typedef struct {
    uint64_t magic;
    uint64_t host_digest;
    uint64_t self_digest;
    uint64_t heartbeat;
    uint64_t flags;
} guard_page_t;

typedef const guard_page_t *(*query_page_fn)(void);
typedef uint64_t (*tick_fn)(uint64_t);

static query_page_fn g_query;
static tick_fn g_tick;
static uint64_t g_last_beat;

static void guard_fail(const char *why) {
    /* 生产环境建议：延迟随机时间后崩溃 + 上报遥测，避免被单点 patch */
    NSLog(@"[guard] integrity check failed: %s", why);
    abort();
}

__attribute__((constructor))
static void host_guard_bootstrap(void) {
    /* 1. 确认 guard dylib 已被加载 */
    void *h = dlopen("@executable_path/Frameworks/libguard.dylib", RTLD_NOW);
    if (!h) h = dlopen("@executable_path/libguard.dylib", RTLD_NOW);
    if (!h) {
        /* dylib 被移除：直接拒绝启动 */
        guard_fail("guard library missing");
    }

    /* 2. 解析互锁接口（符号名与构建脚本中随机化的名字保持一致） */
    g_query = (query_page_fn)dlsym(h, "guard_query_page");
    g_tick  = (tick_fn)dlsym(h, "guard_tick");
    if (!g_query || !g_tick) guard_fail("guard interface missing");

    const guard_page_t *p = g_query();
    if (!p || p->magic != 0x4755415244303031ULL) guard_fail("bad guard page");
    g_last_beat = p->heartbeat;

    /* 3. 周期性校验：心跳必须递增、共享页必须完好 */
    dispatch_source_t timer = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
        dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0));
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                              2 * NSEC_PER_SEC, 500 * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(timer, ^{
        const guard_page_t *pg = g_query();
        if (!pg || pg->magic != 0x4755415244303031ULL) guard_fail("page corrupted");
        if (pg->heartbeat <= g_last_beat) guard_fail("guard stalled"); /* dylib 线程被杀 */
        g_last_beat = pg->heartbeat;
        uint64_t expect = g_tick(g_last_beat);
        if (expect == 0) guard_fail("tick mismatch");
        /* 可选：校验 guard 自身报告的风险位 */
        if (pg->flags & 0x7) guard_fail("risk detected");
    });
    dispatch_resume(timer);
}
