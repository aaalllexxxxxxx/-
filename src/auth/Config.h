#ifndef AUTH_CONFIG_H
#define AUTH_CONFIG_H

// ====== 验证配置:按部署环境修改 ======

// 卡密验证后台地址(docs/client-integration.md 对应的服务端)
// 代码会自动拼接 /api/activate、/api/heartbeat(末尾带不带 /api 均可)
#define AUTH_SERVER_URL   @"https://sm3kmw6g.sc.monkeycode-ai.online"

// 验证弹窗标题
#define AUTH_APP_TITLE    @"应用验证"

// ====== 可选配置 ======

// 项目隔离(可选):填项目 slug 后,activate/heartbeat 请求带 project 参数,
// 专属卡跨项目会被拒;留空 @"" = 不启用项目校验(兼容通用卡)
#define AUTH_PROJECT_SLUG @""

// 心跳间隔(秒),服务端可调区间 60-600,默认 60
// (遗留参数:运行期巡检间隔由 AUTH_PATROL_MIN/MAX_SECONDS 控制,
//  该值仅保留给内部依赖心跳约定的旧逻辑引用)
#define AUTH_HEARTBEAT_SECONDS 60

// 离线容忍:最后一次心跳成功后 N 小时内,断网也放行
// (遗留参数:当前巡检策略下 NetworkError 直接判定未通过,此值仅保留兼容)
#define AUTH_OFFLINE_GRACE_HOURS 24

// 卡密巡检间隔区间(秒):每轮在 [MIN, MAX] 内随机取值后重设定时器,
// 本地凭据判定与真实服务端心跳同时执行,任一未通过即终止进程
#define AUTH_PATROL_MIN_SECONDS 10
#define AUTH_PATROL_MAX_SECONDS 20

#endif /* AUTH_CONFIG_H */
