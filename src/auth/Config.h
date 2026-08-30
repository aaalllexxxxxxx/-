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
#define AUTH_HEARTBEAT_SECONDS 60

// 离线容忍:最后一次心跳成功后 N 小时内,断网也放行
// (服务端宽限默认 0 天,此值仅影响断网期间的本地体验,联网后服务端仍会实时校验)
#define AUTH_OFFLINE_GRACE_HOURS 24

#endif /* AUTH_CONFIG_H */
