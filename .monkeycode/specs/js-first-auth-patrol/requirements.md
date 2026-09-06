# 需求文档：JS 启动即生效 + 卡密周期巡检闪退

Feature Name: js-first-auth-patrol
Updated: 2026-09-06

## Introduction

重构 guard dylib 的 JS 加载与卡密验证联动策略。现状是"验证通过才加载 JS"（前置门禁），改为"JS 启动立即加载 + 周期巡检卡密状态、任一环节未通过则闪退"（后置巡检）。同时保持并强化 JS 密文与验证 dylib 的防破解措施。

## Glossary

- **guard dylib**: 注入宿主 App 的加固动态库，由 `src/guard.c` 与 `src/auth/` 合并编译
- **JS agent**: 注入后随宿主运行的 Frida Gadget 脚本（仓库根目录 `agent.js`）
- **巡检（patrol）**: 运行期周期性执行的卡密状态检查，包含本地凭据判定与真实服务端心跳
- **闪退（die）**: 通过 `guard_request_die()` 触发的随机延迟 SIGSEGV 崩溃
- **严格判定**: 巡检判定与激活面板展示状态解耦，面板打开期间照常执行判定

## Requirements

### R1 JS 启动即生效

**User Story:** AS 最终用户，I want 打开应用后 JS 功能立即可用，so that 无需等待卡密验证往返即可使用功能。

#### Acceptance Criteria

1. WHEN guard dylib constructor 执行，System SHALL 立即触发 JS agent 加载，无论本地卡密凭据是否存在。
2. WHEN JS 加载失败（密文缺失/解密失败/Gadget 拉起失败），System SHALL 按退避策略重试至多 3 次。
3. WHEN JS 加载成功，System SHALL 保持现有清理行为（临时明文文件删除、内存抹除）。

### R2 卡密周期巡检与闪退

**User Story:** AS 软件作者，I want 运行期持续校验卡密状态，so that 未通过验证的用户无法持续使用。

#### Acceptance Criteria

1. WHILE 应用处于运行状态，System SHALL 以 10~20 秒区间的随机间隔执行卡密巡检，巡检同时覆盖本地凭据判定与真实服务端心跳。
2. WHEN 巡检结果为 AuthResultNeedActivate 或 AuthResultSecurityError，System SHALL 调用 `guard_request_die()` 终止进程。
3. WHEN 巡检结果为 AuthResultNetworkError，System SHALL 调用 `guard_request_die()` 终止进程。
4. WHEN 巡检结果为 AuthResultOK，System SHALL 继续巡检。
5. System SHALL 保证同一时刻仅存在一个巡检调度源（防止心跳 seq 单调校验冲突导致误杀）。
6. System SHALL 保持严格判定：激活面板展示或激活请求进行中，巡检照常执行与判定。

### R3 防破解措施保持与强化

**User Story:** AS 软件作者，I want JS 密文与验证 dylib 保持高强度防护，so that 破解者无法提取明文逻辑或绕过巡检。

#### Acceptance Criteria

1. JS agent SHALL 以 AES-256-GCM 密文形态存储，密钥派生绑定宿主 Mach-O digest 与构建期随机 salt（现有机制保持）。
2. JS agent 的磁盘文件 SHALL 使用随机 magic 识别的伪装文件名，明文 SHALL 仅在内存短暂存在、加载后即删（现有机制保持）。
3. 验证 dylib SHALL 默认以 OLLVM 混淆编译（控制流平坦化、伪造控制流、指令替换、字符串编译期 XOR 加密），云端工作流混淆开关默认开启。
4. 巡检间隔 SHALL 在配置区间内随机抖动，防止固定周期被定位。
5. 反调试（PT_DENY_ATTACH + P_TRACED 轮询）、反 hook（前导指令校验）、注入框架检测、越狱检测 SHALL 保持现有 guard_loop 500ms 轮询机制。
6. 终止动作 SHALL 保持随机延迟 0-30 秒后无效地址写入 SIGSEGV，崩溃点与检测点分离。

### R4 配置与文档

#### Acceptance Criteria

1. `src/auth/Config.h` SHALL 新增巡检间隔下限与上限配置项（默认 10 秒与 20 秒）。
2. `docs/README.md` SHALL 更新联动策略说明以反映新行为。

## 已确认决策

1. 激活面板豁免：无豁免，巡检到点即判定，未通过立即闪退（含激活面板展示期间）。
2. 断网策略：NetworkError 立即闪退，离线宽限机制停用。
3. 巡检频率：每个巡检周期同时执行本地凭据判定与真实服务端心跳，任一未通过即闪退。
