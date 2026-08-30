# IPA 加固工作流：dylib 注入 + 混淆 + 反破解互锁

## 目标

把加固 dylib 注入 ipa，实现：

- 混淆（OLLVM：控制流平坦化、伪造控制流、指令替换、字符串加密）
- 反调试（PT_DENY_ATTACH + P_TRACED 轮询）
- 反 hook（关键函数前导指令校验、Frida/Substrate 等注入框架检测）
- 互锁：dylib 被去除或被 kill，宿主 App 无法启动/运行中崩溃

## 文件结构

```
ipa-hardening/
├── src/
│   ├── guard.c          # 加固 dylib 源码（反调试/反 hook/心跳守护）
│   └── guard_host.m     # 宿主侧互锁代码（编译进 App 源码时最强）
├── scripts/
│   ├── build_guard.sh      # 普通编译
│   ├── obfuscate_build.sh  # OLLVM 混淆编译
│   ├── inject_ipa.sh       # 解包/注入/重签/打包
│   └── verify.sh           # 注入结果自检
└── docs/
```

## 完整流程

### 1. 编译 dylib

```bash
# 普通构建
./scripts/build_guard.sh build

# OLLVM 混淆构建（防护强度更高）
OLLVM_HOME=/opt/obfuscator-llvm/build ./scripts/obfuscate_build.sh build_obf
```

### 2. 注入并重签

```bash
./scripts/inject_ipa.sh \
  MyApp.ipa \
  build_obf/libguard.dylib \
  MyApp.mobileprovision \
  "iPhone Distribution: Your Company (TEAMID)" \
  MyApp_hardened.ipa
```

### 3. 自检

```bash
unzip -q MyApp_hardened.ipa -d /tmp/chk
./scripts/verify.sh /tmp/chk/Payload/MyApp.app
```

## 互锁原理

| 攻击手段 | 防护响应 |
|---|---|
| 移除 LC_LOAD / 删除 dylib | 宿主 `dlopen` 失败，`guard_fail` 拒绝启动 |
| 对 guard 函数 inline hook | `prologue_tampered` 检测前导指令，abort |
| kill 守护线程 | 心跳停止递增，宿主侧 2 秒内检测并终止 |
| Frida/Substrate 注入 | dyld 镜像枚举命中特征，abort |
| 调试器附加 | PT_DENY_ATTACH 阻止 + P_TRACED 轮询兜底 |
| 静态特征匹配 | 字符串编译期 XOR，密钥每次构建随机 |

## 强度分级建议

1. **基础**：dylib 注入 + 重签（脚本即可，无源码）
2. **标准**：+ OLLVM 混淆 + 字符串加密
3. **最强**：把 `guard_host.m` 合并进 App 源码编译（而非仅靠注入），互锁逻辑分散到业务代码多个位置调用 `guard_tick`，并启用崩溃延迟与遥测上报

注意：纯二进制注入场景下，宿主侧互锁需要向现有二进制打补丁调用 guard 接口（可用 Hopper/汇编补丁或运行时 swizzle）。有源码时强度远高于纯重签方案。

## GitHub Actions 云端工作流（越狱 / TrollStore，无需 Mac、无需证书）

工作流文件：`.github/workflows/harden.yml`，运行在 GitHub 免费 macos-14 runner。
针对越狱/巨魔场景做了以下简化：

- 使用 `ldid` 伪签名（brew 自动安装），**不需要** p12 证书、描述文件和任何 Secrets
- 保留 ipa 原有 entitlements，并可通过输入参数追加（如 `task_for_pid-allow`、`get-task-allow`）
- 无壳 ipa 直接注入，无砸壳步骤

### 触发

**方式一：push 自动触发（推荐）**

把 ipa 和（可选的）你自己编译好的 `libguard.dylib` 推到仓库根目录，push 即自动加固：

```bash
# 仓库根目录放入文件
cp MyApp.ipa app.ipa
cp /path/to/your/libguard.dylib .   # 可选：自带 dylib 则跳过编译
git add app.ipa libguard.dylib && git commit -m "add ipa" && git push
```

**方式二：手动触发**

Actions → "IPA Hardening" → Run workflow：

| 输入 | 说明 |
|---|---|
| `ipa_url` | ipa 下载地址，留空用仓库内第一个 `.ipa` |
| `use_ollvm` | 仅在仓库**没有**自带 dylib 时生效，`true` 启用 OLLVM 混淆编译 |
| `entitlements` | 追加的 entitlements，逗号分隔，如 `task_for_pid-allow,get-task-allow` |

### dylib 选择逻辑

1. 仓库根目录存在 `libguard.dylib` → 直接使用，跳过整个编译步骤
2. 否则现场编译 `src/guard.c`（是否混淆取决于 `use_ollvm`）

> 自带 dylib 须满足：导出 `guard_query_page` / `guard_tick` 符号（宿主互锁用），install_name 为 `@executable_path/Frameworks/libguard.dylib`。若不是，可用 `install_name_tool -id` 修正后再放入仓库。

### 对 ipa 的要求

工作流会在加固前自动执行 `scripts/check_ipa.sh`，硬性要求只有三条：

| 要求 | 说明 |
|---|---|
| 无壳 | `cryptid=0`，即已脱壳的 ipa（App Store 原版带 FairPlay 加密，必须先砸壳） |
| 含 arm64 | 真机运行的必须切片 |
| 未注入过 libguard | 避免重复注入导致 load command 冲突 |

关于 entitlements：**不需要独立的 plist 文件**。entitlements 内嵌在 Mach-O 里（`__TEXT,__entitlements`）是标准形式，`ldid -e` 直接从二进制 dump，`ldid -S` 重签时也写回二进制。检查项未通过时只会告警并自动补一个空 dict（TrollStore 要求主二进制必须带 entitlements，哪怕是空的）。

### Frida JS 受控加载（可选）

把 Frida 脚本命名为 `agent.js` 放到仓库根目录，push 后工作流自动完成：下载 FridaGadget → 注入 guard → 用宿主 digest 派生密钥加密 JS → 打包 Gadget + 密文 JS。

加载与破解的对应关系：

| 场景 | 结果 |
|---|---|
| 正常运行 | guard 验证通过 → 解密 JS 到临时文件 → dlopen Gadget 加载 → 删除临时文件 |
| guard 被移除 | 无人拉起 Gadget，ipa 内 JS 是密文，Frida 功能彻底消失 |
| guard 被 patch / 宿主二进制被改 | host_digest 变化 → 密钥派生错误 → 解密出垃圾 → 头校验失败拒绝加载 |
| 运行中被 hook | 守护线程检测到 → abort，进程死亡，JS 随之终止 |

**使用自带 dylib 时**：必须把编译该 dylib 时生成的 `salt.txt` 一并放入仓库（`build_guard.sh` 每次构建会输出到 `build/salt.txt`），否则工作流直接报错，因为 JS 密钥派生依赖编译进二进制的 salt。

### 伪装防护（重命名 + 运行时发现）

注入时所有敏感文件按 `camouflage.conf` 改名，攻击者翻包看不到 guard/frida/agent 任何痕迹：

| 原始身份 | 伪装示例 | 改名方式 |
|---|---|---|
| 验证 dylib | `libimgpipeline.dylib` | 文件改名 + `install_name_tool -id` 改写 install_name + LC_LOAD 写伪装路径 |
| FridaGadget | `libavmediacore.dylib` | 文件改名 + install_name 改写，配置文件自动取同 basename |
| JS 密文 | `pipeline_cache.bin` | 任意文件名任意扩展名，伪装成资源文件 |

**改名不影响加载的原理**：guard 二进制中不保存任何固定文件名，运行时用特征扫描发现目标——

- JS 密文：头部嵌入 8 字节随机 magic（编译期 `-DGUARD_JS_MAGIC` 注入，与 salt 同款机制），guard 遍历 Frameworks 目录逐文件比对 magic 识别
- FridaGadget：枚举 Frameworks 下所有 dylib，排除自身后取体积最大者（Gadget 30MB+，业务库远小于 8MB 阈值）

**使用自带 dylib 时必须配套三个文件**（同一套编译期材料）：

| 文件 | 内容 |
|---|---|
| `libguard.dylib` | 你的验证 dylib |
| `salt.txt` | 编译时 `-DGUARD_JS_SALT=` 的值（如 `0x3f9a...`） |
| `magic.txt` | 编译时 `-DGUARD_JS_MAGIC=` 的值 |

**自定义伪装名**：编辑仓库根目录 `camouflage.conf`，建议参考你 App 内已有库的命名风格，避免 crypto/guard/frida/agent 等敏感词。

### 卡密验证整合（AuthDylib，src/auth/）

`src/auth/` 存在时，构建脚本自动把 AuthDylib 卡密验证与 `guard.c` 合并编译为**单一 dylib**，并通过 `src/guard_bridge.mm` 实现 JS 加载与卡密状态的硬联动：

| 卡密状态 | JS 加载行为 |
|---|---|
| 无本地凭据（新用户） | 卡密面板弹出挡界面，JS 不加载 |
| 激活成功 | 收到 `AuthUIActivatedNotification`，立即加载 JS |
| 老用户（有凭据） | 离线宽限期内先加载，同时心跳确认；心跳 OK 也加载 |
| 服务端拒绝（禁用/解绑/验签失败） | 已加载的 JS 随进程终止（`guard_request_die`） |
| 卡密逻辑被 patch 移除 | guard 反 hook 检测命中，随机延迟崩溃 |

**配置**：`src/auth/Config.h` 已包含后台地址（`AUTH_SERVER_URL`）、面板标题、心跳间隔、离线宽限，开箱即用；仅当后台地址变更时才需要修改。

### 生产级安全设计

### 生产级安全设计

**JS 加密（AES-256-GCM）**

- 密文格式：`nonce(12) ∥ ciphertext ∥ tag(16)`
- 密钥派生：`key = SHA-256(host_digest ∥ salt ∥ plain_len)`，三方任一变化密钥即错
- GCM 认证标签：对密文的任何篡改导致解密失败，无需哨兵头
- 解密使用 iOS 系统 CommonCrypto，dylib 零第三方依赖
- 明文 JS 解密后在内存用完即抹除（`memset`），临时文件加载后即删

**反破解终止策略**

检测命中后不再立即 `abort`：随机延迟 0-30 秒，随后通过无效地址写入触发 SIGSEGV。崩溃点与检测点分离，崩溃日志里看不到 guard 的检测函数栈，显著提高攻击者用断点/日志定位检测逻辑的成本。

**工作流加固**

| 项 | 说明 |
|---|---|
| 并发锁 | 同分支串行构建，防 artifact 互相覆盖 |
| 前置检查 | Mach-O / arm64 / cryptid / 重复注入，不合格直接失败 |
| 明文泄露检查 | 打包后扫描整个 app，JS 明文特征出现在任何文件即失败 |
| 审计清单 | 每次构建产出 `manifest.json`（输入输出 sha256、dylib 来源、是否嵌 JS、run id） |
| 敏感清理 | salt、明文 JS 不进入 artifact，结束时显式抹除 |
| 工具缓存 | insert_dylib 走 actions/cache，缩短构建时间 |

### 产出

Artifacts 中下载 `hardened-ipa`，可直接通过 TrollStore 安装。

流程：下载 ipa → 安装 insert_dylib + ldid → 编译 guard dylib（可选 OLLVM）→ 注入 + ldid 伪签 → 自检 → 上传。

> 若需要 App Store 正式重签场景，使用 `scripts/inject_ipa.sh`（需证书），并参照 git 历史中的旧版工作流。

## 工具依赖

- macOS + Xcode 命令行工具
- insert_dylib: https://github.com/Tyilo/insert_dylib
- obfuscator-llvm（可选）: https://github.com/obfuscator-llvm/obfuscator
- 有效的 Apple 开发者证书与描述文件

## 合规提醒

仅对拥有合法权益的 App（自有产品或获书面授权）执行加固与重签。
