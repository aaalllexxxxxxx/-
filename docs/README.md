# IPA 加固工作流：dylib 注入 + O-MVLL 混淆 + guard 密钥绑定 JS

面向越狱 / TrollStore 场景的 IPA 加固流水线。一条 GitHub Actions 工作流完成：编译加固 dylib（O-MVLL 混淆）→ 注入主二进制 → 嵌入 FridaGadget + 加密 JS → 伪签名 → 自检 → 产出可安装的加固 IPA。**无需 Mac、无需 p12 证书、无需 Secrets。**

## 能力

- **混淆**：[O-MVLL](https://obfuscator.re/omvll/) 插件挂载 Apple Clang（控制流平坦化、算术混淆、控制流分裂、间接调用），无需自建 LLVM 工具链
- **反调试**：PT_DENY_ATTACH + P_TRACED 轮询
- **反 hook**：关键函数前导指令校验、Frida/Substrate 等注入框架检测
- **JS 加载互锁**：业务 JS 经 guard 导出密钥加密，guard 被移除则 JS 不加载
- **宿主无关**：JS 绑定 guard dylib 自身，不依赖宿主二进制内容，**适用于任意 IPA**，不受 TrollStore/越狱安装对二进制改动的影响
- **卡密联动**：`src/auth/` 存在时合并 AuthDylib，巡检未通过即闪退

## 文件结构

```
├── src/
│   ├── guard.c              # 加固 dylib：反调试/反 hook/守护线程/JS 密钥导出
│   ├── guard_bridge.mm      # AuthDylib 联动桥接（JS 加载 + 卡密巡检）
│   └── auth/                # AuthDylib 卡密验证（可选）
├── scripts/
│   ├── build_guard.sh       # 普通编译（生成 guard_js_key.inc + js_key.bin）
│   ├── obfuscate_build.sh   # O-MVLL 混淆编译
│   ├── gen_loader.py         # loader 壳生成（guard 密钥绑定加密 + 业务 JS 混淆包装）
│   ├── embed_js.sh          # Gadget 下载 / loader+config 嵌入（gadget/payload 两阶段）
│   ├── inject_ipa_ldid.sh   # 解包/注入 LC_LOAD/伪签/打包
│   ├── check_ipa.sh         # ipa 合规预检
│   └── verify_blob.py       # （遗留，当前工作流未使用）
├── camouflage.conf          # 伪装命名配置
├── omvll_config.py          # O-MVLL 混淆 pass 配置
├── agent.js                 # Frida 业务脚本（可选）
└── .github/workflows/harden.yml
```

## GitHub Actions 工作流

工作流文件 `.github/workflows/harden.yml`，运行在 `macos-26` runner（自带 O-MVLL 1.9.1 要求的 Xcode 26.5）。

### 触发

**push 自动触发**：push `.ipa` / `libguard.dylib` / `agent.js` / `salt.txt` 到仓库即自动加固。

**手动触发**（Actions → IPA Hardening → Run workflow）：

| 输入 | 说明 |
|---|---|
| `ipa_url` | ipa 下载地址，留空则用仓库内第一个 `.ipa` |
| `use_ollvm` | `true`（默认）用 O-MVLL 混淆编译；`false` 走 plain build |
| `entitlements` | 追加 entitlements，逗号分隔，如 `task_for_pid-allow,get-task-allow` |
| `output_name` | 输出文件名 |
| `frida_version` | FridaGadget 版本，默认 `16.5.9` |

> push 触发时 `inputs.*` 为空，默认走 O-MVLL 混淆路径。

### dylib 来源

1. 仓库根目录存在 `libguard.dylib` → 直接使用，跳过编译
2. 否则现场编译 `src/guard.c`（+ `src/guard_bridge.mm` + `src/auth/*.mm`，是否混淆取决于 `use_ollvm`）

### 对 ipa 的要求（`check_ipa.sh` 自动预检）

| 要求 | 说明 |
|---|---|
| 无壳 | `cryptid=0`（App Store 原版带 FairPlay，须先砸壳） |
| 含 arm64 | 真机必须切片 |
| 未注入过 libguard | 避免重复 LC_LOAD 冲突 |

## JS 加载方案（guard 密钥绑定，A2-universal）

设计目标：JS 加载链路**全静态、零运行时写文件、不依赖初始化时序**，且**适用于任意 IPA**。曾经尝试过"绑定宿主二进制前 4096 字节"和"`__TEXT` 0x4000 窗口"两种方案，均因 TrollStore 安装时 ldid 重签改动二进制而失配，已废弃。

### 密钥机制

构建期（`build_guard.sh` / `obfuscate_build.sh`）：
- 随机生成 32 字节 `js_key`，写入 `build/guard_js_key.inc`（`static const unsigned char g_js_key[32]`）经 `-include` 注入 guard.c，同时写 `build/js_key.bin` 供打包用
- guard.c 导出 `const void *guard_js_key(void)` 返回该密钥

打包期（`embed_js.sh payload` → `gen_loader.py`）：
- 业务 JS 先过 javascript-obfuscator（控制流平坦化 + 字符串数组 + 标识符十六进制化）
- `keystream_i = SHA256(js_key ∥ salt(8) ∥ counter(u32,LE))`，每块 32 字节
- `明文 = magic(4, 随机) ∥ 混淆后 JS`，`密文 = 明文 XOR keystream`
- 生成 loader 壳（Frameworks/`<JS_DOC_NAME>`，后缀可任意伪装）+ Gadget config

运行期 loader：
1. `Module.getExportByName(null, 'guard_js_key')` 调 guard 导出符号取 32 字节密钥
2. SHA256 计数器链派生 keystream 解密
3. 校验 magic（不匹配则静默拒绝，密钥不对解出垃圾）
4. eval 业务 JS

**为什么适用于任意 IPA**：密钥来自 guard dylib 自身，不读宿主二进制任何字节。guard 的 `__TEXT` 不被安装环节改动（重签只动签名 blob），所以内存密钥与构建期一致。

### 互锁关系

| 场景 | 结果 |
|---|---|
| 正常运行 | guard 提供密钥 → loader 解密 → Gadget 加载脚本 |
| guard 被移除（删 LC_LOAD 重签） | loader 找不到 `guard_js_key` 符号 → JS 不加载 |
| guard 被 patch | 密钥仍在（在 `__DATA`），但 guard 反 hook / 反调试独立生效 |
| 业务 JS 被静态提取 | 拿到的是混淆后的代码；解密密钥在 guard dylib 里（需 Mach-O 解析） |
| 运行中被 hook | 守护线程检测 → 随机延迟崩溃，进程死亡，JS 随之终止 |

### Gadget 加载

FridaGadget 经 `insert_dylib` 写 LC_LOAD 由 dyld 启动时直接加载（不再依赖 guard 运行时 dlopen 或按体积发现 Gadget）。config（`<GADGET_NAME>.config`）构建期预置，相对路径由 frida-core 解析：先查数据容器 Documents（不存在）→ 回退 Gadget 所在 Frameworks 目录命中静态 loader。loader 文件后缀任意（当前 `.pipeline_cache.dat`），Gadget 按字节内容区分源码/字节码，不看扩展名。

> 历史：早期 loader 用 `atob` 解 base64，但 frida 的 QuickJS 运行时不提供 `atob`（已核实 gadget 16.5.9 符号），loader 第一行即抛 `ReferenceError` 导致脚本静默失败。现改为纯 hex 解码（`parseInt` + `String.fromCharCode`，零依赖）。

### 伪装防护（`camouflage.conf`）

| 原始身份 | 伪装名 | 说明 |
|---|---|---|
| 加固 dylib | `libimgpipeline.dylib` | LC_LOAD 路径 + install_name 同步改写 |
| FridaGadget | `libavmediacore.dylib` | 文件改名 + install_name；config 自动取同 basename |
| loader JS | `.pipeline_cache.dat` | 静态文件，后缀伪装成数据文件 |

guard 二进制不保存固定文件名（运行时靠导出符号发现，不靠体积扫描）。自定义改名编辑 `camouflage.conf`，建议参考 App 内已有库命名风格，避免 crypto/guard/frida/agent 等敏感词。

## O-MVLL 混淆（`omvll_config.py`）

| pass | 状态 |
|---|---|
| 控制流平坦化 `flatten_cfg` | 启用 |
| 算术混淆 `obfuscate_arithmetic` | 启用 |
| 控制流分裂 `break_control_flow` | 启用 |
| 间接调用 `indirect_call` | 启用 |
| 字符串加密 `obfuscate_string` | **禁用**：其生成的"指针→CString 重定向"结构会让 Xcode 26 的 ld 与 ld_classic 都崩溃 |
| 函数抽取 / 基本块复制 | **禁用**：会把 ARC block 辅助符号提升为强符号，跨编译单元 duplicate symbol |

调试 loader 用 `GEN_LOADER_DEBUG=1` 环境变量构建（见下）。

## 调试（真机定位）

loader 内置分阶段上报（`stage1` 取密钥 → `stage2` keystream → `stage3` magic 校验 → `stage4` eval），失败即弹 `UIAlertView` 显示具体环节。

- **生产构建（默认）**：`GEN_LOADER_DEBUG` 未设置 → `gen_loader.py` **完全不输出** report 函数、stage 字符串、UIAlertView 代码，catch 仅 `return;`，软件零痕迹
- **调试构建**：设 `GEN_LOADER_DEBUG=1` → 输出完整弹窗代码，真机启动即可看到卡在哪一步

```bash
# 调试包（本地手动调 gen_loader.py 时）
GEN_LOADER_DEBUG=1 python3 scripts/gen_loader.py build/js_key.bin agent.js /tmp/loader.dat /tmp/gadget.config
```

> 工作流默认生产。需要调试包时可临时在 `harden.yml` 的构建步骤加 `env: GEN_LOADER_DEBUG: '1'` 触发一次。

## 卡密验证整合（AuthDylib，`src/auth/`）

`src/auth/` 存在时，构建脚本自动把 AuthDylib 与 `guard.c` 合并编译为**单一 dylib**，经 `guard_bridge.mm` 实现 JS 加载与卡密巡检的硬联动。

- **JS 先行**：constructor 立即加载 JS，与卡密状态解耦（失败 1s/3s/9s 退避重试 3 次）
- **巡检门禁**：`guard_bridge.mm` 以随机间隔调度 `verifyWithCallback`（全仓库唯一调度源，避免心跳 seq 并发冲突）

| 巡检结果 | 处理 |
|---|---|
| OK | 继续巡检 |
| NeedActivate / SecurityError / NetworkError | `guard_request_die()` 闪退 |
| 激活面板展示中 | 巡检照常判定（严格模式，无豁免） |
| 卡密逻辑被整体 patch | guard 反 hook 检测命中，随机延迟崩溃 |

判定与崩溃点分离：`guard_die()` 随机延迟 0–30 秒后经无效地址写入触发 SIGSEGV，崩溃日志看不到检测函数栈。配置见 `src/auth/Config.h`（后台地址、巡检区间、面板标题）。

## 安全强度与已知边界

**能防**：静态提取可用 JS（密钥在 guard dylib，需 Mach-O 解析 + 符号查找）、移植到其他 App（guard 不在则无密钥）、guard 被移除（JS 不加载）、运行时 hook（守护线程闪退）。

**防不住（注入式方案本质限制）**：运行时内存 dump 拿明文 JS、对进程本身的动态分析。目标是把"静态拿到可用 JS"的成本提高到不值得，而非对抗内存级逆向。

**与旧 A2（宿主二进制绑定）的取舍**：旧方案理论上更强（patch 宿主即废 JS），但在 TrollStore/越狱安装流程下二进制被改动导致密钥失配，根本立不住；现方案牺牲"patch 宿主即废"换取"任意 IPA 通用 + 安装稳定"。

## 本地复现（需 macOS + Xcode 26.5）

```bash
# 编译 guard（生成 build/libguard.dylib + build/js_key.bin + build/guard_js_key.inc）
./scripts/build_guard.sh build                    # plain
OMVLL_HOME=/path/to/omvll ./scripts/obfuscate_build.sh build   # O-MVLL 混淆

# 注入 + 嵌入 JS + 伪签
./scripts/inject_ipa_ldid.sh app.ipa build/libguard.dylib app_hardened.ipa

# 自检（工作流内已集成）
unzip -q app_hardened.ipa -d /tmp/chk
otool -L /tmp/chk/Payload/*.app/* | grep libimgpipeline   # guard LC_LOAD
otool -L /tmp/chk/Payload/*.app/* | grep libavmediacore   # gadget LC_LOAD
```
