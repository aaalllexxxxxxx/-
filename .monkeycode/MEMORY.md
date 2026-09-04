# User Instruction Memory

This file records user instructions, preferences, and teachings for reference in future interactions.

## Format

### User Instruction Entry
User instruction entries should follow this format:

[User Instruction Summary]
- Date: [YYYY-MM-DD]
- Context: [Mentioned scenario or time]
- Instructions:
  - [Content of user teaching or instruction, described line by line]

### Project Knowledge Entry
Entries discovered by the Agent during task execution should follow this format:

[Project Knowledge Summary]
- Date: [YYYY-MM-DD]
- Context: Discovered by Agent while performing [specific task description]
- Category: [Operations & Deployment|Build Methods|Testing Methods|Troubleshooting & Debugging|Workflow & Collaboration|Environment Configuration]
- Instructions:
  - [Specific knowledge points, described line by line]

## Deduplication Strategy
- Before adding a new entry, check for similar or identical instructions.
- If a duplicate is found, skip the new entry or merge it with the existing one.
- When merging, update the context or date information.
- This helps avoid redundant entries and keeps the memory file tidy.

## Entries

[GitHub API 与工作流操作]
- Date: 2026-09-04
- Context: IPA 加固工作流触发与状态监控
- Category: Workflow & Collaboration
- Instructions:
  - GitHub 匿名 API 易限流，必须带 token：`TOKEN=$(echo -e 'protocol=https\nhost=github.com\n' | git credential fill | grep password | cut -d= -f2)`，再 `-H "Authorization: token $TOKEN"`
  - 工作流 ID 345763101；push src/ 等文件不命中 paths 过滤器，需手动 dispatch：`POST /actions/workflows/345763101/dispatches -d '{"ref":"main"}'`（HTTP 204 即成功）
  - 构建约 1-2 分钟，用 runs API 轮询 status=completed 后取 artifact
  - 下载 artifact：`GET /actions/artifacts/{id}/zip`（带 token），zip 内是 app_hardened.ipa + manifest.json

[frida-core 16.5.9 Gadget 机制（源码验证）]
- Date: 2026-09-04
- Context: 排查 JS 脚本加载失败（listen 模式假象）时下载源码确认
- Category: Troubleshooting & Debugging
- Instructions:
  - GitHub API 拉源码被限流时用 codeload tarball：`https://codeload.github.com/frida/frida-core/tar.gz/refs/tags/16.5.9`（源码在 lib/gadget/gadget.vala）
  - Gadget 无 FRIDA_GADGET_CONFIG 环境变量支持（勿再走此路）
  - config 发现：先 `<Gadget同目录>/<同名>.config`；不存在且目录名为 Frameworks 时找父目录；找不到则默认 listen 模式（on_load=wait 阻塞启动）
  - iOS 上 script 相对路径解析：先试 `<app Documents>/<path>`（存在才用），否则 `<Gadget同目录>/<path>`
  - config 是静态 JSON，构建期预置到 ipa 即可（bundle 只读无影响）；运行期动态写 bundle 必然失败（EROFS）

[加固产物验证清单]
- Date: 2026-09-04
- Context: 每次构建后验证 artifact 完整性
- Category: Testing Methods
- Instructions:
  - Frameworks/ 必含四件套：guard dylib（libimgpipeline.dylib）、Gadget（libavmediacore.dylib 约 40MB）、加密 JS（pipeline_cache.bin）、Gadget config（libavmediacore.config）
  - config 内容应为 `{"interaction":{"type":"script","path":".pipeline_cache.js","on_change":"ignore"}}`
  - 运行时链路：guard 解密 JS → Documents/.pipeline_cache.js（loader 壳，业务代码 XOR+base64 包装）→ dlopen Gadget → 加载脚本 → dlopen 返回后立即 unlink（guard_loop 3s 兜底）
  - 完整校验用 scripts/verify_blob.py：解密 blob 验证 GCM 认证 + loader 前缀 + 载荷与 agent.js 逐字节一致（需真实 salt/magic，仅 runner 上可用）
  - blob magic/salt 来自 dylib 构建期生成的 build/magic.txt 与 build/salt.txt，逐次构建不同，勿用默认值硬校验
