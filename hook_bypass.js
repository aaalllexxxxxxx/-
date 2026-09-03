/*
 * StarbucksSTE (Via-Air) 卡密验证 Bypass 脚本
 * 适配 Via-Air 1.7.0 (com.StarbucksSTE.Air)
 *
 * 本二进制与 ViaPro 1.8.1 使用相同的验证框架和混淆类名:
 *   _A7xK9mR2pL  = WYVerifyManager (验证管理器)
 *   _B3nQ8wF5jD  = WYVerifyViewController (登录页面VC)
 *   BSVerifyUltraProxy / BSVerifyUltraProxyResult / DOSceneDelegate 类名未变
 *
 * 进程名: StarbucksSTE (对应 ViaPro 的 MT)
 * BundleID: com.StarbucksSTE.Air
 * IDA ImageBase: 0x100000000
 */

var TAG = "[StarbucksSTE]";

function log(msg) {
    console.log(TAG + " " + msg);
}

// 找到主模块基址
function getMainBase() {
    var mods = Process.enumerateModules();
    // 进程名为 StarbucksSTE
    for (var i = 0; i < mods.length; i++) {
        var name = mods[i].name;
        if (name === "StarbucksSTE" || name.indexOf("StarbucksSTE") === 0) {
            return mods[i].base;
        }
    }
    // 兜底: 取第一个模块
    log("⚠️ 未找到 StarbucksSTE 模块, 使用第一个模块: " + mods[0].name);
    return mods[0].base;
}

// ============ 反调试绕过 ============
function bypassAntiDebug() {
    log("========== 安装反调试绕过 ==========");

    // 1. ObjC 反调试方法 (BSVerifyUltraProxy 类名未变)
    var bsProxy = ObjC.classes.BSVerifyUltraProxy;
    if (bsProxy) {
        ["- debuggerAttached", "- jailbroken", "- injected", "- vpnProxyActive",
         "- suspiciousImages", "- blockingRiskMask", "- riskMask"].forEach(function(sel) {
            try {
                var m = bsProxy[sel];
                if (m) {
                    Interceptor.attach(m.implementation, {
                        onLeave: function(retval) { retval.replace(ptr(0)); }
                    });
                }
            } catch(e) {}
        });

        // localGuardPass → YES
        try {
            var gp = bsProxy["- localGuardPass"];
            if (gp) Interceptor.attach(gp.implementation, {
                onLeave: function(retval) { retval.replace(ptr(1)); }
            });
        } catch(e) {}

        // 空实现
        ["- runtimePatchFingerprint", "- reportRisk:", "- reportRiskSilently:"].forEach(function(sel) {
            try {
                var m = bsProxy[sel];
                if (m) Interceptor.attach(m.implementation, {
                    onEnter: function(args) {}
                });
            } catch(e) {}
        });
    }

    // _A7xK9mR2pL 的反调试方法
    var wyMgr = ObjC.classes._A7xK9mR2pL;
    if (wyMgr) {
        ["+ setupAntiDebug", "+ _periodicAntiDebugCheck"].forEach(function(sel) {
            try {
                var m = wyMgr[sel];
                if (m) Interceptor.attach(m.implementation, {
                    onEnter: function(args) {}
                });
            } catch(e) {}
        });
    }

    // 2. 系统级反调试
    // getenv
    try {
        var getenvAddr = Module.findGlobalExportByName("getenv");
        if (getenvAddr) {
            Interceptor.attach(getenvAddr, {
                onEnter: function(args) {
                    if (!args[0].isNull()) this.varName = args[0].readUtf8String();
                },
                onLeave: function(retval) {
                    if (this.varName === "DYLD_INSERT_LIBRARIES" || this.varName === "MSSafeMode") {
                        retval.replace(ptr(0));
                    }
                }
            });
        }
    } catch(e) {}

    // sysctl - 清除 P_TRACED
    try {
        var sysctlAddr = Module.findGlobalExportByName("sysctl");
        if (sysctlAddr) {
            Interceptor.attach(sysctlAddr, {
                onEnter: function(args) { this.oldp = args[2]; },
                onLeave: function(retval) {
                    if (this.oldp && !this.oldp.isNull()) {
                        try {
                            var flagPtr = this.oldp.add(0x20);
                            var flags = flagPtr.readU32();
                            if (flags & 0x800) flagPtr.writeU32(flags & ~0x800);
                        } catch(e) {}
                    }
                }
            });
        }
    } catch(e) {}

    // 3. 阻止退出
    ["exit", "_exit", "abort", "_Exit"].forEach(function(fname) {
        try {
            var addr = Module.findGlobalExportByName(fname);
            if (addr) {
                Interceptor.replace(addr, new NativeCallback(function() {
                    log("🛡️ " + fname + "() 拦截");
                }, 'void', []));
            }
        } catch(e) {
            try {
                var addr = Module.findGlobalExportByName(fname);
                if (addr) Interceptor.attach(addr, {
                    onEnter: function(args) { log("🛡️ " + fname + "() 调用"); }
                });
            } catch(e2) {}
        }
    });

    // kill/raise/pthread_kill
    ["kill", "raise", "pthread_kill"].forEach(function(fname) {
        try {
            var addr = Module.findGlobalExportByName(fname);
            if (addr) Interceptor.attach(addr, {
                onEnter: function(args) { log("🛡️ " + fname + "() 调用"); },
                onLeave: function(retval) { retval.replace(ptr(0)); }
            });
        } catch(e) {}
    });

    // 4. Hook ptrace
    try {
        var ptraceAddr = Module.findGlobalExportByName("ptrace");
        if (ptraceAddr) {
            Interceptor.attach(ptraceAddr, {
                onEnter: function(args) { log("🛡️ ptrace() 调用"); },
                onLeave: function(retval) { retval.replace(ptr(0)); }
            });
        }
    } catch(e) {}

    log("✅ 反调试绕过完成");
}

// ============ 卡密验证 Bypass ============
function bypassVerification() {
    log("========== 安装验证 Bypass ==========");

    var base = getMainBase();
    log("主模块基址: " + base);

    // _A7xK9mR2pL (WYVerifyManager) 验证管理器
    var wyMgr = ObjC.classes._A7xK9mR2pL;
    if (wyMgr) {
        // hasValidSession → _s5c4z7n2 → 返回 YES
        try {
            Interceptor.attach(wyMgr["- _s5c4z7n2"].implementation, {
                onLeave: function(retval) {
                    retval.replace(ptr(1));
                    log("🚀 _s5c4z7n2 (hasValidSession) → YES");
                }
            });
        } catch(e) { log("⚠️ _s5c4z7n2: " + e.message); }

        // status → 2 (已验证)
        try {
            Interceptor.attach(wyMgr["- status"].implementation, {
                onLeave: function(retval) {
                    retval.replace(ptr(2));
                    log("🚀 status → 2");
                }
            });
        } catch(e) {}

        // 拦截过期弹窗
        try {
            Interceptor.attach(wyMgr["- _showExpiredAlertAndExitWithMessage:"].implementation, {
                onEnter: function(args) {
                    log("🚀 拦截过期退出弹窗");
                }
            });
        } catch(e) {}

        // formattedExpireTime → _s1j2q7u4 → 返回一个未来日期
        try {
            Interceptor.attach(wyMgr["- _s1j2q7u4"].implementation, {
                onLeave: function(retval) {
                    var futureDate = ObjC.classes.NSString.stringWithString_("2099-12-31 23:59:59");
                    retval.replace(futureDate);
                    log("🚀 _s1j2q7u4 (formattedExpireTime) → 2099");
                }
            });
        } catch(e) {}
    } else {
        log("⚠️ _A7xK9mR2pL (WYVerifyManager) 未找到!");
    }

    // BSVerifyUltraProxyResult success → YES (类名未变)
    var resultClass = ObjC.classes.BSVerifyUltraProxyResult;
    if (resultClass) {
        try {
            Interceptor.attach(resultClass["- success"].implementation, {
                onLeave: function(retval) {
                    retval.replace(ptr(1));
                    log("🚀 Result.success → YES");
                }
            });
        } catch(e) {}

        // 拦截 fail:code:raw:, 替换为 ok:raw:
        try {
            Interceptor.attach(resultClass["+ fail:code:raw:"].implementation, {
                onEnter: function(args) {
                    var msg = "(unknown)";
                    try { msg = new ObjC.Object(args[2]).toString(); } catch(e) {}
                    log("🚀 拦截 fail: " + msg);
                },
                onLeave: function(retval) {
                    var okResult = resultClass["+ ok:raw:"].call(resultClass, null, null, ObjC.classes.NSDictionary.dictionary());
                    retval.replace(okResult);
                    log("🚀 fail → 替换为 ok");
                }
            });
        } catch(e) { log("⚠️ fail hook: " + e.message); }
    }

    // BSVerifyUltraProxy (类名未变)
    var bsProxy = ObjC.classes.BSVerifyUltraProxy;
    if (bsProxy) {
        // 拦截 finish:result: 让 result 的 success=YES
        try {
            Interceptor.attach(bsProxy["- finish:result:"].implementation, {
                onEnter: function(args) {
                    log("🚀 finish:result: 拦截");
                    var result = new ObjC.Object(args[3]);
                    if (result.respondsToSelector_(ObjC.selector("setSuccess:"))) {
                        result.setSuccess_(1);
                        log("🚀 已设置 success=YES");
                    }
                }
            });
        } catch(e) {}

        // hasValidFeatureLease / hasValidCoreLease → YES
        ["- hasValidFeatureLease", "- hasValidCoreLease"].forEach(function(sel) {
            try {
                var m = bsProxy[sel];
                if (m) Interceptor.attach(m.implementation, {
                    onLeave: function(retval) { retval.replace(ptr(1)); }
                });
            } catch(e) {}
        });
    }

    log("✅ 验证 Bypass 完成");
}

// ============ 监控 (精简) ============
function installMonitor() {
    log("========== 安装监控 ==========");

    var wyMgr = ObjC.classes._A7xK9mR2pL;
    if (wyMgr) {
        // loginWithKami:completion: → _s3b8y1m6:completion:
        try {
            Interceptor.attach(wyMgr["- _s3b8y1m6:completion:"].implementation, {
                onEnter: function(args) {
                    var kami = "(null)";
                    try { kami = new ObjC.Object(args[2]).toString(); } catch(e) {}
                    log("🔑 _s3b8y1m6 (loginWithKami): " + kami);
                }
            });
        } catch(e) {}

        try {
            Interceptor.attach(wyMgr["- setStatus:"].implementation, {
                onEnter: function(args) {
                    log("📊 setStatus: " + args[2].toInt32());
                }
            });
        } catch(e) {}
    }

    var resultClass = ObjC.classes.BSVerifyUltraProxyResult;
    if (resultClass) {
        try {
            Interceptor.attach(resultClass["+ ok:raw:"].implementation, {
                onLeave: function(retval) {
                    var obj = new ObjC.Object(retval);
                    log("✅ Result ok → success=" + obj.success() + " msg=" + obj.message());
                }
            });
        } catch(e) {}

        try {
            Interceptor.attach(resultClass["+ fail:code:raw:"].implementation, {
                onEnter: function(args) {
                    var msg = "";
                    try { msg = new ObjC.Object(args[2]).toString(); } catch(e) {}
                    var code = args[3].toInt32();
                    log("❌ Result fail → code=" + code + " msg=" + msg);
                }
            });
        } catch(e) {}
    }

    // NSURLSession
    var urlSession = ObjC.classes.NSURLSession;
    if (urlSession) {
        try {
            Interceptor.attach(urlSession["- dataTaskWithRequest:completionHandler:"].implementation, {
                onEnter: function(args) {
                    try {
                        var req = new ObjC.Object(args[2]);
                        var url = req.URL();
                        if (url) log("🌐 " + req.HTTPMethod() + " " + url.absoluteString());
                    } catch(e) {}
                }
            });
        } catch(e) {}
    }

    log("✅ 监控安装完成");
}

// ============ 修改登录页面UI ============
// 视图层级(来自反编译):
//   UIView → UIScrollView → UIView → UIView → UIStackView
//     ├─ UILabel: 标题 (加密文本, 运行时解密)
//     ├─ UILabel: 副标题 (加密文本)
//     ├─ UILabel: "卡密" (加密文本)
//     ├─ _buildInputField → UIView (inputContainer) → UITextField (kamiField)
//     ├─ _buildLoginButton → UIButton (loginButton)
//     ├─ UILabel: (statusLabel)
//     └─ _buildAnnouncementSection → UIView (announcement)
//
// ⚠️ 本版本UI文本被phantom加密保护, 无法像ViaPro那样直接匹配明文
// 改用通用策略: 遍历视图树, 按位置/类型修改
function bypassLoginUI() {
    log("========== 安装登录页UI修改 ==========");

    var VC = ObjC.classes._B3nQ8wF5jD;
    if (!VC) {
        log("⚠️ _B3nQ8wF5jD (WYVerifyViewController) 未找到");
        return;
    }

    // --- 递归遍历视图树，修改所有Label/TextField/Button ---
    function patchViewTree(view, depth) {
        if (!view) return;
        try {
            // UILabel: 修改文字
            if (view.isKindOfClass_(ObjC.classes.UILabel)) {
                var text = view.text();
                var t = text ? text.toString() : "";
                // 标题Label (大字号) → 修改
                if (depth === 0 && t.length > 0) {
                    view.setText_("StarbucksSTE");
                    log("🎨 标题 Label '" + t + "' → 'StarbucksSTE'");
                }
                // 副标题/提示Label → 隐藏不必要的
                else if (t.indexOf("卡密") !== -1 || t.indexOf("请输入") !== -1) {
                    view.setText_("");
                    view.setHidden_(1);
                    log("🎨 Label '" + t + "' → 隐藏");
                }
                // 到期时间相关
                else if (t.indexOf("到期") !== -1 || t.indexOf("过期") !== -1 || t.indexOf("有效") !== -1 || t.indexOf("永久") !== -1 || t.indexOf("未知") !== -1) {
                    view.setText_("");
                    view.setHidden_(1);
                    log("🎨 Label 到期时间 → 隐藏");
                }
            }

            // UITextField: 固定文本 + 禁止编辑
            if (view.isKindOfClass_(ObjC.classes.UITextField)) {
                view.setText_("bypass_mode");
                view.setUserInteractionEnabled_(0);
                view.setEnabled_(0);
                log("🎨 TextField → 固定文本+禁止编辑");
            }

            // UIButton: 修改按钮文字
            if (view.isKindOfClass_(ObjC.classes.UIButton)) {
                var title = view.titleForState_(0);
                var tt = title ? title.toString() : "";
                if (tt.length > 0) {
                    view.setTitle_forState_("进入软件", 0);
                    log("🎨 Button '" + tt + "' → '进入软件'");
                }
            }

            // 递归遍历子视图
            var subs = view.subviews();
            var count = subs ? subs.count() : 0;
            for (var i = 0; i < count; i++) {
                patchViewTree(subs.objectAtIndex_(i), depth + 1);
            }
        } catch(e) {}
    }

    // --- 通过self指针直接patch视图树 + 属性访问 ---
    function patchVC(vcPtr) {
        try {
            var vc = new ObjC.Object(vcPtr);
            patchViewTree(vc.view(), 0);

            // 属性访问 (安全检查)
            try {
                var field = vc.kamiField();
                if (field && !field.isNull()) {
                    field.setText_("bypass_mode");
                    field.setUserInteractionEnabled_(0);
                    field.setEnabled_(0);
                    log("🎨 kamiField已设固定文本+禁止编辑");
                }
            } catch(e) {}

            try {
                var btn = vc.loginButton();
                if (btn && !btn.isNull()) {
                    btn.setTitle_forState_("进入软件", 0);
                    log("🎨 loginButton已设'进入软件'");
                }
            } catch(e) {}

            try {
                var lbl = vc.statusLabel();
                if (lbl && !lbl.isNull()) {
                    lbl.setText_("");
                    lbl.setHidden_(1);
                    log("🎨 statusLabel已隐藏");
                }
            } catch(e) {}

            // announcementLabel 也隐藏
            try {
                var annLbl = vc.announcementLabel();
                if (annLbl && !annLbl.isNull()) {
                    annLbl.setText_("");
                    annLbl.setHidden_(1);
                    log("🎨 announcementLabel已隐藏");
                }
            } catch(e) {}
        } catch(e) { log("⚠️ patchVC: " + e.message); }
    }

    // 1. Hook _buildUI: 返回时同步patch视图树 (最快, 无闪烁)
    try {
        var origBuildUI = VC["- _buildUI"].implementation;
        Interceptor.attach(origBuildUI, {
            onEnter: function(args) {
                this.vcPtr = args[0];
                log("🎨 _buildUI 开始");
            },
            onLeave: function(retval) {
                patchVC(this.vcPtr);
                log("🎨 _buildUI 完成, 视图树已patch");
            }
        });
    } catch(e) { log("⚠️ _buildUI hook: " + e.message); }

    // 2. Hook viewDidLayoutSubviews: 兜底
    try {
        var origViewDidLayout = VC["- viewDidLayoutSubviews"].implementation;
        if (origViewDidLayout) {
            Interceptor.attach(origViewDidLayout, {
                onEnter: function(args) {
                    this.vcPtr = args[0];
                },
                onLeave: function(retval) {
                    patchVC(this.vcPtr);
                    log("🎨 viewDidLayoutSubviews patch完成");
                }
            });
        }
    } catch(e) { log("⚠️ viewDidLayoutSubviews hook: " + e.message); }

    // 3. Hook _showStatus:isError: 拦截到期时间显示
    try {
        var origShowStatus = VC["- _showStatus:isError:"].implementation;
        if (origShowStatus) {
            Interceptor.attach(origShowStatus, {
                onEnter: function(args) {
                    try {
                        var msg = "(unknown)";
                        try { msg = new ObjC.Object(args[2]).toString(); } catch(e) {}
                        log("🎨 拦截 _showStatus: '" + msg + "'");
                    } catch(e) {}
                }
            });
        }
    } catch(e) { log("⚠️ _showStatus hook: " + e.message); }

    // 4. Hook _onLogin: 登录前再patch一次确保
    try {
        var origOnLogin = VC["- _onLogin"].implementation;
        if (origOnLogin) {
            Interceptor.attach(origOnLogin, {
                onEnter: function(args) {
                    this.vcPtr = args[0];
                    patchVC(args[0]);
                    log("🎨 _onLogin patch完成");
                }
            });
        }
    } catch(e) { log("⚠️ _onLogin hook: " + e.message); }

    log("✅ 登录页UI修改完成");
}

// ============ 启动 ============
if (ObjC.available) {
    bypassAntiDebug();
    bypassVerification();
    bypassLoginUI();
    installMonitor();
    log("========== 全部完成, 等待 App 操作 ==========");
} else {
    log("❌ ObjC 不可用");
}
