/*
 * ViaPro 卡密验证 Bypass 脚本 v2 (适配1.8.1版类名混淆)
 * 
 * 新版本类名混淆映射:
 *   WYVerifyManager        → _A7xK9mR2pL
 *   WYVerifyViewController  → _B3nQ8wF5jD
 *   hasValidSession         → _s5c4z7n2
 *   formattedExpireTime     → _s1j2q7u4
 *   loginWithKami:completion: → _s3b8y1m6:completion:
 *   presentVerifyUIOnVC:    → _s9k8p1v6:completion:
 *   _showVerifyGate         → _p7h4q3r8 (DOSceneDelegate)
 *   _transitionToMainUI     → _p3f2m9n0 (DOSceneDelegate)
 *
 * BSVerifyUltraProxy / BSVerifyUltraProxyResult / DOSceneDelegate 类名未变
 *
 * 用法 (MT 包名 com.STE.Pro, spawn 注入保证验证逻辑执行前拦截):
 *   frida -U -f com.STE.Pro -l e:\破解\新版本\新版本via\pro\hook_bypass.js
 *   (若 MT 已在运行: frida -U -n MT -l e:\破解\新版本\新版本via\pro\hook_bypass.js)
 */

var TAG = "[ViaPro]";

function log(msg) {
    console.log(TAG + " " + msg);
}

// 找到主模块基址
function getMainBase() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        var n = mods[i].name;
        var p = (mods[i].path || "").toLowerCase();
        if (n === "MT" || n.indexOf("MT") === 0 || p.indexOf("ste.pro") !== -1 || p.indexOf("mt.app") !== -1) {
            return mods[i].base;
        }
    }
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

    // ⚠️ 新版 WYVerifyManager → _A7xK9mR2pL
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

    // ⚠️ 新版 C 函数地址变化 (ImageBase=0x100000000)
    // 旧版 LFExpireIsExpired=0xe044, LFExpireHasKnownState=0xdd64
    // 新版需重新确认 — 如果找不到符号就跳过, ObjC层面的bypass已够用
    // 暂时注释掉C函数hook, 因为新版符号名可能已变
    /*
    try {
        Interceptor.attach(base.add(0xe044), {
            onLeave: function(retval) {
                retval.replace(ptr(0));
                log("🚀 LFExpireIsExpired → 0 (未过期)");
            }
        });
    } catch(e) { log("⚠️ LFExpireIsExpired: " + e.message); }

    try {
        Interceptor.attach(base.add(0xdd64), {
            onLeave: function(retval) {
                retval.replace(ptr(0));
                log("🚀 LFExpireHasKnownState → 0");
            }
        });
    } catch(e) { log("⚠️ LFExpireHasKnownState: " + e.message); }
    */

    // ⚠️ 新版 WYVerifyManager → _A7xK9mR2pL
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

        // 拦截过期弹窗 (方法名未变)
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

    // 4. BSVerifyUltraProxyResult success → YES (类名未变)
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

    // 5. BSVerifyUltraProxy (类名未变)
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

    // ⚠️ 新版 WYVerifyManager → _A7xK9mR2pL
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

// ============ 启动 ============
if (ObjC.available) {
    bypassAntiDebug();
    bypassVerification();
    installMonitor();
    log("========== 全部完成, 等待 App 操作 ==========");
} else {
    log("❌ ObjC 不可用");
}
