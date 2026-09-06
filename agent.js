/*
 * JH (com.aughpjy.jh) - 卡密验证绕过脚本 V16
 *
 * V16 关键修复 (基于真实卡密数据捕获 + IDA 静态分析):
 *
 * 1.【根因】dyld 反注入检测:
 *    sub_100004000/sub_1000040B0 遍历 dyld image, sub_100004050 用 strstr 匹配黑名单
 *    (FridaGadget/frida-agent/frida-gadget/libcycript/Cycript/SSLKillSwitch/sslkill/
 *     SSLKill/RevealServer/Flex.dylib/libFlex), 命中即调 sub_10020BC10:
 *      → +[NwGameOffsets clear] 清空偏移 + setRuntimeLicenseOK:0 + 引擎撤销标志
 *    真实卡密下心跳/watch会重新拉取自愈; 绕过模式下被清即永久失效 → 绘制不生效
 *    修复: 替换 sub_100004050 永远返回0(未检测到) + 置空 sub_10020BC10 (双保险)
 *
 * 2.【数据】真实偏移: gWorld = 0x1148B608 (旧值 0x10C464C8 已过期)
 *    字典格式与旧版一致: {"game":"pubg","cfg_ver":1,"exp":...,"offsets":{...}}
 *
 * 3. 保持 V15 全部 license 检查放行 hook
 */

if (ObjC.available) {

    function getImpl(className, sel) {
        var cls = ObjC.classes[className];
        if (!cls) return null;
        var m = cls[sel];
        if (!m) return null;
        return m.implementation;
    }

    // ==========================================
    // 0. 中和 dyld 反注入检测 (V16 核心)
    //    IDA imagebase = 0x100000000
    // ==========================================

    // 注意: 越狱设备上 enumerateModules()[0] 可能是 systemhook 注入库, 必须用 mainModule
    var mainMod = Process.mainModule || (function () {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            var p = mods[i].path;
            if (p.indexOf('.app/') !== -1 && p.slice(-5) !== '.dylib') return mods[i];
        }
        return mods[0];
    })();

    var BASE = mainMod.base;
    var IDA_BASE = ptr('0x100000000');

    function rt(idaAddr) {
        var a = BASE.add(ptr(idaAddr).sub(IDA_BASE));
        // 范围校验: 换算地址必须落在主模块内, 防止错误基址毁掉其他 dylib
        if (a.compare(BASE) < 0 || a.compare(BASE.add(mainMod.size)) >= 0) {
            throw new Error('地址越界: ' + idaAddr + ' → ' + a + ' 不在主模块内');
        }
        return a;
    }

    console.log('[+] 主模块: ' + mainMod.name + ' @ ' + BASE);
    console.log('[+] 模块路径: ' + mainMod.path);

    // 0a. 黑名单匹配器 sub_100004050 → 永远返回 0 (未检测到)
    try {
        Interceptor.replace(rt('0x100004050'), new NativeCallback(function(name) {
            return 0;
        }, 'bool', ['pointer']));
        console.log('[+] 反注入匹配器 sub_100004050 已中和');
    } catch (e) {
        console.log('[!] sub_100004050 中和失败: ' + e);
    }

    // 0b. 撤销动作 sub_10020BC10 → no-op (双保险, 无论谁调用都无效)
    try {
        Interceptor.replace(rt('0x10020bc10'), new NativeCallback(function() {
            console.log('[!] 检测到撤销动作 sub_10020BC10 被调用 → 已拦截');
        }, 'void', []));
        console.log('[+] 撤销动作 sub_10020BC10 已置空');
    } catch (e) {
        console.log('[!] sub_10020BC10 置空失败: ' + e);
    }

    // 0c. +[NwGameOffsets clear] 监控 (撤销已拦截, 此处仅确认是否还有其他清理路径)
    var clearImpl = getImpl('NwGameOffsets', '+ clear');
    if (clearImpl) {
        Interceptor.attach(clearImpl, { onEnter: function() { console.log('[!] NwGameOffsets clear 被调用! (检测到其他清理路径)'); } });
    }

    // ==========================================
    // 1. 真实偏移数据 (来自真实卡密捕获)
    // ==========================================

    var OFFSETS = {
        'gWorld': '0x1148B608'
    };

    var FAKE_EXP = 4102444800; // 2100-01-01

    // ==========================================
    // 2. REPLACE beginVerification → 直接 finishSuccess
    // ==========================================

    var beginVerificationAddr = getImpl('NwEntryPanel', '- beginVerification');
    if (beginVerificationAddr) {
        var replaceBegin = new NativeCallback(function(self, sel) {
            console.log('[*] ===== beginVerification (REPLACE) =====');

            try {
                var panel = new ObjC.Object(self);

                panel.setBusy_message_(1, '正在加载配置…');

                try {
                    // 真实格式注入 (与服务器下发解密后完全一致的 key 结构)
                    var offsetsInner = ObjC.classes.NSMutableDictionary.dictionary();
                    offsetsInner.setObject_forKey_('0x1148B608', 'gWorld');

                    var offsetsDict = ObjC.classes.NSMutableDictionary.dictionary();
                    offsetsDict.setObject_forKey_('pubg', 'game');
                    offsetsDict.setObject_forKey_(1, 'cfg_ver');
                    offsetsDict.setObject_forKey_(FAKE_EXP, 'exp');
                    offsetsDict.setObject_forKey_(offsetsInner, 'offsets');
                    ObjC.classes.NwGameOffsets.applyDictionary_(offsetsDict);
                    console.log('[+] NwGameOffsets applyDictionary: gWorld=0x1148B608');

                    var featDict = ObjC.classes.NSMutableDictionary.dictionary();
                    featDict.setObject_forKey_(1, 'esp_enabled');
                    featDict.setObject_forKey_(1, 'cfg_ver');
                    featDict.setObject_forKey_(FAKE_EXP, 'exp');
                    ObjC.classes.NxFeat.applyDictionary_(featDict);
                    console.log('[+] NxFeat applyDictionary: esp_enabled=1');
                } catch (e) {
                    console.log('[!] applyDictionary 注入: ' + e);
                }

                var shared = ObjC.classes.NwSession.shared();
                if (shared) {
                    shared.setRuntimeLicenseOK_(1);
                    console.log('[+] setRuntimeLicenseOK: YES');
                }

                panel.setBusy_message_(0, '');

                ObjC.schedule(ObjC.mainQueue, function() {
                    try {
                        console.log('[*] → 调用 finishSuccess (原始)');
                        panel.finishSuccess();
                        console.log('[*] → finishSuccess 完成, 偏移已注入且受保护');
                    } catch (e) {
                        console.log('[!] finishSuccess: ' + e);
                    }
                });

            } catch (e) {
                console.log('[!] beginVerification REPLACE: ' + e);
            }
        }, 'void', ['pointer', 'pointer']);

        Interceptor.replace(beginVerificationAddr, replaceBegin);
        console.log('[+] beginVerification REPLACEd');
    }

    // ==========================================
    // 3. 保护性 Hook - 阻止吊销/心跳/定时器/退出/清token
    // ==========================================

    var emptyVoid = new NativeCallback(function() {}, 'void', ['pointer', 'pointer']);
    var emptyVoid2 = new NativeCallback(function() {}, 'void', ['pointer', 'pointer', 'pointer']);
    var emptyVoid3 = new NativeCallback(function() {}, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);
    var emptyVoidDbl = new NativeCallback(function() {}, 'void', ['pointer', 'pointer', 'double']);

    var nw_revoke = getImpl('NwSession', '- nw_revokeRuntimeLicense:');
    if (nw_revoke) Interceptor.replace(nw_revoke, emptyVoid2);

    var nw_sessEnd = getImpl('NwSession', '- nw_sessEnd:status:');
    if (nw_sessEnd) Interceptor.replace(nw_sessEnd, emptyVoid3);

    var showExit = getImpl('NwSession', '+ showForceExitAlertWithMessage:');
    if (showExit) Interceptor.replace(showExit, emptyVoid2);

    var startWatch = getImpl('NwSession', '- startLicenseWatchWithInterval:');
    if (startWatch) Interceptor.replace(startWatch, emptyVoidDbl);

    var startHeartbeat = getImpl('NwSession', '- startHeartbeatWithInterval:onResult:');
    if (startHeartbeat) {
        var emptyHb = new NativeCallback(function() {}, 'void', ['pointer', 'pointer', 'int', 'pointer']);
        Interceptor.replace(startHeartbeat, emptyHb);
    }

    var clearSession = getImpl('NwSession', '- clearSession');
    if (clearSession) Interceptor.replace(clearSession, emptyVoid);

    var clearTokenOnly = getImpl('NwSession', '- clearTokenOnly');
    if (clearTokenOnly) Interceptor.replace(clearTokenOnly, emptyVoid);

    var nw_refresh = getImpl('NwSession', '- nw_refreshRuntimeLicenseState');
    if (nw_refresh) Interceptor.replace(nw_refresh, emptyVoid);

    var nw_tick = getImpl('NwSession', '- nw_performLicenseTick');
    if (nw_tick) Interceptor.replace(nw_tick, emptyVoid);

    var nw_mirror = getImpl('NwSession', '- nw_mirrorRuntimeLicense:');
    if (nw_mirror) Interceptor.replace(nw_mirror, emptyVoid2);

    var runtimeLicenseOK = getImpl('NwSession', '+ runtimeLicenseOK');
    if (runtimeLicenseOK) Interceptor.attach(runtimeLicenseOK, { onLeave: function(r) { r.replace(ptr(1)); } });

    var setRuntimeLicenseOK = getImpl('NwSession', '- setRuntimeLicenseOK:');
    if (setRuntimeLicenseOK) Interceptor.attach(setRuntimeLicenseOK, { onEnter: function(a) { a[2] = ptr(1); } });

    var isKamiExpiredLocally = getImpl('NwSession', '- isKamiExpiredLocally');
    if (isKamiExpiredLocally) Interceptor.attach(isKamiExpiredLocally, { onLeave: function(r) { r.replace(ptr(0)); } });

    var isLocallyActivated = getImpl('NwSession', '- isLocallyActivated');
    if (isLocallyActivated) Interceptor.attach(isLocallyActivated, { onLeave: function(r) { r.replace(ptr(1)); } });

    var nw_shouldSessEnd = getImpl('NwSession', '- nw_shouldSessEndForVerifyFailureStatus:message:');
    if (nw_shouldSessEnd) Interceptor.attach(nw_shouldSessEnd, { onLeave: function(r) { r.replace(ptr(0)); } });

    var nw_isTerminal = getImpl('NwSession', '- nw_isTerminalAuthFailureMessage:');
    if (nw_isTerminal) Interceptor.attach(nw_isTerminal, { onLeave: function(r) { r.replace(ptr(0)); } });

    var nw_saveKamiExp = getImpl('NwSession', '- nw_saveKamiExp:');
    if (nw_saveKamiExp) Interceptor.attach(nw_saveKamiExp, { onEnter: function(a) { a[2] = ptr(9999999999); } });

    // ==========================================
    // 4. NxFeat 特性门控 → 全部放行
    // ==========================================

    var espEnabled = getImpl('NxFeat', '+ espEnabled');
    if (espEnabled) Interceptor.attach(espEnabled, { onLeave: function(r) { if (r.toInt32() == 0) r.replace(ptr(1)); } });

    var hasConfig = getImpl('NxFeat', '+ hasConfig');
    if (hasConfig) Interceptor.attach(hasConfig, { onLeave: function(r) { if (r.toInt32() == 0) r.replace(ptr(1)); } });

    var featReady = getImpl('NxFeat', '+ isReady');
    if (featReady) Interceptor.attach(featReady, { onLeave: function(r) { if (r.toInt32() == 0) r.replace(ptr(1)); } });

    var isConfigStale = getImpl('NxFeat', '+ isConfigStale');
    if (isConfigStale) Interceptor.attach(isConfigStale, { onLeave: function(r) { if (r.toInt32() != 0) r.replace(ptr(0)); } });

    var configVersion = getImpl('NxFeat', '+ configVersion');
    if (configVersion) Interceptor.attach(configVersion, { onLeave: function(r) { if (r.toInt32() == 0) r.replace(ptr(1)); } });

    // ==========================================
    // 5. NwGameOffsets 就绪检查 → 全部放行
    // ==========================================

    var offsetsReady = getImpl('NwGameOffsets', '+ isReady');
    if (offsetsReady) Interceptor.attach(offsetsReady, { onLeave: function(r) { if (r.toInt32() == 0) r.replace(ptr(1)); } });

    var offsetsReadyForKey = getImpl('NwGameOffsets', '+ isReadyForGameKey:');
    if (offsetsReadyForKey) {
        Interceptor.attach(offsetsReadyForKey, {
            onLeave: function(r) {
                if (r.toInt32() == 0) {
                    console.log('[+] NwGameOffsets isReadyForGameKey: → YES');
                    r.replace(ptr(1));
                }
            }
        });
    }

    var offsetsStale = getImpl('NwGameOffsets', '+ isStale');
    if (offsetsStale) Interceptor.attach(offsetsStale, { onLeave: function(r) { if (r.toInt32() != 0) r.replace(ptr(0)); } });

    // ==========================================
    // 6. 偏移读侧拦截 —— 强制覆盖
    // ==========================================

    var u64Impl = getImpl('NwGameOffsets', '+ u64:');
    if (u64Impl) {
        Interceptor.attach(u64Impl, {
            onEnter: function(args) {
                this.key = null;
                try { this.key = new ObjC.Object(args[2]).toString(); } catch (e) {}
            },
            onLeave: function(retval) {
                if (!this.key) return;
                if (this.key in OFFSETS) {
                    retval.replace(ptr(OFFSETS[this.key]));
                }
            }
        });
        console.log('[+] u64: 读侧拦截已挂载');
    }

    // ==========================================
    // 7. accessToken / tokenExpireUnix → 非空且不过期
    // ==========================================

    var accessTokenImpl = getImpl('NwSession', '- accessToken');
    if (accessTokenImpl) {
        Interceptor.attach(accessTokenImpl, {
            onLeave: function(retval) {
                if (retval.isNull()) {
                    var fakeToken = ObjC.classes.NSString.stringWithString_('fake_token_bypass_v16');
                    retval.replace(fakeToken);
                }
            }
        });
    }

    var tokenExpireUnixImpl = getImpl('NwSession', '- tokenExpireUnix');
    if (tokenExpireUnixImpl) {
        Interceptor.attach(tokenExpireUnixImpl, {
            onLeave: function(retval) {
                if (retval.toInt32() == 0 || retval.toInt32() < 1700000000) {
                    retval.replace(ptr(4102444800));
                }
            }
        });
    }

    // ==========================================
    // 8. setBusy:message: - 拦截错误消息
    // ==========================================

    var setBusy = getImpl('NwEntryPanel', '- setBusy:message:');
    if (setBusy) {
        Interceptor.attach(setBusy, {
            onEnter: function(args) {
                var busy = args[2].toInt32();
                try {
                    var msg = new ObjC.Object(args[3]);
                    var msgStr = msg.toString();
                    if (busy == 0 && msgStr.length > 0 &&
                        (msgStr.indexOf('失败') !== -1 ||
                         msgStr.indexOf('不存在') !== -1 ||
                         msgStr.indexOf('未加载') !== -1 ||
                         msgStr.indexOf('未就绪') !== -1 ||
                         msgStr.indexOf('无法') !== -1 ||
                         msgStr.indexOf('请先') !== -1 ||
                         msgStr.indexOf('无效') !== -1 ||
                         msgStr.indexOf('过期') !== -1)) {
                        args[3] = ObjC.classes.NSString.stringWithString_('').handle;
                    }
                } catch (e) {}
            }
        });
    }

    console.log('[+] JH V16 已加载');
    console.log('[+] 核心: dyld反注入检测已中和 (匹配器+撤销动作双拦截)');
    console.log('[+] 数据: gWorld=0x1148B608 (真实捕获值)\n');

} else {
    console.log('[!] ObjC runtime not available');
}
