/*
 * Yuve (Tesla 9.5, com.tsl.jhap) - card-key license bypass V1
 *
 * The binary shares the exact same 'Nw*' auth framework as JH
 * (teacher's bypass_kami_v16.js): NwEntryPanel / NwSession / NwGameOffsets
 * / NxFeat / NwSessionResult. All ObjC method hooks are therefore portable.
 *
 * IDA imagebase = 0x100000000
 *
 * Yuve-specific addresses (differ from JH V16):
 *   0x100004074  JHLooksHostile(const char*)   strstr blacklist matcher
 *                (blacklist table @0x100820CB8: FridaGadget, frida-agent,
 *                 frida-gadget, SSLKillSwitch, sslkill, SSLKill,
 *                 RevealServer, Flex.dylib, libFlex)  -> force return 0
 *   0x100004178  JHApplyLock(void)  -> NwGateLockdown()  -> no-op
 *   0x1002876A4  NwGateLockdown(void)                     -> no-op (extra)
 *   0x100287A60  NwGateIsLocked(void)                     -> force return 0
 *   0x1008D332C  lock flag global (atomic, read by NwGateIsLocked) -> 0
 *
 * Game key in this build: "dfm"  (finishSuccess waits for
 *   NwGameOffsets isReadyForGameKey:("dfm"))
 * gWorld offset = 0x178B44E0, extracted from THOR-HUD (free DFM reference):
 *   Cosmk() does DuQu<long>(gameBase + 395003104) -> GWorld pointer.
 * Full pointer chain also recovered (see documentation).
 */

if (ObjC.available) {

    // ------------------------------------------------------------------
    // CONFIG
    // ------------------------------------------------------------------
    var GAME_KEY = 'dfm';
    var FAKE_EXP = 4102444800;               // 2100-01-01

    // name -> hex address. gWorld extracted from THOR-HUD (free DFM ref)
    // Cosmk() function: DuQu<long>(base + 395003104) = GWorld pointer.
    // 395003104 decimal = 0x178B44E0
    var OFFSETS = {
        'gWorld': '0x178B44E0'
    };

    var COORD_CAPTURE_MODE = false;  // set true to dump applyDictionary args

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------
    function getImpl(className, sel) {
        var cls = ObjC.classes[className];
        if (!cls) return null;
        var m = cls[sel];
        if (!m) return null;
        return m.implementation;
    }

    // main module: the app itself. On jailbroken devices modules[0] may be
    // the injection library (systemhook/opainject), so never trust index 0.
    var mainMod = Process.mainModule || (function () {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            var p = mods[i].path;
            if (p.indexOf('Yuve.app') !== -1 && p.slice(-5) !== '.dylib') return mods[i];
        }
        return mods[0];
    })();

    var BASE = mainMod.base;                 // runtime base (ASLR)
    var IDA_BASE = ptr('0x100000000');

    function rt(idaAddr) {
        var a = BASE.add(ptr(idaAddr).sub(IDA_BASE));
        if (a.compare(BASE) < 0 || a.compare(BASE.add(mainMod.size)) >= 0) {
            throw new Error('rt out of range: ' + idaAddr + ' -> ' + a);
        }
        return a;
    }
    var OFFS = function (idaAddr) { return ptr(idaAddr).sub(IDA_BASE); };

    console.log('[+] main module: ' + mainMod.name + ' @ ' + BASE);
    console.log('[+] path: ' + mainMod.path);

    // ==================================================================
    // 0. neutralise dyld anti-injection detection (V1 core)
    // ==================================================================
    // 0a. JHLooksHostile -> always 0 (not hostile)
    try {
        Interceptor.replace(rt('0x100004074'), new NativeCallback(function (name) {
            return 0;
        }, 'bool', ['pointer']));
        console.log('[+] JHLooksHostile (blacklist matcher) neutralised');
    } catch (e) {
        console.log('[!] JHLooksHostile replace failed: ' + e);
    }

    // 0b. JHApplyLock -> no-op (the only caller of NwGateLockdown)
    try {
        Interceptor.replace(rt('0x100004178'), new NativeCallback(function () {
            console.log('[!] JHApplyLock called -> intercepted');
        }, 'void', []));
        console.log('[+] JHApplyLock neutralised');
    } catch (e) {
        console.log('[!] JHApplyLock replace failed: ' + e);
    }

    // 0c. NwGateLockdown -> no-op (extra safety)
    try {
        Interceptor.replace(rt('0x1002876a4'), new NativeCallback(function () {
            console.log('[!] NwGateLockdown called -> intercepted');
        }, 'void', []));
        console.log('[+] NwGateLockdown neutralised');
    } catch (e) {
        console.log('[!] NwGateLockdown replace failed: ' + e);
    }

    // 0d. NwGateIsLocked -> always 0 (recover from a lock applied pre-attach)
    try {
        Interceptor.replace(rt('0x100287a60'), new NativeCallback(function () {
            return 0;
        }, 'long', []));
        console.log('[+] NwGateIsLocked forced 0');
    } catch (e) {
        console.log('[!] NwGateIsLocked replace failed: ' + e);
    }

    // 0e. clear the lock flag global (0x1008D332C, read atomically)
    try {
        var lockGlobal = BASE.add(OFFS('0x1008D332C'));
        lockGlobal.writeU32(0);
        console.log('[+] lock flag global cleared (0x1008D332C)');
    } catch (e) {
        console.log('[!] lock global write failed: ' + e);
    }

    // 0f. monitor NwGameOffsets clear (any other wipe path?)
    var offsetsClear = getImpl('NwGameOffsets', '+ clear');
    if (offsetsClear) {
        Interceptor.attach(offsetsClear, { onEnter: function () {
            console.log('[!] NwGameOffsets clear called! (unexpected wipe path)');
        }});
    }

    // ==================================================================
    // helper: build the offsets dictionary the way applyDictionary expects
    // (frida setObject_forKey_(obj, key) -> dict[key] = obj)
    // ==================================================================
    function buildOffsetsDict() {
        var inner = ObjC.classes.NSMutableDictionary.dictionary();
        for (var k in OFFSETS) {
            if (OFFSETS[k]) inner.setObject_forKey_(OFFSETS[k], k);
        }
        var outer = ObjC.classes.NSMutableDictionary.dictionary();
        outer.setObject_forKey_(GAME_KEY, 'game');
        outer.setObject_forKey_(1, 'cfg_ver');
        outer.setObject_forKey_(FAKE_EXP, 'exp');
        outer.setObject_forKey_(inner, 'offsets');
        return outer;
    }

    function injectLicensedState() {
        try {
            ObjC.classes.NwGameOffsets.applyDictionary_(buildOffsetsDict());
            console.log('[+] NwGameOffsets.applyDictionary injected (game=' + GAME_KEY + ')');
        } catch (e) { console.log('[!] offsets inject: ' + e); }

        try {
            var feat = ObjC.classes.NSMutableDictionary.dictionary();
            feat.setObject_forKey_(1, 'esp_enabled');
            feat.setObject_forKey_(1, 'cfg_ver');
            feat.setObject_forKey_(FAKE_EXP, 'exp');
            ObjC.classes.NxFeat.applyDictionary_(feat);
            console.log('[+] NxFeat.applyDictionary injected (esp_enabled=1)');
        } catch (e) { console.log('[!] feat inject: ' + e); }

        try {
            var shared = ObjC.classes.NwSession.shared();
            if (shared) {
                shared.setRuntimeLicenseOK_(1);
                console.log('[+] NwSession runtimeLicenseOK = 1');
            }
        } catch (e) { console.log('[!] setRuntimeLicenseOK: ' + e); }
    }

    // ==================================================================
    // 1. REPLACE beginVerification -> direct finishSuccess
    // ==================================================================
    var beginVerificationAddr = getImpl('NwEntryPanel', '- beginVerification');
    if (beginVerificationAddr) {
        var replaceBegin = new NativeCallback(function (self, sel) {
            console.log('[*] ===== beginVerification (REPLACE) =====');
            try {
                var panel = new ObjC.Object(self);
                panel.setBusy_message_(1, 'verifying bypass...');
                injectLicensedState();
                ObjC.schedule(ObjC.mainQueue, function () {
                    try {
                        panel.finishSuccess();
                        console.log('[*] finishSuccess done -> entry panel should close');
                    } catch (e) { console.log('[!] finishSuccess: ' + e); }
                });
            } catch (e) {
                console.log('[!] beginVerification REPLACE: ' + e);
            }
        }, 'void', ['pointer', 'pointer']);
        Interceptor.replace(beginVerificationAddr, replaceBegin);
        console.log('[+] beginVerification REPLACEd');
    } else {
        console.log('[!] beginVerification NOT found');
    }

    // ==================================================================
    // 2. protective hooks - block revoke / session-end / exit / timers
    // ==================================================================
    var emptyVoid  = new NativeCallback(function () {}, 'void', ['pointer', 'pointer']);
    var emptyVoid2 = new NativeCallback(function () {}, 'void', ['pointer', 'pointer', 'pointer']);
    var emptyVoid3 = new NativeCallback(function () {}, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);
    var emptyVoidDbl = new NativeCallback(function () {}, 'void', ['pointer', 'pointer', 'double']);

    var nw_revoke = getImpl('NwSession', '- nw_revokeRuntimeLicense:');
    if (nw_revoke) Interceptor.replace(nw_revoke, emptyVoid2);

    var nw_sessEnd = getImpl('NwSession', '- nw_sessEnd:status:');
    if (nw_sessEnd) Interceptor.replace(nw_sessEnd, emptyVoid3);

    var showExit = getImpl('NwSession', '+ showForceExitAlertWithMessage:');
    if (showExit) Interceptor.replace(showExit, emptyVoid2);

    var startWatch = getImpl('NwSession', '- startLicenseWatchWithInterval:');
    if (startWatch) Interceptor.replace(startWatch, emptyVoidDbl);

    var startHearthbeat = getImpl('NwSession', '- startHeartbeatWithInterval:onResult:');
    if (startHearthbeat) {
        var emptyHb = new NativeCallback(function () {}, 'void', ['pointer', 'pointer', 'int', 'pointer']);
        Interceptor.replace(startHearthbeat, emptyHb);
    }

    var clearSession = getImpl('NwSession', '- clearSession');
    if (clearSession) Interceptor.replace(clearSession, emptyVoid);

    var clearTokenOnly = getImpl('NwSession', '- clearTokenOnly');
    if (clearTokenOnly) Interceptor.replace(clearTokenOnly, emptyVoid);

    var nw_mirror = getImpl('NwSession', '- nw_mirrorRuntimeLicense:');
    if (nw_mirror) Interceptor.replace(nw_mirror, emptyVoid2);

    var nw_tick = getImpl('NwSession', '- nw_performLicenseTick');
    if (nw_tick) Interceptor.replace(nw_tick, emptyVoid);

    var nw_shouldSessEnd = getImpl('NwSession', '- nw_shouldSessEndForVerifyFailureStatus:message:');
    if (nw_shouldSessEnd) Interceptor.attach(nw_shouldSessEnd, { onLeave: function (r) { r.replace(ptr(0)); } });

    var nw_saveKamiExp = getImpl('NwSession', '- nw_saveKamiExp:');
    if (nw_saveKamiExp) Interceptor.attach(nw_saveKamiExp, { onEnter: function (a) { a[2] = ptr(FAKE_EXP); } });

    // ==================================================================
    // 3. license state getters -> all-allow
    // ==================================================================
    var runtimeLicenseOK = getImpl('NwSession', '+ runtimeLicenseOK');
    if (runtimeLicenseOK) Interceptor.attach(runtimeLicenseOK, { onLeave: function (r) { r.replace(ptr(1)); } });

    var setRuntimeLicenseOK = getImpl('NwSession', '- setRuntimeLicenseOK:');
    if (setRuntimeLicenseOK) Interceptor.attach(setRuntimeLicenseOK, { onEnter: function (a) { a[2] = ptr(1); } });

    var isKamiExpiredLocally = getImpl('NwSession', '- isKamiExpiredLocally');
    if (isKamiExpiredLocally) Interceptor.attach(isKamiExpiredLocally, { onLeave: function (r) { r.replace(ptr(0)); } });

    var isLocallyActivated = getImpl('NwSession', '- isLocallyActivated');
    if (isLocallyActivated) Interceptor.attach(isLocallyActivated, { onLeave: function (r) { r.replace(ptr(1)); } });

    // ==================================================================
    // 4. NxFeat feature gates -> all-allow
    // ==================================================================
    var espEnabled = getImpl('NxFeat', '+ espEnabled');
    if (espEnabled) Interceptor.attach(espEnabled, { onLeave: function (r) { if (r.toInt32() == 0) r.replace(ptr(1)); } });

    var hasConfig = getImpl('NxFeat', '+ hasConfig');
    if (hasConfig) Interceptor.attach(hasConfig, { onLeave: function (r) { if (r.toInt32() == 0) r.replace(ptr(1)); } });

    var featReady = getImpl('NxFeat', '+ isReady');
    if (featReady) Interceptor.attach(featReady, { onLeave: function (r) { if (r.toInt32() == 0) r.replace(ptr(1)); } });

    var isConfigStale = getImpl('NxFeat', '+ isConfigStale');
    if (isConfigStale) Interceptor.attach(isConfigStale, { onLeave: function (r) { if (r.toInt32() != 0) r.replace(ptr(0)); } });

    var configVersion = getImpl('NxFeat', '+ configVersion');
    if (configVersion) Interceptor.attach(configVersion, { onLeave: function (r) { if (r.toInt32() == 0) r.replace(ptr(1)); } });

    // ==================================================================
    // 5. NwGameOffsets readiness checks -> all-allow
    // ==================================================================
    var offsetsReady = getImpl('NwGameOffsets', '+ isReady');
    if (offsetsReady) Interceptor.attach(offsetsReady, { onLeave: function (r) { if (r.toInt32() == 0) r.replace(ptr(1)); } });

    var offsetsReadyForKey = getImpl('NwGameOffsets', '+ isReadyForGameKey:');
    if (offsetsReadyForKey) {
        Interceptor.attach(offsetsReadyForKey, {
            onLeave: function (r) {
                if (r.toInt32() == 0) {
                    console.log('[+] isReadyForGameKey: -> YES');
                    r.replace(ptr(1));
                }
            }
        });
    }

    var offsetsStale = getImpl('NwGameOffsets', '+ isStale');
    if (offsetsStale) Interceptor.attach(offsetsStale, { onLeave: function (r) { if (r.toInt32() != 0) r.replace(ptr(0)); } });

    var currentGameKey = getImpl('NwGameOffsets', '+ currentGameKey');
    if (currentGameKey) {
        Interceptor.attach(currentGameKey, {
            onLeave: function (r) {
                if (r.isNull()) {
                    r.replace(ObjC.classes.NSString.stringWithString_(GAME_KEY));
                }
            }
        });
    }

    // ==================================================================
    // 5b. coordinate capture mode (for filling in the real OFFSETS table)
    // ==================================================================
    if (COORD_CAPTURE_MODE) {
        var applyDictImpl = getImpl('NwGameOffsets', '+ applyDictionary:');
        if (applyDictImpl) {
            Interceptor.attach(applyDictImpl, {
                onEnter: function (args) {
                    try {
                        console.log('[*] applyDictionary: ' + new ObjC.Object(args[2]).toString());
                    } catch (e) { console.log('[!] dump applyDictionary: ' + e); }
                }
            });
        }
        console.log('[+] COORD_CAPTURE_MODE ON - dump any applyDictionary payload');
    }

    // ==================================================================
    // 6. offsets read-side interception - force override for known keys
    // ==================================================================
    var u64Impl = getImpl('NwGameOffsets', '+ u64:');
    if (u64Impl) {
        Interceptor.attach(u64Impl, {
            onEnter: function (args) {
                this.key = null;
                try { this.key = new ObjC.Object(args[2]).toString(); } catch (e) {}
            },
            onLeave: function (retval) {
                if (!this.key) return;
                if (this.key in OFFSETS && OFFSETS[this.key]) {
                    retval.replace(ptr(OFFSETS[this.key]));
                }
            }
        });
        console.log('[+] u64: read-side override mounted');
    }

    var longValImpl = getImpl('NwGameOffsets', '+ longVal:');
    if (longValImpl) {
        Interceptor.attach(longValImpl, {
            onEnter: function (args) {
                this.key = null;
                try { this.key = new ObjC.Object(args[2]).toString(); } catch (e) {}
            },
            onLeave: function (retval) {
                if (!this.key) return;
                if (this.key in OFFSETS && OFFSETS[this.key]) {
                    retval.replace(ptr(OFFSETS[this.key]));
                }
            }
        });
        console.log('[+] longVal: read-side override mounted');
    }

    // ==================================================================
    // 7. accessToken / tokenExpireUnix -> non-empty and future expiry
    // ==================================================================
    var accessTokenImpl = getImpl('NwSession', '- accessToken');
    if (accessTokenImpl) {
        Interceptor.attach(accessTokenImpl, {
            onLeave: function (retval) {
                if (retval.isNull()) {
                    retval.replace(ObjC.classes.NSString.stringWithString_('fake_token_bypass_yuve'));
                }
            }
        });
    }

    var tokenExpireUnixImpl = getImpl('NwSession', '- tokenExpireUnix');
    if (tokenExpireUnixImpl) {
        Interceptor.attach(tokenExpireUnixImpl, {
            onLeave: function (retval) {
                if (retval.toInt32() == 0 || retval.toInt32() < 1700000000) {
                    retval.replace(ptr(FAKE_EXP));
                }
            }
        });
    }

    // ==================================================================
    // 8. setBusy:message: - swallow error messages on the entry panel
    // ==================================================================
    var setBusy = getImpl('NwEntryPanel', '- setBusy:message:');
    if (setBusy) {
        Interceptor.attach(setBusy, {
            onEnter: function (args) {
                var busy = args[2].toInt32();
                try {
                    var msg = new ObjC.Object(args[3]);
                    var msgStr = msg.toString();
                    if (busy == 0 && msgStr.length > 0 &&
                        (msgStr.indexOf('fail') !== -1 ||
                         msgStr.indexOf('invalid') !== -1 ||
                         msgStr.indexOf('expired') !== -1 ||
                         msgStr.indexOf('error') !== -1)) {
                        args[3] = ObjC.classes.NSString.stringWithString_('').handle;
                    }
                } catch (e) {}
            }
        });
    }

    console.log('[+] Yuve/DFM V1 bypass loaded');
    console.log('[+] core: dyld anti-injection neutralised (matcher+lock)');
    console.log('[+] game: ' + GAME_KEY + '  |  offsets keys: ' + JSON.stringify(OFFSETS));

} else {
    console.log('[!] ObjC runtime not available');
}