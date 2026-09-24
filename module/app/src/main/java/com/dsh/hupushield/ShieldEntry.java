package com.dsh.hupushield;

import android.app.Application;
import android.content.Context;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * HupuShield entry point.
 *
 * Background: 虎扑 8.2.62 is hardened with NetEase Yidun (com.netease.nis.wrapper).
 * On this device (KernelSU + Zygisk Next + Shamiko + LSPosed) the shell detects the
 * Xposed framework, shows a "检测到Xposed环境" toast and then kills the process about
 * one second later, making the app completely unusable.
 *
 * The module is scoped to com.hupu.games via the xposedscope meta-data, so nothing
 * here ever runs inside another app.
 */
public class ShieldEntry implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null || !Cfg.TARGET_PACKAGE.equals(lpparam.packageName)) {
            return;
        }
        try {
            XLog.i("=== HupuShield attached === pkg=" + lpparam.packageName
                    + " process=" + lpparam.processName
                    + " versionName=" + BuildInfo.VERSION_NAME);
        } catch (Throwable ignored) {
        }

        ClassLoader cl = lpparam.classLoader;

        // Must run first: gives us the file log channel before anything else can fail.
        safe("Ctx.init", Ctx::init);
        safe("Native", () -> {
            Native.load();
            Native.init(Ctx.EXT_DIR + "/hupushield.log", Cfg.nativeFlags());
            Native.install();
        });
        safe("Forensics", () -> Forensics.install(cl));
        safe("Hiders", () -> Hiders.install(cl));
        safe("Guards", () -> Guards.install(cl));
        safe("fast heartbeat", Forensics::startFastHeartbeat);

        XLog.i("=== HupuShield install complete ===");
    }

    /**
     * Writes a once-per-second liveness line to the module's own log file. The shell kills
     * this process a couple of seconds after launch, and logcat drops our lines under the
     * process log quota, so the file is the only reliable record of how far it got.
     */
    private static void startHeartbeat() {
        Thread t = new Thread(() -> {
            long t0 = System.currentTimeMillis();
            for (int i = 1; i <= 60; i++) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    return;
                }
                XLog.i("[HEARTBEAT] alive " + i + "s  pid=" + android.os.Process.myPid()
                        + "  elapsed=" + (System.currentTimeMillis() - t0) + "ms");
            }
        }, "HupuShield-heartbeat");
        t.setDaemon(true);
        t.start();
    }

    private static void hookAppOnCreate() {
        XposedHelpers.findAndHookMethod(Application.class, "onCreate", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                XLog.i("[PROBE] Application.onCreate -> " + param.thisObject.getClass().getName());
            }
        });
    }

    private interface Task {
        void run();
    }

    private static void safe(String what, Task t) {
        try {
            t.run();
        } catch (Throwable e) {
            XLog.e("install failed: " + what, e);
        }
    }
}
