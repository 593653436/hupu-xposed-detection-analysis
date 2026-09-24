package com.dsh.hupushield;

import android.app.Application;
import android.content.ContentProvider;
import android.content.Context;
import android.content.ContextWrapper;

import java.io.File;
import java.io.FileInputStream;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

/**
 * Forensic timeline probe.
 *
 * The shell kills this process roughly 300 ms after {@code handleBindApplication}, before
 * {@code Application.onCreate} — and it does so cleanly (no tombstone), which points at a
 * native {@code exit()}. Java hooks cannot stop that, so the first job is to find out exactly
 * how far the process gets and what it touches on the way.
 *
 * Every line carries a "[T+<ms>]" stamp measured from module attach, so the file log's last
 * line tells us the exact lifetime of the process.
 */
public final class Forensics {

    private static volatile long sT0 = -1L;

    private Forensics() {
    }

    public static long t0() {
        if (sT0 < 0) {
            sT0 = android.os.SystemClock.elapsedRealtime();
        }
        return sT0;
    }

    public static void mark(String what) {
        XLog.i("[T+" + (android.os.SystemClock.elapsedRealtime() - t0()) + "ms] " + what);
    }

    public static void install(ClassLoader cl) {
        mark("Forensics.install begin pid=" + android.os.Process.myPid());

        // --- earliest Java milestones -------------------------------------------------
        hook("Application.<init>", () -> XposedHelpers.findAndHookMethod(
                Application.class, "<init>", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        mark("NEW Application -> " + param.thisObject.getClass().getName());
                    }
                }));

        hook("ContextWrapper.attachBaseContext", () -> XposedHelpers.findAndHookMethod(
                ContextWrapper.class, "attachBaseContext", Context.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        if (param.thisObject instanceof Application) {
                            mark("attachBaseContext on " + param.thisObject.getClass().getName());
                        }
                    }
                }));

        hook("ContentProvider.attachInfo", () -> XposedHelpers.findAndHookMethod(
                ContentProvider.class, "attachInfo", Context.class,
                android.content.pm.ProviderInfo.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        mark("Provider.attachInfo -> " + param.thisObject.getClass().getName());
                    }
                }));

        hook("ContentProvider.onCreate", () -> XposedHelpers.findAndHookMethod(
                ContentProvider.class, "onCreate", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        mark("Provider.onCreate -> " + param.thisObject.getClass().getName());
                    }
                }));

        hook("Application.onCreate", () -> XposedHelpers.findAndHookMethod(
                Application.class, "onCreate", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        mark("Application.onCreate -> " + param.thisObject.getClass().getName());
                    }
                }));

        // --- native library loading (when does libnesec/libnshelper appear?) ----------
        //
        // NEVER hook System.loadLibrary / System.load: they are @CallerSensitive and use
        // Reflection.getCallerClass() to pick the caller's classloader for library lookup.
        // Behind an Xposed hook that caller becomes the hook bridge, so the library is
        // resolved in the wrong namespace and the app dies with
        // "UnsatisfiedLinkError: dlopen failed: library ... not found".
        //
        // Runtime.loadLibrary0 takes the owning Class explicitly, so it is safe to hook.
        hook("Runtime.loadLibrary0(Class,String)", () -> XposedHelpers.findAndHookMethod(
                Runtime.class, "loadLibrary0", Class.class, String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        mark("loadLibrary0(" + param.args[1] + ") from "
                                + (param.args[0] == null ? "null" : ((Class<?>) param.args[0]).getName()));
                    }

                    /**
                     * The critical moment: the instant the library is mapped we re-patch every
                     * GOT, so the shell's very next native call into libnesec goes through us.
                     */
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        boolean failed = param.hasThrowable();
                        mark("loadLibrary0 done(" + param.args[1] + ") failed=" + failed);
                        Native.refresh();
                        mark("native GOT refresh done after " + param.args[1]);
                    }
                }));

        hook("Runtime.loadLibrary0(ClassLoader,String)", () -> XposedHelpers.findAndHookMethod(
                Runtime.class, "loadLibrary0", ClassLoader.class, String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        mark("loadLibrary0(" + param.args[1] + ") loader=" + param.args[0]);
                    }
                }));

        // --- class loading: what does the shell look for? -----------------------------
        //
        // The one-argument Class.forName is @CallerSensitive for the same reason as
        // loadLibrary, so hook the three-argument overload instead — the one-argument
        // form delegates straight into it.
        hook("Class.forName(String,boolean,ClassLoader)", () -> XposedHelpers.findAndHookMethod(
                Class.class, "forName", String.class, boolean.class, ClassLoader.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String n = (String) param.args[0];
                        if (interesting(n)) {
                            mark("Class.forName(" + n + ")");
                        }
                    }
                }));

        hook("ClassLoader.loadClass", () -> XposedHelpers.findAndHookMethod(
                ClassLoader.class, "loadClass", String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String n = (String) param.args[0];
                        if (interesting(n)) {
                            mark("loadClass(" + n + ")");
                        }
                    }
                }));

        // --- filesystem recon ---------------------------------------------------------
        hook("File.exists", () -> XposedHelpers.findAndHookMethod(
                File.class, "exists", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String p = ((File) param.thisObject).getAbsolutePath();
                        if (interestingPath(p)) {
                            mark("exists(" + p + ")");
                        }
                    }
                }));

        hook("FileInputStream(String)", () -> XposedHelpers.findAndHookMethod(
                FileInputStream.class, "<init>", String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        mark("FileInputStream(" + param.args[0] + ")");
                    }
                }));

        // --- package / process recon --------------------------------------------------
        hook("PackageManager.getPackageInfo", () -> XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager", cl,
                "getPackageInfo", String.class, int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        mark("getPackageInfo(" + param.args[0] + ")");
                    }
                }));

        hook("Runtime.exec(String)", () -> XposedHelpers.findAndHookMethod(
                Runtime.class, "exec", String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        mark("Runtime.exec(" + param.args[0] + ")");
                    }
                }));

        // --- the exit path (log only here; Guards owns blocking) ----------------------
        hook("Process.killProcess", () -> XposedHelpers.findAndHookMethod(
                android.os.Process.class, "killProcess", int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        mark("!! Process.killProcess(" + param.args[0] + ") from:"
                                + Probe.frames(new Throwable()));
                    }
                }));

        hook("System.exit", () -> XposedHelpers.findAndHookMethod(
                System.class, "exit", int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        mark("!! System.exit(" + param.args[0] + ") from:"
                                + Probe.frames(new Throwable()));
                    }
                }));

        mark("Forensics.install done");
    }

    /** Class names worth recording — anything a hardened shell would probe for. */
    private static boolean interesting(String n) {
        if (n == null || n.isEmpty()) {
            return false;
        }
        return n.contains("xposed") || n.contains("Xposed")
                || n.contains("lspd") || n.contains("LSPosed") || n.contains("lsposed")
                || n.contains("lsplant") || n.contains("riru") || n.contains("zygisk")
                || n.contains("magisk") || n.contains("shamiko") || n.contains("substrate")
                || n.contains("Superuser") || n.contains("supersu") || n.contains("superuser")
                || n.contains("nesec") || n.contains("nis.wrapper") || n.contains("yidun")
                || n.contains("root") || n.contains("Root")
                || n.contains("hook") || n.contains("Hook")
                || n.contains("frida") || n.contains("Frida")
                || n.contains("detect") || n.contains("Detect")
                || n.contains("risk") || n.contains("Risk")
                || n.contains("security") || n.contains("Security")
                || n.contains("sec") || n.contains("Sec");
    }

    private static boolean interestingPath(String p) {
        if (p == null || p.isEmpty()) {
            return false;
        }
        return p.startsWith("/data/adb") || p.contains("/su") || p.contains("magisk")
                || p.contains("Superuser") || p.contains("superuser") || p.contains("busybox")
                || p.contains("/proc/self/maps") || p.contains("/proc/self/mount")
                || p.contains("xposed") || p.contains("Xposed") || p.contains("lspd")
                || p.contains("lsposed") || p.contains("riru") || p.contains("zygisk")
                || p.contains("shamiko") || p.contains("frida");
    }

    // ------------------------------------------------------------------ plumbing

    private interface Task {
        void run();
    }

    private static void hook(String what, Task t) {
        try {
            t.run();
            mark("probe ok: " + what);
        } catch (Throwable e) {
            mark("probe FAILED: " + what + " -> " + e);
        }
    }

    /**
     * Fast liveness ticker. The default heartbeat fires at +1 s, which this process never
     * reaches, so this one starts immediately and ticks 4x per second.
     */
    public static void startFastHeartbeat() {
        Thread t = new Thread(() -> {
            for (int i = 1; i <= 200; i++) {
                try {
                    Thread.sleep(250);
                } catch (InterruptedException e) {
                    return;
                }
                mark("alive #" + i);
            }
        }, "HupuShield-forensics");
        t.setDaemon(true);
        t.start();
    }
}
