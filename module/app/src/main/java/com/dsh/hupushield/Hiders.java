package com.dsh.hupushield;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

/**
 * Detection-primitive hider — the "root cause" layer.
 *
 * Everything here was derived from scanning the target APK for the strings its
 * (NetEase Yidun hardened) shell uses. All of them live in classes.dex; the 69
 * native libraries contain none of them, which is why a Java-level module can work.
 */
public final class Hiders {

    /** su / root-manager paths found verbatim in the target's string table. */
    private static final String[] SU_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/su/bin/",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/system/bin/.ext/su",
            "/system/usr/we-need-root/su", "/data/local/su", "/data/local/xbin/su",
            "/data/local/bin/su", "/system/app/Superuser.apk",
            "/dev/com.koushikdutta.superuser.daemon/",
            // KernelSU / Magisk specific
            "/system/bin/ksud", "/data/adb/ksu/bin/su", "/data/adb/magisk",
            "/sbin/.magisk", "/system/bin/magisk", "/data/adb/modules",
    };

    /** Root-manager / Xposed-manager packages. */
    private static final String[] HIDDEN_PACKAGES = {
            "com.topjohnwu.magisk", "me.weishu.kernelsu", "org.lsposed.manager",
            "de.robv.android.xposed.installer", "com.solohsu.android.edxp.manager",
            "org.meowcat.edxposed.manager", "com.elderdrivers.riru.edxp.manager",
            "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.thirdparty.superuser",
            "com.noshufou.android.su", "com.kingroot.kinguser", "com.kingo.root",
            "com.saurik.substrate",
            // Xposed modules actually present on the target device
            "com.fkzhang.wechatxposed", "com.fkzhang.qqxposed", "com.jy.xposed.skip",
            "com.houvven.guise", "me.hd.wauxv", "io.github.wauxv.v1",
            "com.keshav.capturesposed", "com.bug.hookvip", "com.wye4.hookforvip",
            "com.coderstory.toolkit", "com.luckyzyx.luckytool",
    };

    /** Class names that must appear not to exist. */
    private static final String[] XPOSED_PREFIXES = {
            "de.robv.android.xposed.",
            "com.elderdrivers.riru.edxp.",
            "org.lsposed.",
            "io.github.lsposed.",
    };

    private static final String[] STACK_BAD = {
            "de.robv.android.xposed", "LSPHooker_", "org.lsposed", "XposedBridge",
            "com.elderdrivers.riru", "lspd", "com.dsh.hupushield",
    };

    private static final String[] EXEC_BAD = {
            "su", "magisk", "ksu", "supersu", "which", "busybox", "mount",
            "/proc/self/maps", "pm list packages", "cmd package",
    };

    private Hiders() {
    }

    public static void install(ClassLoader cl) {
        hookFileExists();
        hookClassLookup();
        hookPackageManager(cl);
        hookStackTraces();
        hookExec();
        hookSystemProperties(cl);
        hookBuildFields();
    }

    // --------------------------------------------------------------- helpers

    private static boolean startsWithAny(String s, String[] prefixes) {
        if (s == null) {
            return false;
        }
        for (String p : prefixes) {
            if (s.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isHiddenPackage(String pkg) {
        if (pkg == null) {
            return false;
        }
        for (String p : HIDDEN_PACKAGES) {
            if (p.equals(pkg)) {
                return true;
            }
        }
        return false;
    }

    /** Any package whose manifest carries the Xposed module meta-data. */
    private static boolean isXposedModule(PackageInfo pi) {
        try {
            ApplicationInfo ai = pi.applicationInfo;
            Bundle b = ai == null ? null : ai.metaData;
            return b != null && b.getBoolean("xposedmodule", false);
        } catch (Throwable t) {
            return false;
        }
    }

    // ------------------------------------------------------------ file paths

    private static void hookFileExists() {
        try {
            XC_MethodHook h = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (!Cfg.hideFramework) {
                        return;
                    }
                    try {
                        String path = ((File) param.thisObject).getAbsolutePath();
                        for (String su : SU_PATHS) {
                            if (su.equals(path)) {
                                Probe.hit("File.exists", path);
                                param.setResult(Boolean.FALSE);
                                return;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            };
            XposedHelpers.findAndHookMethod(File.class, "exists", h);
            XLog.i("hook installed: File.exists");
        } catch (Throwable t) {
            XLog.e("hookFileExists", t);
        }
    }

    // --------------------------------------------------------- class lookup

    private static void hookClassLookup() {
        try {
            // NOTE: do NOT hook the one-argument Class.forName(String) — it is
            // @CallerSensitive and resolves the classloader via Reflection.getCallerClass().
            // Behind a hook that caller becomes the Xposed bridge, which breaks framework
            // and app code that relies on it. The one-argument form delegates to this
            // three-argument overload, so hooking here covers both.
            XposedHelpers.findAndHookMethod(Class.class, "forName", String.class, boolean.class,
                    ClassLoader.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            if (!Cfg.hideFramework) {
                                return;
                            }
                            String name = (String) param.args[0];
                            if (startsWithAny(name, XPOSED_PREFIXES)) {
                                Probe.hit("Class.forName", name);
                                throw new ClassNotFoundException(name);
                            }
                        }
                    });

            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            if (!Cfg.hideFramework) {
                                return;
                            }
                            String name = (String) param.args[0];
                            if (startsWithAny(name, XPOSED_PREFIXES)) {
                                Probe.hit("ClassLoader.loadClass", name);
                                throw new ClassNotFoundException(name);
                            }
                        }
                    });
            XLog.i("hook installed: Class.forName / ClassLoader.loadClass");
        } catch (Throwable t) {
            XLog.e("hookClassLookup", t);
        }
    }

    // ------------------------------------------------------- package manager

    @SuppressWarnings("unchecked")
    private static void hookPackageManager(ClassLoader cl) {
        final String CLS = "android.app.ApplicationPackageManager";
        try {
            XposedHelpers.findAndHookMethod(CLS, cl, "getPackageInfo", String.class, int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            if (!Cfg.hideFramework) {
                                return;
                            }
                            String pkg = (String) param.args[0];
                            if (isHiddenPackage(pkg)) {
                                Probe.hit("PackageManager.getPackageInfo", pkg);
                                throw new PackageManager.NameNotFoundException(pkg);
                            }
                        }
                    });

            XposedHelpers.findAndHookMethod(CLS, cl, "getInstalledPackages", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            filterPackages(param, "getInstalledPackages");
                        }
                    });

            XposedHelpers.findAndHookMethod(CLS, cl, "getInstalledApplications", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (!Cfg.hideFramework) {
                                return;
                            }
                            Object r = param.getResult();
                            if (!(r instanceof List)) {
                                return;
                            }
                            List<Object> in = (List<Object>) r;
                            List<Object> out = new ArrayList<>(in.size());
                            int dropped = 0;
                            for (Object o : in) {
                                String pn = null;
                                try {
                                    pn = ((ApplicationInfo) o).packageName;
                                } catch (Throwable ignored) {
                                }
                                if (isHiddenPackage(pn)) {
                                    dropped++;
                                    continue;
                                }
                                out.add(o);
                            }
                            if (dropped > 0) {
                                Probe.hit("PackageManager.getInstalledApplications",
                                        "dropped " + dropped);
                                param.setResult(out);
                            }
                        }
                    });
            XLog.i("hook installed: ApplicationPackageManager");
        } catch (Throwable t) {
            XLog.e("hookPackageManager", t);
        }
    }

    @SuppressWarnings("unchecked")
    private static void filterPackages(XC_MethodHook.MethodHookParam param, String where) {
        if (!Cfg.hideFramework) {
            return;
        }
        try {
            Object r = param.getResult();
            if (!(r instanceof List)) {
                return;
            }
            List<Object> in = (List<Object>) r;
            List<Object> out = new ArrayList<>(in.size());
            int dropped = 0;
            for (Object o : in) {
                PackageInfo pi = (PackageInfo) o;
                if (isHiddenPackage(pi.packageName) || isXposedModule(pi)) {
                    dropped++;
                    continue;
                }
                out.add(o);
            }
            if (dropped > 0) {
                Probe.hit("PackageManager." + where, "dropped " + dropped);
                param.setResult(out);
            }
        } catch (Throwable t) {
            XLog.e("filterPackages " + where, t);
        }
    }

    // --------------------------------------------------------- stack traces

    private static void hookStackTraces() {
        try {
            XposedHelpers.findAndHookMethod(Throwable.class, "getStackTrace",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (!Cfg.hideFramework) {
                                return;
                            }
                            param.setResult(filter((StackTraceElement[]) param.getResult()));
                        }
                    });
            XLog.i("hook installed: Throwable.getStackTrace");
        } catch (Throwable t) {
            XLog.e("hookStackTraces", t);
        }
    }

    private static StackTraceElement[] filter(StackTraceElement[] in) {
        if (in == null || in.length == 0) {
            return in;
        }
        List<StackTraceElement> out = new ArrayList<>(in.length);
        for (StackTraceElement e : in) {
            String cn = e.getClassName();
            boolean bad = false;
            for (String b : STACK_BAD) {
                if (cn.startsWith(b) || cn.contains(b)) {
                    bad = true;
                    break;
                }
            }
            if (!bad) {
                out.add(e);
            }
        }
        return out.size() == in.length ? in : out.toArray(new StackTraceElement[0]);
    }

    // ------------------------------------------------------------------ exec

    private static boolean badCommand(Object cmd) {
        if (cmd == null) {
            return false;
        }
        String s = cmd instanceof String[] ? String.join(" ", (String[]) cmd) : String.valueOf(cmd);
        for (String b : EXEC_BAD) {
            if (s.contains(b)) {
                return true;
            }
        }
        return false;
    }

    private static void hookExec() {
        try {
            XposedHelpers.findAndHookMethod(Runtime.class, "exec", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            if (Cfg.hideFramework && badCommand(param.args[0])) {
                                Probe.hit("Runtime.exec", String.valueOf(param.args[0]));
                                throw new java.io.IOException("exec blocked");
                            }
                        }
                    });
            XposedHelpers.findAndHookMethod(Runtime.class, "exec", String[].class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            if (Cfg.hideFramework && badCommand(param.args[0])) {
                                Probe.hit("Runtime.exec[]", String.valueOf((Object) param.args[0]));
                                throw new java.io.IOException("exec blocked");
                            }
                        }
                    });
            XposedHelpers.findAndHookMethod(ProcessBuilder.class, "start", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    List<String> c = ((ProcessBuilder) param.thisObject).command();
                    if (Cfg.hideFramework && badCommand(c == null ? null : c.toArray(new String[0]))) {
                        Probe.hit("ProcessBuilder.start", String.valueOf(c));
                        throw new java.io.IOException("exec blocked");
                    }
                }
            });
            XLog.i("hook installed: Runtime.exec / ProcessBuilder.start");
        } catch (Throwable t) {
            XLog.e("hookExec", t);
        }
    }

    // ------------------------------------------------------ system properties

    private static final Map<String, String> FAKE_PROPS = new java.util.HashMap<>();

    static {
        FAKE_PROPS.put("ro.debuggable", "0");
        FAKE_PROPS.put("ro.secure", "1");
        FAKE_PROPS.put("ro.build.type", "user");
        FAKE_PROPS.put("ro.build.tags", "release-keys");
        FAKE_PROPS.put("ro.boot.verifiedbootstate", "green");
        FAKE_PROPS.put("ro.boot.flash.locked", "1");
        FAKE_PROPS.put("service.adb.root", "0");
    }

    private static void hookSystemProperties(ClassLoader cl) {
        try {
            Class<?> sp = XposedHelpers.findClass("android.os.SystemProperties", cl);
            XposedHelpers.findAndHookMethod(sp, "get", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (!Cfg.hideFramework) {
                        return;
                    }
                    String v = FAKE_PROPS.get((String) param.args[0]);
                    if (v != null) {
                        Probe.hit("SystemProperties.get", String.valueOf(param.args[0]));
                        param.setResult(v);
                    }
                }
            });
            XposedHelpers.findAndHookMethod(sp, "get", String.class, String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            if (!Cfg.hideFramework) {
                                return;
                            }
                            String v = FAKE_PROPS.get((String) param.args[0]);
                            if (v != null) {
                                param.setResult(v);
                            }
                        }
                    });
            XLog.i("hook installed: SystemProperties");
        } catch (Throwable t) {
            XLog.w("hookSystemProperties skipped: " + t);
        }
    }

    private static void hookBuildFields() {
        try {
            XposedHelpers.setStaticObjectField(Build.class, "TAGS", "release-keys");
            XposedHelpers.setStaticObjectField(Build.class, "TYPE", "user");
            XLog.i("Build.TAGS/TYPE normalised");
        } catch (Throwable t) {
            XLog.w("hookBuildFields skipped: " + t);
        }
    }

}
