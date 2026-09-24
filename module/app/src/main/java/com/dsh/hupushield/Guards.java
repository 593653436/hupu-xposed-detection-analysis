package com.dsh.hupushield;

import android.os.Process;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import java.lang.reflect.Field;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

/**
 * Behavioural guards — the "keep the app alive" layer.
 *
 * Observed symptom on the target device: about 1.5 s after launch the Yidun shell
 * shows a "检测到Xposed环境" toast and then kills the process (no crash signal, so it
 * is a deliberate exit). This layer (a) swallows the toast and (b) refuses the exit
 * while logging the exact caller, which is also how we discover the detector.
 */
public final class Guards {

    private static final String[] BAD_WORDS = {
            "Xposed", "xposed", "XPOSED", "检测到", "风险", "环境异常", "框架"
    };

    private Guards() {
    }

    public static void install(ClassLoader cl) {
        hookToast();
        hookExit();
    }

    // ---------------------------------------------------------------- toast

    private static boolean isBad(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        for (String w : BAD_WORDS) {
            if (s.contains(w)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Toast text lives in a private field. On modern Android the view may not exist
     * yet for a text toast, so try mText first and fall back to mNextView.
     */
    private static CharSequence toastText(Toast t) {
        try {
            Field f = Toast.class.getDeclaredField("mText");
            f.setAccessible(true);
            Object v = f.get(t);
            if (v instanceof CharSequence) {
                return (CharSequence) v;
            }
        } catch (Throwable ignored) {
        }
        try {
            Field f = Toast.class.getDeclaredField("mNextView");
            f.setAccessible(true);
            Object v = f.get(t);
            if (v instanceof TextView) {
                return ((TextView) v).getText();
            }
            if (v instanceof ViewGroup) {
                ViewGroup g = (ViewGroup) v;
                for (int i = 0; i < g.getChildCount(); i++) {
                    View c = g.getChildAt(i);
                    if (c instanceof TextView) {
                        return ((TextView) c).getText();
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static void hookToast() {
        try {
            XposedHelpers.findAndHookMethod(Toast.class, "show", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        CharSequence cs = toastText((Toast) param.thisObject);
                        String text = cs == null ? "" : cs.toString();
                        if (text.isEmpty()) {
                            return;
                        }
                        XLog.i("[PROBE] Toast.show :: " + text);
                        if (Cfg.blockToast && isBad(text)) {
                            param.setResult(null);
                            XLog.i("[GUARD] suppressed toast :: " + text);
                        }
                    } catch (Throwable t) {
                        XLog.e("toast before", t);
                    }
                }
            });
            XLog.i("hook installed: Toast.show");
        } catch (Throwable t) {
            XLog.e("hookToast", t);
        }
    }

    // ----------------------------------------------------------------- exit

    private interface KillHook {
        void install(String where, Class<?> cls, String method);
    }

    private static void hookExit() {
        KillHook h = (where, cls, method) -> {
            try {
                XposedHelpers.findAndHookMethod(cls, method, int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        int code = (Integer) param.args[0];
                        XLog.i("[PROBE] " + where + "(" + code + ") called from:"
                                + Probe.frames(new Throwable()));
                        if (Cfg.blockKill) {
                            param.setResult(null);
                            XLog.i("[GUARD] blocked " + where + "(" + code + ")");
                        }
                    }
                });
                XLog.i("hook installed: " + where);
            } catch (Throwable t) {
                XLog.e("hook " + where, t);
            }
        };

        h.install("Process.killProcess", Process.class, "killProcess");
        h.install("System.exit", System.class, "exit");
        h.install("Runtime.halt", Runtime.class, "halt");
        h.install("Runtime.exit", Runtime.class, "exit");
    }
}
