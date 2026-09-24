package com.dsh.hupushield;

/**
 * Stack-trace probe. Logs what the shell is looking at, so the exact detector
 * can be pinned down without decompiling the (NetEase Yidun hardened) dex.
 */
public final class Probe {

    private static final ThreadLocal<Boolean> IN_PROBE = new ThreadLocal<>();
    private static final int MAX_FRAMES = 16;

    private Probe() {
    }

    public static void hit(String where, String detail) {
        if (!Cfg.probe) {
            return;
        }
        if (Boolean.TRUE.equals(IN_PROBE.get())) {
            return;
        }
        IN_PROBE.set(Boolean.TRUE);
        try {
            XLog.i("[PROBE] " + where + " :: " + detail);
            XLog.i("[PROBE] stack:" + frames(new Throwable()));
        } catch (Throwable ignored) {
        } finally {
            IN_PROBE.set(Boolean.FALSE);
        }
    }

    /** Compact stack trace with our own frames and the Xposed bridge removed. */
    public static String frames(Throwable t) {
        StringBuilder sb = new StringBuilder();
        try {
            StackTraceElement[] st = t.getStackTrace();
            int n = 0;
            for (StackTraceElement e : st) {
                String cn = e.getClassName();
                if (cn.startsWith("com.dsh.hupushield")) {
                    continue;
                }
                if (cn.startsWith("de.robv.android.xposed")) {
                    continue;
                }
                sb.append("\n        at ").append(e);
                if (++n >= MAX_FRAMES) {
                    sb.append("\n        ...");
                    break;
                }
            }
            if (n == 0) {
                sb.append(" (no app frames)");
            }
        } catch (Throwable ignored) {
        }
        return sb.toString();
    }
}
