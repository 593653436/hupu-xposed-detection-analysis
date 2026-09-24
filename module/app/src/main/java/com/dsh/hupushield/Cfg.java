package com.dsh.hupushield;

/**
 * Central place for the module's runtime switches. Values can be overridden at
 * runtime by dropping a file at
 * /sdcard/Android/data/com.hupu.games/files/hupushield.conf containing lines
 * like "blockKill=0". This lets us iterate on the device without rebuilding.
 */
public final class Cfg {

    /** LSPosed scope target — the only app this module ever touches. */
    public static final String TARGET_PACKAGE = "com.hupu.games";

    /** Log the stack trace of every interesting call (discovery mode). */
    public static volatile boolean probe = true;

    /** Drop the "检测到Xposed环境" toast. */
    public static volatile boolean blockToast = true;

    /** Refuse the shell's self-kill (Process.killProcess / System.exit / Runtime.halt). */
    public static volatile boolean blockKill = true;

    /** Hide Xposed / root artifacts from Java-level detection. */
    public static volatile boolean hideFramework = true;

    /** Native layer: block exit()/_exit()/abort()/kill() instead of only logging them. */
    public static volatile boolean blockNative = false;

    /** Native layer: seccomp user-notification tracer that reports every openat path. */
    public static volatile boolean traceOpenat = false;

    /** Native layer: serve a filtered /proc/self/maps to the probe (implies traceOpenat). */
    public static volatile boolean fakeMaps = false;

    /** Native layer: ShadowHook inline hooks for dl_iterate_phdr and sigaction. */
    public static volatile boolean inlineHooks = false;

    /** Packed native flags. */
    public static int nativeFlags() {
        int f = 0;
        if (blockNative) {
            f |= 1; // FLAG_BLOCK_NATIVE
        }
        if (traceOpenat) {
            f |= 2; // FLAG_TRACE_OPENAT
        }
        if (fakeMaps) {
            f |= 4; // FLAG_FAKE_MAPS
        }
        if (inlineHooks) {
            f |= 8; // FLAG_INLINE_HOOKS
        }
        return f;
    }

    private Cfg() {
    }
}
