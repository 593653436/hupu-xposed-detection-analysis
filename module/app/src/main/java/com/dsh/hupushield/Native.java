package com.dsh.hupushield;

/**
 * Bridge to libhupushield.so.
 *
 * The native layer GOT-patches exit()/_exit()/abort()/kill() inside the Hupu process so we
 * can see (and later block) the native self-termination that Java cannot reach.
 */
public final class Native {

    private static volatile boolean sLoaded;
    private static volatile boolean sInstalled;
    private static volatile String sFailReason;

    private Native() {
    }

    public static String failReason() {
        return sFailReason;
    }

    public static boolean isLoaded() {
        return sLoaded;
    }

    /** Loads the native library. Safe to call repeatedly. */
    public static synchronized void load() {
        if (sLoaded) {
            return;
        }
        // Calling loadLibrary is fine; HOOKING it is not (it is @CallerSensitive).
        try {
            System.loadLibrary("hupushield");
            sLoaded = true;
            XLog.i("native lib loaded via loadLibrary");
            return;
        } catch (Throwable t) {
            sFailReason = "loadLibrary: " + t;
        }
        if (loadByExtractingFromApk()) {
            return;
        }
        XLog.e("native lib NOT loaded: " + sFailReason, null);
    }

    /**
     * Last resort: unpack libhupushield.so out of this module's own APK into the target app's
     * cache dir (we run under its uid) and dlopen it by absolute path. This sidesteps
     * LspModuleClassLoader entirely when its in-APK lookup fails.
     */
    private static boolean loadByExtractingFromApk() {
        java.io.InputStream in = null;
        java.io.FileOutputStream out = null;
        java.util.zip.ZipFile zf = null;
        try {
            java.security.CodeSource cs = Native.class.getProtectionDomain().getCodeSource();
            if (cs == null || cs.getLocation() == null) {
                sFailReason += "; no code source";
                return false;
            }
            java.io.File apk = new java.io.File(cs.getLocation().toURI());
            if (!apk.exists()) {
                sFailReason += "; apk missing: " + apk;
                return false;
            }
            zf = new java.util.zip.ZipFile(apk);
            java.util.zip.ZipEntry ze = zf.getEntry("lib/arm64-v8a/libhupushield.so");
            if (ze == null) {
                sFailReason += "; no lib entry in " + apk;
                return false;
            }
            java.io.File dst = new java.io.File(
                    "/data/user/0/" + Cfg.TARGET_PACKAGE + "/cache/libhupushield.so");
            java.io.File parent = dst.getParentFile();
            if (parent != null && !parent.exists()) {
                //noinspection ResultOfMethodCallIgnored
                parent.mkdirs();
            }
            in = zf.getInputStream(ze);
            out = new java.io.FileOutputStream(dst);
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            out.close();
            out = null;
            in.close();
            in = null;
            System.load(dst.getAbsolutePath());
            sLoaded = true;
            XLog.i("native lib loaded by extraction -> " + dst.getAbsolutePath());
            return true;
        } catch (Throwable t) {
            sFailReason += "; extract fallback: " + t;
            return false;
        } finally {
            closeQuietly(in);
            closeQuietly(out);
            if (zf != null) {
                try {
                    zf.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /** Bitmask shared with libhupushield's nativeInit. */
    public static final int FLAG_BLOCK_NATIVE = 1;
    public static final int FLAG_TRACE_OPENAT = 2;
    public static final int FLAG_FAKE_MAPS = 4;
    public static final int FLAG_INLINE_HOOKS = 8;

    public static synchronized void init(String logPath, int flags) {
        if (!sLoaded) {
            return;
        }
        try {
            nativeInit(logPath, flags);
        } catch (Throwable t) {
            XLog.e("nativeInit", t);
        }
    }

    public static synchronized void install() {
        if (!sLoaded || sInstalled) {
            return;
        }
        sInstalled = true;
        try {
            nativeInstall();
        } catch (Throwable t) {
            XLog.e("nativeInstall", t);
        }
    }

    /** Re-patch GOTs right after a library was dlopen'd, before the shell uses it. */
    public static void refresh() {
        if (!sLoaded) {
            return;
        }
        try {
            nativeRefresh();
        } catch (Throwable ignored) {
        }
    }

    private static native void nativeInit(String logPath, int flags);

    private static native void nativeInstall();

    private static native void nativeRefresh();
}
