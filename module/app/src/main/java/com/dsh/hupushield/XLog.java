package com.dsh.hupushield;

import java.io.File;
import java.io.FileWriter;

/**
 * Dual-channel logger: logcat (readable over adb without root) plus an optional
 * append-only file inside the target app's external files dir
 * (/sdcard/Android/data/com.hupu.games/files/hupushield.log).
 */
public final class XLog {

    public static final String TAG = "HupuShield";

    private static volatile File sFile;
    private static final Object LOCK = new Object();

    private XLog() {
    }

    public static void setDir(File dir) {
        if (dir == null) {
            return;
        }
        try {
            if (!dir.exists()) {
                dir.mkdirs();
            }
            sFile = new File(dir, "hupushield.log");
        } catch (Throwable ignored) {
        }
    }

    public static File logFile() {
        return sFile;
    }

    public static void i(String msg) {
        write(3, msg);
    }

    public static void w(String msg) {
        write(5, msg);
    }

    public static void e(String msg, Throwable t) {
        write(6, msg + " : " + (t == null ? "null" : android.util.Log.getStackTraceString(t)));
    }

    private static void write(int priority, String msg) {
        try {
            android.util.Log.println(priority, TAG, msg == null ? "null" : msg);
        } catch (Throwable ignored) {
        }
        File f = sFile;
        if (f == null) {
            return;
        }
        synchronized (LOCK) {
            FileWriter fw = null;
            try {
                fw = new FileWriter(f, true);
                fw.write(msg == null ? "null" : msg);
                fw.write('\n');
            } catch (Throwable ignored) {
            } finally {
                if (fw != null) {
                    try {
                        fw.close();
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
    }
}
