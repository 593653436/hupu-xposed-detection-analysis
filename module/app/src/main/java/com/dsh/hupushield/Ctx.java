package com.dsh.hupushield;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

/**
 * Context-free bootstrap.
 *
 * We deliberately do NOT hook Application.attachBaseContext: that method is declared on
 * ContextWrapper, not on Application, so XposedHelpers.findMethodExact (which uses
 * getDeclaredMethod and does not walk superclasses) throws NoSuchMethodError on Android 14.
 *
 * It is also unnecessary — an app always has full access to its own external files dir, so
 * the well-known path can be used directly. That keeps this module free of any Context hook
 * and gives us a log channel that logcat's per-process quota cannot drop.
 */
public final class Ctx {

    /** /sdcard/Android/data/com.hupu.games/files */
    public static final String EXT_DIR = "/sdcard/Android/data/" + Cfg.TARGET_PACKAGE + "/files";

    private Ctx() {
    }

    public static void init() {
        File dir = new File(EXT_DIR);
        try {
            if (!dir.exists()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
            }
        } catch (Throwable ignored) {
        }
        XLog.setDir(dir);
        XLog.i("external dir = " + dir + " (writable=" + dir.canWrite() + ")");
        loadConfig(dir);
    }

    /** Reads hupushield.conf next to the log file, e.g. "blockKill=0". */
    private static void loadConfig(File dir) {
        File conf = new File(dir, "hupushield.conf");
        if (!conf.exists()) {
            XLog.i("no config file, using defaults: probe=" + Cfg.probe
                    + " blockToast=" + Cfg.blockToast
                    + " blockKill=" + Cfg.blockKill
                    + " hideFramework=" + Cfg.hideFramework);
            return;
        }
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(conf));
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#") || !line.contains("=")) {
                    continue;
                }
                String k = line.substring(0, line.indexOf('=')).trim();
                String v = line.substring(line.indexOf('=') + 1).trim();
                boolean on = !("0".equals(v) || "false".equalsIgnoreCase(v) || "off".equalsIgnoreCase(v));
                switch (k) {
                    case "probe":
                        Cfg.probe = on;
                        break;
                    case "blockToast":
                        Cfg.blockToast = on;
                        break;
                    case "blockKill":
                        Cfg.blockKill = on;
                        break;
                    case "hideFramework":
                        Cfg.hideFramework = on;
                        break;
                    case "blockNative":
                        Cfg.blockNative = on;
                        break;
                    case "traceOpenat":
                        Cfg.traceOpenat = on;
                        break;
                    case "fakeMaps":
                        Cfg.fakeMaps = on;
                        break;
                    case "inlineHooks":
                        Cfg.inlineHooks = on;
                        break;
                    default:
                        XLog.w("unknown config key: " + k);
                        break;
                }
            }
            XLog.i("config loaded: probe=" + Cfg.probe + " blockToast=" + Cfg.blockToast
                    + " blockKill=" + Cfg.blockKill + " hideFramework=" + Cfg.hideFramework);
        } catch (Throwable t) {
            XLog.e("loadConfig", t);
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }
}
