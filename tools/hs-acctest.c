/*
 * hs-acctest — measure the detection paths the way the APP sees them.
 *
 * The ptrace trace told us which paths Yidun probes but not what it gets back, and the
 * ptrace slowdown kept the run from reaching the check at all. This sidesteps both: it
 * drops to the target app's uid and performs the same checks, so DAC decides exactly as
 * it would for the app.
 *
 * ENOENT is clean — the file simply is not there.
 * EACCES is the leak: something IS there and the app is not allowed to look, which is
 * itself the signal a detector keys on.
 *
 * Build: aarch64-linux-android26-clang -O2 -fPIE -pie -o hs-acctest hs-acctest.c
 * Use:   hs-acctest [uid]        (default 10452 = com.hupu.games)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

static const char *paths[] = {
    /* Xposed */
    "/data/data/de.robv.android.xposed.installer",
    "/data/data/com.virtualprotect.exposed",
    "/system/framework/XposedBridge.jar",
    "/system/xposed.prop",
    "/system/lib/libxposed_art.so",
    "/system/lib/libxposed_art.so.no_orig",
    "/system/lib64/libxposed_art.so",
    "/system/lib64/libxposed_art.so.no_orig",
    /* Magisk / Riru / LSPosed */
    "/data/adb/lspd",
    "/data/adb/riru/modules/lspd",
    "/data/adb/riru/modules/edxp.prop",
    "/data/adb/riru/modules/dreamland",
    "/data/misc/riru/modules/edxp",
    "/data/misc/riru/modules/dreamland",
    "/data/misc/taichi",
    "/sbin/.magisk/modules/riru-core",
    "/sbin/.magisk/modules/riru_lsposed",
    "/sbin/.magisk/modules/riru_edxposed",
    "/sbin/.magisk/modules/taichi",
    "/system/lib64/libriruloader.so",
    "/system/lib64/libriru_edxp.so",
    "/data/data/com.topjohnwu.magisk",
    /* root / su */
    "/sbin/su",
    "/su/suhide",
    "/system/usr/we-need-root/su-backup",
    "/system/app/Superuser.apk",
    "/system/bin/magiskpolicy",
    /* instrumentation */
    "/data/local/tmp/re.frida.server/",
    "/data/local/tmp/frida-server",
    "/proc/self/maps",
    /* emulator / cloud phone */
    "/sys/devices/virtual/misc/vboxuser",
    "/sys/devices/virtual/redfinger_audio",
    /* the directory itself, for reference */
    "/data/adb",
};

static const char *ename(int e) {
    switch (e) {
        case 0:   return "";
        case 1:   return "EPERM";
        case 2:   return "ENOENT";
        case 13:  return "EACCES";
        case 20:  return "ENOTDIR";
        case 40:  return "ELOOP";
        default:  return "other";
    }
}
static const char *verdict(int r, int e) {
    if (r == 0) return "EXISTS   <== LEAK";
    if (e == 2) return "ENOENT   (clean)";
    if (e == 13) return "EACCES   <== LEAK (exists but hidden)";
    if (e == 1) return "EPERM    <== LEAK";
    return "";
}

static void show_caps(const char *when) {
    FILE *f = fopen("/proc/self/status", "r");
    if (f == NULL) return;
    char line[256];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            printf("### CapEff %-12s %s", when, line + 7);
            break;
        }
    }
    fclose(f);
}

struct cap_hdr { unsigned int version; int pid; };
struct cap_data { unsigned int effective, permitted, inheritable; };

/* The NDK's <sys/syscall.h> does not spell this one out for arm64. */
#ifndef __NR_capset
#define __NR_capset 91
#endif
#ifndef PR_SET_KEEPCAPS
#define PR_SET_KEEPCAPS 8
#endif

int main(int argc, char **argv) {
    uid_t u = (argc > 1) ? (uid_t) atoi(argv[1]) : 10452;
    printf("### running as uid=%d (before: uid=%d)\n", (int) u, (int) getuid());
    if (u != 0) {
        /*
         * Turn KEEPCAPS off FIRST, then drop the uid. KernelSU's su sets PR_SET_KEEPCAPS,
         * so without this the effective capability set survives the uid change and
         * CAP_DAC_OVERRIDE keeps opening 0700-root directories — which silently turned the
         * first run of this tool into an existence check instead of an access check.
         */
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
        if (setresuid(u, u, u) != 0) { perror("setresuid"); return 1; }
        /*
         * Dropping the uid is not enough. KernelSU's su sets PR_SET_KEEPCAPS, so
         * CAP_DAC_OVERRIDE survives and every 0700-root directory still opens — which
         * silently turned the first run of this tool into an existence check instead of an
         * access check. Clear the capability sets explicitly so the results are the ones a
         * real app would get.
         */
        struct cap_hdr hdr;
        struct cap_data data[2];
        memset(&hdr, 0, sizeof(hdr));
        memset(data, 0, sizeof(data));
        hdr.version = 0x20080522; /* _LINUX_CAPABILITY_VERSION_3 */
        long rc = syscall(__NR_capset, &hdr, data);
        printf("### capset(zero) -> %ld %s\n", rc, rc == 0 ? "" : strerror(errno));
    }
    show_caps("after drop:");
    printf("### now uid=%d euid=%d\n\n", (int) getuid(), (int) geteuid());
    printf("%-52s %-8s %-18s %s\n", "path", "access", "errno", "verdict");

    int n = (int) (sizeof(paths) / sizeof(paths[0]));
    int leaks = 0;
    for (int i = 0; i < n; i++) {
        errno = 0;
        int r = faccessat(AT_FDCWD, paths[i], F_OK, 0);
        int e = errno;
        struct stat st;
        int r2 = stat(paths[i], &st);
        (void) r2;
        int leak = (r == 0) || (e == 13) || (e == 1);
        if (leak) leaks++;
        printf("%-52s %-8d %-6d %-11s %s\n", paths[i], r, e, ename(e), verdict(r, e));
    }
    printf("\n### %d of %d paths are visible-but-blocked or present\n", leaks, n);
    return 0;
}
