/*
 * hs-su.c — 判定 KernelSU 的 /system/bin/su 隐藏是否依赖 allowlist 条目
 *
 * 用法:  hs-su <uid>
 * 以指定 uid（清空能力位）实测 /system/bin/su 等路径的可见性。
 * 关键对照组：uid 10452 = 虎扑（在 .allowlist 里，allow=0）
 *             uid 10999 = 任意一个"不在名单里"的 uid
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

struct cap_hdr { unsigned int version; int pid; };
struct cap_data { unsigned int effective, permitted, inheritable; };

#ifndef __NR_capset
#define __NR_capset 91
#endif
#ifndef PR_SET_KEEPCAPS
#define PR_SET_KEEPCAPS 8
#endif

static const char *paths[] = {
    "/system/bin/su",
    "/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/system/bin/sh",          /* 对照组：一定存在 */
    "/data/adb",
    "/data/adb/lspd",
    "/cache/su",
};

static const char *ename(int e) {
    switch (e) {
        case 0:  return "";
        case 2:  return "ENOENT";
        case 13: return "EACCES";
        case 1:  return "EPERM";
        default: return "?";
    }
}

int main(int argc, char **argv) {
    uid_t u = (argc > 1) ? (uid_t) atoi(argv[1]) : 10452;

    if (u != 0) {
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
        if (setresuid(u, u, u) != 0) { perror("setresuid"); return 1; }
        struct cap_hdr hdr;
        struct cap_data data[2];
        memset(&hdr, 0, sizeof(hdr));
        memset(data, 0, sizeof(data));
        hdr.version = 0x20080522;
        syscall(__NR_capset, &hdr, data);
    }

    printf("### uid=%d  (euid=%d)\n", (int) getuid(), (int) geteuid());
    printf("%-24s %-8s %-8s %s\n", "path", "access", "errno", "verdict");

    int n = (int) (sizeof(paths) / sizeof(paths[0]));
    for (int i = 0; i < n; i++) {
        errno = 0;
        int r = faccessat(AT_FDCWD, paths[i], F_OK, 0);
        int e = errno;
        printf("%-24s %-8d %-8s %s\n", paths[i], r, ename(e),
               (r == 0) ? "EXISTS" : (e == 13 ? "EACCES(hidden)" : (e == 2 ? "ENOENT(hidden)" : "?")));
    }
    printf("\n");
    return 0;
}
