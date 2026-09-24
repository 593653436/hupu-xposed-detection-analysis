/*
 * hs-nshide — hide a path inside ONE process's mount namespace.
 *
 * Android gives every app its own mount namespace (verified: init, zygote, systemui, the
 * KernelSU manager and WeChat all report distinct mnt: inodes), so a mount made in one
 * app's namespace is invisible to root, to other apps and to KernelSU itself.
 *
 * Why this is interesting for the Hupu problem: /data/adb is 0700 root:root, so any
 * "/data/adb/..." probe from an app returns EACCES rather than ENOENT, and "refused" is
 * itself the tell that something is hidden. Overmounting an empty tmpfs on /data/adb
 * inside just that app's namespace turns those probes into clean ENOENT — with no code
 * injected into the app, no LSPosed, and no kernel change.
 *
 * The device's toybox nsenter ignores -t/--target entirely (resolves to /proc/0), so this
 * does the setns itself.
 *
 * Build: aarch64-linux-android26-clang -O2 -fPIE -pie -o hs-nshide hs-nshide.c
 * Use:   hs-nshide <pid> [mountpoint]      (default mountpoint: /data/adb)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>

/* Probe a path the way a plain app would, and report the errno. */
static void probe(const char *p) {
    errno = 0;
    int r = access(p, F_OK);
    int e = errno;
    const char *v;
    if (r == 0) v = "EXISTS  <== visible";
    else if (e == 2) v = "ENOENT  (clean)";
    else if (e == 13) v = "EACCES  <== leak";
    else v = "";
    printf("    %-34s access=%d errno=%-3d %s\n", p, r, e, v);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pid> [mountpoint]\n", argv[0]);
        return 2;
    }
    int pid = atoi(argv[1]);
    const char *mp = (argc > 2) ? argv[2] : "/data/adb";
    if (pid <= 1) { fprintf(stderr, "invalid pid %d\n", pid); return 2; }

    char nspath[64];
    snprintf(nspath, sizeof(nspath), "/proc/%d/ns/mnt", pid);
    printf("=== target pid=%d, namespace %s ===\n", pid, nspath);

    printf("-- before (still in our own namespace) --\n");
    probe("/data/adb");
    probe("/data/adb/lspd");

    int fd = open(nspath, O_RDONLY);
    if (fd < 0) { perror("open ns"); return 1; }
    if (setns(fd, CLONE_NEWNS) != 0) { perror("setns"); return 1; }
    close(fd);
    printf("-- entered target namespace --\n");
    probe("/data/adb");
    probe("/data/adb/lspd");

    if (mount("none", mp, "tmpfs", 0, NULL) != 0) {
        perror("mount");
        return 1;
    }
    printf("-- overmounted tmpfs on %s --\n", mp);
    probe("/data/adb");
    probe("/data/adb/lspd");
    probe("/data/adb/riru/modules/lspd");
    probe("/data/adb/ksud");
    return 0;
}
