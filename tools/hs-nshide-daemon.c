/*
 * hs-nshide-daemon — watch for a target app and overmount a path in ITS namespace.
 *
 * The mechanism (validated separately by hs-nshide): every Android app has its own mount
 * namespace, so a tmpfs mounted on /data/adb inside one app's namespace makes every
 * "/data/adb/..." probe from that app return ENOENT instead of EACCES — while root, the
 * KernelSU manager and every other app keep seeing the real directory.
 *
 * Why it has to be a daemon: the mount must be in place before the app's hardening shell
 * runs its checks, which is milliseconds after the process appears.
 *
 * The fork is not optional. setns() moves the CALLING process into the target namespace and
 * never comes back, so the watcher itself has to stay in the init namespace or it would
 * start seeing the app's view of the world — including for its own /proc scan.
 *
 * Build: aarch64-linux-android26-clang -O2 -fPIE -pie -o hs-nshide-daemon hs-nshide-daemon.c
 * Use:   hs-nshide-daemon <package> [mountpoint] [logfile]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>

static const char *g_log = "/data/local/tmp/nshide.log";

static void logf_(const char *fmt, ...) {
    int fd = open(g_log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char buf[512];
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int n = snprintf(buf, sizeof(buf), "[%ld.%03ld] ", (long) ts.tv_sec, ts.tv_nsec / 1000000);
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(buf + n, sizeof(buf) - n - 2, fmt, ap);
    va_end(ap);
    buf[n++] = '\n';
    ssize_t r = write(fd, buf, (size_t) n);
    (void) r;
    close(fd);
}

/** Find a process by the exact first word of its /proc/<pid>/cmdline. */
static int find_pid(const char *name) {
    DIR *d = opendir("/proc");
    if (d == NULL) return -1;
    struct dirent *e;
    int found = -1;
    while ((e = readdir(d)) != NULL) {
        int pid = atoi(e->d_name);
        if (pid <= 0) continue;
        char p[64];
        snprintf(p, sizeof(p), "/proc/%d/cmdline", pid);
        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        char buf[256];
        ssize_t k = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (k <= 0) continue;
        buf[k] = '\0';
        if (strcmp(buf, name) == 0) { found = pid; break; }
    }
    closedir(d);
    return found;
}

/** Runs in a forked child: enter the target's mount namespace and overmount. */
static int hide_in(int pid, const char *mp) {
    char nsp[64];
    snprintf(nsp, sizeof(nsp), "/proc/%d/ns/mnt", pid);
    int fd = open(nsp, O_RDONLY);
    if (fd < 0) return -1;
    if (setns(fd, CLONE_NEWNS) != 0) { close(fd); return -1; }
    close(fd);
    if (mount("none", mp, "tmpfs", 0, NULL) != 0) return -1;
    return 0;
}

/** Already overmounted? Ask the target's own mountinfo. */
static int already_mounted(int pid, const char *mp) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/mountinfo", pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return 0;
    char buf[8192];
    ssize_t k = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (k <= 0) return 0;
    buf[k] = '\0';
    /* Look for a tmpfs entry whose mount point is exactly the target path. */
    char needle[128];
    snprintf(needle, sizeof(needle), " - tmpfs none %s ", mp);
    return strstr(buf, needle) != NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <package> [mountpoint] [logfile]\n", argv[0]);
        return 2;
    }
    const char *target = argv[1];
    const char *mp = (argc > 2) ? argv[2] : "/data/adb";
    if (argc > 3) g_log = argv[3];

    signal(SIGCHLD, SIG_IGN);   /* reap mount children automatically */
    logf_("daemon start: target=%s mount=%s", target, mp);

    int last_done = -1;
    for (;;) {
        int pid = find_pid(target);
        if (pid > 0 && pid != last_done) {
            if (already_mounted(pid, mp)) {
                last_done = pid;
            } else {
                pid_t c = fork();
                if (c == 0) {
                    int rc = hide_in(pid, mp);
                    _exit(rc == 0 ? 0 : 1);
                }
                int st = 0;
                waitpid(c, &st, 0);
                int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
                logf_("pid=%d mount %s -> %s", pid, mp, ok ? "OK" : "FAILED");
                if (ok) last_done = pid;
            }
        } else if (pid <= 0) {
            last_done = -1;
        }
        usleep(2000);
    }
    return 0;
}
