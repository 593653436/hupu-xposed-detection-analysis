/*
 * hs-trace — minimal aarch64 syscall tracer for Android.
 *
 * v2 adds the piece that actually answers the question: the RETURN VALUE.
 *
 * Knowing which paths a detector probes is only half the story. faccessat("/data/adb/lspd")
 * returning ENOENT is clean; returning EACCES means "something is there but hidden", which
 * is itself the finding. The two are indistinguishable without rval, and rval only arrives
 * at the syscall-EXIT stop — so entry and exit stops are now paired per thread.
 *
 * Output is aggregated rather than streamed: a table of (path, return) with hit counts,
 * sorted so the incriminating results come first. -v additionally streams raw calls.
 *
 * Build:  aarch64-linux-android26-clang -O2 -fPIE -pie -o hs-trace hs-trace.c
 * Use:    hs-trace --wait com.hupu.games 60
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/syscall.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 0x00000001
#endif
#ifndef PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE 0x00000008
#endif
#ifndef PTRACE_O_TRACEFORK
#define PTRACE_O_TRACEFORK 0x00000002
#endif
#ifndef PTRACE_O_TRACEVFORK
#define PTRACE_O_TRACEVFORK 0x00000004
#endif
#ifndef PTRACE_O_TRACEEXIT
#define PTRACE_O_TRACEEXIT 0x00000040
#endif

#define TRACED_MAX 1024
#define PATH_MAX_ 512

struct tinfo {
    int tid;
    long long nr;
    int pending;              /* an interesting call is in flight on this thread */
    int logged;               /* already streamed in verbose mode (for exit-only calls) */
    char path[PATH_MAX_];
};

static struct tinfo tinfos[TRACED_MAX];
static int ntraced = 0;

static int verbose = 0;
static int maxlines = 40000;
static int lines = 0;
static long long deadline = 0;

/* ---- aggregation: the actual deliverable ---------------------------------- */

#define AGG_MAX 8192
struct agg {
    char path[PATH_MAX_];
    long long nr;
    long rval;
    int count;
};
static struct agg aggs[AGG_MAX];
static int nagg = 0;

static int agg_find(long long nr, const char *path, long rval) {
    for (int i = 0; i < nagg; i++) {
        if (aggs[i].nr == nr && aggs[i].rval == rval && strcmp(aggs[i].path, path) == 0) {
            aggs[i].count++;
            return i;
        }
    }
    if (nagg >= AGG_MAX) return -1;
    aggs[nagg].nr = nr;
    aggs[nagg].rval = rval;
    aggs[nagg].count = 1;
    snprintf(aggs[nagg].path, sizeof(aggs[nagg].path), "%s", path);
    return nagg++;
}

static int agg_cmp(const void *a, const void *b) {
    const struct agg *x = a, *y = b;
    /* Incriminating first: success (0) then EACCES/etc, then ENOENT (clean). */
    if (x->rval != y->rval) return (x->rval < y->rval) ? -1 : 1;
    return strcmp(x->path, y->path);
}

static const char *verdict(long rval) {
    if (rval == 0) return "EXISTS      <== leak";
    switch (-rval) {
        case 1:  return "EPERM       <== leak";
        case 2:  return "ENOENT (clean)";
        case 13: return "EACCES      <== leak";
        case 20: return "ENOTDIR";
        default: return "";
    }
}

/* --------------------------------------------------------------------------- */

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static int slot_of(int tid) {
    for (int i = 0; i < ntraced; i++) if (tinfos[i].tid == tid) return i;
    return -1;
}
static int add_tid(int tid) {
    if (slot_of(tid) >= 0) return 0;
    if (ntraced >= TRACED_MAX) return -1;
    memset(&tinfos[ntraced], 0, sizeof(tinfos[0]));
    tinfos[ntraced].tid = tid;
    ntraced++;
    return 0;
}
static void del_tid(int tid) {
    int s = slot_of(tid);
    if (s < 0) return;
    tinfos[s] = tinfos[--ntraced];
}

static void read_str(int tid, unsigned long long addr, char *buf, size_t n) {
    buf[0] = '\0';
    if (addr == 0) return;
    struct iovec local = { buf, n - 1 };
    struct iovec remote = { (void *) addr, n - 1 };
    ssize_t got = syscall(__NR_process_vm_readv, tid, &local, 1, &remote, 1, 0);
    if (got > 0) { buf[got] = '\0'; return; }
    size_t i = 0;
    while (i + sizeof(long) <= n - 1) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, tid, (void *) (addr + i), 0);
        if (errno != 0) break;
        memcpy(buf + i, &w, sizeof(long));
        if (memchr(&w, '\0', sizeof(long)) != NULL) break;
        i += sizeof(long);
    }
    buf[n - 1] = '\0';
}

static void full_path(int tid, long long dirfd, const char *path, char *out, size_t n) {
    if (path[0] == '/') { snprintf(out, n, "%s", path); return; }
    char base[400], link[64];
    if (dirfd == -100) snprintf(link, sizeof(link), "/proc/%d/cwd", tid);
    else snprintf(link, sizeof(link), "/proc/%d/fd/%lld", tid, dirfd);
    ssize_t k = readlink(link, base, sizeof(base) - 1);
    if (k <= 0) { snprintf(out, n, "%s", path); return; }
    base[k] = '\0';
    snprintf(out, n, "%s/%s", base, path);
}

/* Which syscalls can express "is there root/Xposed here?". */
static int path_arg(long long nr) {
    switch (nr) {
        case 48: case 439: case 56: case 437:
        case 79: case 291: case 78: case 221: case 281:
            return 1;
        default:
            return 0;
    }
}
static const char *nr_name(long long nr) {
    switch (nr) {
        case 48:  return "faccessat";
        case 439: return "faccessat2";
        case 56:  return "openat";
        case 437: return "openat2";
        case 79:  return "newfstatat";
        case 291: return "statx";
        case 78:  return "readlinkat";
        case 221: return "execve";
        case 281: return "execveat";
        case 94:  return "exit_group";
        case 93:  return "exit";
        case 129: return "kill";
        case 131: return "tgkill";
        case 203: return "connect";
        default:  return NULL;
    }
}

static void stream_line(const char *fmt, ...);

static void on_entry(int tid, const struct ptrace_syscall_info *i) {
    long long nr = (long long) i->entry.nr;
    if (nr_name(nr) == NULL) return;
    int s = slot_of(tid);
    if (s < 0) return;
    struct tinfo *t = &tinfos[s];
    t->nr = nr;
    t->path[0] = '\0';
    t->pending = 1;
    t->logged = 0;

    if (path_arg(nr)) {
        char raw[PATH_MAX_], full[PATH_MAX_];
        read_str(tid, (unsigned long long) i->entry.args[1], raw, sizeof(raw));
        full_path(tid, (long long) i->entry.args[0], raw, full, sizeof(full));
        snprintf(t->path, sizeof(t->path), "%s", full);
    }

    /* exit_group never produces an exit stop: it is the last thing the thread does. */
    if (nr == 94 || nr == 93) {
        if (verbose && lines < maxlines) { lines++; printf("[%d] %s code=%lld\n", tid, nr_name(nr), (long long) i->entry.args[0]); fflush(stdout); }
        agg_find(nr, "<exit>", 0);
    }
}

static void on_exit(int tid, const struct ptrace_syscall_info *i) {
    int s = slot_of(tid);
    if (s < 0) return;
    struct tinfo *t = &tinfos[s];
    if (!t->pending) return;
    t->pending = 0;
    long long nr = t->nr;
    const char *name = nr_name(nr);
    if (name == NULL) return;
    if (nr == 94 || nr == 93) return;

    long rval = (long) i->exit.rval;
    if (!path_arg(nr)) return;

    int idx = agg_find(nr, t->path, rval);
    (void) idx;
    if (verbose && lines < maxlines) {
        lines++;
        printf("[%d] %-11s %-72s -> %ld  %s\n", tid, name, t->path, rval, verdict(rval));
        fflush(stdout);
    }
}

static void stream_line(const char *fmt, ...) { (void) fmt; }

static int find_process(const char *name) {
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

static int attach_all(int pid) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/task", pid);
    DIR *d = opendir(p);
    if (d == NULL) return -1;
    struct dirent *e;
    long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK
                | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT;
    while ((e = readdir(d)) != NULL) {
        int tid = atoi(e->d_name);
        if (tid <= 0 || slot_of(tid) >= 0) continue;
        if (ptrace(PTRACE_ATTACH, tid, 0, 0) != 0) {
            printf("### ATTACH failed tid=%d: %s\n", tid, strerror(errno));
            continue;
        }
        int st;
        waitpid(tid, &st, __WALL);
        ptrace(PTRACE_SETOPTIONS, tid, 0, (void *) opts);
        add_tid(tid);
        ptrace(PTRACE_SYSCALL, tid, 0, 0);
    }
    closedir(d);
    return 0;
}

static void dump_agg(void) {
    printf("\n=========== RESULT TABLE (%d distinct path/return pairs) ===========\n", nagg);
    printf("%-9s %-72s %8s %6s  %s\n", "syscall", "path", "rval", "hits", "meaning");
    qsort(aggs, nagg, sizeof(aggs[0]), agg_cmp);
    for (int i = 0; i < nagg; i++) {
        printf("%-9s %-72s %8ld %6d  %s\n", nr_name(aggs[i].nr), aggs[i].path,
               aggs[i].rval, aggs[i].count, verdict(aggs[i].rval));
    }
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pid>|<--wait name> [seconds] [-v]\n", argv[0]);
        return 2;
    }
    int wait_mode = 0;
    const char *target = argv[1];
    int argi = 2;
    if (strcmp(argv[1], "--wait") == 0) { wait_mode = 1; if (argc < 3) return 2; target = argv[2]; argi = 3; }
    int secs = 60;
    if (argc > argi) { if (strcmp(argv[argi], "-v") != 0) { secs = atoi(argv[argi]); argi++; } }
    if (argc > argi && strcmp(argv[argi], "-v") == 0) verbose = 1;
    deadline = now_ms() + (long long) secs * 1000;

    int pid = 0;
    if (wait_mode) {
        printf("### waiting for '%s' ...\n", target);
        fflush(stdout);
        while (now_ms() < deadline) {
            pid = find_process(target);
            if (pid > 0) break;
            usleep(2000);
        }
        if (pid <= 0) { printf("### never appeared\n"); return 1; }
    } else {
        pid = atoi(target);
    }
    if (pid <= 1) { printf("### refusing invalid pid (%d)\n", pid); return 1; }

    printf("### attached to %s pid=%d, tracing %d s%s\n", target, pid, secs,
           verbose ? " (verbose)" : "");
    fflush(stdout);

    if (attach_all(pid) != 0) { printf("### cannot enumerate threads\n"); return 1; }

    long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK
                | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT;

    while (ntraced > 0 && now_ms() < deadline) {
        int st = 0;
        int tid = waitpid(-1, &st, __WALL | WNOHANG);
        if (tid <= 0) { usleep(500); continue; }

        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (WIFSIGNALED(st)) printf("### tid=%d died: signal %d\n", tid, WTERMSIG(st));
            else printf("### tid=%d exited: code %d\n", tid, WEXITSTATUS(st));
            fflush(stdout);
            del_tid(tid);
            continue;
        }
        if (!WIFSTOPPED(st)) continue;
        int sig = WSTOPSIG(st);

        if (sig == (SIGTRAP | 0x80)) {
            struct ptrace_syscall_info info;
            memset(&info, 0, sizeof(info));
            long n = ptrace(PTRACE_GET_SYSCALL_INFO, tid, (void *) sizeof(info), &info);
            if (n >= 0) {
                if (info.op == PTRACE_SYSCALL_INFO_ENTRY) on_entry(tid, &info);
                else if (info.op == PTRACE_SYSCALL_INFO_EXIT) on_exit(tid, &info);
            }
            ptrace(PTRACE_SYSCALL, tid, 0, 0);
            continue;
        }
        if (sig == SIGTRAP) {
            int ev = st >> 16;
            if (ev == PTRACE_EVENT_CLONE || ev == PTRACE_EVENT_FORK || ev == PTRACE_EVENT_VFORK) {
                unsigned long newtid = 0;
                ptrace(PTRACE_GETEVENTMSG, tid, 0, &newtid);
                if (newtid > 0 && add_tid((int) newtid) == 0) {
                    ptrace(PTRACE_SETOPTIONS, (int) newtid, 0, (void *) opts);
                }
            }
            ptrace(PTRACE_SYSCALL, tid, 0, 0);
            continue;
        }
        if (sig == SIGSTOP || sig == SIGCONT) { ptrace(PTRACE_SYSCALL, tid, 0, 0); continue; }
        ptrace(PTRACE_SYSCALL, tid, 0, (void *) (long) sig);
    }

    dump_agg();
    for (int i = 0; i < ntraced; i++) ptrace(PTRACE_DETACH, tinfos[i].tid, 0, 0);
    printf("### done\n");
    return 0;
}
