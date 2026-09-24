/*
 * HupuShield native layer.
 *
 * Why this exists: 虎扑 (com.hupu.games) is hardened with NetEase Yidun. Forensic probing
 * showed the process dies immediately after the shell loads libnesec.so, with no Java
 * exception and no tombstone — i.e. a deliberate native exit. Nothing above Java can
 * intercept that, so this library patches the GOT of every loaded library to route
 * exit()/_exit()/abort()/kill() through us.
 *
 * Timing caveat: xhook can only patch libraries that are already loaded. If the shell's
 * JNI_OnLoad calls exit() we are too late; that is why the Java side re-runs
 * nativeRefresh() the instant Runtime.loadLibrary0 returns, and why every hook is
 * log-only in this build. The backtraces tell us exactly who calls what, which decides
 * whether GOT patching is sufficient or we need inline hooking of libc.
 */

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>
#include <unwind.h>

/*
 * seccomp user notification. The NDK's kernel headers vary in whether they carry these, so
 * everything is defined locally against our own structs. The struct layout matches the
 * kernel's exactly, which is what makes the _IOWR-encoded ioctl numbers identical.
 */
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 0x00000001
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

struct hs_seccomp_notif {
    __u64 id;
    __u32 pid;
    __u32 flags;
    struct seccomp_data data;
};

struct hs_seccomp_notif_resp {
    __u64 id;
    __s64 val;
    __s32 error;
    __u32 flags;
};

struct hs_seccomp_notif_addfd {
    __u64 id;
    __u32 flags;
    __u32 srcfd;
    __u32 newfd;
    __u32 newfd_flags;
};

/*
 * Note the indices and directions, straight from the kernel's seccomp.h:
 *   NOTIF_RECV     = IOWR(0)
 *   NOTIF_SEND     = IOWR(1)
 *   NOTIF_ID_VALID = IOW (2)   <- index 2 belongs to ID_VALID, not ADDFD
 *   NOTIF_ADDFD    = IOW (3)
 * Getting either the index or the direction wrong yields EINVAL from the ioctl.
 */
#define HS_NOTIF_RECV _IOWR('!', 0, struct hs_seccomp_notif)
#define HS_NOTIF_SEND _IOWR('!', 1, struct hs_seccomp_notif_resp)
#define HS_NOTIF_ADDFD _IOW('!', 3, struct hs_seccomp_notif_addfd)

#ifndef SECCOMP_ADDFD_FLAG_SEND
#define SECCOMP_ADDFD_FLAG_SEND 0x00000002
#endif
#ifndef SECCOMP_ADDFD_FLAG_SETFD
#define SECCOMP_ADDFD_FLAG_SETFD 0x00000001
#endif

/*
 * A fixed descriptor number for injected maps fds.
 *
 * Without SETFD the kernel allocates a fresh number every time, so hundreds of map reads
 * grow the target's descriptor table for as long as it fails to close them. Pinning one
 * high number keeps that bounded: each injection replaces the previous entry (dup2
 * semantics) instead of adding to it.
 */
#define HS_FAKE_FD 1000

#include "xhook/xhook.h"

#define TAG "HupuShield-Native"
#define LOGBUF 4096

static char g_log_path[512];
static pthread_mutex_t g_lock;
static volatile int g_block = 0;
static volatile int g_trace = 0;
static volatile int g_inline_hooks = 0;

/* Bitmask shared with Native.java's nativeInit. */
#define HS_FLAG_BLOCK_NATIVE  1
#define HS_FLAG_TRACE_OPENAT  2
#define HS_FLAG_FAKE_MAPS     4
#define HS_FLAG_INLINE_HOOKS  8

/*
 * Names an instrumentation probe hunts for, shared by the maps filter and the
 * dl_iterate_phdr filter. Kept near the top because both sections use it.
 */
static const char *MAPS_DROP[] = {
        "lspd", "lsplant", "LSPosed", "lsposed", "riru", "zygisk",
        "magisk", "shamiko", "edxp", "Xposed", "xposed", "libhupushield",
        /* The package name, not the library name — the APK path in the maps carries this
         * one. Rule (2) below covers it generically; this is the fallback for the case
         * where the package could not be recovered from the log path. */
        "com.dsh.hupushield",
};
static volatile int g_installed = 0;
static volatile long g_t0 = 0;

/* ------------------------------------------------------------------ logging */

static void nlog_line(const char *msg) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "%s", msg);
    if (g_log_path[0] == '\0') {
        return;
    }
    pthread_mutex_lock(&g_lock);
    int fd = open(g_log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        long now = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
        char line[LOGBUF + 64];
        int n = snprintf(line, sizeof(line), "[N+%ldms] %s\n", now - g_t0, msg);
        if (n > 0) {
            ssize_t ignored = write(fd, line, (size_t) n);
            (void) ignored;
        }
        close(fd);
    }
    pthread_mutex_unlock(&g_lock);
}

static void nlogf(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    nlog_line(buf);
}

/* ---------------------------------------------------------------- backtrace */

struct bt_ctx {
    void *frames[48];
    int n;
};

static _Unwind_Reason_Code bt_cb(struct _Unwind_Context *ctx, void *arg) {
    struct bt_ctx *c = (struct bt_ctx *) arg;
    uintptr_t pc = _Unwind_GetIP(ctx);
    if (pc != 0 && c->n < 48) {
        c->frames[c->n++] = (void *) pc;
    }
    return _URC_NO_REASON;
}

/** Resolve every frame to "library + offset" — enough to identify the killer. */
static void log_backtrace(const char *why) {
    struct bt_ctx c;
    c.n = 0;
    _Unwind_Backtrace(bt_cb, &c);

    char buf[LOGBUF];
    int off = snprintf(buf, sizeof(buf), "!! %s -- backtrace:", why);
    for (int i = 0; i < c.n && off < (int) sizeof(buf) - 200; i++) {
        Dl_info info;
        if (dladdr(c.frames[i], &info) != 0 && info.dli_fname != NULL) {
            off += snprintf(buf + off, sizeof(buf) - off, "\n      #%02d %s + 0x%zx",
                            i, info.dli_fname,
                            (size_t) ((uintptr_t) c.frames[i] - (uintptr_t) info.dli_fbase));
        } else {
            off += snprintf(buf + off, sizeof(buf) - off, "\n      #%02d %p", i, c.frames[i]);
        }
    }
    nlog_line(buf);
}

/* -------------------------------------------------------------------- hooks */

static void (*orig_exit)(int) = NULL;
static void (*orig__exit)(int) = NULL;
static void (*orig_abort)(void) = NULL;
static int (*orig_kill)(pid_t, int) = NULL;
static long (*orig_syscall)(long, ...) = NULL;

/*
 * Terminate via the raw syscall, deliberately NOT via _exit().
 * xhook patches the GOT of every library matching the target regex — so a PLT call to
 * _exit() from inside our own hook could land back in my__exit() and recurse until the
 * stack dies.
 */
static void hard_exit(int code) {
    syscall(__NR_exit_group, code);
    __builtin_unreachable();
}

static void my_exit(int code) {
    log_backtrace("exit() called");
    if (g_block) {
        nlog_line(">> exit() BLOCKED");
        return; /* caller continues; may or may not cope */
    }
    if (orig_exit != NULL) {
        orig_exit(code);
    }
    hard_exit(code);
}

static void my__exit(int code) {
    log_backtrace("_exit() called");
    if (g_block) {
        nlog_line(">> _exit() BLOCKED");
        return;
    }
    if (orig__exit != NULL) {
        orig__exit(code);
    }
    hard_exit(code);
}

static void my_abort(void) {
    log_backtrace("abort() called");
    if (g_block) {
        nlog_line(">> abort() BLOCKED");
        return;
    }
    if (orig_abort != NULL) {
        orig_abort();
    }
    hard_exit(134);
}

static int my_kill(pid_t pid, int sig) {
    if (pid == getpid()) {
        log_backtrace("kill(self) called");
        if (g_block) {
            nlogf(">> kill(self, %d) BLOCKED", sig);
            return 0;
        }
    }
    return orig_kill != NULL ? orig_kill(pid, sig) : -1;
}

/*
 * Covers the "syscall(SYS_exit_group, ...)" route. bionic's own _exit() inlines the svc
 * instruction instead, and a hardened library can do the same, so this is coverage, not a
 * guarantee — which is exactly what the log-only build is meant to establish.
 */
static long my_syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    if (number == __NR_exit_group || number == __NR_exit) {
        log_backtrace("syscall(exit_group) called");
        if (g_block) {
            nlogf(">> syscall(%ld, %ld) BLOCKED", number, a1);
            return 0;
        }
    }
    if (orig_syscall == NULL) {
        return -1;
    }
    return orig_syscall(number, a1, a2, a3, a4, a5, a6);
}

/* Forward declarations: register_all() references these before their definitions below. */
typedef void (*hs_handler_t)(int);
static int (*orig_open)(const char *, int, ...);
static int (*orig_openat)(int, const char *, int, ...);
static FILE *(*orig_fopen)(const char *, const char *);
static ssize_t (*orig_readlink)(const char *, char *, size_t);
static int my_open(const char *path, int flags, ...);
static int my_openat(int dirfd, const char *path, int flags, ...);
static FILE *my_fopen(const char *path, const char *mode);
static ssize_t my_readlink(const char *path, char *buf, size_t size);
static int (*orig_sigaction)(int, const struct sigaction *, struct sigaction *);
static hs_handler_t (*orig_signal)(int, hs_handler_t);
static int my_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
static hs_handler_t my_signal(int signum, hs_handler_t handler);
static hs_handler_t (*orig_signal)(int, hs_handler_t) = NULL;

static void register_all(void) {
    /*
     * Deliberately narrow. An earlier build used ".*\.so$", which made xhook rewrite the GOT
     * of every loaded library — 228 ms on the main thread during handleBindApplication, in a
     * process that only lives a few hundred milliseconds, and with libart/liblspd caught in
     * the blast radius. The shell's libraries are all we care about.
     */
    const char *target = ".*(libnesec|libnshelper).*\\.so$";
    const char *self = ".*libhupushield\\.so$";

    /* Never redirect calls made by this library itself (see hard_exit). */
    xhook_ignore(self, "exit");
    xhook_ignore(self, "_exit");
    xhook_ignore(self, "abort");
    xhook_ignore(self, "kill");
    xhook_ignore(self, "syscall");
    xhook_ignore(self, "open");
    xhook_ignore(self, "openat");
    xhook_ignore(self, "fopen");
    xhook_ignore(self, "readlink");

    xhook_register(target, "exit", (void *) my_exit, (void **) &orig_exit);
    xhook_register(target, "_exit", (void *) my__exit, (void **) &orig__exit);
    xhook_register(target, "abort", (void *) my_abort, (void **) &orig_abort);
    xhook_register(target, "kill", (void *) my_kill, (void **) &orig_kill);
    xhook_register(target, "syscall", (void *) my_syscall, (void **) &orig_syscall);

    /*
     * Not there to block anything — these are how we prove the GOT patch actually landed on
     * libnesec.so (if nothing shows up, the hook never took effect) and how we see what the
     * detector inspects. /proc/self/maps is the prime suspect for an Xposed check.
     */
    xhook_register(target, "open", (void *) my_open, (void **) &orig_open);
    xhook_register(target, "openat", (void *) my_openat, (void **) &orig_openat);
    xhook_register(target, "fopen", (void *) my_fopen, (void **) &orig_fopen);
    xhook_register(target, "readlink", (void *) my_readlink, (void **) &orig_readlink);

    /*
     * The decisive one. The watchdog proved our SIGILL disposition stayed installed and was
     * still never invoked — the shell restores SIG_DFL and executes the udf within a window
     * far shorter than any polling interval can cover. Denying the change outright is
     * deterministic where racing it is not, and it is reachable: the reset is a libc call,
     * so it goes through the GOT we patch ~170 ms before the trap fires.
     */
    xhook_register(target, "sigaction", (void *) my_sigaction, (void **) &orig_sigaction);
    xhook_register(target, "signal", (void *) my_signal, (void **) &orig_signal);
}

static int my_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    if (signum == SIGILL && act != NULL) {
        void (*h)(int) = act->sa_handler;
        if (h == SIG_DFL || h == SIG_IGN) {
            nlog_line("!! blocked attempt to restore SIGILL to default/ignore");
            return 0; /* report success, change nothing */
        }
    }
    return orig_sigaction != NULL ? orig_sigaction(signum, act, oldact) : -1;
}

static hs_handler_t my_signal(int signum, hs_handler_t handler) {
    if (signum == SIGILL && (handler == SIG_DFL || handler == SIG_IGN)) {
        nlog_line("!! blocked signal() attempt to reset SIGILL");
        return SIG_ERR;
    }
    return orig_signal != NULL ? orig_signal(signum, handler) : SIG_ERR;
}

/* --------------------------------------------------- filesystem recon probes */

static int (*orig_open)(const char *, int, ...) = NULL;
static int (*orig_openat)(int, const char *, int, ...) = NULL;
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static ssize_t (*orig_readlink)(const char *, char *, size_t) = NULL;

static int my_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    if (path != NULL) {
        nlogf("open(%s, 0x%x)", path, flags);
    }
    return orig_open != NULL ? orig_open(path, flags, mode) : -1;
}

static int my_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    if (path != NULL) {
        nlogf("openat(%d, %s, 0x%x)", dirfd, path, flags);
    }
    return orig_openat != NULL ? orig_openat(dirfd, path, flags, mode) : -1;
}

static FILE *my_fopen(const char *path, const char *mode) {
    if (path != NULL) {
        nlogf("fopen(%s, %s)", path, mode == NULL ? "?" : mode);
    }
    return orig_fopen != NULL ? orig_fopen(path, mode) : NULL;
}

static ssize_t my_readlink(const char *path, char *buf, size_t size) {
    if (path != NULL) {
        nlogf("readlink(%s)", path);
    }
    return orig_readlink != NULL ? orig_readlink(path, buf, size) : -1;
}

/* ------------------------------------------------------------ SIGILL defeat */

/*
 * The real death cause, established from the system log: every single time the process dies
 * it is "exited due to signal 4 (Illegal instruction)". That is the hardening shell's
 * self-destruct instruction (__builtin_trap -> udf). It defeats both previous approaches:
 * it is not a function call, so GOT patching never sees it, and it is not a syscall, so
 * seccomp has no say either.
 *
 * SIGILL is catchable, though. On AArch64 every instruction is 4 bytes, so stepping the
 * saved PC past the trapping instruction resumes execution right after the trap.
 */
static struct sigaction g_old_sigill;
static volatile int g_sigill_count = 0;
static volatile int g_sigill_logged = 0;
#define SIGILL_LOG_LIMIT 40

/*
 * ------------------------------------------------------------ lock-free channel
 *
 * The handler has to report while the process is in its most fragile state, and it cannot
 * take a single lock to do it.
 *
 * The original version called dladdr() and nlogf(). dladdr() takes the dynamic linker's
 * lock, and the trap fires immediately around libnesec's dlopen — so the lock may well be
 * held by a thread that is itself waiting for the one we just interrupted. nlogf() takes the
 * stdio lock. Either one deadlocks the handler on its first statement, which is
 * indistinguishable from "the handler never ran", and is the likeliest reason a handler that
 * was installed and watchdog-verified produced exactly zero lines of output.
 *
 * So: a descriptor opened before the seccomp filter exists, a raw write(), and integer
 * formatting done by hand. No stdio, no dladdr, no allocation.
 */
static volatile int g_evt_fd = -1;

static char *hs_pstr(char *p, const char *s) {
    while (*s != '\0') { *p++ = *s++; }
    return p;
}

static char *hs_pnum(char *p, unsigned long v) {
    char tmp[24];
    int i = 0;
    if (v == 0) { tmp[i++] = '0'; }
    while (v != 0) { tmp[i++] = (char) ('0' + (int) (v % 10)); v /= 10; }
    while (i > 0) { *p++ = tmp[--i]; }
    return p;
}

static char *hs_phex(char *p, unsigned long v) {
    static const char HEX[] = "0123456789abcdef";
    char tmp[20];
    int i = 0;
    if (v == 0) { tmp[i++] = '0'; }
    while (v != 0) { tmp[i++] = HEX[v & 0xf]; v >>= 4; }
    while (i > 0) { *p++ = tmp[--i]; }
    return p;
}

/** Emit "<tag> <dec> <hex> <hex>\n" via a pre-opened fd. Async-signal-safe. */
static void hs_evt(const char *tag, unsigned long a, unsigned long b, unsigned long c) {
    int fd = g_evt_fd;
    if (fd < 0) { return; }
    char buf[256];
    char *p = buf;
    p = hs_pstr(p, tag);
    *p++ = ' ';
    p = hs_pnum(p, a);
    *p++ = ' ';
    p = hs_phex(p, b);
    *p++ = ' ';
    p = hs_phex(p, c);
    *p++ = '\n';
    syscall(__NR_write, (long) fd, buf, (size_t) (p - buf));
}

/** Open "<log>.events" while openat is still allowed. */
static void hs_evt_open(void) {
    if (g_evt_fd >= 0 || g_log_path[0] == '\0') { return; }
    char path[560];
    size_t n = strlen(g_log_path);
    if (n + 8 >= sizeof(path)) { return; }
    memcpy(path, g_log_path, n);
    memcpy(path + n, ".events", 8);
    long fd = syscall(__NR_openat, (long) AT_FDCWD, path,
                      O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { g_evt_fd = (int) fd; }
}

static void sigill_handler(int sig, siginfo_t *info, void *uctx) {
    (void) sig;
    ucontext_t *uc = (ucontext_t *) uctx;
    uintptr_t pc = (uintptr_t) uc->uc_mcontext.pc;
    int n = ++g_sigill_count;

    if (n <= SIGILL_LOG_LIMIT) {
        hs_evt("SIGILL", (unsigned long) n, (unsigned long) pc,
               (unsigned long) (info != NULL ? info->si_code : -1));
    } else if (n == SIGILL_LOG_LIMIT + 1) {
        hs_evt("SIGILL_MORE", (unsigned long) n, 0UL, 0UL);
    }
    g_sigill_logged = 1;

    /*
     * AArch64 is fixed-width — every instruction is 4 bytes — so the instruction after a
     * udf is simply pc + 4, and execution resumes there. That is the entire defeat: the
     * shell's self-destruct instruction is skipped and the thread carries on.
     */
    uc->uc_mcontext.pc = pc + 4;
}

#define HS_ALTSTACK_SIZE (64 * 1024)
static char g_altstack[HS_ALTSTACK_SIZE];

static int install_sigill_handler(void) {
    hs_evt_open();

    /*
     * SA_ONSTACK with a private stack, because the shell is free to trap while the
     * interrupted thread's own stack is unusable — deep inside a fault, mid-unwind, or
     * deliberately wrecked. With no alternate stack the kernel cannot push the sigframe at
     * all, abandons the handler and applies the default action, which again looks exactly
     * like "the handler was never called".
     */
    stack_t ss;
    ss.ss_sp = g_altstack;
    ss.ss_size = sizeof(g_altstack);
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigill_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    /*
     * Mask SIGILL inside the handler explicitly rather than leaning on SA_NODEFER's
     * opposite. A repeated trap must not re-enter and walk the alternate stack down.
     */
    sigaddset(&sa.sa_mask, SIGILL);
    if (sigaction(SIGILL, &sa, &g_old_sigill) != 0) {
        nlogf("SIGILL handler install failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * Installing the handler once is not enough. The shell sets its own disposition up after we
 * do (it initialises during libnesec load, roughly 10 ms after us) and then restores SIG_DFL
 * right before trapping, so the death looks like an ordinary crash. Racing it is the only
 * way: a tight watchdog re-claims SIGILL whenever the disposition stops being ours.
 */
static volatile int g_watchdog_stop = 0;
static volatile int g_watchdog_takeovers = 0;

static void *sigill_watchdog(void *arg) {
    (void) arg;
    int announced = 0;
    while (!g_watchdog_stop) {
        struct sigaction cur;
        memset(&cur, 0, sizeof(cur));
        /*
         * Query form only — act == NULL — and the seccomp filter below deliberately allows
         * exactly that shape. It used to refuse every rt_sigaction carrying SIGILL, which
         * silently turned this loop into a no-op the instant the filter was installed: the
         * query came back EPERM, the branch was skipped, and the watchdog never looked
         * again. A guard that can no longer see is worse than no guard, because it reports
         * "disposition verified" forever.
         */
        if (sigaction(SIGILL, NULL, &cur) == 0) {
            if (cur.sa_sigaction != sigill_handler) {
                int n = ++g_watchdog_takeovers;
                hs_evt("SIGILL_TAKEN", (unsigned long) n,
                       (unsigned long) cur.sa_sigaction, 0UL);
                if (n <= 20) {
                    nlogf("!! SIGILL disposition was taken away (now %p) -> reclaiming (#%d)",
                          (void *) cur.sa_sigaction, n);
                }
                install_sigill_handler();
            } else if (!announced) {
                announced = 1;
                nlog_line("SIGILL watchdog running, disposition verified");
            }
        }
        usleep(500);
    }
    return NULL;
}

static void start_sigill_watchdog(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, sigill_watchdog, NULL) == 0) {
        pthread_detach(t);
        nlog_line("SIGILL watchdog started");
    } else {
        nlog_line("SIGILL watchdog failed to start");
    }
}

/* ------------------------------------------------------------ seccomp blocker */

/*
 * Not every NDK revision spells these out; the AArch64 numbers are stable ABI.
 */
#ifndef __NR_rt_sigqueueinfo
#define __NR_rt_sigqueueinfo 138
#endif
#ifndef __NR_rt_tgsigqueueinfo
#define __NR_rt_tgsigqueueinfo 240
#endif
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif
/* Path-taking syscalls the /data/adb guard has to see. */
#ifndef __NR_newfstatat
#define __NR_newfstatat 79
#endif
#ifndef __NR_readlinkat
#define __NR_readlinkat 78
#endif
#ifndef __NR_statx
#define __NR_statx 291
#endif
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

/*
 * The shell terminates via an inlined exit_group syscall, which no GOT patch can see (we
 * verified that: libnesec's GOT was patched and yet none of exit/_exit/abort/kill/syscall
 * ever fired). seccomp is the one lever that works below the libc layer: it makes the
 * kernel itself turn those calls into -EPERM, so the process simply does not die.
 *
 * Measured effect, and it is the strongest evidence we have that this layer is the right
 * one: with the blocker disabled every process ends in a clean, log-free exit; with the
 * blocker enabled those same processes instead die of SIGILL. The shell's first choice is
 * exit_group, and blocking it makes the shell fall through to its second-stage udf trap.
 * Two stages, two mechanisms, and only the second one remains.
 *
 * Filters are inherited by threads created afterwards, so installing this early on the main
 * thread during handleBindApplication covers everything the shell spawns later.
 */
static int install_seccomp_block(void) {
    struct sock_filter filter[] = {
            /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (__u32) offsetof(struct seccomp_data, arch)),
            /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
            /* 2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            /* 3 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (__u32) offsetof(struct seccomp_data, nr)),
            /*
             * Everything that can end this process without leaving a crash log, all of it
             * landing on the single RET_ERRNO at 17.
             *
             * tgkill and kill cover raise()/abort() and friends. The three that follow are
             * the quieter ways to send a signal — notably rt_sigqueueinfo, which can deliver
             * SIGKILL and is not covered by blocking tgkill or kill.
             */
            /* 4 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 12, 0),
            /* 5 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 11, 0),
            /* 6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tgkill, 10, 0),
            /* 7 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 9, 0),
            /* 8 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigqueueinfo, 8, 0),
            /* 9 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_tgsigqueueinfo, 7, 0),
            /*10 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pidfd_send_signal, 6, 0),
            /*
             * rt_sigprocmask is deliberately NOT here.
             *
             * Refusing it outright does defeat the shell's second stage — one coarse rule and
             * the SIGILL handler that had been installed, watchdog-verified and silent for
             * three rounds finally started firing, 197 times. But it also takes the mask
             * machinery away from ART and pthreads, which is far too much collateral: the
             * deaths simply moved on to SIGSEGV. The mask can only be judged properly by
             * reading the set it points at, and no BPF program can dereference a pointer, so
             * that decision belongs to the user-notification guard below.
             */
            /*
             * rt_sigaction gets narrowed handling. The shell restores SIG_DFL with an inlined
             * syscall just before trapping, so refusing the write is what keeps our handler
             * installed — but the QUERY form (act == NULL) must stay permitted, or the
             * watchdog goes blind the moment this filter lands.
             */
            /*11 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 4),
            /*12 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (__u32) offsetof(struct seccomp_data, args[1])),
            /*13 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 0),
            /*14 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (__u32) offsetof(struct seccomp_data, args[0])),
            /*15 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (__u32) SIGILL, 1, 0),
            /*16 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            /*17 */ BPF_STMT(BPF_RET | BPF_K,
                            SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    };
    struct sock_fprog prog;
    prog.len = (unsigned short) (sizeof(filter) / sizeof(filter[0]));
    prog.filter = filter;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        nlogf("seccomp: PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
        return -1;
    }

    /*
     * TSYNC, so the filter also binds threads that already exist. The shell's tripwire
     * workers are exactly the kind of thread that may predate us, and a plain prctl only
     * covers the calling thread plus threads it later spawns.
     *
     * TSYNC is legal here precisely because this filter needs no listener
     * (SECCOMP_FILTER_FLAG_NEW_LISTENER | TSYNC is what the kernel rejects with EINVAL, and
     * that combination is what the openat tracer had to give up).
     */
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog) != 0) {
        nlogf("seccomp: TSYNC failed (%s), falling back to this thread only", strerror(errno));
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
            nlogf("seccomp: PR_SET_SECCOMP failed: %s", strerror(errno));
            return -1;
        }
        nlog_line("seccomp: exit_group/exit/tgkill/kill now return -EPERM (this thread only)");
        return 0;
    }
    nlog_line("seccomp: exit_group/exit/tgkill/kill now return -EPERM (TSYNC, all threads)");
    return 0;
}

/* ------------------------------------------- sigprocmask guard (user notif) */

/*
 * The shell's second stage, and the reason our SIGILL handler stayed silent for three rounds:
 *
 *     1. block SIGILL with rt_sigprocmask
 *     2. execute udf
 *
 * A synchronous signal cannot be left pending — the thread would re-execute the faulting
 * instruction forever — so once the mask blocks it the kernel has no way to deliver it and
 * applies the default action instead. The handler is installed, the watchdog confirms the
 * disposition is still ours, and it is never entered, because the signal never arrives.
 *
 * Refusing every rt_sigprocmask proves the theory (the handler fired 197 times) but wrecks
 * ART and pthreads. The mask can only be judged by reading the set the call points at, and
 * no BPF program can dereference a pointer — so the decision has to happen in a supervisor,
 * which is what SECCOMP_RET_USER_NOTIF exists for.
 *
 * SECCOMP_FILTER_FLAG_NEW_LISTENER cannot be combined with TSYNC, so this second filter binds
 * to the installing thread alone. That is sufficient here and the evidence says why: the trap
 * is taken on the main thread, right after libnesec loads from MyApplication.attachBaseContext.
 */
static volatile int g_sp_fd = -1;
static volatile int g_sp_denied = 0;

static void *sigprocmask_supervisor(void *arg) {
    (void) arg;
    while (g_sp_fd < 0) {
        usleep(200);
    }
    int fd = g_sp_fd;
    __android_log_print(ANDROID_LOG_INFO, TAG, "sigprocmask guard armed on fd %d", fd);

    for (;;) {
        struct hs_seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(fd, HS_NOTIF_RECV, &req) != 0) {
            usleep(1000);
            continue;
        }

        struct hs_seccomp_notif_resp resp;
        memset(&resp, 0, sizeof(resp));
        resp.id = req.id;

        /*
         * how: SIG_BLOCK(0) / SIG_UNBLOCK(1) / SIG_SETMASK(2). Only the two that can ADD
         * SIGILL to the mask are worth refusing; SIG_UNBLOCK is always allowed through.
         */
        unsigned long how = (unsigned long) req.data.args[0];
        unsigned long setp = (unsigned long) req.data.args[1];
        unsigned long size = (unsigned long) req.data.args[2];
        int deny = 0;
        unsigned long bits = 0;

        if (setp != 0 && (how == 0 || how == 2)) {
            size_t n = size > sizeof(bits) ? sizeof(bits) : (size_t) size;
            /*
             * Safe to dereference: the supervisor shares the address space with the caller, so
             * this is an ordinary read of the caller's own sigset — no process_vm_readv dance.
             */
            if (n > 0) {
                memcpy(&bits, (const void *) setp, n);
                if ((bits & (1UL << (SIGILL - 1))) != 0) {
                    deny = 1;
                }
            }
        }

        if (deny) {
            int n = ++g_sp_denied;
            resp.error = EPERM;
            hs_evt("SPROCMASK_DENY", how, bits, (unsigned long) n);
        } else {
            /*
             * Continue: let the kernel run the real syscall. Anything else here — including
             * simply not answering — hangs the caller on every mask change the process makes.
             */
            resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        }

        if (ioctl(fd, HS_NOTIF_SEND, &resp) != 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "sigprocmask guard: SEND failed: %s",
                                strerror(errno));
        }
    }
    return NULL;
}

static int install_sigprocmask_guard(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, sigprocmask_supervisor, NULL) != 0) {
        nlog_line("sigprocmask guard: supervisor thread failed");
        return -1;
    }
    pthread_detach(t);

    struct sock_filter filter[] = {
            /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (__u32) offsetof(struct seccomp_data, arch)),
            /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
            /* 2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            /* 3 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (__u32) offsetof(struct seccomp_data, nr)),
            /* 4 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigprocmask, 0, 1),
            /* 5 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
            /* 6 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog;
    prog.len = (unsigned short) (sizeof(filter) / sizeof(filter[0]));
    prog.filter = filter;

    long fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                      SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (fd < 0) {
        nlogf("sigprocmask guard: seccomp(NEW_LISTENER) failed: %s", strerror(errno));
        return -1;
    }
    g_sp_fd = (int) fd;
    nlog_line("sigprocmask guard armed: SIGILL masks refused, everything else continued");
    return 0;
}

/* ============================ ShadowHook inline hooks ========================= */

/*
 * These cover the two Yidun tripwires that seccomp structurally cannot reach:
 *
 *   dl_iterate_phdr  — a walk of loaded shared objects. Not a syscall, so no seccomp
 *                      filter can see it, and it is how injected modules are found.
 *   sigaction        — the signal tripwires, armed from inside libnesec's constructors.
 *                      A GOT patch lands only after dlopen returns, i.e. too late; an
 *                      inline hook replaces the body outright, and can additionally tell
 *                      WHICH library is calling, so ART's own handlers stay untouched.
 */
#ifdef HS_HAVE_SHADOWHOOK
#include "shadowhook.h"
#include <link.h>
#include <stdbool.h>

/*
 * ShadowHook is resolved at runtime, never linked — and that is not a style choice.
 *
 * With it in DT_NEEDED the module was dead on arrival. ART probes a freshly loaded library
 * for its entry point with dlsym(handle, "JNI_OnLoad"), and dlsym searches the dependency
 * chain as well as the library itself. We do not define that symbol; libshadowhook.so does,
 * and it returns JNI_ERR. ART therefore rejected our library outright —
 *   "JNI_ERR returned from JNI_OnLoad in .../libhupushield.so"
 * — so not one line of the native code below ever executed, which is exactly what the logs
 * showed: no ShadowHook banner, no seccomp banner, nothing.
 *
 * dlopen keeps our symbol namespace our own, and lets a missing ShadowHook degrade into
 * "inline hooks unavailable" instead of taking the whole module down with it.
 */
typedef int (*hs_sh_init_fn)(shadowhook_mode_t, bool);
typedef const char *(*hs_sh_msg_fn)(int);
typedef int (*hs_sh_errno_fn)(void);
typedef void *(*hs_sh_hook_fn)(const char *, const char *, void *, void **);
typedef void *(*hs_sh_hook_addr_fn)(void *, void *, void **);

static void *g_sh_handle = NULL;
static hs_sh_init_fn sh_init = NULL;
static hs_sh_msg_fn sh_to_errmsg = NULL;
static hs_sh_errno_fn sh_get_errno = NULL;
static hs_sh_hook_fn sh_hook_sym_name = NULL;
static hs_sh_hook_addr_fn sh_hook_sym_addr = NULL;

/** Assign a dlsym result without the object/function pointer cast warning. */
#define HS_DLSYM(h, symbol, ptr) do { *(void **) (void *) &(ptr) = dlsym((h), (symbol)); } while (0)

static int hs_load_shadowhook(void) {
    if (g_sh_handle != NULL) {
        return 0;
    }

    /*
     * The plain soname first: the module's classloader namespace already carries the APK's
     * lib directory on its search path. The sibling lookup is the fallback for when this
     * code is reached through a namespace that does not — in the APK the two libraries sit
     * next to each other, so libhupushield.so's own path locates libshadowhook.so.
     */
    g_sh_handle = dlopen("libshadowhook.so", RTLD_NOW | RTLD_LOCAL);
    if (g_sh_handle == NULL) {
        Dl_info info;
        if (dladdr((void *) &hs_load_shadowhook, &info) != 0 && info.dli_fname != NULL) {
            const char *slash = strrchr(info.dli_fname, '/');
            char alt[512];
            if (slash != NULL) {
                size_t n = (size_t) (slash - info.dli_fname) + 1;
                if (n + 20 < sizeof(alt)) {
                    memcpy(alt, info.dli_fname, n);
                    snprintf(alt + n, sizeof(alt) - n, "libshadowhook.so");
                    nlogf("shadowhook: soname dlopen failed (%s), retrying %s", dlerror(), alt);
                    g_sh_handle = dlopen(alt, RTLD_NOW | RTLD_LOCAL);
                }
            }
        }
    }
    if (g_sh_handle == NULL) {
        nlogf("shadowhook: dlopen failed: %s", dlerror());
        return -1;
    }

    HS_DLSYM(g_sh_handle, "shadowhook_init", sh_init);
    HS_DLSYM(g_sh_handle, "shadowhook_to_errmsg", sh_to_errmsg);
    HS_DLSYM(g_sh_handle, "shadowhook_get_errno", sh_get_errno);
    HS_DLSYM(g_sh_handle, "shadowhook_hook_sym_name", sh_hook_sym_name);
    HS_DLSYM(g_sh_handle, "shadowhook_hook_sym_addr", sh_hook_sym_addr);
    if (sh_init == NULL || sh_hook_sym_name == NULL) {
        nlog_line("shadowhook: dlopen succeeded but required symbols are missing");
        return -1;
    }

    nlog_line("shadowhook: loaded via dlopen (not linked)");
    return 0;
}

/** Errno text for a failed hook call, tolerating a partially resolved ShadowHook. */
static const char *hs_sh_reason(void) {
    if (sh_to_errmsg == NULL || sh_get_errno == NULL) {
        return "shadowhook call failed";
    }
    return sh_to_errmsg(sh_get_errno());
}

static int (*orig_dl_iterate_phdr)(int (*)(struct dl_phdr_info *, size_t, void *), void *) = NULL;
static int (*orig_sigaction)(int, const struct sigaction *, struct sigaction *) = NULL;

static volatile int g_dl_hidden = 0;
static volatile int g_sig_blocked = 0;
static volatile int g_dl_survey_done = 0;

/*
 * NOT const, and that word cost two full test rounds.
 *
 * Declared `const`, this landed in .rodata — a read-only mapping — while the trampoline
 * below writes into it with strncpy. Every dl_iterate_phdr call therefore died with
 * SIGSEGV / SEGV_ACCERR, i.e. a permission fault rather than a bad address, which is the
 * tombstone's way of saying "you wrote to a read-only page":
 *
 *   #00 strncpy+24                      libc.so
 *   #01 libhupushield.so                <- the trampoline
 *   #02 __dl__Z18do_dl_iterate_phdr...  linker64
 *   #04 dl_iterate_phdr                 libdl.so
 *   #05 libhupushield.so
 *   #06-#10 libshadowhook.so
 *
 * The visible symptom was misleading: the native log stopped dead right after
 * "hook dl_iterate_phdr -> ok", which looked exactly like ShadowHook deadlocking on its own
 * lock, and the tombstones never reached logcat, so the process appeared to die silently.
 * The re-entrancy guard above is kept as genuine hygiene, but it was not the bug.
 */
static char DL_SURVEY[512][192];
static volatile int g_dl_survey_count = 0;

static int hs_is_tripwire_signal(int s) {
    return s == SIGILL || s == SIGTRAP || s == SIGBUS || s == SIGSEGV;
}

/** Library the current caller lives in — how we avoid breaking ART's own handlers. */
static const char *hs_caller_lib(void) {
    static __thread char buf[256];
    buf[0] = '\0';
    Dl_info info;
    void *ra = __builtin_return_address(0);
    if (ra != NULL && dladdr(ra, &info) != 0 && info.dli_fname != NULL) {
        strncpy(buf, info.dli_fname, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
    }
    return buf;
}

static int hs_module_is_hidden(const char *name) {
    if (name == NULL || name[0] == '\0') {
        return 0; /* the main executable is reported with an empty name */
    }
    if (name[0] != '/') {
        return 1; /* anything that is not a real path is an injected mapping */
    }
    for (size_t i = 0; i < sizeof(MAPS_DROP) / sizeof(MAPS_DROP[0]); i++) {
        if (strstr(name, MAPS_DROP[i]) != NULL) {
            return 1;
        }
    }
    if (strstr(name, "memfd") != NULL) {
        return 1;
    }
    return 0;
}

struct hs_dl_ctx {
    int (*user_cb)(struct dl_phdr_info *, size_t, void *);
    void *user_data;
};

static int hs_dl_trampoline(struct dl_phdr_info *info, size_t size, void *arg) {
    struct hs_dl_ctx *c = (struct hs_dl_ctx *) arg;
    const char *name = info->dlpi_name;

    /*
     * Survey first: guessing what an injected module looks like is exactly the mistake
     * that wasted a whole round on the maps keyword list. Record every distinct name once.
     */
    if (!g_dl_survey_done && name != NULL) {
        int known = 0;
        for (int i = 0; i < g_dl_survey_count; i++) {
            if (strncmp(DL_SURVEY[i], name, sizeof(DL_SURVEY[0]) - 1) == 0) {
                known = 1;
                break;
            }
        }
        if (!known && g_dl_survey_count < 512) {
            strncpy((char *) DL_SURVEY[g_dl_survey_count], name, sizeof(DL_SURVEY[0]) - 1);
            __android_log_print(ANDROID_LOG_INFO, TAG, "[dl_iterate_phdr] sees: %s", name);
            g_dl_survey_count++;
        }
    }

    if (hs_module_is_hidden(name)) {
        if (g_dl_hidden < 20) {
            g_dl_hidden++;
            __android_log_print(ANDROID_LOG_INFO, TAG, "[dl_iterate_phdr] HIDING: %s", name);
        }
        return 0; /* pretend this module is not loaded */
    }
    return c->user_cb(info, size, c->user_data);
}

static __thread int hs_in_dl_iterate = 0;

static int hs_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (orig_dl_iterate_phdr == NULL) {
        return -1;
    }

    /*
     * Re-entrancy guard, and it is not theoretical: hook machinery asks the linker the very
     * question we are intercepting — resolving where a library is loaded means walking the
     * module list. A nested call must reach the real function untouched, otherwise it
     * re-enters this filter while the outer caller still holds its own internal lock, and
     * the process stops dead at exactly the point the first hook was installed.
     */
    if (hs_in_dl_iterate) {
        return orig_dl_iterate_phdr(cb, data);
    }

    struct hs_dl_ctx c;
    c.user_cb = cb;
    c.user_data = data;
    hs_in_dl_iterate = 1;
    int r = orig_dl_iterate_phdr(hs_dl_trampoline, &c);
    hs_in_dl_iterate = 0;
    return r;
}

static int hs_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    if (act != NULL && hs_is_tripwire_signal(signum)) {
        const char *lib = hs_caller_lib();
        if (strstr(lib, "nesec") != NULL || strstr(lib, "nshelper") != NULL) {
            if (g_sig_blocked < 20) {
                g_sig_blocked++;
                __android_log_print(ANDROID_LOG_INFO, TAG,
                                    "[sigaction] NEUTRALISED signal %d from %s", signum, lib);
            }
            return 0; /* report success, install nothing — ART keeps its own handlers */
        }
    }
    return orig_sigaction != NULL ? orig_sigaction(signum, act, oldact) : -1;
}

static void install_inline_hooks(void) {
    if (hs_load_shadowhook() != 0) {
        nlog_line("inline hooks: SKIPPED, shadowhook unavailable");
        return;
    }

    int r = sh_init(SHADOWHOOK_MODE_UNIQUE, false);
    nlogf("shadowhook_init -> %d (%s)", r, sh_to_errmsg != NULL ? sh_to_errmsg(r) : "?");

    /*
     * sigaction first, deliberately. It is the known-good hook, and it must be in place even
     * if the dl_iterate_phdr hook below turns out to be the thing that kills the process —
     * ordering these the other way round cost a full test round: the log stopped dead right
     * after "hook dl_iterate_phdr -> ok" and sigaction never got installed at all.
     */
    nlog_line("inline: hooking sigaction");
    void *stub = sh_hook_sym_name("libc.so", "sigaction",
                                  (void *) hs_sigaction, (void **) &orig_sigaction);
    nlogf("inline: hook sigaction -> %s", stub == NULL ? hs_sh_reason() : "ok");

    /*
     * dl_iterate_phdr is not where it looks like it is.
     *
     * Asking for it in libc.so fails with "Find symbol in ELF failed", and readelf explains
     * why: on Android 14 bionic, libc.so carries only an UNDEFINED `dl_iterate_phdr@LIBC`
     * placeholder of size 0. The real thing — a 28-byte veneer into the linker — lives in
     * libdl.so as a WEAK symbol. Reference it there, and if the ELF lookup still balks, hook
     * the address dlsym already resolved for us.
     */
    nlog_line("inline: hooking dl_iterate_phdr");
    stub = sh_hook_sym_name("libdl.so", "dl_iterate_phdr",
                            (void *) hs_dl_iterate_phdr,
                            (void **) &orig_dl_iterate_phdr);
    if (stub == NULL) {
        nlogf("inline: libdl.so lookup failed (%s), trying resolved address", hs_sh_reason());
        void *addr = dlsym(RTLD_DEFAULT, "dl_iterate_phdr");
        if (addr != NULL && sh_hook_sym_addr != NULL) {
            stub = sh_hook_sym_addr(addr, (void *) hs_dl_iterate_phdr,
                                    (void **) &orig_dl_iterate_phdr);
        }
    }
    nlogf("inline: hook dl_iterate_phdr -> %s", stub == NULL ? hs_sh_reason() : "ok");
    nlog_line("inline: hooks done");
}
#endif /* HS_HAVE_SHADOWHOOK */

/* --------------------------------------------------- openat tracer (user notif) */

/*
 * Step 1 of the "fake the evidence" plan, and cheap on its own: intercept every openat and
 * report the path, then let the syscall run for real. Nothing is faked and no behaviour is
 * changed — the point is to finally see what the shell reads before it decides to die.
 *
 * Why seccomp and not a GOT hook: the decision happens inside libnesec's JNI_OnLoad, i.e.
 * before dlopen returns, so a GOT patch on that library is structurally too late. A seccomp
 * filter takes effect at the syscall boundary itself, where inlining cannot dodge it.
 */

static volatile int g_listener_fd = -1;
static volatile int g_openat_seen = 0;
/* Syscalls answered with -ENOENT because they named /data/adb or something under it. */
static volatile int g_adb_denied = 0;
/* Stat-family notifications actually observed — tells us whether the filter covers the
 * thread the shell probes from. */
static volatile int g_stat_seen = 0;
static volatile int g_fake_maps = 0;
static volatile int g_maps_faked = 0;
/* Maps opens left untouched because they came from the unwinder, not the shell. */
static volatile int g_maps_real_passthrough = 0;

/*
 * Opened before the filter exists, deliberately.
 *
 * The filter is installed with TSYNC so that every thread — including the shell's background
 * workers — sees the faked maps. That also puts the filter on this supervisor, which must
 * therefore never issue openat. Re-reading through a pre-opened descriptor needs only
 * lseek + read, neither of which is intercepted.
 */
static volatile int g_maps_fd = -1;

/* Threads observed reading the map table (see the tid logging in the supervisor). */
static int g_maps_tids[16];
static int g_maps_unique_tids = 0;
/* (mmap/mprotect observation was removed from the filter; nothing logs here any more.) */

/*
 * Deliberately small.
 *
 * Every one of these lines is a blocking __android_log_print from the supervisor — the one
 * thread that must never stall, because every filtered openat in the process is waiting on
 * it. 500 lines was enough to starve ART's unwinder and produce an ANR. 30 is plenty to see
 * the shape of the traffic.
 */
#define OPENAT_LOG_LIMIT 30

/** Substring search over an explicit length (the maps buffer is not NUL-terminated per line). */
static int contains_at(const char *hay, size_t hlen, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > hlen) {
        return 0;
    }
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Decide whether one maps line should be removed.
 *
 * Keyword matching alone was useless: Zygisk/LSPosed payloads are loaded from memory via
 * memfd, so their mappings carry NO file pathname at all — the survey found only the app's
 * own libnesec.so among non-system libraries. What gives injected code away is instead the
 * shape of the line: an executable mapping with no pathname behind it (or one pointing at a
 * memfd). Legitimate JIT regions are labelled with a [bracket] pseudo-name, so requiring
 * "no pathname at all" keeps those intact.
 *
 * Returns 1 to drop.
 */
/*
 * The package this process belongs to, recovered from the log path we were handed
 * ("/sdcard/Android/data/<pkg>/files/hupushield.log").
 *
 * This is the rule that actually matters. The maps snapshot of a live Hupu process showed
 * exactly one incriminating line, and it was not any of the guessed keywords:
 *
 *   /data/app/~~EZUyzBqwQjzgVoUX9UZQzA==/com.dsh.hupushield-PSoHRqhLixUMvqaGHbaQzQ==/base.apk
 *
 * The keyword table held "libhupushield" — the .so name — which that path does not contain,
 * so the line sailed straight through. More generally: from inside the target process, an
 * APK under /data/app belonging to some OTHER package is precisely what an Xposed module
 * looks like, whatever it is called. Keep our own and drop the rest.
 */
static char g_own_pkg[128];

static void hs_own_pkg_init(void) {
    if (g_own_pkg[0] != '\0') {
        return;
    }
    const char *marker = "/Android/data/";
    const char *p = strstr(g_log_path, marker);
    if (p == NULL) {
        return;
    }
    p += strlen(marker);
    const char *e = strchr(p, '/');
    size_t n = (e == NULL) ? strlen(p) : (size_t) (e - p);
    if (n == 0 || n >= sizeof(g_own_pkg)) {
        return;
    }
    memcpy(g_own_pkg, p, n);
    g_own_pkg[n] = '\0';
}

/** Lines that looked injected but were deliberately KEPT — logged so this stays honest. */
static volatile int g_maps_kept_anon = 0;

static int maps_line_is_suspicious(const char *line, size_t len) {
    hs_own_pkg_init();

    /* (1) Named artefacts. Belt and braces for modules other than our own. */
    for (size_t i = 0; i < sizeof(MAPS_DROP) / sizeof(MAPS_DROP[0]); i++) {
        if (contains_at(line, len, MAPS_DROP[i])) {
            return 1;
        }
    }

    /* (2) The evidence-backed rule: any /data/app entry that is not this app's own. */
    if (contains_at(line, len, "/data/app/")) {
        if (g_own_pkg[0] != '\0' && !contains_at(line, len, g_own_pkg)) {
            return 1;
        }
    }

    /*
     * (3) Anonymous executable mappings are NOT dropped any more.
     *
     * An earlier revision dropped these, plus anything whose path mentioned "memfd", on the
     * guess that injected code must look like that. Two problems with it. ART's own JIT
     * caches are literally /memfd:jit-cache and /memfd:jit-zygote-cache, so the rule deleted
     * perfectly normal entries and manufactured exactly the kind of gap a detector looks for.
     * And the survey of a real process never showed such a mapping in the first place.
     *
     * So they are counted and reported instead, which keeps the observation without betting
     * the whole approach on a guess.
     */
    int fields = 0;
    int exec = 0;
    size_t i = 0;
    size_t path_start = len;
    while (i < len) {
        while (i < len && (line[i] == ' ' || line[i] == '\t')) {
            i++;
        }
        if (i >= len) {
            break;
        }
        size_t start = i;
        while (i < len && line[i] != ' ' && line[i] != '\t') {
            i++;
        }
        fields++;
        if (fields == 2) {
            for (size_t k = start; k < i; k++) {
                if (line[k] == 'x') {
                    exec = 1;
                    break;
                }
            }
        }
        if (fields == 5) {
            path_start = i;
            break;
        }
    }
    while (path_start < len && (line[path_start] == ' ' || line[path_start] == '\t')) {
        path_start++;
    }
    if (exec && path_start >= len && g_maps_kept_anon < 20) {
        g_maps_kept_anon++;
        __android_log_print(ANDROID_LOG_INFO, TAG, "[maps kept] anonymous exec: %.*s",
                            (int) (len > 120 ? 120 : len), line);
    }
    return 0;
}

static int is_maps_path(const char *path) {
    if (path == NULL) {
        return 0;
    }
    if (strcmp(path, "/proc/self/maps") == 0) {
        return 1;
    }
    char own[64];
    snprintf(own, sizeof(own), "/proc/%d/maps", getpid());
    return strcmp(path, own) == 0;
}

/*
 * Produce a memfd holding /proc/self/maps with every injection artefact removed. The
 * supervisor runs unfiltered (it is created before seccomp() and the filter is installed
 * without TSYNC), so it can open and read the real file itself.
 *
 * The filtered text is cached for 100 ms: maps barely changes over the few hundred
 * milliseconds this process lives, and the shell opens it hundreds of times.
 */
static int build_filtered_maps_fd(int *dropped_out) {
    static char raw[1024 * 1024];
    static char filtered[1024 * 1024];
    static size_t filtered_len = 0;
    static long last_ms = 0;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long now = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;

    if (filtered_len == 0 || now - last_ms > 100) {
        if (g_maps_fd < 0) {
            return -1;
        }
        /*
         * /proc files are generated lazily: a single read() hands back roughly one page, so
         * the whole table only arrives if we loop to EOF. Reading once was silently
         * truncating the maps to its first ~4 KB — which contains no application mappings at
         * all, and therefore nothing to strip.
         *
         * The descriptor is rewound instead of reopened (see g_maps_fd).
         */
        if (lseek(g_maps_fd, 0, SEEK_SET) != 0) {
            return -1;
        }
        size_t total = 0;
        for (;;) {
            if (total >= sizeof(raw) - 1) {
                break;
            }
            ssize_t r = read(g_maps_fd, raw + total, sizeof(raw) - 1 - total);
            if (r <= 0) {
                break;
            }
            total += (size_t) r;
        }
        if (total == 0) {
            return -1;
        }
        raw[total] = '\0';
        ssize_t n = (ssize_t) total;

        size_t out = 0;
        int dropped = 0;
        char *p = raw;
        while (*p != '\0') {
            char *nl = strchr(p, '\n');
            size_t len = (nl == NULL) ? strlen(p) : (size_t) (nl - p + 1);
            int bad = maps_line_is_suspicious(p, len);
            if (bad) {
                dropped++;
            } else if (out + len < sizeof(filtered)) {
                memcpy(filtered + out, p, len);
                out += len;
            }
            if (nl == NULL) {
                break;
            }
            p = nl + 1;
        }
        filtered_len = out;
        last_ms = now;

        /*
         * Report the libraries the filter table does not already cover, i.e. anything mapped
         * from outside the system partitions. That list is what an Xposed probe is reading
         * for, and it is how we learn the real names to strip — guessing keywords was
         * demonstrably wrong (the first run dropped zero lines).
         */
        {
            /*
             * Survey the first few snapshots, not just the first one. The earliest maps a
             * probe asks for is a ~4 KB, ~57-entry table from the freshly forked process —
             * no app libraries, no injections. The interesting one is after libnesec and the
             * LSPosed payload are mapped, which lands in a later refresh.
             */
            static int surveys = 0;
            if (surveys < 6) {
                surveys++;
                int shown = 0;
                int dataApp = 0;
                char *q = raw;
                while (*q != '\0' && shown < 30) {
                    char *e = strchr(q, '\n');
                    size_t l = (e == NULL) ? strlen(q) : (size_t) (e - q);
                    if (l > 0 && contains_at(q, l, ".so")
                        && !contains_at(q, l, "/system")
                        && !contains_at(q, l, "/apex")
                        && !contains_at(q, l, "/vendor")
                        && !contains_at(q, l, "/dev/")) {
                        __android_log_print(ANDROID_LOG_INFO, TAG, "[maps survey %d] %.*s",
                                            surveys, (int) l, q);
                        shown++;
                    }
                    if (l > 0 && contains_at(q, l, "/data/app")) {
                        dataApp++;
                    }
                    if (e == NULL) {
                        break;
                    }
                    q = e + 1;
                }
                __android_log_print(ANDROID_LOG_INFO, TAG,
                                    "maps survey %d: raw=%zd bytes, data_app_lines=%d, "
                                    "non_system_so_shown=%d, dropped=%d, out=%zu",
                                    surveys, n, dataApp, shown, dropped, out);
            }
        }

        if (dropped_out != NULL) {
            *dropped_out = dropped;
        }
    } else if (dropped_out != NULL) {
        *dropped_out = -1; /* cached */
    }

    int mfd = (int) syscall(__NR_memfd_create, "hs_maps", 0);
    if (mfd < 0) {
        return -1;
    }
    size_t written = 0;
    while (written < filtered_len) {
        ssize_t w = write(mfd, filtered + written, filtered_len - written);
        if (w <= 0) {
            break;
        }
        written += (size_t) w;
    }
    lseek(mfd, 0, SEEK_SET);
    return mfd;
}

/*
 * Supervisor thread.
 *
 * Hard rule: this thread must never issue openat itself. Every openat in a filtered thread
 * blocks until this thread answers it, so a supervisor that opened a file would wait on a
 * notification only it could deliver — deadlock. Hence logcat only (a pre-opened socket and
 * a plain write), never the file logger.
 *
 * It is created before seccomp() runs and the filter is installed without TSYNC, so the
 * supervisor itself carries no filter at all, while the installing thread (the main thread,
 * which is where handleBindApplication and the shell's native init both run) does.
 */
static void *openat_supervisor(void *arg) {
    (void) arg;
    __android_log_print(ANDROID_LOG_INFO, TAG, "openat supervisor started, awaiting fd");

    while (g_listener_fd < 0) {
        usleep(500);
    }
    int fd = g_listener_fd;
    __android_log_print(ANDROID_LOG_INFO, TAG, "openat supervisor armed on fd %d", fd);

    for (;;) {
        struct hs_seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(fd, HS_NOTIF_RECV, &req) != 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "openat RECV failed: %s", strerror(errno));
            usleep(1000);
            continue;
        }

        long nr = (long) req.data.nr;
        int dirfd = (int) req.data.args[0];
        unsigned int flags = (unsigned int) req.data.args[2];
        int tid = (int) req.pid;

        /*
         * Snapshot the pathname BEFORE answering. Once ADDFD/SEND completes, the blocked
         * thread is released and may immediately reuse the buffer the string lived in, which
         * is why a later read of `path` produced garbage like "E" or "u" in the logs.
         *
         * Every path-taking syscall in the filter keeps its pathname in args[1].
         */
        int is_path_call = (nr == __NR_openat || nr == __NR_openat2
                            || nr == __NR_newfstatat || nr == __NR_faccessat
                            || nr == __NR_faccessat2 || nr == __NR_statx
                            || nr == __NR_readlinkat);
        char snap[256];
        snap[0] = '\0';
        if (is_path_call) {
            const char *p = (const char *) (uintptr_t) req.data.args[1];
            if (p != NULL) {
                strncpy(snap, p, sizeof(snap) - 1);
                snap[sizeof(snap) - 1] = '\0';
            }
        }

        /* -------------------------------------------------- /data/adb guard */
        /*
         * The one thing left on this device that a detector can still see.
         *
         * /data/adb is 0700 root:root, so an app cannot even traverse it — which means every
         * "/data/adb/..." probe comes back EACCES instead of ENOENT, whether or not the
         * sub-path exists. "Refused" is itself the tell: it says something is being hidden.
         *
         * Measured from the app's own credentials (uid 10452, capability sets verified
         * cleared — KernelSU's su leaves PR_SET_KEEPCAPS on, which otherwise lets
         * CAP_DAC_OVERRIDE walk straight through and makes the test lie):
         *
         *   /data/adb/lspd                     EACCES   <- leak
         *   /data/adb/riru/modules/lspd        EACCES   <- leak
         *   /data/adb/riru/modules/edxp.prop   EACCES   <- leak
         *   /data/adb/riru/modules/dreamland   EACCES   <- leak
         *   /data/adb                          exists   <- weak signal
         *
         * while all 27 other paths the shell probes — Xposed, Magisk, Riru, su, Frida,
         * cloud-phone — come back ENOENT and are clean.
         *
         * So the whole fix is this prefix test. It runs first, touches no locks, and does no
         * I/O after the first few lines: the supervisor is the single point every filtered
         * syscall in the process waits on, and a blocking log call here is what turned an
         * earlier build into an ANR.
         */
        if (snap[0] == '/' && strncmp(snap, "/data/adb", 9) == 0
            && (snap[9] == '\0' || snap[9] == '/')) {
            int n = ++g_adb_denied;
            if (n <= 20) {
                __android_log_print(ANDROID_LOG_INFO, TAG,
                                    "ADB HIDE #%d: %s -> ENOENT (nr=%ld tid=%d)",
                                    n, snap, nr, tid);
            }
            struct hs_seccomp_notif_resp deny;
            memset(&deny, 0, sizeof(deny));
            deny.id = req.id;
            deny.error = ENOENT;
            ioctl(fd, HS_NOTIF_SEND, &deny);
            continue;
        }

        if (!is_path_call) {
            struct hs_seccomp_notif_resp r2;
            memset(&r2, 0, sizeof(r2));
            r2.id = req.id;
            r2.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            ioctl(fd, HS_NOTIF_SEND, &r2);
            continue;
        }

        /*
         * The stat family exists in this filter only to feed the guard above. Once /data/adb
         * is out of the way there is nothing to fake for them, and they are far too frequent
         * to do anything else with — answer immediately and do not log.
         */
        if (nr != __NR_openat && nr != __NR_openat2) {
            /*
             * Diagnostic, and it answers a structural question rather than a behavioural one.
             * A NEW_LISTENER filter cannot carry TSYNC, so it binds to the installing thread
             * alone (plus whatever that thread goes on to create). If the shell's path probes
             * run on some ART thread that already existed, this counter stays at zero and no
             * amount of path logic will ever see them.
             */
            if (g_stat_seen < 25) {
                g_stat_seen++;
                __android_log_print(ANDROID_LOG_INFO, TAG,
                                    "STAT #%d: nr=%ld tid=%d %s", g_stat_seen, nr, tid, snap);
            }
            struct hs_seccomp_notif_resp r3;
            memset(&r3, 0, sizeof(r3));
            r3.id = req.id;
            r3.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            ioctl(fd, HS_NOTIF_SEND, &r3);
            continue;
        }

        int is_maps = is_maps_path(snap);
        if (is_maps) {
            /*
             * Record which threads read the map table. If every read comes from a single
             * thread, per-thread filters cannot be what is missing and the cause lies
             * elsewhere; if several threads appear, covering them is the next move.
             */
            int known = 0;
            for (int i = 0; i < g_maps_unique_tids; i++) {
                if (g_maps_tids[i] == tid) {
                    known = 1;
                    break;
                }
            }
            if (!known && g_maps_unique_tids < 16) {
                g_maps_tids[g_maps_unique_tids++] = tid;
                __android_log_print(ANDROID_LOG_INFO, TAG,
                                    "maps read from tid=%d (distinct so far: %d)",
                                    tid, g_maps_unique_tids);
            }
        }

        /* Same address space as the blocked thread, so the pointer is readable as-is. */
        if (snap[0] != '\0' && g_openat_seen < OPENAT_LOG_LIMIT) {
            g_openat_seen++;
            __android_log_print(ANDROID_LOG_INFO, TAG, "[openat %d] dirfd=%d flags=0x%x %s",
                                g_openat_seen, dirfd, flags, snap);
        } else if (g_openat_seen == OPENAT_LOG_LIMIT) {
            g_openat_seen++;
            __android_log_print(ANDROID_LOG_INFO, TAG, "openat trace: limit reached");
        }

        /*
         * For a maps read, hand back a memfd whose contents have the injection artefacts
         * stripped, so the probe finds nothing. ADDFD installs that fd straight into the
         * target's table and completes the syscall with it — which is the one thing a
         * seccomp response can do that a userspace hook cannot do reliably.
         */
        /*
         * The unwinder must be given the REAL table.
         *
         * Two different callers ask for /proc/self/maps, and their flags tell them apart.
         * The shell asks with plain flags 0. ART's in-process crash dumper asks with
         * O_CLOEXEC|O_NONBLOCK (0x88000), and it is the one caller that must never be lied
         * to: unwindstack resolves every stack frame through those mappings. Feeding it the
         * filtered table made it time out in unwindstack::ThreadEntry::Wait, froze the main
         * thread for ten seconds and turned what used to be a fast death into an ANR.
         *
         * The ANR trace named the culprit outright — libnesec.so raising a signal, ART's
         * SignalChain catching it, then debuggerd_fallback_handler never finishing:
         *
         *   #11 __dl_debuggerd_fallback_handler
         *   #13 art::SignalChain::Handler
         *   #15 .../com.hupu.games/lib/arm64/libnesec.so
         *
         * So: plain reads get the fiction, non-blocking reads get the truth.
         */
        int unwinder_read = (flags & O_NONBLOCK) != 0;

        if (g_fake_maps && is_maps) {
            int dropped = 0;
            int mfd = -1;
            if (unwinder_read) {
                if (g_maps_real_passthrough < 5) {
                    g_maps_real_passthrough++;
                    __android_log_print(ANDROID_LOG_INFO, TAG,
                                        "MAPS REAL (unwinder, flags=0x%x, tid=%d)", flags, tid);
                }
            } else {
                mfd = build_filtered_maps_fd(&dropped);
            }
            if (mfd >= 0) {
                struct hs_seccomp_notif_addfd add;
                memset(&add, 0, sizeof(add));
                add.id = req.id;
                /*
                 * Auto-allocate the descriptor (no SETFD).
                 *
                 * Pinning a fixed number seemed like good hygiene against descriptor growth,
                 * but it measurably broke things: the shell evidently holds several map
                 * descriptors at once, so a pinned number clobbered the earlier ones and the
                 * surviving process died in the fast loop again (~2 s vs ~11 s). Each
                 * injection therefore gets its own descriptor, as the kernel intends.
                 */
                add.flags = SECCOMP_ADDFD_FLAG_SEND;
                add.srcfd = (__u32) mfd;
                add.newfd = 0;
                add.newfd_flags = O_CLOEXEC;
                /*
                 * ADDFD returns the NEW FD NUMBER on success, not 0. Checking for zero here
                 * is what made an earlier build report "ADDFD failed: Success" while the
                 * faking was in fact working — and then fall through to a SEND for a
                 * notification that no longer existed (hence the ENOENT that followed).
                 */
                long ret = ioctl(fd, HS_NOTIF_ADDFD, &add);
                if (ret >= 0) {
                    if (g_maps_faked < 10) {
                        g_maps_faked++;
                        __android_log_print(ANDROID_LOG_INFO, TAG,
                                            "MAPS FAKED (#%d, tid=%d, %s, dropped=%d, newfd=%ld)",
                                            g_maps_faked, tid, snap, dropped, ret);
                    }
                    close(mfd);
                    continue;
                }
                __android_log_print(ANDROID_LOG_WARN, TAG,
                                    "ADDFD failed ret=%ld errno=%d (%s)", ret, errno,
                                    strerror(errno));
                close(mfd);
            } else if (!unwinder_read) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "filtered maps fd failed: %s",
                                    strerror(errno));
            }
        }

        struct hs_seccomp_notif_resp resp;
        memset(&resp, 0, sizeof(resp));
        resp.id = req.id;
        resp.val = 0;
        resp.error = 0;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; /* let the real syscall proceed */
        if (ioctl(fd, HS_NOTIF_SEND, &resp) != 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "openat SEND failed: %s", strerror(errno));
        }
    }
    return NULL;
}

static int install_openat_tracer(void) {
    struct sock_filter filter[] = {
            /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (__u32) offsetof(struct seccomp_data, arch)),
            /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
            /* 2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            /* 3 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (__u32) offsetof(struct seccomp_data, nr)),
            /*
             * openat, but only READ-ONLY ones.
             *
             * Notifying on every openat is what caused the ANR. Java's own log writes go
             * through openat with O_WRONLY|O_CREAT|O_APPEND, and the module writes a heartbeat
             * every 250 ms — each one became a full round trip to the supervisor, whose reply
             * path runs through blocking logd writes. That load was enough to starve ART's
             * in-process unwinder when it asked for the maps during an ANR dump, which froze
             * the main thread for ten seconds and got the process SIGKILLed.
             *
             * BPF cannot read the pathname, but the flags are a register and say the same
             * thing for our purposes: the map table is opened read-only (0x0, or 0x88000 with
             * O_CLOEXEC|O_NONBLOCK), while anything being written is not a map read. Testing
             * O_ACCMODE removes the whole self-inflicted round-trip storm.
             *
             * mmap/mprotect are gone from this filter. They were here to watch for
             * executable mappings, and the answer came back negative: a survey of live
             * processes showed Zygisk leaves no anonymous executable mapping in the target,
             * and the only rwx region in Hupu belongs to Yidun's own unpacker. Paying a round
             * trip on every executable mmap bought nothing.
             *
             * What replaced them is the stat family, which is what the /data/adb guard needs.
             * BPF still cannot read a pathname, so those calls are narrowed as far as the
             * registers allow: only AT_FDCWD (absolute) paths are worth a notification, since
             * that is the form every root probe takes. openat keeps its read-only test, which
             * is what keeps the module's own log writes out of the loop.
             */
            /* 4 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 8, 0),
            /* 5 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat2, 11, 0),
            /* 6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 10, 0),
            /* 7 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat, 9, 0),
            /* 8 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat2, 8, 0),
            /* 9 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_statx, 7, 0),
            /*10 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readlinkat, 6, 0),
            /*11 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            /*12 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            /* -- openat arm: notify only when (flags & O_ACCMODE) == 0 -- */
            /*13 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (__u32) offsetof(struct seccomp_data, args[2])),
            /*14 */ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, (__u32) O_ACCMODE),
            /*15 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, 0),
            /*16 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            /* -- stat arm: notify only when the dirfd is AT_FDCWD -- */
            /*17 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (__u32) offsetof(struct seccomp_data, args[0])),
            /*18 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (__u32) -100, 2, 0),
            /*19 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            /*20 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            /*21 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };
    struct sock_fprog prog;
    prog.len = (unsigned short) (sizeof(filter) / sizeof(filter[0]));
    prog.filter = filter;

    pthread_t t;
    if (pthread_create(&t, NULL, openat_supervisor, NULL) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "openat tracer: supervisor thread failed");
        return -1;
    }
    pthread_detach(t);

    /* Must happen while no filter is in force yet (see g_maps_fd). */
    if (g_maps_fd < 0) {
        g_maps_fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
        if (g_maps_fd < 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "openat tracer: maps fd failed: %s",
                                strerror(errno));
            return -1;
        }
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "openat tracer: NO_NEW_PRIVS failed: %s",
                            strerror(errno));
        return -1;
    }

    /*
     * TSYNC so the filter covers every thread, not just this one: a shell that reads /proc
     * for its checks from a background worker would otherwise still see the true map table.
     * If the kernel refuses to sync (a thread stuck in a syscall can block it), fall back to
     * the installing thread only rather than losing the filter altogether.
     */
    long fd = syscall(__NR_seccomp, (long) SECCOMP_SET_MODE_FILTER,
                      (long) (SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_TSYNC),
                      &prog);
    int tsync = 1;
    if (fd < 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "seccomp NEW_LISTENER|TSYNC failed: %s",
                            strerror(errno));
        tsync = 0;
        fd = syscall(__NR_seccomp, (long) SECCOMP_SET_MODE_FILTER,
                     (long) SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    }
    if (fd < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "openat tracer: seccomp(NEW_LISTENER) failed: %s", strerror(errno));
        return -1;
    }
    g_listener_fd = (int) fd;
    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "openat tracer ARMED, listener fd=%ld tsync=%d installing_tid=%d",
                        fd, tsync, (int) syscall(__NR_gettid));
    return 0;
}

/* ---------------------------------------------------------------------- JNI */

/*
 * Defined explicitly, and not only for tidiness.
 *
 * ART resolves this symbol with dlsym(handle, "JNI_OnLoad"), which walks the dependency
 * chain — so a library that does not define it can end up executing a dependency's version
 * instead. That is precisely how the ShadowHook build killed this module. Owning the symbol
 * here makes the entry point unambiguous no matter what gets linked or dlopen'd later.
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) vm;
    (void) reserved;
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
Java_com_dsh_hupushield_Native_nativeInit(JNIEnv *env, jclass clazz, jstring jpath, jint flags) {
    pthread_mutex_init(&g_lock, NULL);
    if (jpath != NULL) {
        const char *p = (*env)->GetStringUTFChars(env, jpath, NULL);
        if (p != NULL) {
            strncpy(g_log_path, p, sizeof(g_log_path) - 1);
            g_log_path[sizeof(g_log_path) - 1] = '\0';
            (*env)->ReleaseStringUTFChars(env, jpath, p);
        }
    }
    g_block = (flags & HS_FLAG_BLOCK_NATIVE) ? 1 : 0;
    g_trace = (flags & (HS_FLAG_TRACE_OPENAT | HS_FLAG_FAKE_MAPS)) ? 1 : 0;
    g_fake_maps = (flags & HS_FLAG_FAKE_MAPS) ? 1 : 0;
    g_inline_hooks = (flags & HS_FLAG_INLINE_HOOKS) ? 1 : 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    g_t0 = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
    nlogf("nativeInit ok: flags=0x%x block=%d trace=%d fakeMaps=%d log=%s",
          flags, g_block, g_trace, g_fake_maps, g_log_path);
}

JNIEXPORT void JNICALL
Java_com_dsh_hupushield_Native_nativeInstall(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    if (g_installed) {
        return;
    }
    g_installed = 1;
    /* Debug on: xhook reports every library and symbol it rewrites (logcat tag "xhook"),
     * which is the only way to confirm the patch actually lands on libnesec.so. */
    xhook_enable_debug(1);
    register_all();
    int r = xhook_refresh(0);
    nlogf("xhook_refresh (initial) -> %d", r);

    if (g_trace) {
        /* Mutually exclusive with the blocker: each installs its own seccomp filter, and
         * step 1 is about observing, not about changing behaviour. */
        install_openat_tracer();
        return;
    }

    /*
     * Install the seccomp filter before the shell gets anywhere near its native check: the
     * filter is inherited by every thread created afterwards, which is what makes it cover
     * the exit_group call we can find no other way to intercept.
     */
    if (g_block) {
        /*
         * ORDER MATTERS. The seccomp filter refuses rt_sigaction(SIGILL), which is what stops
         * the shell from restoring SIG_DFL before trapping — but that same refusal applies to
         * us. Installing the handler first is therefore mandatory; doing it the other way
         * round makes our own sigaction() fail with EPERM and leaves us with no handler at
         * all (which is exactly what build 2.2 did).
         */
        if (install_sigill_handler() == 0) {
            nlog_line("SIGILL handler installed BEFORE seccomp (required order)");
            start_sigill_watchdog();
        } else {
            nlog_line("SIGILL handler could not be installed; continuing without it");
        }
        install_seccomp_block();
        /*
         * Second, separate filter. The blocker above covers every thread; this one needs a
         * listener, and the kernel refuses to hand one to a TSYNC install, so it necessarily
         * binds to this thread only — which is exactly the thread the shell traps on.
         */
        install_sigprocmask_guard();
    } else {
        nlog_line("seccomp/SIGILL: skipped (observe-only mode)");
    }

    /*
     * Inline hooks go LAST, also deliberately.
     *
     * seccomp is the primary weapon — it is the only layer that can see the shell's raw
     * `svc` exit_group — while the inline hooks are secondary. Running them first cost a
     * round: the process died inside install_inline_hooks() and the seccomp filter, the
     * thing that actually matters, had not been installed yet. Whatever the inline hooks do
     * from here on, the primary protection is already in place.
     */
#ifdef HS_HAVE_SHADOWHOOK
    if (g_inline_hooks) {
        install_inline_hooks();
    }
#endif
}

/**
 * Called from Java the moment Runtime.loadLibrary0 returns, so a freshly loaded library
 * (libnesec.so) gets its GOT patched before the shell makes its next native call.
 */
JNIEXPORT void JNICALL
Java_com_dsh_hupushield_Native_nativeRefresh(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    register_all();
    int r = xhook_refresh(0);
    nlogf("xhook_refresh (after loadLibrary0) -> %d", r);
}
