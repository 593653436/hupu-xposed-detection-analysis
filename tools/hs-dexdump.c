/*
 * hs-dexdump — carve decrypted DEX images out of a live process's memory.
 *
 * Why this is needed: Yidun's shell dex is 100 MB of which the header describes only 30
 * classes. Its real detection strings — the paths we watched it probe with faccessat — do
 * not appear anywhere in the file, in either the packed or the unpacked build of Hupu.
 * They are decrypted at runtime, so the only way to read the check is to catch the dex
 * after the packer has produced it and before the process dies.
 *
 * The check runs BEFORE the code is used, so the decrypted image is guaranteed to exist by
 * the time anything interesting happens — we just have to be quick and thorough.
 *
 * Reading /proc/<pid>/mem needs PTRACE_MODE_ATTACH, which SELinux refuses for untrusted_app
 * on this device (dontaudit hides the denial). Run with SELinux permissive for the capture.
 *
 * Build: aarch64-linux-android26-clang -O2 -fPIE -pie -o hs-dexdump hs-dexdump.c
 * Use:   hs-dexdump --wait <package> <outdir> [seconds]
 *        hs-dexdump <pid> <outdir> [seconds]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>

#define MAXREG 4096
#define CHUNK  (1024 * 1024)

struct region { unsigned long long start, end; };

static const unsigned char DEXMAGIC[8] = { 'd','e','x','\n','0','3','5','\0' };

static int find_process(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
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

static int load_regions(int pid, struct region *out, int max) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/maps", pid);
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), f) && n < max) {
        unsigned long long s, e;
        char perms[8];
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        /* readable only; skip the huge file-backed system mappings where no dex can live */
        if (perms[0] != 'r') continue;
        if (strstr(line, "/system/") || strstr(line, "/apex/") || strstr(line, "/vendor/")
            || strstr(line, "/system_ext/") || strstr(line, "/product/")) continue;
        out[n].start = s;
        out[n].end = e;
        n++;
    }
    fclose(f);
    return n;
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid>|--wait <pkg> <outdir> [seconds]\n", argv[0]);
        return 2;
    }
    int wait_mode = 0, argi = 1;
    const char *target = argv[1];
    if (strcmp(argv[1], "--wait") == 0) { wait_mode = 1; target = argv[2]; argi = 3; }
    const char *outdir = argv[argi];
    int secs = (argc > argi + 1) ? atoi(argv[argi + 1]) : 40;
    long long deadline = now_ms() + (long long) secs * 1000;

    mkdir(outdir, 0755);

    int pid = 0;
    if (wait_mode) {
        printf("### waiting for %s ...\n", target);
        fflush(stdout);
        while (now_ms() < deadline) {
            pid = find_process(target);
            if (pid > 0) break;
            usleep(1000);
        }
        if (pid <= 0) { printf("### never appeared\n"); return 1; }
    } else {
        pid = atoi(target);
    }
    printf("### pid=%d, dumping to %s for %d s\n", pid, outdir, secs);
    fflush(stdout);

    char mempath[64];
    snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pid);

    struct region regs[MAXREG];
    unsigned char *buf = malloc(CHUNK);
    int total_dex = 0;

    while (now_ms() < deadline) {
        if (kill(pid, 0) != 0) { printf("### process gone\n"); break; }
        int fd = open(mempath, O_RDONLY);
        if (fd < 0) { printf("### open mem failed: %s\n", strerror(errno)); break; }
        int nr = load_regions(pid, regs, MAXREG);
        for (int i = 0; i < nr; i++) {
            unsigned long long a = regs[i].start;
            while (a < regs[i].end) {
                size_t want = (size_t) (regs[i].end - a);
                if (want > CHUNK) want = CHUNK;
                ssize_t got = pread(fd, buf, want, (off_t) a);
                if (got <= 0) break;
                /* scan this chunk for the dex magic */
                for (ssize_t k = 0; k + 8 <= got; k++) {
                    if (memcmp(buf + k, DEXMAGIC, 8) == 0) {
                        unsigned long long dexaddr = a + (unsigned long long) k;
                        /* read the header from the same address to get file_size */
                        unsigned char hdr[112];
                        if (pread(fd, hdr, sizeof(hdr), (off_t) dexaddr) == (ssize_t) sizeof(hdr)) {
                            unsigned int fsize = (unsigned int) hdr[32] | ((unsigned int) hdr[33] << 8)
                                               | ((unsigned int) hdr[34] << 16) | ((unsigned int) hdr[35] << 24);
                            unsigned int strids = (unsigned int) hdr[56] | ((unsigned int) hdr[57] << 8)
                                                | ((unsigned int) hdr[58] << 16) | ((unsigned int) hdr[59] << 24);
                            unsigned int classes = (unsigned int) hdr[96] | ((unsigned int) hdr[97] << 8)
                                                 | ((unsigned int) hdr[98] << 16) | ((unsigned int) hdr[99] << 24);
                            if (fsize >= 112 && fsize <= 300u * 1024u * 1024u) {
                                char outp[512];
                                snprintf(outp, sizeof(outp), "%s/dex_%llx_%u_%u.dex",
                                         outdir, dexaddr, strids, classes);
                                if (access(outp, F_OK) != 0) {
                                    int of = open(outp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                                    if (of >= 0) {
                                        unsigned long long left = fsize;
                                        unsigned long long off = dexaddr;
                                        unsigned char *out = malloc(CHUNK);
                                        while (left > 0) {
                                            size_t w = left > CHUNK ? CHUNK : (size_t) left;
                                            ssize_t r2 = pread(fd, out, w, (off_t) off);
                                            if (r2 <= 0) break;
                                            ssize_t w2 = write(of, out, (size_t) r2);
                                            if (w2 <= 0) break;
                                            off += (unsigned long long) r2;
                                            left -= (unsigned long long) r2;
                                        }
                                        free(out);
                                        close(of);
                                        total_dex++;
                                        printf("### DEX @ %llx  size=%u  strings=%u  classes=%u  -> %s\n",
                                               dexaddr, fsize, strids, classes, outp);
                                        fflush(stdout);
                                    }
                                }
                            }
                        }
                    }
                }
                a += (unsigned long long) got;
            }
        }
        close(fd);
        usleep(20000);
    }
    printf("### done, %d dex image(s) dumped\n", total_dex);
    return 0;
}
