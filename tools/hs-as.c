/*
 * hs-as — read files with an APP's credentials.
 *
 * Same idea as hs-acctest: drop to the target uid AND clear the capability sets (KernelSU's
 * su leaves PR_SET_KEEPCAPS on, so CAP_DAC_OVERRIDE otherwise walks straight through every
 * permission check and the result is meaningless).
 *
 * Use: hs-as <uid> <path> [path...]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

struct cap_hdr { unsigned int version; int pid; };
struct cap_data { unsigned int effective, permitted, inheritable; };
#ifndef __NR_capset
#define __NR_capset 91
#endif
#ifndef PR_SET_KEEPCAPS
#define PR_SET_KEEPCAPS 8
#endif

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <uid> <path>...\n", argv[0]); return 2; }
    uid_t u = (uid_t) atoi(argv[1]);
    if (u != 0) {
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
        if (setresuid(u, u, u) != 0) { perror("setresuid"); return 1; }
        struct cap_hdr h; struct cap_data d[2];
        memset(&h, 0, sizeof(h)); memset(d, 0, sizeof(d));
        h.version = 0x20080522;
        syscall(__NR_capset, &h, d);
    }
    printf("### uid=%d euid=%d\n", (int) getuid(), (int) geteuid());
    for (int i = 2; i < argc; i++) {
        errno = 0;
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) {
            printf("%-40s OPEN FAILED errno=%d (%s)\n", argv[i], errno, strerror(errno));
            continue;
        }
        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n < 0) {
            printf("%-40s READ FAILED errno=%d (%s)\n", argv[i], errno, strerror(errno));
            continue;
        }
        buf[n] = '\0';
        printf("%-40s READ OK (%zd bytes):\n", argv[i], n);
        /* Print it in a readable way, wrapping long single-line files. */
        if (strchr(buf, '\n') == NULL && n > 200) {
            for (ssize_t k = 0; k < n; k += 110) {
                printf("      %.*s\n", (int) (n - k > 110 ? 110 : n - k), buf + k);
            }
        } else {
            printf("      %s\n", buf);
        }
    }
    return 0;
}
