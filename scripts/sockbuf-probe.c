/*
 * Measures the Linux kernel's UDP receive-buffer accounting, the facts crates/snare/src/limits.rs
 * models: the skb truesize a loopback datagram is charged (SO_MEMINFO SK_MEMINFO_RMEM_ALLOC, man 7
 * socket), how SO_RCVBUF/SO_SNDBUF round a request, the default buffer sizes, and how many
 * datagrams a small buffer admits. Built static and run as /init of an initramfs by
 * scripts/measure-sockbuf.sh, so it brings up loopback and mounts /proc itself; run as an
 * ordinary program it skips both when they are already there. As /init it then runs every
 * program in /tests (the snare test binaries the script copies in), so they can compare the sim
 * with that kernel.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SO_MEMINFO
#define SO_MEMINFO 55
#endif

static char payload[70000];

static void lo_up(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "lo");
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0 && !(ifr.ifr_flags & IFF_UP)) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) perror("SIOCSIFFLAGS");
    }
    close(fd);
}

static void sysctl(const char *path) {
    char buf[256] = {0};
    FILE *f = fopen(path, "r");
    if (!f) { printf("%s: missing\n", path); return; }
    if (fgets(buf, sizeof buf, f)) buf[strcspn(buf, "\n")] = 0;
    fclose(f);
    printf("%s = %s\n", path, buf);
}

static int geti(int fd, int name) {
    int v = -1; socklen_t len = sizeof v;
    getsockopt(fd, SOL_SOCKET, name, &v, &len);
    return v;
}

static void loopback(int family, struct sockaddr_storage *ss, socklen_t *len) {
    memset(ss, 0, sizeof *ss);
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)ss;
        a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        *len = sizeof *a;
    } else {
        struct sockaddr_in6 *a = (void *)ss;
        a->sin6_family = AF_INET6; a->sin6_addr = in6addr_loopback;
        *len = sizeof *a;
    }
}

/* A bound receiver and an unbound sender of `family`; `to` is the receiver's address. */
static int pair(int family, int *tx, struct sockaddr_storage *to, socklen_t *tolen) {
    int rx = socket(family, SOCK_DGRAM, 0);
    loopback(family, to, tolen);
    if (bind(rx, (void *)to, *tolen) != 0) { perror("bind"); exit(1); }
    getsockname(rx, (void *)to, tolen);
    *tx = socket(family, SOCK_DGRAM, 0);
    return rx;
}

static void drain(int rx) {
    char buf[70000];
    while (recv(rx, buf, sizeof buf, MSG_DONTWAIT) >= 0) {}
}

static unsigned rmem_alloc(int rx) {
    unsigned m[9] = {0}; socklen_t len = sizeof m;
    getsockopt(rx, SOL_SOCKET, SO_MEMINFO, m, &len);
    return m[0];
}

/* Prints each payload length at which the truesize of a lone queued datagram changes. */
static void truesize(int family, int max) {
    int tx; struct sockaddr_storage to; socklen_t tolen;
    int rx = pair(family, &tx, &to, &tolen);
    int big = 8 << 20;
    setsockopt(rx, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    long prev = -1;
    for (int len = 0; len <= max; len++) {
        if (sendto(tx, payload, len, 0, (void *)&to, tolen) != len) { perror("sendto"); break; }
        struct pollfd p = { rx, POLLIN, 0 };
        poll(&p, 1, 1000);
        long t = rmem_alloc(rx);
        if (t != prev) printf("truesize %s len %d -> %ld\n", family == AF_INET ? "v4" : "v6", len, t);
        prev = t;
        drain(rx);
    }
    close(rx); close(tx);
}

static void rounding(void) {
    int vals[] = {0, 1, 1000, 1152, 5000, -1};
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    printf("udp default SO_RCVBUF %d SO_SNDBUF %d\n", geti(s, SO_RCVBUF), geti(s, SO_SNDBUF));
    for (unsigned i = 0; i < sizeof vals / sizeof *vals; i++) {
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, &vals[i], sizeof vals[i]);
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, &vals[i], sizeof vals[i]);
        printf("set %d -> SO_RCVBUF %d SO_SNDBUF %d\n", vals[i], geti(s, SO_RCVBUF), geti(s, SO_SNDBUF));
    }
    close(s);
    int t = socket(AF_INET, SOCK_STREAM, 0);
    printf("tcp default SO_RCVBUF %d SO_SNDBUF %d\n", geti(t, SO_RCVBUF), geti(t, SO_SNDBUF));
    close(t);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned m[9] = {0}; socklen_t len = sizeof m;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &one, sizeof one);
    getsockopt(s, SOL_SOCKET, SO_MEMINFO, m, &len);
    printf("meminfo of an empty SO_RCVBUF=1 socket: rcvbuf %u fwd_alloc %u\n", m[1], m[4]);
    close(s);
}

/* The os_parity `overflow_counts_match_real_os` cases. */
static void overflow(void) {
    int bufs[] = {2000, 8000};
    int lens[] = {1, 10, 100, 200, 500, 1000, 1472};
    for (int b = 0; b < 2; b++) for (int l = 0; l < 7; l++) {
        int tx; struct sockaddr_storage to; socklen_t tolen;
        int rx = pair(AF_INET, &tx, &to, &tolen);
        setsockopt(rx, SOL_SOCKET, SO_RCVBUF, &bufs[b], sizeof bufs[b]);
        for (int i = 0; i < 120; i++) sendto(tx, payload, lens[l], 0, (void *)&to, tolen);
        usleep(30000);
        char buf[2048]; int n = 0;
        while (recv(rx, buf, sizeof buf, MSG_DONTWAIT) >= 0) n++;
        printf("overflow rcvbuf %d len %d admitted %d\n", bufs[b], lens[l], n);
        close(rx); close(tx);
    }
}

/* Runs each program in /tests with its working directory and HOME in a fresh /tmp. */
static void run_tests(void) {
    DIR *d = opendir("/tests");
    if (!d) return;
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    mount("tmpfs", "/tmp", "tmpfs", 0, NULL);
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof path, "/tests/%s", e->d_name);
        printf("== test %s\n", e->d_name);
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            char *args[] = {path, NULL};
            char *env[] = {"HOME=/tmp", "PATH=/bin", "RUST_BACKTRACE=1", NULL};
            if (chdir("/tmp") != 0) _exit(126);
            execve(path, args, env);
            _exit(127);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        printf("== test %s exit %d\n", e->d_name, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        fflush(stdout);
    }
    closedir(d);
}

int main(int argc, char **argv) {
    int init = getpid() == 1;
    if (init) mount("proc", "/proc", "proc", 0, NULL);
    lo_up();
    struct utsname u; uname(&u);
    printf("== kernel %s %s %s\n", u.sysname, u.release, u.machine);
    int max = argc > 1 ? atoi(argv[1]) : 17000;
    sysctl("/proc/sys/net/core/rmem_default");
    sysctl("/proc/sys/net/core/rmem_max");
    sysctl("/proc/sys/net/core/wmem_default");
    sysctl("/proc/sys/net/core/wmem_max");
    sysctl("/proc/sys/net/ipv4/tcp_rmem");
    sysctl("/proc/sys/net/ipv4/tcp_wmem");
    rounding();
    overflow();
    truesize(AF_INET, max);
    truesize(AF_INET6, max);
    if (init) run_tests();
    printf("== done\n");
    fflush(stdout);
    if (init) { sync(); reboot(RB_POWER_OFF); }
    return 0;
}
