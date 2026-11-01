#include "sys.h"

#if defined(TB_FREESTANDING) && TB_FREESTANDING

/* Ensure NX (non-executable) stack marking for GNU ld */
__asm__(".section .note.GNU-stack,\"\",@progbits\n.previous\n");

int    tb_errno   = 0;
char **tb_environ = NULL;

/* ── Raw Linux x86_64 Syscall Primitives ── */
#define NR_read           0
#define NR_write          1
#define NR_open           2
#define NR_close          3
#define NR_stat           4
#define NR_fstat          5
#define NR_poll           7
#define NR_mmap           9
#define NR_munmap         11
#define NR_rt_sigaction   13
#define NR_rt_sigreturn   15
#define NR_ioctl          16
#define NR_mremap         25
#define NR_madvise        28
#define NR_dup2           33
#define NR_nanosleep      35
#define NR_getpid         39
#define NR_socket         41
#define NR_connect        42
#define NR_accept         43
#define NR_sendto         44
#define NR_recvfrom       45
#define NR_bind           49
#define NR_listen         50
#define NR_getsockname    51
#define NR_setsockopt     54
#define NR_getsockopt     55
#define NR_fork           57
#define NR_execve         59
#define NR_exit           60
#define NR_wait4          61
#define NR_kill           62
#define NR_fcntl          72
#define NR_getcwd         79
#define NR_chdir          80
#define NR_unlink         87
#define NR_readlink       89
#define NR_clock_gettime  228
#define NR_exit_group     231
#define NR_openat         257
#define NR_newfstatat     262
#define NR_pipe2          293
#define NR_getrandom      318

static inline long sc0(long nr) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(nr) : "rcx", "r11", "memory");
    return ret;
}

static inline long sc1(long nr, long a1) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a1)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sc2(long nr, long a1, long a2) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a1), "S"(a2)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sc3(long nr, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sc4(long nr, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sc5(long nr, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sc6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sc_ret(long r) {
    if ((unsigned long)r > (unsigned long)-4096L) {
        tb_errno = (int)(-r);
        return -1;
    }
    return r;
}

/* ── Freestanding _start & Signal Restorer Trampoline ── */
extern int main(int argc, char **argv, char **envp);

#define MAX_ATEXIT 16
static void (*g_atexit_fns[MAX_ATEXIT])(void);
static int g_atexit_cnt = 0;

int atexit(void (*function)(void)) {
    if (!function || g_atexit_cnt >= MAX_ATEXIT) return -1;
    g_atexit_fns[g_atexit_cnt++] = function;
    return 0;
}

void _exit(int status) {
    sc1(NR_exit_group, status);
    sc1(NR_exit, status);
    __builtin_unreachable();
}

void exit(int status) {
    while (g_atexit_cnt > 0) {
        void (*fn)(void) = g_atexit_fns[--g_atexit_cnt];
        if (fn) fn();
    }
    fflush(stdout);
    fflush(stderr);
    _exit(status);
}

void tb_libc_start(long *sp) __attribute__((noreturn, used));
void tb_libc_start(long *sp) {
    int    argc = (int)sp[0];
    char **argv = (char **)&sp[1];
    char **envp = argv + argc + 1;
    tb_environ  = envp;
    int rc      = main(argc, argv, envp);
    exit(rc);
}

__asm__(
    ".text\n"
    ".globl _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "    xor %rbp, %rbp\n"
    "    mov %rsp, %rdi\n"
    "    and $-16, %rsp\n"
    "    call tb_libc_start\n"
    ".size _start, .-_start\n"
);

void tb_sig_restorer(void);
__asm__(
    ".text\n"
    ".globl tb_sig_restorer\n"
    ".type tb_sig_restorer, @function\n"
    "tb_sig_restorer:\n"
    "    mov $15, %rax\n"
    "    syscall\n"
    ".size tb_sig_restorer, .-tb_sig_restorer\n"
);

/* ── POSIX Syscall Wrappers ── */
int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, unsigned int);
        va_end(ap);
    }
    return (int)sc_ret(sc4(NR_openat, AT_FDCWD, (long)path, flags, mode));
}

ssize_t read(int fd, void *buf, size_t count) {
    return (ssize_t)sc_ret(sc3(NR_read, fd, (long)buf, (long)count));
}

ssize_t write(int fd, const void *buf, size_t count) {
    return (ssize_t)sc_ret(sc3(NR_write, fd, (long)buf, (long)count));
}

int close(int fd) {
    return (int)sc_ret(sc1(NR_close, fd));
}

int stat(const char *path, struct stat *st) {
    return (int)sc_ret(sc4(NR_newfstatat, AT_FDCWD, (long)path, (long)st, 0));
}

int fstat(int fd, struct stat *st) {
    return (int)sc_ret(sc2(NR_fstat, fd, (long)st));
}

int unlink(const char *path) {
    return (int)sc_ret(sc2(NR_unlink, (long)path, 0));
}

int fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);
    return (int)sc_ret(sc3(NR_fcntl, fd, cmd, arg));
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout_ms) {
    return (int)sc_ret(sc3(NR_poll, (long)fds, (long)nfds, timeout_ms));
}

int ioctl(int fd, unsigned long req, ...) {
    va_list ap;
    va_start(ap, req);
    long arg = va_arg(ap, long);
    va_end(ap);
    return (int)sc_ret(sc3(NR_ioctl, fd, (long)req, arg));
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    long r = sc6(NR_mmap, (long)addr, (long)length, prot, flags, fd, offset);
    if ((unsigned long)r > (unsigned long)-4096L) {
        tb_errno = (int)(-r);
        return MAP_FAILED;
    }
    return (void *)r;
}

int munmap(void *addr, size_t length) {
    return (int)sc_ret(sc2(NR_munmap, (long)addr, (long)length));
}

void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags) {
    long r = sc4(NR_mremap, (long)old_addr, (long)old_size, (long)new_size, flags);
    if ((unsigned long)r > (unsigned long)-4096L) {
        tb_errno = (int)(-r);
        return MAP_FAILED;
    }
    return (void *)r;
}

int madvise(void *addr, size_t length, int advice) {
    return (int)sc_ret(sc3(NR_madvise, (long)addr, (long)length, advice));
}

int socket(int domain, int type, int protocol) {
    return (int)sc_ret(sc3(NR_socket, domain, type, protocol));
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    return (int)sc_ret(sc3(NR_connect, fd, (long)addr, addrlen));
}

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    return (int)sc_ret(sc3(NR_bind, fd, (long)addr, addrlen));
}

int listen(int fd, int backlog) {
    return (int)sc_ret(sc2(NR_listen, fd, backlog));
}

int accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    return (int)sc_ret(sc3(NR_accept, fd, (long)addr, (long)addrlen));
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    return (int)sc_ret(sc3(NR_getsockname, fd, (long)addr, (long)addrlen));
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    return (int)sc_ret(sc5(NR_setsockopt, fd, level, optname, (long)optval, optlen));
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    return (int)sc_ret(sc5(NR_getsockopt, fd, level, optname, (long)optval, (long)optlen));
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    return (ssize_t)sc_ret(sc6(NR_sendto, fd, (long)buf, (long)len, flags,
                               (long)dest_addr, addrlen));
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    return (ssize_t)sc_ret(sc6(NR_recvfrom, fd, (long)buf, (long)len, flags,
                               (long)src_addr, (long)addrlen));
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    return sendto(fd, buf, len, flags, NULL, 0);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    return recvfrom(fd, buf, len, flags, NULL, NULL);
}

pid_t getpid(void) {
    return (pid_t)sc_ret(sc0(NR_getpid));
}

pid_t fork(void) {
    return (pid_t)sc_ret(sc0(NR_fork));
}

pid_t waitpid(pid_t pid, int *wstatus, int options) {
    return (pid_t)sc_ret(sc4(NR_wait4, pid, (long)wstatus, options, 0));
}

int kill(pid_t pid, int sig) {
    return (int)sc_ret(sc2(NR_kill, pid, sig));
}

int pipe(int pipefd[2]) {
    return (int)sc_ret(sc2(NR_pipe2, (long)pipefd, 0));
}

int dup2(int oldfd, int newfd) {
    return (int)sc_ret(sc2(NR_dup2, oldfd, newfd));
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    return (int)sc_ret(sc3(NR_execve, (long)pathname, (long)argv,
                           (long)(envp ? envp : (char *const *)tb_environ)));
}

int chdir(const char *path) {
    return (int)sc_ret(sc1(NR_chdir, (long)path));
}

char *getcwd(char *buf, size_t size) {
    long r = sc2(NR_getcwd, (long)buf, (long)size);
    if ((unsigned long)r > (unsigned long)-4096L) {
        tb_errno = (int)(-r);
        return NULL;
    }
    return buf;
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    return (ssize_t)sc_ret(sc3(NR_readlink, (long)pathname, (long)buf, (long)bufsiz));
}

int clock_gettime(int clk_id, struct timespec *tp) {
    return (int)sc_ret(sc2(NR_clock_gettime, clk_id, (long)tp));
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
    return (int)sc_ret(sc2(NR_nanosleep, (long)req, (long)rem));
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    struct sigaction kact;
    const struct sigaction *ap = NULL;
    if (act) {
        kact = *act;
        kact.sa_flags   |= SA_RESTORER;
        kact.sa_restorer = tb_sig_restorer;
        ap = &kact;
    }
    return (int)sc_ret(sc4(NR_rt_sigaction, signum, (long)ap, (long)oldact, sizeof(uint64_t)));
}

int tcgetattr(int fd, struct termios *termios_p) {
    return ioctl(fd, TCGETS, termios_p);
}

int tcsetattr(int fd, int optional_actions, const struct termios *termios_p) {
    unsigned long req = TCSETS;
    if (optional_actions == TCSADRAIN) req = TCSETSW;
    else if (optional_actions == TCSAFLUSH) req = TCSETSF;
    return ioctl(fd, req, (void *)termios_p);
}

int isatty(int fd) {
    struct termios t;
    return ioctl(fd, TCGETS, &t) == 0 ? 1 : 0;
}

bool tb_getrandom(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        long r = sc3(NR_getrandom, (long)(p + off), (long)(len - off), 0);
        if (r > 0) {
            off += (size_t)r;
            continue;
        }
        if (r == -EINTR) continue;
        break;
    }
    if (off == len) return true;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n > 0) off += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else break;
    }
    close(fd);
    return off == len;
}

#else /* TB_FREESTANDING == 0 */

#include <sys/random.h>

bool tb_getrandom(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t r = getrandom(p + off, len - off, 0);
        if (r > 0) { off += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    if (off == len) return true;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n > 0) off += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else break;
    }
    close(fd);
    return off == len;
}

#endif /* TB_FREESTANDING */
