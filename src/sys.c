#include "sys.h"
#include "math_tb.h"
#include "mem.h"

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

/* ── Core Memory & String Primitives (disable loop-to-builtin recursion!) ── */
typedef uint64_t __attribute__((__may_alias__, aligned(1))) tb_u64_unaligned_t;

__attribute__((optimize("no-tree-loop-distribute-patterns")))
void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n >= 8) {
        *(tb_u64_unaligned_t *)d = *(const tb_u64_unaligned_t *)s;
        d += 8;
        s += 8;
        n -= 8;
    }
    while (n--) *d++ = *s++;
    return dst;
}

__attribute__((optimize("no-tree-loop-distribute-patterns")))
void *memmove(void *dst, const void *src, size_t n) {
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

__attribute__((optimize("no-tree-loop-distribute-patterns")))
void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    uint8_t  b = (uint8_t)c;
    uint64_t w = (uint64_t)b * 0x0101010101010101ULL;
    while (n >= 8) {
        *(tb_u64_unaligned_t *)p = w;
        p += 8;
        n -= 8;
    }
    while (n--) *p++ = b;
    return s;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *a = (const uint8_t *)s1;
    const uint8_t *b = (const uint8_t *)s2;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
    }
    return 0;
}

void *memchr(const void *s, int c, size_t n) {
    const uint8_t *p = (const uint8_t *)s;
    uint8_t target = (uint8_t)c;
    for (size_t i = 0; i < n; i++) {
        if (p[i] == target) return (void *)(p + i);
    }
    return NULL;
}

size_t strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

size_t strnlen(const char *s, size_t maxlen) {
    size_t i = 0;
    while (i < maxlen && s[i]) i++;
    return i;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s1 == *s2) { s1++; s2++; }
    return (int)(uint8_t)*s1 - (int)(uint8_t)*s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint8_t a = (uint8_t)s1[i];
        uint8_t b = (uint8_t)s2[i];
        if (a != b || a == 0) return (int)a - (int)b;
    }
    return 0;
}

__attribute__((optimize("no-tree-loop-distribute-patterns")))
char *strcpy(char *dst, const char *src) {
    char *d = dst;
    while ((*d++ = *src++) != '\0') {}
    return dst;
}

char *strchr(const char *s, int c) {
    char target = (char)c;
    for (; ; s++) {
        if (*s == target) return (char *)s;
        if (*s == '\0') return NULL;
    }
}

char *strrchr(const char *s, int c) {
    char target = (char)c;
    const char *last = NULL;
    for (; ; s++) {
        if (*s == target) last = s;
        if (*s == '\0') return (char *)last;
    }
}

char *strstr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    size_t nlen = strlen(needle);
    for (; *haystack; haystack++) {
        if (*haystack == *needle && strncmp(haystack, needle, nlen) == 0) {
            return (char *)haystack;
        }
    }
    return NULL;
}

char *strcasestr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    size_t nlen = strlen(needle);
    int n0 = tolower((uint8_t)*needle);
    for (; *haystack; haystack++) {
        if (tolower((uint8_t)*haystack) == n0) {
            size_t i = 1;
            while (i < nlen && haystack[i] &&
                   tolower((uint8_t)haystack[i]) == tolower((uint8_t)needle[i])) {
                i++;
            }
            if (i == nlen) return (char *)haystack;
        }
    }
    return NULL;
}

char *strpbrk(const char *s, const char *accept) {
    for (; *s; s++) {
        for (const char *a = accept; *a; a++) {
            if (*s == *a) return (char *)s;
        }
    }
    return NULL;
}

char *strtok_r(char *str, const char *delim, char **saveptr) {
    char *p = str ? str : *saveptr;
    if (!p) return NULL;
    while (*p && strchr(delim, *p)) p++;
    if (!*p) {
        *saveptr = p;
        return NULL;
    }
    char *tok = p;
    while (*p && !strchr(delim, *p)) p++;
    if (*p) {
        *p = '\0';
        *saveptr = p + 1;
    } else {
        *saveptr = p;
    }
    return tok;
}

char *strerror(int errnum) {
    switch (errnum) {
        case 0:            return "Success";
        case EPERM:        return "Operation not permitted";
        case ENOENT:       return "No such file or directory";
        case EINTR:        return "Interrupted system call";
        case EIO:          return "Input/output error";
        case EBADF:        return "Bad file descriptor";
        case EAGAIN:       return "Resource temporarily unavailable";
        case ENOMEM:       return "Out of memory";
        case EACCES:       return "Permission denied";
        case EEXIST:       return "File exists";
        case ENOTDIR:      return "Not a directory";
        case EISDIR:       return "Is a directory";
        case EINVAL:       return "Invalid argument";
        case EPIPE:        return "Broken pipe";
        case ERANGE:       return "Result not representable";
        case ECONNRESET:   return "Connection reset by peer";
        case ETIMEDOUT:    return "Connection timed out";
        case ECONNREFUSED: return "Connection refused";
        case EHOSTUNREACH: return "No route to host";
        case EINPROGRESS:  return "Operation in progress";
        default:           return "OS error";
    }
}

/* ── Minimal Zero-Heap FILE Streams ── */
struct TbFile {
    int  fd;
    bool in_use;
    bool close_fd;
};

static struct TbFile g_stdio_files[3] = {
    { .fd = 0, .in_use = true, .close_fd = false },
    { .fd = 1, .in_use = true, .close_fd = false },
    { .fd = 2, .in_use = true, .close_fd = false }
};
FILE *stdin  = &g_stdio_files[0];
FILE *stdout = &g_stdio_files[1];
FILE *stderr = &g_stdio_files[2];

static struct TbFile g_file_pool[16];

FILE *fopen(const char *path, const char *mode) {
    if (!path || !mode) { tb_errno = EINVAL; return NULL; }
    int flags = O_RDONLY;
    if (mode[0] == 'w') flags = O_WRONLY | O_CREAT | O_TRUNC;
    else if (mode[0] == 'a') flags = O_WRONLY | O_CREAT | O_APPEND;
    if (strchr(mode, '+')) flags = (flags & ~(O_RDONLY | O_WRONLY)) | O_RDWR;

    int fd = open(path, flags, 0644);
    if (fd < 0) return NULL;

    for (size_t i = 0; i < sizeof(g_file_pool) / sizeof(g_file_pool[0]); i++) {
        if (!g_file_pool[i].in_use) {
            g_file_pool[i].fd       = fd;
            g_file_pool[i].in_use   = true;
            g_file_pool[i].close_fd = true;
            return &g_file_pool[i];
        }
    }
    close(fd);
    tb_errno = EMFILE;
    return NULL;
}

int fclose(FILE *stream) {
    if (!stream) return -1;
    int rc = 0;
    if (stream->close_fd && stream->fd >= 0) {
        rc = close(stream->fd);
    }
    if (stream != stdin && stream != stdout && stream != stderr) {
        stream->fd     = -1;
        stream->in_use = false;
    }
    return rc;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!ptr || !stream || size == 0 || nmemb == 0) return 0;
    size_t total = size * nmemb;
    uint8_t *p = (uint8_t *)ptr;
    size_t got = 0;
    while (got < total) {
        ssize_t n = read(stream->fd, p + got, total - got);
        if (n > 0) got += (size_t)n;
        else if (n < 0 && tb_errno == EINTR) continue;
        else break;
    }
    return got / size;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!ptr || !stream || size == 0 || nmemb == 0) return 0;
    size_t total = size * nmemb;
    const uint8_t *p = (const uint8_t *)ptr;
    size_t put = 0;
    while (put < total) {
        ssize_t n = write(stream->fd, p + put, total - put);
        if (n > 0) put += (size_t)n;
        else if (n < 0 && tb_errno == EINTR) continue;
        else break;
    }
    return put / size;
}

int fflush(FILE *stream) {
    (void)stream;
    return 0;
}

/* ── Integer & IEEE-754 Floating-Point vsnprintf ── */
typedef struct {
    char  *dst;
    size_t cap;
    size_t pos;
} FmtOut;

static inline void fmt_putc(FmtOut *o, char c) {
    if (o->dst && o->pos + 1 < o->cap) {
        o->dst[o->pos] = c;
    }
    o->pos++;
}

static void fmt_puts_n(FmtOut *o, const char *s, size_t len) {
    for (size_t i = 0; i < len; i++) fmt_putc(o, s[i]);
}

static void fmt_pad(FmtOut *o, char pad_ch, int count) {
    while (count-- > 0) fmt_putc(o, pad_ch);
}

static void fmt_float(FmtOut *o, double val, char spec, int width, int prec,
                      bool left_adj, bool zero_pad, bool force_plus, bool space_sign) {
    bool upper = (spec == 'E' || spec == 'G' || spec == 'F');
    char lspec = (char)tolower((uint8_t)spec);
    bool neg   = tb_signbit(val);

    char tmp[128];
    int  tlen = 0;

    if (tb_isnan(val)) {
        const char *ns = upper ? "NAN" : "nan";
        memcpy(tmp, ns, 3);
        tlen = 3;
        zero_pad = false;
    } else if (tb_isinf(val)) {
        if (neg) tmp[tlen++] = '-';
        else if (force_plus) tmp[tlen++] = '+';
        else if (space_sign) tmp[tlen++] = ' ';
        const char *is = upper ? "INF" : "inf";
        memcpy(tmp + tlen, is, 3);
        tlen += 3;
        zero_pad = false;
    } else {
        double aval = tb_fabs(val);
        if (prec < 0) prec = 6;
        if (lspec == 'g' && prec == 0) prec = 1;
        if (prec > 32) prec = 32;

        /* Normalize aval into [1.0, 10.0) * 10^exp10 */
        int exp10 = 0;
        uint8_t digits[48];
        memset(digits, 0, sizeof(digits));

        if (aval > 0.0) {
            /* Exact integer fast path for values <= 2^53 */
            if (aval >= 1.0 && aval <= 9007199254740992.0 && tb_floor(aval) == aval) {
                uint64_t iv = (uint64_t)aval;
                char rev[24];
                int rlen = 0;
                while (iv > 0ULL) {
                    rev[rlen++] = (char)(iv % 10ULL);
                    iv /= 10ULL;
                }
                exp10 = rlen - 1;
                for (int i = 0; i < rlen && i < (int)sizeof(digits); i++) {
                    digits[i] = (uint8_t)rev[rlen - 1 - i];
                }
            } else {
                double m = aval;
                if (m < 1e-307) { m *= 1e16; exp10 -= 16; }
                static const double P10[9]  = { 1e256, 1e128, 1e64, 1e32, 1e16, 1e8, 1e4, 1e2, 1e1 };
                static const int    E10[9]  = {   256,   128,   64,   32,   16,   8,   4,   2,   1 };
                if (m >= 10.0) {
                    for (int i = 0; i < 9; i++) {
                        if (m >= P10[i]) { m /= P10[i]; exp10 += E10[i]; }
                    }
                } else if (m < 1.0) {
                    for (int i = 0; i < 9; i++) {
                        if (m * P10[i] < 10.0) { m *= P10[i]; exp10 -= E10[i]; }
                    }
                    if (m < 1.0) { m *= 10.0; exp10 -= 1; }
                }
                if (m >= 10.0) { m /= 10.0; exp10 += 1; }

                /* Extract 17 IEEE-754 significant digits from normalized mantissa */
                for (int i = 0; i < 17; i++) {
                    int d = (int)m;
                    if (d < 0) d = 0;
                    if (d > 9) d = 9;
                    digits[i] = (uint8_t)d;
                    m = (m - (double)d) * 10.0;
                }
                if (m >= 5.0) {
                    int k = 16;
                    while (k >= 0) {
                        if (++digits[k] < 10) break;
                        digits[k--] = 0;
                    }
                    if (k < 0) {
                        digits[0] = 1;
                        exp10++;
                    }
                }
            }
        }

        /* Determine effective style ('f' vs 'e') and round at target digit */
        bool use_exp = (lspec == 'e');
        int  frac_digits = prec;
        int  sig_keep = 0;

        if (lspec == 'g') {
            /* Pre-round to `prec` significant digits first to check if exp10 bumps */
            sig_keep = prec;
        } else if (lspec == 'e') {
            sig_keep = prec + 1;
        } else {
            /* 'f' */
            sig_keep = (aval == 0.0) ? 0 : (exp10 + 1 + prec);
        }

        if (aval > 0.0) {
            if (sig_keep < 0) {
                memset(digits, 0, sizeof(digits));
                aval  = 0.0;
                exp10 = 0;
            } else if (sig_keep == 0) {
                bool round_up = (digits[0] >= 5);
                memset(digits, 0, sizeof(digits));
                if (round_up) {
                    digits[0] = 1;
                    exp10++;
                } else {
                    aval  = 0.0;
                    exp10 = 0;
                }
            } else if (sig_keep < (int)sizeof(digits)) {
                if (digits[sig_keep] >= 5) {
                    int k = sig_keep - 1;
                    while (k >= 0) {
                        if (++digits[k] < 10) break;
                        digits[k--] = 0;
                    }
                    if (k < 0) {
                        for (int j = sig_keep; j > 0; j--) digits[j] = digits[j - 1];
                        digits[0] = 1;
                        exp10++;
                    }
                }
                for (int j = sig_keep; j < (int)sizeof(digits); j++) digits[j] = 0;
            }
        }

        if (lspec == 'g') {
            if (aval != 0.0 && (exp10 < -4 || exp10 >= prec)) {
                use_exp     = true;
                frac_digits = prec - 1;
            } else {
                use_exp     = false;
                frac_digits = (aval == 0.0) ? (prec - 1) : (prec - 1 - exp10);
                if (frac_digits < 0) frac_digits = 0;
            }
        }

        char sign_ch = 0;
        if (neg) sign_ch = '-';
        else if (force_plus) sign_ch = '+';
        else if (space_sign) sign_ch = ' ';

        char body[112];
        int  blen = 0;

        if (use_exp) {
            body[blen++] = (char)('0' + digits[0]);
            if (frac_digits > 0) {
                body[blen++] = '.';
                for (int i = 0; i < frac_digits && blen < 96; i++) {
                    uint8_t dg = (1 + i < (int)sizeof(digits)) ? digits[1 + i] : 0;
                    body[blen++] = (char)('0' + dg);
                }
                if (lspec == 'g') {
                    while (blen > 0 && body[blen - 1] == '0') blen--;
                    if (blen > 0 && body[blen - 1] == '.') blen--;
                }
            }
            body[blen++] = upper ? 'E' : 'e';
            int eabs = (aval == 0.0) ? 0 : exp10;
            body[blen++] = (eabs < 0) ? '-' : '+';
            if (eabs < 0) eabs = -eabs;
            if (eabs >= 100) body[blen++] = (char)('0' + (eabs / 100));
            body[blen++] = (char)('0' + ((eabs / 10) % 10));
            body[blen++] = (char)('0' + (eabs % 10));
        } else {
            if (aval == 0.0 || exp10 < 0) {
                body[blen++] = '0';
                if (frac_digits > 0) {
                    body[blen++] = '.';
                    int lead_zeros = (aval == 0.0) ? 0 : (-exp10 - 1);
                    for (int i = 0; i < frac_digits && blen < 104; i++) {
                        uint8_t dg = 0;
                        if (aval != 0.0 && i >= lead_zeros) {
                            int di = i - lead_zeros;
                            if (di < (int)sizeof(digits)) dg = digits[di];
                        }
                        body[blen++] = (char)('0' + dg);
                    }
                }
            } else {
                int int_digits = exp10 + 1;
                for (int i = 0; i < int_digits && blen < 104; i++) {
                    uint8_t dg = (i < (int)sizeof(digits)) ? digits[i] : 0;
                    body[blen++] = (char)('0' + dg);
                }
                if (frac_digits > 0) {
                    body[blen++] = '.';
                    for (int i = 0; i < frac_digits && blen < 104; i++) {
                        int di = int_digits + i;
                        uint8_t dg = (di < (int)sizeof(digits)) ? digits[di] : 0;
                        body[blen++] = (char)('0' + dg);
                    }
                }
            }
            if (lspec == 'g' && memchr(body, '.', (size_t)blen)) {
                while (blen > 0 && body[blen - 1] == '0') blen--;
                if (blen > 0 && body[blen - 1] == '.') blen--;
            }
        }

        int total_len = blen + (sign_ch ? 1 : 0);
        int pad = (width > total_len) ? (width - total_len) : 0;
        if (!left_adj && !zero_pad) fmt_pad(o, ' ', pad);
        if (sign_ch) fmt_putc(o, sign_ch);
        if (!left_adj && zero_pad) fmt_pad(o, '0', pad);
        fmt_puts_n(o, body, (size_t)blen);
        if (left_adj) fmt_pad(o, ' ', pad);
        return;
    }

    int pad = (width > tlen) ? (width - tlen) : 0;
    if (!left_adj) fmt_pad(o, zero_pad ? '0' : ' ', pad);
    fmt_puts_n(o, tmp, (size_t)tlen);
    if (left_adj) fmt_pad(o, ' ', pad);
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap) {
    FmtOut o = { .dst = str, .cap = size, .pos = 0 };
    if (!format) format = "";

    for (const char *p = format; *p; ) {
        if (*p != '%') {
            fmt_putc(&o, *p++);
            continue;
        }
        p++; /* skip '%' */
        if (*p == '%') {
            fmt_putc(&o, *p++);
            continue;
        }

        bool left_adj   = false;
        bool force_plus = false;
        bool space_sign = false;
        bool alt_form   = false;
        bool zero_pad   = false;

        for (;;) {
            if (*p == '-')      { left_adj   = true; p++; }
            else if (*p == '+') { force_plus = true; p++; }
            else if (*p == ' ') { space_sign = true; p++; }
            else if (*p == '#') { alt_form   = true; p++; }
            else if (*p == '0') { zero_pad   = true; p++; }
            else break;
        }

        int width = 0;
        if (*p == '*') {
            width = va_arg(ap, int);
            if (width < 0) { left_adj = true; width = -width; }
            p++;
        } else {
            while (*p >= '0' && *p <= '9') {
                width = width * 10 + (*p - '0');
                p++;
            }
        }

        int prec = -1;
        if (*p == '.') {
            p++;
            if (*p == '*') {
                prec = va_arg(ap, int);
                p++;
            } else {
                prec = 0;
                while (*p >= '0' && *p <= '9') {
                    prec = prec * 10 + (*p - '0');
                    p++;
                }
            }
        }

        int len_mod = 0; /* 0=int, 1=l, 2=ll, 3=z, -1=h, -2=hh */
        if (*p == 'l') {
            p++;
            len_mod = (*p == 'l') ? (p++, 2) : 1;
        } else if (*p == 'z') {
            len_mod = 3;
            p++;
        } else if (*p == 'h') {
            p++;
            len_mod = (*p == 'h') ? (p++, -2) : -1;
        }

        char spec = *p ? *p++ : '\0';
        if (!spec) break;

        if (spec == 'c') {
            char ch = (char)va_arg(ap, int);
            int pad = (width > 1) ? (width - 1) : 0;
            if (!left_adj) fmt_pad(&o, ' ', pad);
            fmt_putc(&o, ch);
            if (left_adj) fmt_pad(&o, ' ', pad);
        } else if (spec == 's') {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            size_t slen = (prec >= 0) ? strnlen(s, (size_t)prec) : strlen(s);
            int pad = (width > (int)slen) ? (width - (int)slen) : 0;
            if (!left_adj) fmt_pad(&o, ' ', pad);
            fmt_puts_n(&o, s, slen);
            if (left_adj) fmt_pad(&o, ' ', pad);
        } else if (spec == 'f' || spec == 'F' || spec == 'e' || spec == 'E' ||
                   spec == 'g' || spec == 'G') {
            double dv = va_arg(ap, double);
            fmt_float(&o, dv, spec, width, prec, left_adj, zero_pad, force_plus, space_sign);
        } else if (spec == 'd' || spec == 'i' || spec == 'u' ||
                   spec == 'x' || spec == 'X' || spec == 'o' || spec == 'p') {
            bool is_signed = (spec == 'd' || spec == 'i');
            uint64_t uval  = 0;
            bool     neg   = false;

            if (spec == 'p') {
                uval     = (uint64_t)(uintptr_t)va_arg(ap, void *);
                alt_form = true;
            } else if (is_signed) {
                int64_t sval = 0;
                if (len_mod == 2)      sval = va_arg(ap, long long);
                else if (len_mod == 1) sval = va_arg(ap, long);
                else if (len_mod == 3) sval = (int64_t)va_arg(ap, ssize_t);
                else                   sval = va_arg(ap, int);
                if (sval < 0) {
                    neg  = true;
                    uval = (uint64_t)(-(sval + 1)) + 1ULL;
                } else {
                    uval = (uint64_t)sval;
                }
            } else {
                if (len_mod == 2)      uval = va_arg(ap, unsigned long long);
                else if (len_mod == 1) uval = va_arg(ap, unsigned long);
                else if (len_mod == 3) uval = va_arg(ap, size_t);
                else                   uval = va_arg(ap, unsigned int);
            }

            unsigned int base = 10U;
            if (spec == 'x' || spec == 'X' || spec == 'p') base = 16U;
            else if (spec == 'o') base = 8U;

            const char *digits = (spec == 'X') ? "0123456789ABCDEF" : "0123456789abcdef";
            char rev[32];
            int  rlen = 0;
            if (!(uval == 0ULL && prec == 0)) {
                do {
                    rev[rlen++] = digits[uval % base];
                    uval /= base;
                } while (uval > 0ULL);
            }

            int zprec = (prec > rlen) ? (prec - rlen) : 0;
            if (prec >= 0) zero_pad = false;

            char sign_ch = 0;
            if (is_signed) {
                if (neg) sign_ch = '-';
                else if (force_plus) sign_ch = '+';
                else if (space_sign) sign_ch = ' ';
            }

            const char *prefix = "";
            int pfx_len = 0;
            if (alt_form && base == 16U && (rlen > 0 || spec == 'p')) {
                prefix  = (spec == 'X') ? "0X" : "0x";
                pfx_len = 2;
            }

            int total = (sign_ch ? 1 : 0) + pfx_len + zprec + rlen;
            int pad   = (width > total) ? (width - total) : 0;

            if (!left_adj && !zero_pad) fmt_pad(&o, ' ', pad);
            if (sign_ch) fmt_putc(&o, sign_ch);
            if (pfx_len) fmt_puts_n(&o, prefix, (size_t)pfx_len);
            if (!left_adj && zero_pad) fmt_pad(&o, '0', pad);
            fmt_pad(&o, '0', zprec);
            while (rlen > 0) fmt_putc(&o, rev[--rlen]);
            if (left_adj) fmt_pad(&o, ' ', pad);
        }
    }

    if (o.dst && o.cap > 0) {
        size_t term = (o.pos < o.cap) ? o.pos : (o.cap - 1);
        o.dst[term] = '\0';
    }
    return (int)o.pos;
}

int snprintf(char *str, size_t size, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(str, size, format, ap);
    va_end(ap);
    return n;
}

int fprintf(FILE *stream, const char *format, ...) {
    char stack_buf[1024];
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(stack_buf, sizeof(stack_buf), format, ap);
    va_end(ap);
    if (n <= 0) return n;
    if ((size_t)n < sizeof(stack_buf)) {
        fwrite(stack_buf, 1, (size_t)n, stream ? stream : stdout);
        return n;
    }
    char *heap_buf = (char *)tb_malloc((size_t)n + 1);
    if (!heap_buf) {
        fwrite(stack_buf, 1, sizeof(stack_buf) - 1, stream ? stream : stdout);
        return n;
    }
    va_start(ap, format);
    vsnprintf(heap_buf, (size_t)n + 1, format, ap);
    va_end(ap);
    fwrite(heap_buf, 1, (size_t)n, stream ? stream : stdout);
    tb_free(heap_buf);
    return n;
}

int printf(const char *format, ...) {
    char stack_buf[1024];
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(stack_buf, sizeof(stack_buf), format, ap);
    va_end(ap);
    if (n <= 0) return n;
    if ((size_t)n < sizeof(stack_buf)) {
        fwrite(stack_buf, 1, (size_t)n, stdout);
        return n;
    }
    char *heap_buf = (char *)tb_malloc((size_t)n + 1);
    if (!heap_buf) {
        fwrite(stack_buf, 1, sizeof(stack_buf) - 1, stdout);
        return n;
    }
    va_start(ap, format);
    vsnprintf(heap_buf, (size_t)n + 1, format, ap);
    va_end(ap);
    fwrite(heap_buf, 1, (size_t)n, stdout);
    tb_free(heap_buf);
    return n;
}

int puts(const char *s) {
    if (!s) s = "(null)";
    size_t len = strlen(s);
    if (len > 0) fwrite(s, 1, len, stdout);
    fwrite("\n", 1, 1, stdout);
    return (int)len + 1;
}

/* ── Number Conversions, PRNG, qsort, getenv, realpath ── */
static uint64_t g_prng_state = 0x853c49e6748fea9bULL;
static bool     g_prng_init  = false;

void srand(unsigned int seed) {
    g_prng_state = ((uint64_t)seed << 1) | 1ULL;
    g_prng_init  = true;
}

int rand(void) {
    if (!g_prng_init) {
        uint64_t s = 0;
        if (tb_getrandom(&s, sizeof(s)) && s != 0) g_prng_state = s;
        g_prng_init = true;
    }
    uint64_t x = g_prng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_prng_state = x;
    return (int)((x * 0x2545F4914F6CDD1DULL) >> 33);
}

static uint64_t parse_int_common(const char *nptr, char **endptr, int base,
                                 bool *out_neg, bool *out_any, bool *out_ovf) {
    const char *p = nptr;
    while (*p && isspace((uint8_t)*p)) p++;

    bool neg = false;
    if (*p == '-') { neg = true; p++; }
    else if (*p == '+') { p++; }

    if ((base == 0 || base == 16) && p[0] == '0' && (p[1] == 'x' || p[1] == 'X') &&
        isxdigit((uint8_t)p[2])) {
        base = 16;
        p += 2;
    } else if (base == 0) {
        base = (p[0] == '0') ? 8 : 10;
    }

    uint64_t acc = 0;
    bool     any = false;
    bool     ovf = false;
    uint64_t cutoff = UINT64_MAX / (uint64_t)base;
    uint64_t cutlim = UINT64_MAX % (uint64_t)base;

    for (; *p; p++) {
        int d;
        uint8_t c = (uint8_t)*p;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'z') d = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'Z') d = 10 + (c - 'A');
        else break;
        if (d >= base) break;
        any = true;
        if (acc > cutoff || (acc == cutoff && (uint64_t)d > cutlim)) {
            ovf = true;
        } else {
            acc = acc * (uint64_t)base + (uint64_t)d;
        }
    }

    if (endptr) *endptr = (char *)(any ? p : nptr);
    *out_neg = neg;
    *out_any = any;
    *out_ovf = ovf;
    return acc;
}

unsigned long long strtoull(const char *nptr, char **endptr, int base) {
    if (base != 0 && (base < 2 || base > 36)) {
        if (endptr) *endptr = (char *)nptr;
        tb_errno = EINVAL;
        return 0;
    }
    bool neg = false, any = false, ovf = false;
    uint64_t v = parse_int_common(nptr, endptr, base, &neg, &any, &ovf);
    if (!any) return 0;
    if (ovf) { tb_errno = ERANGE; return ULLONG_MAX; }
    return neg ? (unsigned long long)(0ULL - v) : (unsigned long long)v;
}

long long strtoll(const char *nptr, char **endptr, int base) {
    if (base != 0 && (base < 2 || base > 36)) {
        if (endptr) *endptr = (char *)nptr;
        tb_errno = EINVAL;
        return 0;
    }
    bool neg = false, any = false, ovf = false;
    uint64_t v = parse_int_common(nptr, endptr, base, &neg, &any, &ovf);
    if (!any) return 0;
    if (neg) {
        if (ovf || v > (uint64_t)LLONG_MAX + 1ULL) {
            tb_errno = ERANGE;
            return LLONG_MIN;
        }
        return (v == (uint64_t)LLONG_MAX + 1ULL) ? LLONG_MIN : -(long long)v;
    }
    if (ovf || v > (uint64_t)LLONG_MAX) {
        tb_errno = ERANGE;
        return LLONG_MAX;
    }
    return (long long)v;
}

long strtol(const char *nptr, char **endptr, int base) {
    return (long)strtoll(nptr, endptr, base);
}

unsigned long strtoul(const char *nptr, char **endptr, int base) {
    return (unsigned long)strtoull(nptr, endptr, base);
}

int atoi(const char *nptr) {
    return (int)strtol(nptr, NULL, 10);
}

double strtod(const char *nptr, char **endptr) {
    const char *p = nptr;
    while (*p && isspace((uint8_t)*p)) p++;

    bool neg = false;
    if (*p == '-') { neg = true; p++; }
    else if (*p == '+') { p++; }

    if (tolower((uint8_t)p[0]) == 'i' && tolower((uint8_t)p[1]) == 'n' && tolower((uint8_t)p[2]) == 'f') {
        if (tolower((uint8_t)p[3]) == 'i' && tolower((uint8_t)p[4]) == 'n' &&
            tolower((uint8_t)p[5]) == 'i' && tolower((uint8_t)p[6]) == 't' &&
            tolower((uint8_t)p[7]) == 'y') {
            p += 8;
        } else {
            p += 3;
        }
        if (endptr) *endptr = (char *)p;
        return neg ? -TB_INFINITY : TB_INFINITY;
    }
    if (tolower((uint8_t)p[0]) == 'n' && tolower((uint8_t)p[1]) == 'a' && tolower((uint8_t)p[2]) == 'n') {
        p += 3;
        if (endptr) *endptr = (char *)p;
        return TB_NAN;
    }

    /* Hex float 0x1.8p+2 */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X') &&
        (isxdigit((uint8_t)p[2]) || (p[2] == '.' && isxdigit((uint8_t)p[3])))) {
        p += 2;
        double hv = 0.0;
        int bexp = 0;
        while (isxdigit((uint8_t)*p)) {
            int d = isdigit((uint8_t)*p) ? (*p - '0') : (10 + tolower((uint8_t)*p) - 'a');
            hv = hv * 16.0 + (double)d;
            p++;
        }
        if (*p == '.') {
            p++;
            double frac = 1.0 / 16.0;
            while (isxdigit((uint8_t)*p)) {
                int d = isdigit((uint8_t)*p) ? (*p - '0') : (10 + tolower((uint8_t)*p) - 'a');
                hv += (double)d * frac;
                frac /= 16.0;
                p++;
            }
        }
        if (*p == 'p' || *p == 'P') {
            const char *ep = p + 1;
            bool eneg = false;
            if (*ep == '-') { eneg = true; ep++; }
            else if (*ep == '+') { ep++; }
            if (isdigit((uint8_t)*ep)) {
                int ev = 0;
                while (isdigit((uint8_t)*ep)) {
                    if (ev < 100000) ev = ev * 10 + (*ep - '0');
                    ep++;
                }
                bexp = eneg ? -ev : ev;
                p = ep;
            }
        }
        if (endptr) *endptr = (char *)p;
        double res = tb_ldexp(hv, bexp);
        return neg ? -res : res;
    }

    uint64_t mant     = 0;
    int      sig_digs = 0;
    int      dec_exp  = 0;
    bool     has_digs = false;

    while (*p >= '0' && *p <= '9') {
        has_digs = true;
        int d = *p++ - '0';
        if (mant == 0 && d == 0) continue;
        if (sig_digs < 19) {
            mant = mant * 10ULL + (uint64_t)d;
            sig_digs++;
        } else {
            dec_exp++;
        }
    }

    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9') {
            has_digs = true;
            int d = *p++ - '0';
            if (mant == 0 && d == 0) {
                dec_exp--;
                continue;
            }
            if (sig_digs < 19) {
                mant = mant * 10ULL + (uint64_t)d;
                sig_digs++;
                dec_exp--;
            }
        }
    }

    if (!has_digs) {
        if (endptr) *endptr = (char *)nptr;
        return 0.0;
    }

    if (*p == 'e' || *p == 'E') {
        const char *ep = p + 1;
        bool eneg = false;
        if (*ep == '-') { eneg = true; ep++; }
        else if (*ep == '+') { ep++; }
        if (*ep >= '0' && *ep <= '9') {
            int ev = 0;
            while (*ep >= '0' && *ep <= '9') {
                if (ev < 100000) ev = ev * 10 + (*ep - '0');
                ep++;
            }
            dec_exp += eneg ? -ev : ev;
            p = ep;
        }
    }

    if (endptr) *endptr = (char *)p;
    if (mant == 0ULL) return neg ? -0.0 : 0.0;
    if (dec_exp > 310) return neg ? -TB_INFINITY : TB_INFINITY;
    if (dec_exp < -345) return neg ? -0.0 : 0.0;

    /* Clinger fast exact IEEE-754 path when mant < 2^53 and |dec_exp| <= 22 */
    static const double EXACT_P10[23] = {
        1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,
        1e8,  1e9,  1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
        1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22
    };
    double res = (double)mant;
    if (mant <= 9007199254740992ULL && dec_exp >= -22 && dec_exp <= 22) {
        if (dec_exp > 0) res *= EXACT_P10[dec_exp];
        else if (dec_exp < 0) res /= EXACT_P10[-dec_exp];
        return neg ? -res : res;
    }

    static const double P10[9] = { 1e256, 1e128, 1e64, 1e32, 1e16, 1e8, 1e4, 1e2, 1e1 };
    static const int    E10[9] = {   256,   128,   64,   32,   16,   8,   4,   2,   1 };
    if (dec_exp > 0) {
        for (int i = 0; i < 9; i++) {
            while (dec_exp >= E10[i]) { res *= P10[i]; dec_exp -= E10[i]; }
        }
    } else if (dec_exp < 0) {
        int ne = -dec_exp;
        for (int i = 0; i < 9; i++) {
            while (ne >= E10[i]) { res /= P10[i]; ne -= E10[i]; }
        }
    }
    return neg ? -res : res;
}

double atof(const char *nptr) {
    return strtod(nptr, NULL);
}

static void swap_bytes(uint8_t *a, uint8_t *b, size_t sz) {
    while (sz--) {
        uint8_t t = *a;
        *a++ = *b;
        *b++ = t;
    }
}

static void heap_sift_down(uint8_t *arr, size_t root, size_t count, size_t size,
                           int (*compar)(const void *, const void *)) {
    while (root < count / 2) {
        size_t child = 2 * root + 1;
        size_t swap_idx = root;
        if (compar(arr + swap_idx * size, arr + child * size) < 0) {
            swap_idx = child;
        }
        if (child + 1 < count && compar(arr + swap_idx * size, arr + (child + 1) * size) < 0) {
            swap_idx = child + 1;
        }
        if (swap_idx == root) break;
        swap_bytes(arr + root * size, arr + swap_idx * size, size);
        root = swap_idx;
    }
}

void qsort(void *base, size_t nmemb, size_t size,
           int (*compar)(const void *, const void *)) {
    if (!base || nmemb < 2 || size == 0 || !compar) return;
    uint8_t *arr = (uint8_t *)base;

    /* Bottom-up Floyd max-heapify + sortdown: O(N log N) worst-case, O(1) stack */
    for (size_t start = nmemb / 2; start > 0; ) {
        start--;
        heap_sift_down(arr, start, nmemb, size, compar);
    }
    for (size_t end = nmemb; end > 1; ) {
        end--;
        swap_bytes(arr, arr + end * size, size);
        heap_sift_down(arr, 0, end, size, compar);
    }
}

char *getenv(const char *name) {
    if (!name || !*name || !tb_environ) return NULL;
    size_t nlen = strlen(name);
    for (char **ep = tb_environ; *ep; ep++) {
        if (strncmp(*ep, name, nlen) == 0 && (*ep)[nlen] == '=') {
            return (*ep) + nlen + 1;
        }
    }
    return NULL;
}

char *realpath(const char *path, char *resolved_path) {
    if (!path || !*path) { tb_errno = EINVAL; return NULL; }

    char work[PATH_MAX];
    if (path[0] == '/') {
        snprintf(work, sizeof(work), "%s", path);
    } else {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd))) return NULL;
        snprintf(work, sizeof(work), "%s/%s", cwd, path);
    }

    char out[PATH_MAX];
    int  symlinks = 0;

    for (;;) {
        size_t opos = 0;
        out[opos++] = '/';
        out[opos]   = '\0';

        const char *p = work;
        bool restarted = false;

        while (*p) {
            while (*p == '/') p++;
            if (!*p) break;
            const char *seg = p;
            while (*p && *p != '/') p++;
            size_t slen = (size_t)(p - seg);

            if (slen == 1 && seg[0] == '.') {
                continue;
            }
            if (slen == 2 && seg[0] == '.' && seg[1] == '.') {
                if (opos > 1) {
                    opos--;
                    while (opos > 1 && out[opos - 1] != '/') opos--;
                    out[opos] = '\0';
                }
                continue;
            }

            if (opos > 1 && opos + 1 < sizeof(out)) out[opos++] = '/';
            if (opos + slen >= sizeof(out)) { tb_errno = ERANGE; return NULL; }
            memcpy(out + opos, seg, slen);
            opos += slen;
            out[opos] = '\0';

            char linkbuf[PATH_MAX];
            ssize_t rlen = readlink(out, linkbuf, sizeof(linkbuf) - 1);
            if (rlen > 0) {
                if (++symlinks > 16) { tb_errno = EINVAL; return NULL; }
                linkbuf[rlen] = '\0';
                char next_work[PATH_MAX];
                if (linkbuf[0] == '/') {
                    snprintf(next_work, sizeof(next_work), "%s%s", linkbuf, p);
                } else {
                    size_t dir_end = opos - slen;
                    if (dir_end > 1) dir_end--;
                    out[dir_end] = '\0';
                    snprintf(next_work, sizeof(next_work), "%s/%s%s", out, linkbuf, p);
                }
                snprintf(work, sizeof(work), "%s", next_work);
                restarted = true;
                break;
            }
        }
        if (!restarted) break;
    }

    struct stat st;
    if (stat(out, &st) != 0) return NULL;

    if (resolved_path) {
        snprintf(resolved_path, PATH_MAX, "%s", out);
        return resolved_path;
    }
    return tb_strdup(out);
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
