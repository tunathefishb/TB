#ifndef TB_SYS_H
#define TB_SYS_H

#if !defined(TB_FREESTANDING) || !TB_FREESTANDING
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <float.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(TB_FREESTANDING) && TB_FREESTANDING

#if !defined(__linux__) || !defined(__x86_64__)
#error "TB_FREESTANDING=1 currently targets Linux x86_64; build with FREESTANDING=0 on other hosts."
#endif

typedef int64_t  ssize_t;
typedef int64_t  off_t;
typedef int32_t  pid_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef uint32_t mode_t;
typedef uint32_t socklen_t;
typedef int64_t  time_t;
typedef int      sig_atomic_t;

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

extern int tb_errno;
#define errno tb_errno

#define EPERM        1
#define ENOENT       2
#define ESRCH        3
#define EINTR        4
#define EIO          5
#define ENXIO        6
#define EBADF        9
#define ECHILD       10
#define EAGAIN       11
#define EWOULDBLOCK  11
#define ENOMEM       12
#define EACCES       13
#define EFAULT       14
#define EEXIST       17
#define ENOTDIR      20
#define EISDIR       21
#define EINVAL       22
#define EMFILE       24
#define ENOTTY       25
#define EPIPE        32
#define ERANGE       34
#define ECONNRESET   104
#define ETIMEDOUT    110
#define ECONNREFUSED 111
#define EHOSTUNREACH 113
#define EALREADY     114
#define EINPROGRESS  115

/* File & fcntl flags (Linux x86_64 UAPI) */
#define O_RDONLY   00000000
#define O_WRONLY   00000001
#define O_RDWR     00000002
#define O_CREAT    00000100
#define O_TRUNC    00001000
#define O_APPEND   00002000
#define O_NONBLOCK 00004000
#define O_CLOEXEC  02000000
#define AT_FDCWD   (-100)

#define F_GETFL 3
#define F_SETFL 4

/* Linux x86_64 kernel struct stat (144 bytes) */
struct stat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t __pad0;
    uint64_t st_rdev;
    int64_t  st_size;
    int64_t  st_blksize;
    int64_t  st_blocks;
    uint64_t st_atime;
    uint64_t st_atime_nsec;
    uint64_t st_mtime;
    uint64_t st_mtime_nsec;
    uint64_t st_ctime;
    uint64_t st_ctime_nsec;
    int64_t  __unused[3];
};

#define S_IFMT  0170000U
#define S_IFDIR 0040000U
#define S_IFREG 0100000U
#define S_IFLNK 0120000U
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)

/* Virtual memory */
#define PROT_NONE      0x0
#define PROT_READ      0x1
#define PROT_WRITE     0x2
#define PROT_EXEC      0x4
#define MAP_SHARED     0x01
#define MAP_PRIVATE    0x02
#define MAP_ANONYMOUS  0x20
#define MAP_FAILED     ((void *)-1)
#define MREMAP_MAYMOVE 1
#define MADV_DONTNEED  4

/* Poll */
typedef unsigned long nfds_t;
struct pollfd {
    int   fd;
    short events;
    short revents;
};
#define POLLIN   0x0001
#define POLLPRI  0x0002
#define POLLOUT  0x0004
#define POLLERR  0x0008
#define POLLHUP  0x0010
#define POLLNVAL 0x0020

/* Clocks & Time */
struct timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};
struct timeval {
    int64_t tv_sec;
    int64_t tv_usec;
};
#define CLOCK_REALTIME  0
#define CLOCK_MONOTONIC 1

/* Terminal & ioctl (Linux x86_64 UAPI struct termios = 36 bytes) */
typedef unsigned int  tcflag_t;
typedef unsigned char cc_t;
struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t     c_line;
    cc_t     c_cc[19];
};
struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};
#define TCGETS     0x5401UL
#define TCSETS     0x5402UL
#define TCSETSW    0x5403UL
#define TCSETSF    0x5404UL
#define TIOCGWINSZ 0x5413UL

#define TCSANOW   0
#define TCSADRAIN 1
#define TCSAFLUSH 2

#define BRKINT 0000002U
#define ICRNL  0000400U
#define INPCK  0000020U
#define ISTRIP 0000040U
#define IXON   0002000U
#define OPOST  0000001U
#define CS8    0000060U
#define ISIG   0000001U
#define ICANON 0000002U
#define ECHO   0000010U
#define IEXTEN 0100000U
#define VTIME  5
#define VMIN   6

/* Signals */
#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGKILL   9
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGCHLD   17
#define SIGWINCH  28
#define SA_RESTORER 0x04000000UL

#define SIG_DFL ((void (*)(int))0)
#define SIG_IGN ((void (*)(int))1)

struct sigaction {
    void         (*sa_handler)(int);
    unsigned long  sa_flags;
    void         (*sa_restorer)(void);
    uint64_t       sa_mask;
};

/* Process wait */
#define WNOHANG 1
#define WIFEXITED(s)   (((s) & 0x7f) == 0)
#define WEXITSTATUS(s) (((s) >> 8) & 0xff)

/* Sockets & IP */
typedef uint16_t sa_family_t;
typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;

#define AF_UNSPEC 0
#define AF_UNIX   1
#define AF_INET   2
#define AF_INET6  10

#define SOCK_STREAM   1
#define SOCK_DGRAM    2
#define SOCK_NONBLOCK 00004000
#define SOCK_CLOEXEC  02000000

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define SOL_SOCKET   1
#define SO_REUSEADDR 2
#define SO_ERROR     4
#define SO_RCVTIMEO  20
#define SO_SNDTIMEO  21
#define MSG_NOSIGNAL 0x4000

#define INADDR_ANY      0x00000000U
#define INADDR_LOOPBACK 0x7F000001U

struct sockaddr {
    sa_family_t sa_family;
    char        sa_data[14];
};

struct in_addr {
    uint32_t s_addr;
};

struct sockaddr_in {
    sa_family_t    sin_family;
    in_port_t      sin_port;
    struct in_addr sin_addr;
    uint8_t        sin_zero[8];
};

struct in6_addr {
    uint8_t s6_addr[16];
};

struct sockaddr_in6 {
    sa_family_t     sin6_family;
    in_port_t       sin6_port;
    uint32_t        sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t        sin6_scope_id;
};

struct sockaddr_storage {
    sa_family_t ss_family;
    char        __ss_pad[126];
} __attribute__((aligned(8)));

static inline uint16_t htons(uint16_t v) { return __builtin_bswap16(v); }
static inline uint16_t ntohs(uint16_t v) { return __builtin_bswap16(v); }
static inline uint32_t htonl(uint32_t v) { return __builtin_bswap32(v); }
static inline uint32_t ntohl(uint32_t v) { return __builtin_bswap32(v); }

/* Syscall & POSIX wrappers */
int     open(const char *path, int flags, ...);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int     close(int fd);
int     stat(const char *path, struct stat *st);
int     fstat(int fd, struct stat *st);
int     unlink(const char *path);
int     fcntl(int fd, int cmd, ...);
int     poll(struct pollfd *fds, nfds_t nfds, int timeout_ms);
int     ioctl(int fd, unsigned long req, ...);
void   *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int     munmap(void *addr, size_t length);
void   *mremap(void *old_addr, size_t old_size, size_t new_size, int flags);
int     madvise(void *addr, size_t length, int advice);

int     socket(int domain, int type, int protocol);
int     connect(int fd, const struct sockaddr *addr, socklen_t addrlen);
int     bind(int fd, const struct sockaddr *addr, socklen_t addrlen);
int     listen(int fd, int backlog);
int     accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
int     getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen);
int     setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
int     getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t send(int fd, const void *buf, size_t len, int flags);
ssize_t recv(int fd, void *buf, size_t len, int flags);

pid_t   getpid(void);
pid_t   fork(void);
pid_t   waitpid(pid_t pid, int *wstatus, int options);
int     kill(pid_t pid, int sig);
int     pipe(int pipefd[2]);
int     dup2(int oldfd, int newfd);
int     execve(const char *pathname, char *const argv[], char *const envp[]);
int     chdir(const char *path);
char   *getcwd(char *buf, size_t size);
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
int     clock_gettime(int clk_id, struct timespec *tp);
int     nanosleep(const struct timespec *req, struct timespec *rem);
int     sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);

int     isatty(int fd);
int     tcgetattr(int fd, struct termios *termios_p);
int     tcsetattr(int fd, int optional_actions, const struct termios *termios_p);

/* Minimal FILE I/O */
typedef struct TbFile FILE;
extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

FILE  *fopen(const char *path, const char *mode);
int    fclose(FILE *stream);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int    fflush(FILE *stream);

int vsnprintf(char *str, size_t size, const char *format, va_list ap);
int snprintf(char *str, size_t size, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
int printf(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
int fprintf(FILE *stream, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
int puts(const char *s);

/* Memory & String routines */
void  *memcpy(void *dst, const void *src, size_t n);
void  *memmove(void *dst, const void *src, size_t n);
void  *memset(void *s, int c, size_t n);
int    memcmp(const void *s1, const void *s2, size_t n);
void  *memchr(const void *s, int c, size_t n);

size_t strlen(const char *s);
size_t strnlen(const char *s, size_t maxlen);
int    strcmp(const char *s1, const char *s2);
int    strncmp(const char *s1, const char *s2, size_t n);
char  *strcpy(char *dst, const char *src);
char  *strchr(const char *s, int c);
char  *strrchr(const char *s, int c);
char  *strstr(const char *haystack, const char *needle);
char  *strcasestr(const char *haystack, const char *needle);
char  *strpbrk(const char *s, const char *accept);
char  *strtok_r(char *str, const char *delim, char **saveptr);
char  *strerror(int errnum);

/* Character classification */
static inline int isdigit(int c)  { return (c >= '0' && c <= '9'); }
static inline int isalpha(int c)  { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
static inline int isalnum(int c)  { return isalpha(c) || isdigit(c); }
static inline int isxdigit(int c) {
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static inline int isspace(int c)  {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}
static inline int tolower(int c)  { return (c >= 'A' && c <= 'Z') ? (c + 32) : c; }
static inline int toupper(int c)  { return (c >= 'a' && c <= 'z') ? (c - 32) : c; }

/* Number parsing, sort, env, lifecycle */
#define RAND_MAX 0x7fffffff
int                rand(void);
void               srand(unsigned int seed);
int                atoi(const char *nptr);
double             atof(const char *nptr);
long               strtol(const char *nptr, char **endptr, int base);
unsigned long      strtoul(const char *nptr, char **endptr, int base);
long long          strtoll(const char *nptr, char **endptr, int base);
unsigned long long strtoull(const char *nptr, char **endptr, int base);
double             strtod(const char *nptr, char **endptr);
void               qsort(void *base, size_t nmemb, size_t size,
                         int (*compar)(const void *, const void *));
char              *realpath(const char *path, char *resolved_path);
char              *getenv(const char *name);
int                atexit(void (*function)(void));
void               exit(int status) __attribute__((noreturn));
void               _exit(int status) __attribute__((noreturn));

#else /* TB_FREESTANDING == 0 (Hosted POSIX/libc fallback) */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#endif /* TB_FREESTANDING */

/* Cross-build CSPRNG helper backed by Linux getrandom syscall / /dev/urandom */
bool tb_getrandom(void *buf, size_t len);

#endif /* TB_SYS_H */
