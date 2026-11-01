#include "sys.h"
#include "math_tb.h"
#include "mem.h"

#if defined(TB_FREESTANDING) && TB_FREESTANDING

extern char **tb_environ;

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

static double strtod_hex(const char *p, bool neg, char **endptr) {
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

    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X') &&
        (isxdigit((uint8_t)p[2]) || (p[2] == '.' && isxdigit((uint8_t)p[3])))) {
        return strtod_hex(p, neg, endptr);
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

#endif /* TB_FREESTANDING */
