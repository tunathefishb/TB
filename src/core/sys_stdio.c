#include "sys.h"
#include "math_tb.h"
#include "mem.h"

#if defined(TB_FREESTANDING) && TB_FREESTANDING

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

/* Extract up to 17 significant decimal digits and base-10 exponent from aval > 0 */
static void fmt_extract_float_digits(double aval, uint8_t digits[48], int *out_exp10) {
    int exp10 = 0;
    if (aval >= 1.0 && aval <= 9007199254740992.0 && tb_floor(aval) == aval) {
        uint64_t iv = (uint64_t)aval;
        char rev[24];
        int rlen = 0;
        while (iv > 0ULL) {
            rev[rlen++] = (char)(iv % 10ULL);
            iv /= 10ULL;
        }
        exp10 = rlen - 1;
        for (int i = 0; i < rlen && i < 48; i++) {
            digits[i] = (uint8_t)rev[rlen - 1 - i];
        }
    } else {
        double m = aval;
        if (m < 1e-307) { m *= 1e16; exp10 -= 16; }
        static const double P10[9] = { 1e256, 1e128, 1e64, 1e32, 1e16, 1e8, 1e4, 1e2, 1e1 };
        static const int    E10[9] = {   256,   128,   64,   32,   16,   8,   4,   2,   1 };
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
    *out_exp10 = exp10;
}

/* Round extracted decimal digits at position sig_keep */
static void fmt_round_float_digits(double *inout_aval, uint8_t digits[48],
                                   int *inout_exp10, int sig_keep) {
    if (sig_keep < 0) {
        memset(digits, 0, 48);
        *inout_aval  = 0.0;
        *inout_exp10 = 0;
    } else if (sig_keep == 0) {
        bool round_up = (digits[0] >= 5);
        memset(digits, 0, 48);
        if (round_up) {
            digits[0] = 1;
            (*inout_exp10)++;
        } else {
            *inout_aval  = 0.0;
            *inout_exp10 = 0;
        }
    } else if (sig_keep < 48) {
        if (digits[sig_keep] >= 5) {
            int k = sig_keep - 1;
            while (k >= 0) {
                if (++digits[k] < 10) break;
                digits[k--] = 0;
            }
            if (k < 0) {
                for (int j = sig_keep; j > 0; j--) digits[j] = digits[j - 1];
                digits[0] = 1;
                (*inout_exp10)++;
            }
        }
        for (int j = sig_keep; j < 48; j++) digits[j] = 0;
    }
}

static void fmt_float(FmtOut *o, double val, char spec, int width, int prec,
                      bool left_adj, bool zero_pad, bool force_plus, bool space_sign) {
    bool upper = (spec == 'E' || spec == 'G' || spec == 'F');
    char lspec = (char)tolower((uint8_t)spec);
    bool neg   = tb_signbit(val);

    if (tb_isnan(val) || tb_isinf(val)) {
        char tmp[16];
        int  tlen = 0;
        if (tb_isnan(val)) {
            memcpy(tmp, upper ? "NAN" : "nan", 3);
            tlen = 3;
        } else {
            if (neg) tmp[tlen++] = '-';
            else if (force_plus) tmp[tlen++] = '+';
            else if (space_sign) tmp[tlen++] = ' ';
            memcpy(tmp + tlen, upper ? "INF" : "inf", 3);
            tlen += 3;
        }
        int pad = (width > tlen) ? (width - tlen) : 0;
        if (!left_adj) fmt_pad(o, ' ', pad);
        fmt_puts_n(o, tmp, (size_t)tlen);
        if (left_adj) fmt_pad(o, ' ', pad);
        return;
    }

    double aval = tb_fabs(val);
    if (prec < 0) prec = 6;
    if (lspec == 'g' && prec == 0) prec = 1;
    if (prec > 32) prec = 32;

    int exp10 = 0;
    uint8_t digits[48];
    memset(digits, 0, sizeof(digits));
    if (aval > 0.0) {
        fmt_extract_float_digits(aval, digits, &exp10);
    }

    bool use_exp     = (lspec == 'e');
    int  frac_digits = prec;
    int  sig_keep    = (lspec == 'g') ? prec
                     : (lspec == 'e') ? (prec + 1)
                     : ((aval == 0.0) ? 0 : (exp10 + 1 + prec));

    if (aval > 0.0) {
        fmt_round_float_digits(&aval, digits, &exp10, sig_keep);
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

    char sign_ch = neg ? '-' : (force_plus ? '+' : (space_sign ? ' ' : 0));
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

static int vfprintf_internal(FILE *stream, const char *format, va_list ap) {
    FILE *target = stream ? stream : stdout;
    char stack_buf[1024];
    va_list ap_copy;
    va_copy(ap_copy, ap);
    int n = vsnprintf(stack_buf, sizeof(stack_buf), format, ap);
    if (n <= 0) {
        va_end(ap_copy);
        return n;
    }
    if ((size_t)n < sizeof(stack_buf)) {
        va_end(ap_copy);
        fwrite(stack_buf, 1, (size_t)n, target);
        return n;
    }
    char *heap_buf = (char *)tb_malloc((size_t)n + 1);
    if (!heap_buf) {
        va_end(ap_copy);
        fwrite(stack_buf, 1, sizeof(stack_buf) - 1, target);
        return n;
    }
    vsnprintf(heap_buf, (size_t)n + 1, format, ap_copy);
    va_end(ap_copy);
    fwrite(heap_buf, 1, (size_t)n, target);
    tb_free(heap_buf);
    return n;
}

int fprintf(FILE *stream, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    int n = vfprintf_internal(stream, format, ap);
    va_end(ap);
    return n;
}

int printf(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    int n = vfprintf_internal(stdout, format, ap);
    va_end(ap);
    return n;
}

int puts(const char *s) {
    if (!s) s = "(null)";
    size_t len = strlen(s);
    if (len > 0) fwrite(s, 1, len, stdout);
    fwrite("\n", 1, 1, stdout);
    return (int)len + 1;
}

#endif /* TB_FREESTANDING */
