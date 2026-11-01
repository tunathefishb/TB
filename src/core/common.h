#ifndef TB_COMMON_H
#define TB_COMMON_H

#include "mem.h"
#include "sys.h"

/* ── Hex & Endian Primitives ── */

static inline int tb_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static inline uint16_t tb_load16_be(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline void tb_store16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFU);
}

static inline uint32_t tb_load24_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static inline void tb_store24_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 16) & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)(v & 0xFFU);
}

static inline uint32_t tb_load32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void tb_store32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint64_t tb_load64_be(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static inline void tb_store64_be(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

static inline uint32_t tb_load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void tb_store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint64_t tb_load64_le(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void tb_store64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (i * 8)) & 0xFFU);
    }
}

/* ── IPv4 & IPv6 Literal Byte Parsers ── */

static inline bool tb_parse_ipv4_bytes(const char *s, uint8_t out[4]) {
    if (!s || !*s) return false;
    int part = 0;
    const char *p = s;
    while (*p) {
        if (part >= 4 || *p < '0' || *p > '9') return false;
        uint32_t val = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            if (digits == 1 && val == 0) return false; /* Reject leading zero octal */
            val = val * 10U + (uint32_t)(*p - '0');
            if (val > 255U) return false;
            digits++;
            p++;
        }
        out[part++] = (uint8_t)val;
        if (*p == '.') {
            p++;
            if (*p == '\0') return false;
        } else if (*p != '\0') {
            return false;
        }
    }
    return part == 4;
}

static inline bool tb_parse_ipv6_bytes(const char *s, uint8_t out[16]) {
    if (!s || !*s) return false;
    char buf[96];
    size_t slen = strlen(s);
    if (slen >= sizeof(buf)) return false;
    if (s[0] == '[') {
        if (slen < 3 || s[slen - 1] != ']') return false;
        memcpy(buf, s + 1, slen - 2);
        buf[slen - 2] = '\0';
    } else {
        memcpy(buf, s, slen + 1);
    }

    char *pct = strchr(buf, '%');
    if (pct) *pct = '\0';
    if (!strchr(buf, ':')) return false;

    uint16_t head[8] = {0};
    uint16_t tail[8] = {0};
    int nhead = 0, ntail = 0;
    bool saw_dc = false;

    const char *p = buf;
    if (p[0] == ':') {
        if (p[1] != ':') return false;
        saw_dc = true;
        p += 2;
    }

    while (*p) {
        if (!saw_dc && strchr(p, '.') != NULL && !strchr(p, ':')) {
            uint8_t v4[4];
            if (!tb_parse_ipv4_bytes(p, v4) || nhead > 6) return false;
            head[nhead++] = (uint16_t)(((uint16_t)v4[0] << 8) | v4[1]);
            head[nhead++] = (uint16_t)(((uint16_t)v4[2] << 8) | v4[3]);
            break;
        }
        if (saw_dc && strchr(p, '.') != NULL && !strchr(p, ':')) {
            uint8_t v4[4];
            if (!tb_parse_ipv4_bytes(p, v4) || nhead + ntail > 6) return false;
            tail[ntail++] = (uint16_t)(((uint16_t)v4[0] << 8) | v4[1]);
            tail[ntail++] = (uint16_t)(((uint16_t)v4[2] << 8) | v4[3]);
            break;
        }

        uint32_t gval = 0;
        int hdigits = 0;
        while (*p && *p != ':') {
            int hv = tb_hex_val(*p);
            if (hv < 0 || hdigits >= 4) return false;
            gval = (gval << 4) | (uint32_t)hv;
            hdigits++;
            p++;
        }
        if (hdigits == 0) return false;

        if (!saw_dc) {
            if (nhead >= 8) return false;
            head[nhead++] = (uint16_t)gval;
        } else {
            if (ntail >= 8) return false;
            tail[ntail++] = (uint16_t)gval;
        }

        if (*p == ':') {
            if (p[1] == ':') {
                if (saw_dc) return false; /* Only one :: allowed */
                saw_dc = true;
                p += 2;
            } else {
                p++;
                if (*p == '\0') return false;
            }
        }
    }

    if (saw_dc) {
        if (nhead + ntail > 7) return false;
    } else {
        if (nhead != 8) return false;
    }

    uint16_t groups[8] = {0};
    for (int i = 0; i < nhead; i++) groups[i] = head[i];
    for (int i = 0; i < ntail; i++) groups[8 - ntail + i] = tail[i];
    for (int i = 0; i < 8; i++) {
        out[i * 2]     = (uint8_t)(groups[i] >> 8);
        out[i * 2 + 1] = (uint8_t)(groups[i] & 0xFFU);
    }
    return true;
}

static inline bool tb_host_is_ip_literal(const char *host) {
    uint8_t buf[16];
    return tb_parse_ipv4_bytes(host, buf) || tb_parse_ipv6_bytes(host, buf);
}

/* ── Dynamic Byte/String Buffer (TbBuf) ── */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
    bool   oom;
} TbBuf;

static inline void tb_buf_init(TbBuf *b) {
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
    b->oom  = false;
}

static inline void tb_buf_free(TbBuf *b) {
    tb_free(b->data);
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

static inline void tb_buf_clear(TbBuf *b) {
    b->len = 0;
    if (b->data) b->data[0] = '\0';
}

static inline bool tb_buf_reserve(TbBuf *b, size_t extra) {
    if (b->oom) return false;
    if (extra >= (SIZE_MAX / 2) - 1 || b->len > (SIZE_MAX / 2) - 1 - extra) {
        b->oom = true;
        return false;
    }
    size_t need = b->len + extra + 1;
    if (need <= b->cap) return true;
    size_t ncap = b->cap ? b->cap * 2 : 64;
    while (ncap < need) ncap *= 2;
    char *nd = (char *)tb_realloc(b->data, ncap);
    if (!nd) {
        b->oom = true;
        return false;
    }
    b->data = nd;
    b->cap  = ncap;
    return true;
}

static inline bool tb_buf_append(TbBuf *b, const char *s, size_t n) {
    if (n == 0) {
        if (!b->data) {
            if (!tb_buf_reserve(b, 0)) return false;
            b->data[0] = '\0';
        }
        return true;
    }
    if (!tb_buf_reserve(b, n)) return false;
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
    return true;
}

static inline bool tb_buf_append_cstr(TbBuf *b, const char *s) {
    if (!s) return true;
    return tb_buf_append(b, s, strlen(s));
}

static inline bool tb_buf_append_char(TbBuf *b, char c) {
    return tb_buf_append(b, &c, 1);
}

static inline bool tb_buf_printf(TbBuf *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static inline bool tb_buf_printf(TbBuf *b, const char *fmt, ...) {
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return false;
    if ((size_t)n < sizeof(tmp)) {
        return tb_buf_append(b, tmp, (size_t)n);
    }
    if (!tb_buf_reserve(b, (size_t)n)) return false;
    va_start(ap, fmt);
    vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
    return true;
}

static inline char *tb_buf_detach(TbBuf *b, size_t *out_len) {
    if (!b->data) {
        if (out_len) *out_len = 0;
        return tb_strdup("");
    }
    char *res = b->data;
    if (out_len) *out_len = b->len;
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
    return res;
}

/* ── Character & Case-Insensitive String Helpers ── */

static inline char tb_tolower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

static inline char tb_toupper(char c) {
    return (c >= 'a' && c <= 'z') ? (char)(c - ('a' - 'A')) : c;
}

static inline bool tb_isspace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static inline bool tb_isdigit(char c) {
    return c >= '0' && c <= '9';
}

static inline bool tb_isalpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static inline bool tb_isalnum(char c) {
    return tb_isalpha(c) || tb_isdigit(c);
}

static inline bool tb_isxdigit(char c) {
    return tb_hex_val(c) >= 0;
}

static inline int tb_strcasecmp(const char *a, const char *b) {
    if (!a) a = "";
    if (!b) b = "";
    while (*a && *b) {
        int ca = (unsigned char)tb_tolower(*a);
        int cb = (unsigned char)tb_tolower(*b);
        if (ca != cb) return ca - cb;
        a++;
        b++;
    }
    return (unsigned char)tb_tolower(*a) - (unsigned char)tb_tolower(*b);
}

static inline int tb_strncasecmp(const char *a, const char *b, size_t n) {
    if (n == 0) return 0;
    if (!a) a = "";
    if (!b) b = "";
    for (size_t i = 0; i < n; i++) {
        int ca = (unsigned char)tb_tolower(a[i]);
        int cb = (unsigned char)tb_tolower(b[i]);
        if (ca != cb || a[i] == '\0') return ca - cb;
    }
    return 0;
}

/* ── UTF-8 Codec & Display Width ── */

/* UTF-8 decode: returns bytes consumed (>=1), writes codepoint to *cp */
static inline size_t tb_utf8_decode(const char *s, size_t len, uint32_t *cp) {
    if (len == 0) {
        *cp = 0;
        return 0;
    }
    uint8_t b0 = (uint8_t)s[0];
    if (b0 < 0x80) {
        *cp = b0;
        return 1;
    }
    if ((b0 & 0xE0) == 0xC0 && len >= 2 && ((uint8_t)s[1] & 0xC0) == 0x80) {
        *cp = ((uint32_t)(b0 & 0x1F) << 6) | ((uint32_t)s[1] & 0x3F);
        return 2;
    }
    if ((b0 & 0xF0) == 0xE0 && len >= 3 &&
        ((uint8_t)s[1] & 0xC0) == 0x80 && ((uint8_t)s[2] & 0xC0) == 0x80) {
        *cp = ((uint32_t)(b0 & 0x0F) << 12) |
              (((uint32_t)s[1] & 0x3F) << 6) |
              ((uint32_t)s[2] & 0x3F);
        return 3;
    }
    if ((b0 & 0xF8) == 0xF0 && len >= 4 &&
        ((uint8_t)s[1] & 0xC0) == 0x80 &&
        ((uint8_t)s[2] & 0xC0) == 0x80 &&
        ((uint8_t)s[3] & 0xC0) == 0x80) {
        *cp = ((uint32_t)(b0 & 0x07) << 18) |
              (((uint32_t)s[1] & 0x3F) << 12) |
              (((uint32_t)s[2] & 0x3F) << 6) |
              ((uint32_t)s[3] & 0x3F);
        return 4;
    }
    *cp = 0xFFFD;
    return 1;
}

static inline size_t tb_utf8_encode(uint32_t cp, char out[4]) {
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    if (cp <= 0x10FFFF) {
        out[0] = (char)(0xF0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
    out[0] = '?';
    return 1;
}

/* Terminal display column width for a Unicode codepoint */
static inline int tb_unicode_width(uint32_t cp) {
    if (cp == 0) return 0;
    if (cp < 32 || (cp >= 0x7F && cp < 0xA0)) return 0;
    /* Combining marks */
    if ((cp >= 0x0300 && cp <= 0x036F) ||
        (cp >= 0x1AB0 && cp <= 0x1AFF) ||
        (cp >= 0x1DC0 && cp <= 0x1DFF) ||
        (cp >= 0x20D0 && cp <= 0x20FF) ||
        (cp >= 0xFE00 && cp <= 0xFE0F) ||
        (cp >= 0xFE20 && cp <= 0xFE2F)) {
        return 0;
    }
    /* CJK & Wide Emoji ranges */
    if (cp >= 0x1100 &&
        (cp <= 0x115F || cp == 0x2329 || cp == 0x232A ||
         (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) ||
         (cp >= 0xAC00 && cp <= 0xD7A3) ||
         (cp >= 0xF900 && cp <= 0xFAFF) ||
         (cp >= 0xFE10 && cp <= 0xFE19) ||
         (cp >= 0xFE30 && cp <= 0xFE6F) ||
         (cp >= 0xFF00 && cp <= 0xFF60) ||
         (cp >= 0xFFE0 && cp <= 0xFFE6) ||
         (cp >= 0x1F300 && cp <= 0x1FAFF) ||
         (cp >= 0x20000 && cp <= 0x3FFFD))) {
        return 2;
    }
    return 1;
}

static inline uint32_t tb_fnv1a(const char *s, size_t len) {
    uint32_t h = 2166136261U;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619U;
    }
    return h;
}

#endif /* TB_COMMON_H */
