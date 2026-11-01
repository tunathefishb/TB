#include "net.h"
#include "common.h"

/* ============================================================================
 * URL Parsing, Resolution, & Omnibar Normalization
 * ============================================================================ */

void tb_url_normalize_input(const char *input, char *out, size_t cap) {
    if (!input || !*input) {
        snprintf(out, cap, "about:home");
        return;
    }
    while (*input && tb_isspace(*input)) input++;
    if (tb_strncasecmp(input, "http://", 7) == 0 ||
        tb_strncasecmp(input, "https://", 8) == 0 ||
        tb_strncasecmp(input, "file://", 7) == 0 ||
        tb_strncasecmp(input, "about:", 6) == 0 ||
        tb_strncasecmp(input, "data:", 5) == 0) {
        snprintf(out, cap, "%s", input);
        return;
    }
    /* Check if input points to an existing local file */
    struct stat st;
    if (stat(input, &st) == 0 && S_ISREG(st.st_mode)) {
        char resolved[PATH_MAX];
        if (realpath(input, resolved)) {
            snprintf(out, cap, "file://%s", resolved);
            return;
        }
    }
    if (input[0] == '/' || (input[0] == '.' && input[1] == '/')) {
        char resolved[PATH_MAX];
        if (realpath(input, resolved)) {
            snprintf(out, cap, "file://%s", resolved);
        } else {
            snprintf(out, cap, "file://%s", input);
        }
        return;
    }
    if (strncmp(input, "localhost", 9) == 0 || strncmp(input, "127.0.0.1", 9) == 0) {
        snprintf(out, cap, "http://%s", input);
        return;
    }
    snprintf(out, cap, "https://%s", input);
}

bool tb_url_parse(const char *raw, TbUrl *out) {
    if (!raw || !out) return false;
    memset(out, 0, sizeof(*out));
    while (*raw && tb_isspace(*raw)) raw++;

    if (tb_strncasecmp(raw, "about:", 6) == 0) {
        strcpy(out->scheme, "about");
        const char *p = raw + 6;
        const char *hash = strchr(p, '#');
        if (hash) {
            snprintf(out->path, sizeof(out->path), "%.*s", (int)(hash - p), p);
            snprintf(out->fragment, sizeof(out->fragment), "%s", hash + 1);
        } else {
            snprintf(out->path, sizeof(out->path), "%s", p);
        }
        return true;
    }
    if (tb_strncasecmp(raw, "data:", 5) == 0) {
        strcpy(out->scheme, "data");
        snprintf(out->path, sizeof(out->path), "%s", raw + 5);
        return true;
    }
    if (tb_strncasecmp(raw, "file://", 7) == 0) {
        strcpy(out->scheme, "file");
        const char *p = raw + 7;
        const char *hash = strchr(p, '#');
        if (hash) {
            snprintf(out->path, sizeof(out->path), "%.*s", (int)(hash - p), p);
            snprintf(out->fragment, sizeof(out->fragment), "%s", hash + 1);
        } else {
            snprintf(out->path, sizeof(out->path), "%s", p);
        }
        return true;
    }

    const char *sep = strstr(raw, "://");
    if (!sep) return false;
    size_t slen = (size_t)(sep - raw);
    if (slen == 0 || slen >= sizeof(out->scheme)) return false;
    for (size_t i = 0; i < slen; i++) out->scheme[i] = tb_tolower(raw[i]);
    out->scheme[slen] = '\0';

    if (strcmp(out->scheme, "http") == 0) out->port = 80;
    else if (strcmp(out->scheme, "https") == 0) out->port = 443;
    else return false;

    const char *authority = sep + 3;
    const char *slash     = strpbrk(authority, "/?#");
    size_t auth_len       = slash ? (size_t)(slash - authority) : strlen(authority);
    if (auth_len == 0) return false;

    /* Strip userinfo if present */
    const char *at = memchr(authority, '@', auth_len);
    if (at) {
        auth_len -= (size_t)(at + 1 - authority);
        authority = at + 1;
    }

    const char *colon = NULL;
    if (authority[0] == '[') {
        const char *rb = memchr(authority, ']', auth_len);
        if (!rb) return false;
        size_t hlen = (size_t)(rb - authority - 1);
        if (hlen == 0 || hlen >= sizeof(out->host)) return false;
        memcpy(out->host, authority + 1, hlen);
        out->host[hlen] = '\0';
        if ((size_t)(rb + 1 - authority) < auth_len && rb[1] == ':') colon = rb + 1;
    } else {
        colon = memchr(authority, ':', auth_len);
        size_t hlen = colon ? (size_t)(colon - authority) : auth_len;
        if (hlen == 0 || hlen >= sizeof(out->host)) return false;
        memcpy(out->host, authority, hlen);
        out->host[hlen] = '\0';
    }

    if (colon) {
        int port = atoi(colon + 1);
        if (port <= 0 || port > 65535) return false;
        out->port = port;
    }

    if (!slash || *slash == '#') {
        strcpy(out->path, "/");
        if (slash && *slash == '#') {
            snprintf(out->fragment, sizeof(out->fragment), "%s", slash + 1);
        }
    } else {
        const char *hash = strchr(slash, '#');
        if (*slash == '?') {
            if (hash) {
                snprintf(out->path, sizeof(out->path), "/%.*s", (int)(hash - slash), slash);
                snprintf(out->fragment, sizeof(out->fragment), "%s", hash + 1);
            } else {
                snprintf(out->path, sizeof(out->path), "/%s", slash);
            }
        } else {
            if (hash) {
                snprintf(out->path, sizeof(out->path), "%.*s", (int)(hash - slash), slash);
                snprintf(out->fragment, sizeof(out->fragment), "%s", hash + 1);
            } else {
                snprintf(out->path, sizeof(out->path), "%s", slash);
            }
        }
    }
    return true;
}

void tb_url_format(const TbUrl *u, char *out, size_t cap, bool include_frag) {
    if (!u || !out || cap == 0) return;
    if (strcmp(u->scheme, "about") == 0 || strcmp(u->scheme, "data") == 0) {
        if (include_frag && u->fragment[0])
            snprintf(out, cap, "%s:%s#%s", u->scheme, u->path, u->fragment);
        else
            snprintf(out, cap, "%s:%s", u->scheme, u->path);
        return;
    }
    if (strcmp(u->scheme, "file") == 0) {
        if (include_frag && u->fragment[0])
            snprintf(out, cap, "file://%s#%s", u->path, u->fragment);
        else
            snprintf(out, cap, "file://%s", u->path);
        return;
    }
    bool is_v6 = (strchr(u->host, ':') != NULL);
    const char *lb = is_v6 ? "[" : "";
    const char *rb = is_v6 ? "]" : "";
    bool default_port = (strcmp(u->scheme, "http") == 0 && u->port == 80) ||
                        (strcmp(u->scheme, "https") == 0 && u->port == 443);
    if (default_port) {
        if (include_frag && u->fragment[0])
            snprintf(out, cap, "%s://%s%s%s%s#%s", u->scheme, lb, u->host, rb, u->path, u->fragment);
        else
            snprintf(out, cap, "%s://%s%s%s%s", u->scheme, lb, u->host, rb, u->path);
    } else {
        if (include_frag && u->fragment[0])
            snprintf(out, cap, "%s://%s%s%s:%d%s#%s", u->scheme, lb, u->host, rb, u->port, u->path, u->fragment);
        else
            snprintf(out, cap, "%s://%s%s%s:%d%s", u->scheme, lb, u->host, rb, u->port, u->path);
    }
}

static void collapse_dot_segments(char *path) {
    char out[1024];
    char *segs[128];
    int   nseg = 0;

    /* Preserve query string intact */
    char query[512] = "";
    char *q = strchr(path, '?');
    if (q) {
        snprintf(query, sizeof(query), "%s", q);
        *q = '\0';
    }
    bool trailing_slash = (strlen(path) > 1 && path[strlen(path) - 1] == '/');

    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    char *save = NULL;
    for (char *tok = strtok_r(tmp, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
        if (strcmp(tok, ".") == 0) continue;
        if (strcmp(tok, "..") == 0) {
            if (nseg > 0) nseg--;
            continue;
        }
        if (nseg < 128) segs[nseg++] = tok;
    }

    size_t pos = 0;
    out[pos++] = '/';
    for (int i = 0; i < nseg; i++) {
        size_t l = strlen(segs[i]);
        if (pos + l + 2 >= sizeof(out)) break;
        memcpy(out + pos, segs[i], l);
        pos += l;
        if (i + 1 < nseg || trailing_slash) out[pos++] = '/';
    }
    out[pos] = '\0';
    if (pos >= 1024) pos = 1023;
    size_t qlen = strlen(query);
    if (pos + qlen >= 1024) {
        qlen = 1023 - pos;
    }
    memcpy(path, out, pos);
    if (qlen > 0) memcpy(path + pos, query, qlen);
    path[pos + qlen] = '\0';
}

void tb_url_resolve(const TbUrl *base, const char *rel, char *out, size_t cap) {
    if (!rel || !*rel) {
        tb_url_format(base, out, cap, true);
        return;
    }
    while (*rel && tb_isspace(*rel)) rel++;
    if (tb_strncasecmp(rel, "http://", 7) == 0 ||
        tb_strncasecmp(rel, "https://", 8) == 0 ||
        tb_strncasecmp(rel, "file://", 7) == 0 ||
        tb_strncasecmp(rel, "about:", 6) == 0 ||
        tb_strncasecmp(rel, "data:", 5) == 0 ||
        tb_strncasecmp(rel, "javascript:", 11) == 0) {
        snprintf(out, cap, "%s", rel);
        return;
    }
    if (!base) {
        snprintf(out, cap, "%s", rel);
        return;
    }
    if (rel[0] == '/' && rel[1] == '/') {
        const char *scheme = (strcmp(base->scheme, "http") == 0) ? "http" : "https";
        snprintf(out, cap, "%s:%s", scheme, rel);
        return;
    }

    TbUrl u = *base;
    u.fragment[0] = '\0';
    const char *hash = strchr(rel, '#');
    char rel_no_frag[1024];
    if (hash) {
        snprintf(u.fragment, sizeof(u.fragment), "%s", hash + 1);
        snprintf(rel_no_frag, sizeof(rel_no_frag), "%.*s", (int)(hash - rel), rel);
    } else {
        snprintf(rel_no_frag, sizeof(rel_no_frag), "%s", rel);
    }

    if (rel_no_frag[0] == '\0') {
        tb_url_format(&u, out, cap, true);
        return;
    }

    if (rel_no_frag[0] == '/') {
        snprintf(u.path, sizeof(u.path), "%s", rel_no_frag);
        collapse_dot_segments(u.path);
    } else if (rel_no_frag[0] == '?') {
        char *q = strchr(u.path, '?');
        if (q) *q = '\0';
        size_t l = strlen(u.path);
        snprintf(u.path + l, sizeof(u.path) - l, "%s", rel_no_frag);
    } else {
        char *q = strchr(u.path, '?');
        if (q) *q = '\0';
        char *last_slash = strrchr(u.path, '/');
        if (last_slash) *(last_slash + 1) = '\0';
        else strcpy(u.path, "/");
        size_t l = strlen(u.path);
        snprintf(u.path + l, sizeof(u.path) - l, "%s", rel_no_frag);
        collapse_dot_segments(u.path);
    }
    tb_url_format(&u, out, cap, true);
}
