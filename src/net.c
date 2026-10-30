#include "net.h"
#include "common.h"
#include "inflate.h"

#if defined(TB_TLS_OPENSSL) && TB_TLS_OPENSSL
#include <dlfcn.h>
#include <openssl/ssl.h>
#else
#include "tls.h"
#endif

/* ============================================================================
 * TLS Backend Selection: Built-in Zero-Dependency TLS 1.3 (default) vs OpenSSL
 * ============================================================================ */

#if defined(TB_TLS_OPENSSL) && TB_TLS_OPENSSL

static char g_openssl_ca_file[PATH_MAX];

typedef struct {
    void *handle;
    bool  tried;
    const SSL_METHOD *(*p_TLS_client_method)(void);
    SSL_CTX *(*p_SSL_CTX_new)(const SSL_METHOD *);
    void (*p_SSL_CTX_free)(SSL_CTX *);
    void (*p_SSL_CTX_set_verify)(SSL_CTX *, int, SSL_verify_cb);
    int (*p_SSL_CTX_load_verify_dir)(SSL_CTX *, const char *);
    int (*p_SSL_CTX_load_verify_locations)(SSL_CTX *, const char *, const char *);
    long (*p_SSL_CTX_ctrl)(SSL_CTX *, int, long, void *);
    SSL *(*p_SSL_new)(SSL_CTX *);
    void (*p_SSL_free)(SSL *);
    int (*p_SSL_set_fd)(SSL *, int);
    int (*p_SSL_set1_host)(SSL *, const char *);
    long (*p_SSL_ctrl)(SSL *, int, long, void *);
    int (*p_SSL_connect)(SSL *);
    int (*p_SSL_read)(SSL *, void *, int);
    int (*p_SSL_write)(SSL *, const void *, int);
    int (*p_SSL_shutdown)(SSL *);
    SSL_CTX *ctx_verified;
    SSL_CTX *ctx_insecure;
} LazySsl;

static LazySsl g_ssl = {0};

void tb_tls_set_ca_file(const char *pem_path) {
    if (!pem_path || !*pem_path) g_openssl_ca_file[0] = '\0';
    else snprintf(g_openssl_ca_file, sizeof(g_openssl_ca_file), "%s", pem_path);
    if (g_ssl.ctx_verified && g_ssl.p_SSL_CTX_free) {
        g_ssl.p_SSL_CTX_free(g_ssl.ctx_verified);
        g_ssl.ctx_verified = NULL;
    }
}

const char *tb_tls_get_ca_file(void) {
    return g_openssl_ca_file[0] ? g_openssl_ca_file : NULL;
}

static bool ensure_ssl_loaded(bool insecure, SSL_CTX **out_ctx, char *err, size_t err_cap) {
    if (!g_ssl.tried) {
        g_ssl.tried  = true;
        g_ssl.handle = dlopen("libssl.so.3", RTLD_LAZY);
        if (!g_ssl.handle) g_ssl.handle = dlopen("libssl.so", RTLD_LAZY);
        if (g_ssl.handle) {
            *(void **)(&g_ssl.p_TLS_client_method)             = dlsym(g_ssl.handle, "TLS_client_method");
            *(void **)(&g_ssl.p_SSL_CTX_new)                   = dlsym(g_ssl.handle, "SSL_CTX_new");
            *(void **)(&g_ssl.p_SSL_CTX_free)                  = dlsym(g_ssl.handle, "SSL_CTX_free");
            *(void **)(&g_ssl.p_SSL_CTX_set_verify)            = dlsym(g_ssl.handle, "SSL_CTX_set_verify");
            *(void **)(&g_ssl.p_SSL_CTX_load_verify_dir)       = dlsym(g_ssl.handle, "SSL_CTX_load_verify_dir");
            *(void **)(&g_ssl.p_SSL_CTX_load_verify_locations) = dlsym(g_ssl.handle, "SSL_CTX_load_verify_locations");
            *(void **)(&g_ssl.p_SSL_CTX_ctrl)                  = dlsym(g_ssl.handle, "SSL_CTX_ctrl");
            *(void **)(&g_ssl.p_SSL_new)                       = dlsym(g_ssl.handle, "SSL_new");
            *(void **)(&g_ssl.p_SSL_free)                      = dlsym(g_ssl.handle, "SSL_free");
            *(void **)(&g_ssl.p_SSL_set_fd)                    = dlsym(g_ssl.handle, "SSL_set_fd");
            *(void **)(&g_ssl.p_SSL_set1_host)                 = dlsym(g_ssl.handle, "SSL_set1_host");
            *(void **)(&g_ssl.p_SSL_ctrl)                      = dlsym(g_ssl.handle, "SSL_ctrl");
            *(void **)(&g_ssl.p_SSL_connect)                   = dlsym(g_ssl.handle, "SSL_connect");
            *(void **)(&g_ssl.p_SSL_read)                      = dlsym(g_ssl.handle, "SSL_read");
            *(void **)(&g_ssl.p_SSL_write)                     = dlsym(g_ssl.handle, "SSL_write");
            *(void **)(&g_ssl.p_SSL_shutdown)                  = dlsym(g_ssl.handle, "SSL_shutdown");
        }
    }
    if (!g_ssl.handle || !g_ssl.p_TLS_client_method || !g_ssl.p_SSL_CTX_new ||
        !g_ssl.p_SSL_new || !g_ssl.p_SSL_connect || !g_ssl.p_SSL_read || !g_ssl.p_SSL_write) {
        snprintf(err, err_cap, "OpenSSL (libssl.so.3) unavailable for HTTPS");
        return false;
    }

    SSL_CTX **slot = insecure ? &g_ssl.ctx_insecure : &g_ssl.ctx_verified;
    if (!*slot) {
        SSL_CTX *ctx = g_ssl.p_SSL_CTX_new(g_ssl.p_TLS_client_method());
        if (!ctx) {
            snprintf(err, err_cap, "SSL_CTX_new failed");
            return false;
        }
        if (g_ssl.p_SSL_CTX_ctrl) {
            g_ssl.p_SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, SSL_MODE_RELEASE_BUFFERS, NULL);
        }
        if (insecure) {
            g_ssl.p_SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        } else {
            if (g_openssl_ca_file[0] && g_ssl.p_SSL_CTX_load_verify_locations) {
                g_ssl.p_SSL_CTX_load_verify_locations(ctx, g_openssl_ca_file, NULL);
            } else if (g_ssl.p_SSL_CTX_load_verify_dir) {
                g_ssl.p_SSL_CTX_load_verify_dir(ctx, "/etc/ssl/certs");
            }
            g_ssl.p_SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        }
        *slot = ctx;
    }
    *out_ctx = *slot;
    return true;
}

void tb_net_cleanup(void) {
    if (g_ssl.ctx_verified && g_ssl.p_SSL_CTX_free) g_ssl.p_SSL_CTX_free(g_ssl.ctx_verified);
    if (g_ssl.ctx_insecure && g_ssl.p_SSL_CTX_free) g_ssl.p_SSL_CTX_free(g_ssl.ctx_insecure);
    g_ssl.ctx_verified = NULL;
    g_ssl.ctx_insecure = NULL;
    if (g_ssl.handle) {
        dlclose(g_ssl.handle);
        g_ssl.handle = NULL;
    }
    g_ssl.tried = false;
}

#else /* Default: Built-in Zero-Dependency TLS 1.3 + X.509 */

void tb_net_cleanup(void) {
    /* Stateless in-tree TLS 1.3 keeps 0 KB persistent global state */
}

#endif

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

void tb_response_free(TbResponse *resp) {
    if (!resp) return;
    tb_free(resp->body);
    resp->body     = NULL;
    resp->body_len = 0;
}

/* ============================================================================
 * Built-in about: Pages
 * ============================================================================ */

static const char *ABOUT_HOME_HTML =
    "<!DOCTYPE html><html><head><title>TB — Sub-10MB TUI Browser + JS Engine</title>"
    "<style>"
    "body { margin: 1 2; }"
    ".hero { border: 1px solid #38bdf8; background: #0f172a; padding: 1 2; margin-bottom: 1; }"
    "h1 { color: #38bdf8; margin-bottom: 0; }"
    ".sub { color: #94a3b8; }"
    ".card { border: 1px solid #334155; padding: 1 2; margin-bottom: 1; }"
    "h2 { color: #a78bfa; margin-bottom: 1; }"
    ".btn { background: #1e293b; color: #38bdf8; font-weight: bold; }"
    ".ok { color: #4ade80; font-weight: bold; }"
    ".warn { color: #fbbf24; }"
    "code { color: #f472b6; }"
    "</style></head><body>"
    "<div class='hero'>"
    "<h1>⚡ TB: Sub-10MB TUI Web Browser + Custom JS Engine</h1>"
    "<p class='sub'>Zero-dependency C11 browser • Freestanding Linux x86_64 • Custom JS &amp; RegExp VM • Built-in TLS 1.3</p>"
    "<p id='mem-banner' class='ok'>Initializing JS Engine telemetry...</p>"
    "</div>"
    "<div class='card'>"
    "<h2>🧭 Quick Navigation</h2>"
    "<ul>"
    "<li><a href='about:demo'>Interactive JavaScript App Suite (Todo MVC + Calculator + Table Sorter)</a></li>"
    "<li><a href='about:memory'>Live Memory &amp; Garbage Collector Telemetry Lab</a></li>"
    "<li><a href='about:help'>Keyboard / Mouse Controls &amp; Engine Architecture</a></li>"
    "</ul>"
    "</div>"
    "<div class='card'>"
    "<h2>🧪 Live JS + DOM Sanity Widget</h2>"
    "<p>Counter value: <strong id='cnt' style='color:#4ade80'>0</strong> — <span id='msg'>Click a button or press Tab + Enter!</span></p>"
    "<p>"
    "<button id='btn-inc'>+ Increment</button> "
    "<button id='btn-dec'>- Decrement</button> "
    "<button id='btn-fib'>Compute Fib(28)</button> "
    "<button id='btn-gc'>Force GC</button>"
    "</p>"
    "</div>"
    "<script>"
    "let count = 0;"
    "const cntEl = document.getElementById('cnt');"
    "const msgEl = document.getElementById('msg');"
    "const memEl = document.getElementById('mem-banner');"
    "function refreshMem() {"
    "  const m = performance.memory;"
    "  const rssMB = (m.rssBytes / (1024 * 1024)).toFixed(2);"
    "  const anonKB = Math.round(m.anonBytes / 1024);"
    "  const jsKB = Math.round(m.usedJSHeapSize / 1024);"
    "  memEl.textContent = 'LIVE TELEMETRY — OS VmRSS: ' + rssMB + ' MB (< 10.00 MB target!) | Private RssAnon: ' + anonKB + ' KB | JS Heap: ' + jsKB + ' KB';"
    "}"
    "document.getElementById('btn-inc').addEventListener('click', () => {"
    "  count++; cntEl.textContent = String(count);"
    "  msgEl.textContent = 'Updated DOM node via addEventListener!';"
    "  refreshMem();"
    "});"
    "document.getElementById('btn-dec').addEventListener('click', () => {"
    "  count--; cntEl.textContent = String(count);"
    "  msgEl.textContent = 'Decremented counter!';"
    "  refreshMem();"
    "});"
    "document.getElementById('btn-fib').addEventListener('click', () => {"
    "  const t0 = performance.now();"
    "  let a = 0, b = 1;"
    "  for (let i = 0; i < 28; i++) { const t = a + b; a = b; b = t; }"
    "  const dt = (performance.now() - t0).toFixed(2);"
    "  msgEl.textContent = 'Fib(28) = ' + a + ' computed in ' + dt + ' ms';"
    "  refreshMem();"
    "});"
    "document.getElementById('btn-gc').addEventListener('click', () => {"
    "  const freed = tb.gc();"
    "  refreshMem();"
    "  msgEl.textContent = 'Mark-and-Sweep GC complete (' + freed + ' objects swept)';"
    "});"
    "refreshMem();"
    "</script></body></html>";

static const char *ABOUT_DEMO_HTML =
    "<!DOCTYPE html><html><head><title>JS App Showcase — TB</title>"
    "<style>"
    "body { margin: 1 2; }"
    ".box { border: 1px solid #475569; padding: 1 2; margin-bottom: 1; }"
    "h1 { color: #38bdf8; }"
    "h2 { color: #fbbf24; }"
    ".done { color: #64748b; text-decoration: line-through; }"
    ".active-item { color: #e2e8f0; }"
    "th { color: #38bdf8; font-weight: bold; }"
    "</style></head><body>"
    "<p><a href='about:home'>← Back to Home</a> | <a href='about:memory'>Memory Lab →</a></p>"
    "<h1>🚀 Interactive JavaScript Web App Suite</h1>"
    "<div class='box'>"
    "<h2>1. Reactive Todo App (DOM Creation, Event Delegation &amp; Filtering)</h2>"
    "<p>New Task: <input id='todo-in' type='text' value='Ship sub-10MB browser' /> "
    "<button id='todo-add'>Add Task</button> "
    "<button id='todo-clear'>Clear Completed</button></p>"
    "<ul id='todo-list'></ul>"
    "<p id='todo-stats' style='color:#4ade80'></p>"
    "</div>"
    "<div class='box'>"
    "<h2>2. JS Expression Calculator</h2>"
    "<p>Expression: <input id='calc-in' type='text' value='(6 * 7) + Math.sqrt(144)' /> "
    "<button id='calc-run'>Evaluate</button></p>"
    "<p>Result: <strong id='calc-out' style='color:#38bdf8'>54</strong></p>"
    "</div>"
    "<div class='box'>"
    "<h2>3. Dynamic Sortable Benchmarks Table</h2>"
    "<p><button id='sort-mem'>Sort by Memory ↑</button> <button id='sort-name'>Sort by Engine A-Z</button></p>"
    "<table><thead><tr><th>Browser / Engine</th><th>Typical RSS</th><th>JS Engine</th></tr></thead>"
    "<tbody id='bench-body'></tbody></table>"
    "</div>"
    "<script>"
    "let todos = ["
    "  { id: 1, text: 'Write C11 HTML/CSS layout engine', done: true },"
    "  { id: 2, text: 'Implement JS lexer, parser, closures & GC', done: true },"
    "  { id: 3, text: 'Keep active VmRSS strictly under 10 MB', done: false }"
    "];"
    "let nextId = 4;"
    "function renderTodos() {"
    "  const ul = document.getElementById('todo-list');"
    "  ul.innerHTML = '';"
    "  let left = 0;"
    "  todos.forEach(item => {"
    "    if (!item.done) left++;"
    "    const li = document.createElement('li');"
    "    const btn = document.createElement('button');"
    "    btn.textContent = item.done ? '[x]' : '[ ]';"
    "    btn.addEventListener('click', () => { item.done = !item.done; renderTodos(); });"
    "    const span = document.createElement('span');"
    "    span.textContent = ' ' + item.text;"
    "    if (item.done) span.className = 'done';"
    "    li.appendChild(btn);"
    "    li.appendChild(span);"
    "    ul.appendChild(li);"
    "  });"
    "  document.getElementById('todo-stats').textContent = left + ' remaining of ' + todos.length + ' tasks';"
    "}"
    "document.getElementById('todo-add').addEventListener('click', () => {"
    "  const inp = document.getElementById('todo-in');"
    "  const v = inp.value.trim();"
    "  if (v) { todos.push({ id: nextId++, text: v, done: false }); inp.value = ''; renderTodos(); }"
    "});"
    "document.getElementById('todo-clear').addEventListener('click', () => {"
    "  todos = todos.filter(t => !t.done); renderTodos();"
    "});"
    "renderTodos();"
    ""
    "document.getElementById('calc-run').addEventListener('click', () => {"
    "  const expr = document.getElementById('calc-in').value;"
    "  const out = document.getElementById('calc-out');"
    "  try { out.textContent = String(eval(expr)); out.style.color = '#4ade80'; }"
    "  catch (e) { out.textContent = 'Error: ' + e; out.style.color = '#f87171'; }"
    "});"
    ""
    "const rows = ["
    "  { name: 'TB (TinyBrowser C11)', rss: 0.5, js: 'Yes (Built-in TinyJS + TLS 1.3)' },"
    "  { name: 'Lynx / w3m', rss: 6.5, js: 'No JS engine' },"
    "  { name: 'Browsh (Headless Firefox)', rss: 380.0, js: 'Yes (SpiderMonkey)' },"
    "  { name: 'Headless Chromium', rss: 290.0, js: 'Yes (V8)' }"
    "];"
    "function renderTable() {"
    "  const tbEl = document.getElementById('bench-body');"
    "  tbEl.innerHTML = rows.map(r => '<tr><td>' + r.name + '</td><td>' + r.rss.toFixed(1) + ' MB</td><td>' + r.js + '</td></tr>').join('');"
    "}"
    "document.getElementById('sort-mem').addEventListener('click', () => { rows.sort((a,b) => a.rss - b.rss); renderTable(); });"
    "document.getElementById('sort-name').addEventListener('click', () => { rows.sort((a,b) => a.name < b.name ? -1 : 1); renderTable(); });"
    "renderTable();"
    "</script></body></html>";

static const char *ABOUT_MEMORY_HTML =
    "<!DOCTYPE html><html><head><title>Memory &amp; GC Telemetry Lab — TB</title>"
    "<style>"
    "body { margin: 1 2; }"
    ".panel { border: 1px solid #38bdf8; padding: 1 2; margin-bottom: 1; }"
    "h1 { color: #38bdf8; }"
    "th { color: #a78bfa; }"
    ".good { color: #4ade80; font-weight: bold; }"
    "</style></head><body>"
    "<p><a href='about:home'>← Back to Home</a> | <a href='about:demo'>JS App Suite →</a></p>"
    "<h1>🔬 Live Memory &amp; Garbage Collector Lab</h1>"
    "<div class='panel'>"
    "<p class='good' id='verdict'>Checking 10 MB memory budget...</p>"
    "<table><thead><tr><th>Metric</th><th>Current Value</th><th>Budget / Notes</th></tr></thead>"
    "<tbody id='mem-rows'></tbody></table>"
    "<p>"
    "<button id='btn-churn'>Churn 5,000 Temp Objects</button> "
    "<button id='btn-retain'>Retain +500 Objects</button> "
    "<button id='btn-release'>Release Retained</button> "
    "<button id='btn-collect'>Run Mark &amp; Sweep GC</button>"
    "</p>"
    "<p id='action-log' style='color:#fbbf24'>Ready for stress testing.</p>"
    "</div>"
    "<script>"
    "let retained = [];"
    "function updateStats(note) {"
    "  const m = performance.memory;"
    "  const rssMB = (m.rssBytes / 1048576);"
    "  const verdict = document.getElementById('verdict');"
    "  verdict.textContent = rssMB < 10.0"
    "    ? 'PASS: Active OS VmRSS is ' + rssMB.toFixed(2) + ' MB — strictly below 10.00 MB!'"
    "    : 'WARNING: VmRSS is ' + rssMB.toFixed(2) + ' MB';"
    "  const data = ["
    "    ['Kernel VmRSS (Total Resident)', (m.rssBytes / 1024).toFixed(0) + ' KB (' + rssMB.toFixed(2) + ' MB)', 'Hard Target < 10,240 KB'],"
    "    ['Kernel RssAnon (Private Heap/Stack)', (m.anonBytes / 1024).toFixed(0) + ' KB', 'Actual private process RAM'],"
    "    ['Tracked C Heap Live', (m.heapLiveBytes / 1024).toFixed(1) + ' KB', 'Cap: ' + (m.heapLimitBytes / 1024).toFixed(0) + ' KB'],"
    "    ['JS GC Managed Heap', (m.usedJSHeapSize / 1024).toFixed(1) + ' KB', 'Threshold: ' + (m.totalJSHeapSize / 1024).toFixed(1) + ' KB'],"
    "    ['JS Live GC Objects', String(m.jsObjectCount), 'Retained array len: ' + retained.length]"
    "  ];"
    "  document.getElementById('mem-rows').innerHTML = data.map(r =>"
    "    '<tr><td>' + r[0] + '</td><td><strong>' + r[1] + '</strong></td><td>' + r[2] + '</td></tr>'"
    "  ).join('');"
    "  if (note) document.getElementById('action-log').textContent = note;"
    "}"
    "document.getElementById('btn-churn').addEventListener('click', () => {"
    "  const t0 = performance.now();"
    "  let acc = 0;"
    "  for (let i = 0; i < 5000; i++) {"
    "    const tmp = { idx: i, label: 'ephemeral_' + i, arr: [i, i + 1] };"
    "    acc += tmp.arr[1];"
    "  }"
    "  const dt = (performance.now() - t0).toFixed(1);"
    "  updateStats('Churned 5,000 objects + strings + arrays in ' + dt + ' ms (checksum ' + acc + '). Automatic GC kept heap tiny!');"
    "});"
    "document.getElementById('btn-retain').addEventListener('click', () => {"
    "  for (let i = 0; i < 500; i++) retained.push({ k: retained.length, tag: 'held_' + i });"
    "  updateStats('Retained 500 more objects (total ' + retained.length + ').');"
    "});"
    "document.getElementById('btn-release').addEventListener('click', () => {"
    "  retained = [];"
    "  const swept = tb.gc();"
    "  updateStats('Cleared reference & ran GC + madvise trim: swept ' + swept + ' objects!');"
    "});"
    "document.getElementById('btn-collect').addEventListener('click', () => {"
    "  const swept = tb.gc();"
    "  updateStats('Manual GC + madvise trim swept ' + swept + ' unreachable objects.');"
    "});"
    "updateStats();"
    "</script></body></html>";

static const char *ABOUT_HELP_HTML =
    "<!DOCTYPE html><html><head><title>Help &amp; Controls — TB</title>"
    "<style>"
    "body { margin: 1 2; }"
    "h1 { color: #38bdf8; }"
    "h2 { color: #a78bfa; }"
    "th { color: #fbbf24; }"
    ".card { border: 1px solid #334155; padding: 1 2; margin-bottom: 1; }"
    "</style></head><body>"
    "<p><a href='about:home'>← Back to Home</a></p>"
    "<h1>📖 TB Controls &amp; Technical Reference</h1>"
    "<div class='card'>"
    "<h2>Keyboard &amp; Mouse Shortcuts</h2>"
    "<table>"
    "<tr><th>Key</th><th>Action</th></tr>"
    "<tr><td>j / k or ↑ / ↓</td><td>Scroll document line by line (Mouse wheel also scrolls)</td></tr>"
    "<tr><td>Space / PgDn / PgUp</td><td>Scroll page down / page up (Home / End for top / bottom)</td></tr>"
    "<tr><td>Tab / Shift+Tab</td><td>Focus next / previous link, input, button, or JS widget</td></tr>"
    "<tr><td>Enter</td><td>Follow link, click button, toggle checkbox, or edit text input</td></tr>"
    "<tr><td>g or Ctrl+L</td><td>Open URL / Omnibar to navigate to any URL or local file</td></tr>"
    "<tr><td>/ then n / N</td><td>In-page text search, jump to next / previous match</td></tr>"
    "<tr><td>b / H and F</td><td>History Back and Forward (r to Reload page)</td></tr>"
    "<tr><td>c or `</td><td>Toggle split-pane JavaScript Console &amp; Live JS REPL (`:js`)</td></tr>"
    "<tr><td>: (colon)</td><td>Focus Live JS REPL input inside the Console drawer</td></tr>"
    "<tr><td>G</td><td>Force immediate Mark-and-Sweep JS GC + mmap/madvise page reclamation</td></tr>"
    "<tr><td>q or Ctrl+C</td><td>Quit TB cleanly</td></tr>"
    "</table>"
    "</div>"
    "<div class='card'>"
    "<h2>Zero-Dependency Sub-1MB Engineering Highlights</h2>"
    "<ul>"
    "<li><strong>Freestanding Syscall + mmap Slab Allocator:</strong> Static ELF binary with zero shared libraries, hard heap cap, and <code>madvise(MADV_DONTNEED)</code> page reclamation.</li>"
    "<li><strong>In-Tree TLS 1.3 + X.509 &amp; Direct DNS:</strong> Built-in RFC 8446 TLS 1.3 (X25519/P-256, AES-GCM, ChaCha20-Poly1305, RSA/ECDSA) and RFC 1035 UDP/TCP DNS resolver.</li>"
    "<li><strong>Custom TinyJS &amp; RegExp VM:</strong> Contiguous flat-pool AST (~24 B/node), bounded-step RegExp bytecode VM, lexical closures, prototypes, and Mark-and-Sweep GC.</li>"
    "<li><strong>Zero-Dependency Inflate:</strong> Built-in RFC 1951/1952 gzip &amp; deflate decompressor with anti-zip-bomb ceiling.</li>"
    "</ul>"
    "</div></body></html>";

static bool load_about_page(const TbUrl *u, TbResponse *resp) {
    const char *html = NULL;
    if (strcmp(u->path, "home") == 0 || u->path[0] == '\0') html = ABOUT_HOME_HTML;
    else if (strcmp(u->path, "demo") == 0) html = ABOUT_DEMO_HTML;
    else if (strcmp(u->path, "memory") == 0) html = ABOUT_MEMORY_HTML;
    else if (strcmp(u->path, "help") == 0) html = ABOUT_HELP_HTML;
    else if (strcmp(u->path, "blank") == 0) html = "<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>";
    else {
        resp->status = 404;
        strcpy(resp->content_type, "text/html");
        TbBuf b;
        tb_buf_init(&b);
        tb_buf_printf(&b, "<html><body><h1>Unknown page about:%s</h1><p><a href='about:home'>Go Home</a></p></body></html>", u->path);
        resp->body = tb_buf_detach(&b, &resp->body_len);
        return true;
    }
    resp->status = 200;
    strcpy(resp->content_type, "text/html; charset=utf-8");
    resp->body_len = strlen(html);
    resp->body     = tb_strdup(html);
    return resp->body != NULL;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool load_data_url(const TbUrl *u, TbResponse *resp) {
    const char *comma = strchr(u->path, ',');
    if (!comma) {
        snprintf(resp->error, sizeof(resp->error), "Malformed data: URL");
        return false;
    }
    size_t mlen = (size_t)(comma - u->path);
    if (mlen == 0) strcpy(resp->content_type, "text/plain");
    else snprintf(resp->content_type, sizeof(resp->content_type), "%.*s", (int)mlen, u->path);

    const char *src = comma + 1;
    TbBuf b;
    tb_buf_init(&b);
    for (size_t i = 0; src[i]; i++) {
        if (b.len >= TB_MAX_BODY_BYTES) break;
        if (src[i] == '%' && hex_val(src[i + 1]) >= 0 && hex_val(src[i + 2]) >= 0) {
            char decoded = (char)((hex_val(src[i + 1]) << 4) | hex_val(src[i + 2]));
            tb_buf_append_char(&b, decoded);
            i += 2;
        } else {
            tb_buf_append_char(&b, src[i]);
        }
    }
    resp->status = 200;
    resp->body   = tb_buf_detach(&b, &resp->body_len);
    return resp->body != NULL;
}

static bool load_file_url(const TbUrl *u, TbResponse *resp) {
    FILE *f = fopen(u->path, "rb");
    if (!f) {
        snprintf(resp->error, sizeof(resp->error), "Cannot open %.160s: %.70s", u->path, strerror(errno));
        return false;
    }
    TbBuf b;
    tb_buf_init(&b);
    char chunk[8192];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        if (b.len + n > TB_MAX_BODY_BYTES) {
            n = TB_MAX_BODY_BYTES - b.len;
            tb_buf_append(&b, chunk, n);
            break;
        }
        if (!tb_buf_append(&b, chunk, n)) {
            fclose(f);
            tb_buf_free(&b);
            snprintf(resp->error, sizeof(resp->error), "Memory cap reached reading file");
            return false;
        }
    }
    fclose(f);
    resp->status = 200;
    const char *ext = strrchr(u->path, '.');
    if (ext && (tb_strcasecmp(ext, ".json") == 0)) strcpy(resp->content_type, "application/json");
    else if (ext && (tb_strcasecmp(ext, ".txt") == 0)) strcpy(resp->content_type, "text/plain");
    else if (ext && (tb_strcasecmp(ext, ".js") == 0)) strcpy(resp->content_type, "application/javascript");
    else strcpy(resp->content_type, "text/html");
    resp->body = tb_buf_detach(&b, &resp->body_len);
    return resp->body != NULL;
}

/* ============================================================================
 * Direct IPv4/IPv6 Literal Parser + RFC 1035 UDP/TCP DNS Resolver
 * ============================================================================ */

static bool parse_ipv4_literal(const char *s, uint8_t out[4]) {
    if (!s || !*s) return false;
    int parts = 0;
    const char *p = s;
    while (*p) {
        if (parts >= 4 || !tb_isdigit(*p)) return false;
        if (*p == '0' && tb_isdigit(p[1])) return false; /* Reject octal ambiguity */
        int val = 0, digits = 0;
        while (tb_isdigit(*p)) {
            val = val * 10 + (*p - '0');
            if (val > 255) return false;
            p++;
            digits++;
        }
        if (digits == 0) return false;
        out[parts++] = (uint8_t)val;
        if (*p == '.') {
            p++;
            if (!*p) return false;
        } else if (*p != '\0') {
            return false;
        }
    }
    return parts == 4;
}

static bool parse_ipv6_literal(const char *s, uint8_t out[16]) {
    if (!s || !*s) return false;
    char clean[128];
    size_t slen = strlen(s);
    if (s[0] == '[') {
        if (slen < 4 || s[slen - 1] != ']') return false;
        s++;
        slen -= 2;
    }
    /* Strip optional %iface scope suffix */
    const char *pct = memchr(s, '%', slen);
    if (pct) slen = (size_t)(pct - s);
    if (slen < 2 || slen >= sizeof(clean)) return false;
    memcpy(clean, s, slen);
    clean[slen] = '\0';

    uint16_t groups[8] = {0};
    int ng = 0, gap = -1;
    const char *p = clean;
    if (*p == ':') {
        if (p[1] != ':') return false;
        gap = 0;
        p += 2;
        if (!*p) {
            memset(out, 0, 16);
            return true;
        }
    }
    while (*p) {
        if (ng >= 8) return false;
        const char *chk = p;
        while (*chk && *chk != ':' && *chk != '.') chk++;
        if (*chk == '.') {
            if (ng > 6) return false;
            uint8_t v4[4];
            if (!parse_ipv4_literal(p, v4)) return false;
            groups[ng++] = (uint16_t)(((uint16_t)v4[0] << 8) | v4[1]);
            groups[ng++] = (uint16_t)(((uint16_t)v4[2] << 8) | v4[3]);
            p = "";
            break;
        }
        uint32_t val = 0;
        int digits = 0;
        while (*p && *p != ':') {
            int hv = hex_val(*p);
            if (hv < 0 || digits >= 4) return false;
            val = (val << 4) | (uint32_t)hv;
            p++;
            digits++;
        }
        if (digits == 0) return false;
        groups[ng++] = (uint16_t)val;
        if (*p == ':') {
            p++;
            if (*p == ':') {
                if (gap >= 0) return false;
                gap = ng;
                p++;
                if (!*p) break;
            } else if (!*p) {
                return false;
            }
        }
    }

    if (gap >= 0) {
        int zeros = 8 - ng;
        if (zeros < 1) return false;
        for (int i = ng - 1; i >= gap; i--) groups[i + zeros] = groups[i];
        for (int i = 0; i < zeros; i++) groups[gap + i] = 0;
        ng = 8;
    }
    if (ng != 8) return false;
    for (int i = 0; i < 8; i++) {
        out[i * 2]     = (uint8_t)(groups[i] >> 8);
        out[i * 2 + 1] = (uint8_t)groups[i];
    }
    return true;
}

bool tb_parse_ip_literal(const char *host, TbIpAddr *out) {
    if (!host || !out) return false;
    memset(out, 0, sizeof(*out));
    if (parse_ipv4_literal(host, out->addr)) {
        out->family = AF_INET;
        return true;
    }
    if (parse_ipv6_literal(host, out->addr)) {
        out->family = AF_INET6;
        return true;
    }
    return false;
}

typedef struct {
    TbIpAddr ip;
    int      port;
} DnsServer;

static bool      g_dns_has_override = false;
static DnsServer g_dns_override     = {0};

void tb_dns_set_override_server(const char *ip, int port) {
    if (!ip || !*ip || port <= 0 || port > 65535) {
        g_dns_has_override = false;
        memset(&g_dns_override, 0, sizeof(g_dns_override));
        return;
    }
    if (tb_parse_ip_literal(ip, &g_dns_override.ip)) {
        g_dns_override.port = port;
        g_dns_has_override  = true;
    }
}

static void add_unique_addr(TbIpAddr *list, size_t *count, size_t cap, const TbIpAddr *cand) {
    if (*count >= cap) return;
    size_t alen = (cand->family == AF_INET) ? 4 : 16;
    for (size_t i = 0; i < *count; i++) {
        if (list[i].family == cand->family && memcmp(list[i].addr, cand->addr, alen) == 0) {
            return;
        }
    }
    list[(*count)++] = *cand;
}

static void scan_hosts_line(char *line, const char *target_host,
                            TbIpAddr *v4_list, size_t *v4_cnt, size_t v4_cap,
                            TbIpAddr *v6_list, size_t *v6_cnt, size_t v6_cap) {
    char *hash = strchr(line, '#');
    if (hash) *hash = '\0';

    char *save = NULL;
    char *ip_tok = strtok_r(line, " \t\r\n", &save);
    if (!ip_tok) return;

    TbIpAddr ip;
    if (!tb_parse_ip_literal(ip_tok, &ip)) return;

    for (char *alias = strtok_r(NULL, " \t\r\n", &save);
         alias != NULL;
         alias = strtok_r(NULL, " \t\r\n", &save)) {
        if (tb_strcasecmp(alias, target_host) == 0) {
            if (ip.family == AF_INET) add_unique_addr(v4_list, v4_cnt, v4_cap, &ip);
            else                      add_unique_addr(v6_list, v6_cnt, v6_cap, &ip);
            break;
        }
    }
}

static size_t lookup_etc_hosts(const char *host, TbIpAddr *out, size_t max_addrs) {
    int fd = open("/etc/hosts", O_RDONLY);
    TbIpAddr v4[8], v6[8];
    size_t nv4 = 0, nv6 = 0;

    if (fd >= 0) {
        char buf[2048];
        size_t carry = 0;
        bool skip_long = false;
        for (;;) {
            ssize_t r = read(fd, buf + carry, sizeof(buf) - 1 - carry);
            if (r <= 0) {
                if (carry > 0 && !skip_long) {
                    buf[carry] = '\0';
                    scan_hosts_line(buf, host, v4, &nv4, 8, v6, &nv6, 8);
                }
                break;
            }
            size_t total = carry + (size_t)r;
            size_t start = 0;
            for (size_t i = 0; i < total; i++) {
                if (buf[i] == '\n') {
                    buf[i] = '\0';
                    if (!skip_long) {
                        scan_hosts_line(buf + start, host, v4, &nv4, 8, v6, &nv6, 8);
                    }
                    skip_long = false;
                    start = i + 1;
                }
            }
            carry = total - start;
            if (carry >= sizeof(buf) - 1) {
                /* Single line exceeded 2 KB; discard remainder until next newline */
                carry = 0;
                skip_long = true;
            } else if (carry > 0 && start > 0) {
                memmove(buf, buf + start, carry);
            }
        }
        close(fd);
    }

    size_t count = 0;
    for (size_t i = 0; i < nv4 && count < max_addrs; i++) add_unique_addr(out, &count, max_addrs, &v4[i]);
    for (size_t i = 0; i < nv6 && count < max_addrs; i++) add_unique_addr(out, &count, max_addrs, &v6[i]);

    /* RFC 6761 §6.3: localhost and *.localhost always resolve to loopback */
    if (count == 0) {
        size_t hlen = strlen(host);
        bool is_lh  = (tb_strcasecmp(host, "localhost") == 0) ||
                      (hlen > 10 && tb_strcasecmp(host + hlen - 10, ".localhost") == 0);
        if (is_lh) {
            TbIpAddr lo4 = { .family = AF_INET,  .addr = {127, 0, 0, 1} };
            TbIpAddr lo6 = { .family = AF_INET6, .addr = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1} };
            add_unique_addr(out, &count, max_addrs, &lo4);
            add_unique_addr(out, &count, max_addrs, &lo6);
        }
    }
    return count;
}

static size_t load_resolv_servers(DnsServer out[3]) {
    if (g_dns_has_override) {
        out[0] = g_dns_override;
        return 1;
    }

    size_t n = 0;
    int fd = open("/etc/resolv.conf", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t r = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (r > 0) {
            buf[r] = '\0';
            char *line_save = NULL;
            for (char *line = strtok_r(buf, "\r\n", &line_save);
                 line && n < 3;
                 line = strtok_r(NULL, "\r\n", &line_save)) {
                char *c1 = strchr(line, '#');
                if (c1) *c1 = '\0';
                char *c2 = strchr(line, ';');
                if (c2) *c2 = '\0';

                char *tok_save = NULL;
                char *kw = strtok_r(line, " \t", &tok_save);
                if (kw && strcmp(kw, "nameserver") == 0) {
                    char *ns = strtok_r(NULL, " \t", &tok_save);
                    TbIpAddr ip;
                    if (ns && tb_parse_ip_literal(ns, &ip)) {
                        out[n].ip   = ip;
                        out[n].port = 53;
                        n++;
                    }
                }
            }
        }
    }

    if (n == 0) {
        tb_parse_ip_literal("1.1.1.1", &out[0].ip);
        out[0].port = 53;
        tb_parse_ip_literal("8.8.8.8", &out[1].ip);
        out[1].port = 53;
        n = 2;
    }
    return n;
}

size_t tb_dns_build_query(const char *host, uint16_t qtype, uint16_t txid,
                          uint8_t *buf, size_t cap) {
    if (!host || !*host || !buf || cap < 18) return 0;
    size_t hlen = strlen(host);
    while (hlen > 0 && host[hlen - 1] == '.') hlen--;
    if (hlen == 0 || hlen > 253) return 0;

    /* 12-byte RFC 1035 DNS Header */
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)txid;
    buf[2] = 0x01; /* RD = 1 (Recursion Desired) */
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x01; /* QDCOUNT = 1 */

    size_t pos = 12;
    size_t i   = 0;
    while (i < hlen) {
        size_t lstart = i;
        while (i < hlen && host[i] != '.') i++;
        size_t llen = i - lstart;
        if (llen == 0 || llen > 63 || pos + 1 + llen + 5 > cap) return 0;
        buf[pos++] = (uint8_t)llen;
        for (size_t k = 0; k < llen; k++) {
            buf[pos++] = (uint8_t)host[lstart + k];
        }
        if (i < hlen && host[i] == '.') i++;
    }
    buf[pos++] = 0x00; /* Root label */
    buf[pos++] = (uint8_t)(qtype >> 8);
    buf[pos++] = (uint8_t)qtype;
    buf[pos++] = 0x00;
    buf[pos++] = 0x01; /* QCLASS = IN (1) */
    return pos;
}

/* Decodes a DNS wire name with strict bounds and 32-hop pointer-loop detection. */
static bool dns_read_name(const uint8_t *pkt, size_t pkt_len, size_t offset,
                          char *out_name, size_t out_cap, size_t *next_offset) {
    size_t pos     = offset;
    size_t out_len = 0;
    int    jumps   = 0;
    bool   jumped  = false;

    if (out_cap == 0) return false;
    out_name[0] = '\0';

    for (;;) {
        if (pos >= pkt_len) return false;
        uint8_t len = pkt[pos];
        if (len == 0) {
            if (!jumped) *next_offset = pos + 1;
            out_name[out_len] = '\0';
            return true;
        }
        if ((len & 0xC0U) == 0xC0U) {
            if (pos + 1 >= pkt_len) return false;
            size_t target = (((size_t)(len & 0x3FU)) << 8) | pkt[pos + 1];
            if (target >= pkt_len || target == pos) return false;
            if (!jumped) {
                *next_offset = pos + 2;
                jumped = true;
            }
            if (++jumps > 32) return false; /* Pointer loop guard */
            pos = target;
            continue;
        }
        if ((len & 0xC0U) != 0) {
            /* Reserved label encoding bits */
            return false;
        }
        pos++;
        if (pos + len > pkt_len) return false;
        if (out_len > 0) {
            if (out_len + 1 >= out_cap || out_len + 1 > 253) return false;
            out_name[out_len++] = '.';
        }
        if (out_len + len >= out_cap || out_len + len > 253) return false;
        memcpy(out_name + out_len, pkt + pos, len);
        out_len += len;
        pos += len;
    }
}

typedef struct {
    char     owner[256];
    uint16_t rtype;
    uint16_t rclass;
    size_t   rdata_off;
    uint16_t rdlen;
} DnsParsedRR;

size_t tb_dns_parse_response(const uint8_t *pkt, size_t pkt_len,
                             uint16_t expected_txid, uint16_t qtype,
                             bool *out_truncated,
                             TbIpAddr *out_addrs, size_t max_addrs) {
    if (out_truncated) *out_truncated = false;
    if (!pkt || pkt_len < 12 || !out_addrs || max_addrs == 0) return 0;

    uint16_t txid  = ((uint16_t)pkt[0] << 8) | pkt[1];
    uint16_t flags = ((uint16_t)pkt[2] << 8) | pkt[3];
    if (txid != expected_txid) return 0;
    if ((flags & 0x8000U) == 0) return 0; /* QR must be 1 (Response) */

    if ((flags & 0x0200U) != 0) { /* TC (Truncated) */
        if (out_truncated) *out_truncated = true;
    }
    if ((flags & 0x000FU) != 0) return 0; /* Non-zero RCODE (NXDOMAIN / SERVFAIL) */

    uint16_t qdcount = ((uint16_t)pkt[4] << 8) | pkt[5];
    uint16_t ancount = ((uint16_t)pkt[6] << 8) | pkt[7];
    if (ancount == 0) return 0;

    size_t pos = 12;
    char target_name[256] = "";
    for (uint16_t q = 0; q < qdcount; q++) {
        char qname[256];
        size_t next = 0;
        if (!dns_read_name(pkt, pkt_len, pos, qname, sizeof(qname), &next)) return 0;
        if (next + 4 > pkt_len) return 0;
        if (q == 0) snprintf(target_name, sizeof(target_name), "%s", qname);
        pos = next + 4;
    }

    DnsParsedRR rrs[24];
    size_t nrr = 0;
    for (uint16_t a = 0; a < ancount; a++) {
        char owner[256];
        size_t next = 0;
        if (!dns_read_name(pkt, pkt_len, pos, owner, sizeof(owner), &next)) return 0;
        if (next + 10 > pkt_len) return 0;

        uint16_t rtype  = ((uint16_t)pkt[next + 0] << 8) | pkt[next + 1];
        uint16_t rclass = ((uint16_t)pkt[next + 2] << 8) | pkt[next + 3];
        uint16_t rdlen  = ((uint16_t)pkt[next + 8] << 8) | pkt[next + 9];
        size_t rdata_off = next + 10;
        if (rdata_off + rdlen > pkt_len) return 0;
        pos = rdata_off + rdlen;

        if (nrr < 24) {
            snprintf(rrs[nrr].owner, sizeof(rrs[nrr].owner), "%s", owner);
            rrs[nrr].rtype     = rtype;
            rrs[nrr].rclass    = rclass;
            rrs[nrr].rdata_off = rdata_off;
            rrs[nrr].rdlen     = rdlen;
            nrr++;
        }
    }

    /* Follow CNAME chain (up to 8 hops) */
    for (int hop = 0; hop < 8 && target_name[0] != '\0'; hop++) {
        bool followed = false;
        for (size_t i = 0; i < nrr; i++) {
            if (rrs[i].rclass == 1 && rrs[i].rtype == 5 &&
                tb_strcasecmp(rrs[i].owner, target_name) == 0) {
                char cname_target[256];
                size_t dummy = 0;
                if (!dns_read_name(pkt, pkt_len, rrs[i].rdata_off,
                                   cname_target, sizeof(cname_target), &dummy)) {
                    return 0;
                }
                snprintf(target_name, sizeof(target_name), "%s", cname_target);
                followed = true;
                break;
            }
        }
        if (!followed) break;
    }

    size_t count = 0;
    for (size_t i = 0; i < nrr && count < max_addrs; i++) {
        if (rrs[i].rclass != 1 || rrs[i].rtype != qtype) continue;
        if (target_name[0] != '\0' && tb_strcasecmp(rrs[i].owner, target_name) != 0) continue;

        TbIpAddr ip;
        memset(&ip, 0, sizeof(ip));
        if (qtype == 1 && rrs[i].rdlen == 4) {
            ip.family = AF_INET;
            memcpy(ip.addr, pkt + rrs[i].rdata_off, 4);
            add_unique_addr(out_addrs, &count, max_addrs, &ip);
        } else if (qtype == 28 && rrs[i].rdlen == 16) {
            ip.family = AF_INET6;
            memcpy(ip.addr, pkt + rrs[i].rdata_off, 16);
            add_unique_addr(out_addrs, &count, max_addrs, &ip);
        }
    }
    return count;
}

static socklen_t fill_sockaddr(const TbIpAddr *ip, int port, struct sockaddr_storage *ss) {
    memset(ss, 0, sizeof(*ss));
    if (ip->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
        sin->sin_port   = htons((uint16_t)port);
        memcpy(&sin->sin_addr.s_addr, ip->addr, 4);
        return (socklen_t)sizeof(*sin);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port   = htons((uint16_t)port);
        memcpy(&sin6->sin6_addr.s6_addr, ip->addr, 16);
        return (socklen_t)sizeof(*sin6);
    }
}

static int64_t net_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000LL + (int64_t)(ts.tv_nsec / 1000000LL);
}

static int connect_ip_with_timeout(const TbIpAddr *ip, int port, int timeout_ms) {
    struct sockaddr_storage ss;
    socklen_t slen = fill_sockaddr(ip, port, &ss);

    int fd = socket(ip->family, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(fd, (struct sockaddr *)&ss, slen);
    if (rc == 0) {
        fcntl(fd, F_SETFL, flags);
        return fd;
    }
    if (errno == EINPROGRESS) {
        int64_t deadline = net_now_ms() + timeout_ms;
        int prc = 0;
        for (;;) {
            int64_t rem = deadline - net_now_ms();
            if (rem <= 0) { prc = 0; break; }
            struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
            prc = poll(&pfd, 1, (int)rem);
            if (prc < 0 && errno == EINTR) continue;
            break;
        }
        if (prc > 0) {
            int so_err = 0;
            socklen_t elen = sizeof(so_err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &elen);
            if (so_err == 0) {
                fcntl(fd, F_SETFL, flags);
                return fd;
            }
            errno = so_err;
        } else if (prc == 0) {
            errno = ETIMEDOUT;
        }
    }
    close(fd);
    return -1;
}

static ssize_t dns_exchange_udp(const DnsServer *srv, const uint8_t *query, size_t qlen,
                                uint16_t txid, uint8_t *resp, size_t rcap, int timeout_ms) {
    struct sockaddr_storage ss;
    socklen_t slen = fill_sockaddr(&srv->ip, srv->port, &ss);

    int fd = socket(srv->ip.family, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    if (sendto(fd, query, qlen, MSG_NOSIGNAL, (struct sockaddr *)&ss, slen) != (ssize_t)qlen) {
        close(fd);
        return -1;
    }

    int64_t deadline = net_now_ms() + timeout_ms;
    for (;;) {
        int64_t rem = deadline - net_now_ms();
        if (rem <= 0) break;
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int prc = poll(&pfd, 1, (int)rem);
        if (prc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (prc == 0) break;

        ssize_t n = recvfrom(fd, resp, rcap, 0, NULL, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n >= 12 && (((uint16_t)resp[0] << 8) | resp[1]) == txid) {
            close(fd);
            return n;
        }
    }
    close(fd);
    return -1;
}

static ssize_t dns_exchange_tcp(const DnsServer *srv, const uint8_t *query, size_t qlen,
                                uint8_t *resp, size_t rcap, int timeout_ms) {
    int fd = connect_ip_with_timeout(&srv->ip, srv->port, timeout_ms);
    if (fd < 0) return -1;

    /* RFC 1035 §4.2.2: 2-byte big-endian message length prefix over TCP */
    uint8_t tcp_q[516];
    if (2 + qlen > sizeof(tcp_q)) {
        close(fd);
        return -1;
    }
    tcp_q[0] = (uint8_t)(qlen >> 8);
    tcp_q[1] = (uint8_t)qlen;
    memcpy(tcp_q + 2, query, qlen);

    size_t sent = 0;
    while (sent < 2 + qlen) {
        ssize_t w = send(fd, tcp_q + sent, (2 + qlen) - sent, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (w == 0) { close(fd); return -1; }
        sent += (size_t)w;
    }

    int64_t deadline = net_now_ms() + timeout_ms;
    uint8_t len_hdr[2];
    size_t  got = 0;
    while (got < 2) {
        int64_t rem = deadline - net_now_ms();
        if (rem <= 0) { close(fd); return -1; }
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int prc = poll(&pfd, 1, (int)rem);
        if (prc < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (prc == 0) { close(fd); return -1; }
        ssize_t r = recv(fd, len_hdr + got, 2 - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) { close(fd); return -1; }
        got += (size_t)r;
    }

    size_t msg_len = ((size_t)len_hdr[0] << 8) | len_hdr[1];
    if (msg_len < 12 || msg_len > rcap) {
        close(fd);
        return -1;
    }

    got = 0;
    while (got < msg_len) {
        int64_t rem = deadline - net_now_ms();
        if (rem <= 0) { close(fd); return -1; }
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int prc = poll(&pfd, 1, (int)rem);
        if (prc < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (prc == 0) { close(fd); return -1; }
        ssize_t r = recv(fd, resp + got, msg_len - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return (ssize_t)msg_len;
}

static size_t dns_query_rrtype(const DnsServer *servers, size_t nservers,
                               const char *host, uint16_t qtype, int timeout_ms,
                               TbIpAddr *out_addrs, size_t max_addrs,
                               bool *got_any_reply) {
    uint8_t query[512];
    uint8_t udp_resp[1500];

    int per_try_ms = timeout_ms / 2;
    if (per_try_ms < 500)  per_try_ms = 500;
    if (per_try_ms > 2500) per_try_ms = 2500;

    for (int attempt = 0; attempt < 2; attempt++) {
        for (size_t s = 0; s < nservers; s++) {
            uint16_t txid = 0;
            if (!tb_getrandom(&txid, sizeof(txid))) {
                txid = (uint16_t)(0x4200U + attempt * 17U + s);
            }
            size_t qlen = tb_dns_build_query(host, qtype, txid, query, sizeof(query));
            if (qlen == 0) return 0;

            ssize_t rlen = dns_exchange_udp(&servers[s], query, qlen, txid,
                                            udp_resp, sizeof(udp_resp), per_try_ms);
            if (rlen < 12) continue;

            *got_any_reply = true;
            bool truncated = false;
            size_t n = tb_dns_parse_response(udp_resp, (size_t)rlen, txid, qtype,
                                             &truncated, out_addrs, max_addrs);
            if (truncated) {
                /* RFC 1035 TC=1: retry full response over TCP */
                uint8_t *tcp_resp = (uint8_t *)tb_malloc(16384);
                if (tcp_resp) {
                    ssize_t trlen = dns_exchange_tcp(&servers[s], query, qlen,
                                                     tcp_resp, 16384, timeout_ms);
                    if (trlen >= 12) {
                        bool tcp_tc = false;
                        size_t tn = tb_dns_parse_response(tcp_resp, (size_t)trlen, txid, qtype,
                                                          &tcp_tc, out_addrs, max_addrs);
                        tb_free(tcp_resp);
                        return tn;
                    }
                    tb_free(tcp_resp);
                }
            }
            /* Authoritative/recursive reply received (even if 0 records of this qtype) */
            uint8_t rcode = udp_resp[3] & 0x0FU;
            if (n > 0 || rcode == 0 || rcode == 3) {
                return n;
            }
        }
    }
    return 0;
}

size_t tb_dns_resolve(const char *host, int timeout_ms,
                      TbIpAddr *out_addrs, size_t max_addrs,
                      char *err, size_t err_cap) {
    if (!host || !*host || !out_addrs || max_addrs == 0) {
        if (err && err_cap > 0) snprintf(err, err_cap, "Invalid hostname");
        return 0;
    }

    /* 1. Direct IPv4 / IPv6 literal */
    TbIpAddr lit;
    if (tb_parse_ip_literal(host, &lit)) {
        out_addrs[0] = lit;
        return 1;
    }

    /* Strip trailing FQDN dot for /etc/hosts lookup */
    char clean_host[256];
    snprintf(clean_host, sizeof(clean_host), "%s", host);
    size_t clen = strlen(clean_host);
    while (clen > 0 && clean_host[clen - 1] == '.') clean_host[--clen] = '\0';
    if (clen == 0) {
        if (err && err_cap > 0) snprintf(err, err_cap, "Invalid empty hostname");
        return 0;
    }

    /* 2. /etc/hosts + RFC 6761 localhost */
    size_t nhosts = lookup_etc_hosts(clean_host, out_addrs, max_addrs);
    if (nhosts > 0) return nhosts;

    /* 3. /etc/resolv.conf nameservers + RFC 1035 UDP/TCP queries */
    DnsServer servers[3];
    size_t nservers = load_resolv_servers(servers);

    bool got_reply = false;
    size_t count = dns_query_rrtype(servers, nservers, clean_host, 1 /* A */,
                                    timeout_ms, out_addrs, max_addrs, &got_reply);
    if (count == 0) {
        count = dns_query_rrtype(servers, nservers, clean_host, 28 /* AAAA */,
                                 timeout_ms, out_addrs, max_addrs, &got_reply);
    }
    if (count == 0 && err && err_cap > 0) {
        snprintf(err, err_cap, "DNS lookup failed for %.150s (%s)",
                 host, got_reply ? "no A/AAAA records" : "nameserver timeout");
    }
    return count;
}

/* ============================================================================
 * TCP Connection + HTTP/1.1 Fetch Engine
 * ============================================================================ */

static int connect_with_timeout(const char *host, int port, int timeout_ms,
                                char *err, size_t err_cap) {
    TbIpAddr addrs[8];
    size_t naddrs = tb_dns_resolve(host, timeout_ms, addrs, 8, err, err_cap);
    if (naddrs == 0) return -1;

    int fd = -1;
    for (size_t i = 0; i < naddrs; i++) {
        fd = connect_ip_with_timeout(&addrs[i], port, timeout_ms);
        if (fd >= 0) break;
    }

    if (fd < 0) {
        snprintf(err, err_cap, "Connect to %.150s:%d failed: %.64s",
                 host, port, strerror(errno));
    } else {
        struct timeval tv = {
            .tv_sec  = timeout_ms / 1000,
            .tv_usec = (timeout_ms % 1000) * 1000
        };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    return fd;
}

static bool decode_chunked(const char *in, size_t in_len, char **out, size_t *out_len) {
    TbBuf b;
    tb_buf_init(&b);
    size_t pos = 0;
    while (pos < in_len) {
        const char *eol = memchr(in + pos, '\n', in_len - pos);
        if (!eol) break;
        char hexbuf[32];
        size_t l = (size_t)(eol - (in + pos));
        if (l > 0 && in[pos + l - 1] == '\r') l--;
        if (l >= sizeof(hexbuf)) l = sizeof(hexbuf) - 1;
        memcpy(hexbuf, in + pos, l);
        hexbuf[l] = '\0';
        char *semi = strchr(hexbuf, ';');
        if (semi) *semi = '\0';

        char *endp = NULL;
        unsigned long csize = strtoul(hexbuf, &endp, 16);
        if (endp == hexbuf) break;
        pos = (size_t)(eol - in) + 1;
        if (csize == 0) break;
        if (pos + csize > in_len) csize = in_len - pos;
        if (b.len + csize > TB_MAX_BODY_BYTES) csize = TB_MAX_BODY_BYTES - b.len;
        if (!tb_buf_append(&b, in + pos, csize)) {
            tb_buf_free(&b);
            return false;
        }
        pos += csize;
        if (pos < in_len && in[pos] == '\r') pos++;
        if (pos < in_len && in[pos] == '\n') pos++;
        if (b.len >= TB_MAX_BODY_BYTES) break;
    }
    *out = tb_buf_detach(&b, out_len);
    return *out != NULL;
}

bool tb_fetch(const char *url, const char *method, const char *post_body,
              const char *post_ctype, bool insecure_tls, TbResponse *resp) {
    if (!resp) return false;
    memset(resp, 0, sizeof(*resp));
    if (!url || !*url) {
        snprintf(resp->error, sizeof(resp->error), "Empty URL");
        return false;
    }
    if (!method || !*method) method = "GET";

    char curr_url[1536];
    snprintf(curr_url, sizeof(curr_url), "%s", url);

    for (int hop = 0; hop <= 5; hop++) {
        TbUrl u;
        if (!tb_url_parse(curr_url, &u)) {
            snprintf(resp->error, sizeof(resp->error), "Invalid URL: %.220s", curr_url);
            return false;
        }
        tb_url_format(&u, resp->final_url, sizeof(resp->final_url), true);

        if (strcmp(u.scheme, "about") == 0) return load_about_page(&u, resp);
        if (strcmp(u.scheme, "data") == 0)  return load_data_url(&u, resp);
        if (strcmp(u.scheme, "file") == 0)  return load_file_url(&u, resp);

        bool is_https = (strcmp(u.scheme, "https") == 0);

#if defined(TB_TLS_OPENSSL) && TB_TLS_OPENSSL
        SSL_CTX *ssl_ctx = NULL;
        if (is_https && !ensure_ssl_loaded(insecure_tls, &ssl_ctx, resp->error, sizeof(resp->error))) {
            return false;
        }
#endif

        int fd = connect_with_timeout(u.host, u.port, 8000, resp->error, sizeof(resp->error));
        if (fd < 0) return false;

#if defined(TB_TLS_OPENSSL) && TB_TLS_OPENSSL
        SSL *ssl = NULL;
        if (is_https) {
            ssl = g_ssl.p_SSL_new(ssl_ctx);
            if (!ssl) {
                close(fd);
                snprintf(resp->error, sizeof(resp->error), "SSL_new failed");
                return false;
            }
            g_ssl.p_SSL_set_fd(ssl, fd);
            TbIpAddr ip_chk;
            bool is_ip_lit = tb_parse_ip_literal(u.host, &ip_chk);
            if (!is_ip_lit && g_ssl.p_SSL_ctrl) {
                g_ssl.p_SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME,
                                 TLSEXT_NAMETYPE_host_name, (void *)u.host);
            }
            if (!insecure_tls && !is_ip_lit && g_ssl.p_SSL_set1_host) {
                g_ssl.p_SSL_set1_host(ssl, u.host);
            }
            if (g_ssl.p_SSL_connect(ssl) <= 0) {
                g_ssl.p_SSL_free(ssl);
                close(fd);
                snprintf(resp->error, sizeof(resp->error),
                         "TLS handshake failed with %.160s (try -k for self-signed)", u.host);
                return false;
            }
        }
#else
        TbTlsConn *tls = NULL;
        if (is_https) {
            tls = tb_tls_connect(fd, u.host, insecure_tls, 8000, resp->error, sizeof(resp->error));
            if (!tls) {
                close(fd);
                if (!resp->error[0]) {
                    snprintf(resp->error, sizeof(resp->error),
                             "TLS 1.3 handshake failed with %.160s", u.host);
                }
                return false;
            }
        }
#endif

        TbBuf req;
        tb_buf_init(&req);
        bool is_v6 = (strchr(u.host, ':') != NULL);
        const char *lb = is_v6 ? "[" : "";
        const char *rb = is_v6 ? "]" : "";
        bool default_port = (!is_https && u.port == 80) || (is_https && u.port == 443);
        tb_buf_printf(&req, "%s %s HTTP/1.1\r\n", method, u.path[0] ? u.path : "/");
        if (default_port) tb_buf_printf(&req, "Host: %s%s%s\r\n", lb, u.host, rb);
        else              tb_buf_printf(&req, "Host: %s%s%s:%d\r\n", lb, u.host, rb, u.port);
        tb_buf_append_cstr(&req,
                           "User-Agent: TB/2.0 (Linux; TUI; TinyJS; Zero-Deps)\r\n"
                           "Accept: text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.8\r\n"
                           "Accept-Encoding: gzip, deflate\r\n"
                           "Connection: close\r\n");
        size_t blen = post_body ? strlen(post_body) : 0;
        if (blen > 0 || strcmp(method, "POST") == 0) {
            tb_buf_printf(&req, "Content-Type: %s\r\nContent-Length: %zu\r\n",
                          post_ctype ? post_ctype : "application/x-www-form-urlencoded", blen);
        }
        tb_buf_append_cstr(&req, "\r\n");
        if (blen > 0) tb_buf_append(&req, post_body, blen);

        bool write_ok = true;
#if defined(TB_TLS_OPENSSL) && TB_TLS_OPENSSL
        size_t sent = 0;
        while (sent < req.len) {
            ssize_t w = is_https
                            ? g_ssl.p_SSL_write(ssl, req.data + sent, (int)(req.len - sent))
                            : send(fd, req.data + sent, req.len - sent, MSG_NOSIGNAL);
            if (w < 0 && !is_https && errno == EINTR) continue;
            if (w <= 0) { write_ok = false; break; }
            sent += (size_t)w;
        }
#else
        if (is_https) {
            write_ok = tb_tls_write(tls, req.data, req.len, 8000);
        } else {
            size_t sent = 0;
            while (sent < req.len) {
                ssize_t w = send(fd, req.data + sent, req.len - sent, MSG_NOSIGNAL);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) { write_ok = false; break; }
                sent += (size_t)w;
            }
        }
#endif
        tb_buf_free(&req);

        if (!write_ok) {
#if defined(TB_TLS_OPENSSL) && TB_TLS_OPENSSL
            if (ssl) { g_ssl.p_SSL_shutdown(ssl); g_ssl.p_SSL_free(ssl); }
#else
            if (tls) tb_tls_close(tls);
#endif
            close(fd);
            snprintf(resp->error, sizeof(resp->error), "Failed sending HTTP request");
            return false;
        }

        TbBuf raw;
        tb_buf_init(&raw);
        char rbuf[8192];
        size_t max_wire = TB_MAX_BODY_BYTES + 65536;
        for (;;) {
#if defined(TB_TLS_OPENSSL) && TB_TLS_OPENSSL
            ssize_t r = is_https
                            ? g_ssl.p_SSL_read(ssl, rbuf, (int)sizeof(rbuf))
                            : recv(fd, rbuf, sizeof(rbuf), 0);
            if (r < 0 && !is_https && errno == EINTR) continue;
#else
            ssize_t r = is_https
                            ? tb_tls_read(tls, rbuf, sizeof(rbuf), 8000)
                            : recv(fd, rbuf, sizeof(rbuf), 0);
            if (r < 0 && !is_https && errno == EINTR) continue;
#endif
            if (r <= 0) break;
            size_t take = (size_t)r;
            if (raw.len + take > max_wire) take = max_wire - raw.len;
            if (!tb_buf_append(&raw, rbuf, take) || raw.len >= max_wire) break;
        }

#if defined(TB_TLS_OPENSSL) && TB_TLS_OPENSSL
        if (ssl) {
            g_ssl.p_SSL_shutdown(ssl);
            g_ssl.p_SSL_free(ssl);
        }
#else
        if (tls) {
            tb_tls_close(tls);
        }
#endif
        close(fd);

        if (raw.len == 0 || !raw.data) {
            tb_buf_free(&raw);
            snprintf(resp->error, sizeof(resp->error), "Empty HTTP response from %.180s", u.host);
            return false;
        }

        /* Split headers and body */
        char *hdr_end = strstr(raw.data, "\r\n\r\n");
        size_t sep_len = 4;
        if (!hdr_end) {
            hdr_end = strstr(raw.data, "\n\n");
            sep_len = 2;
        }
        if (!hdr_end) {
            tb_buf_free(&raw);
            snprintf(resp->error, sizeof(resp->error), "Malformed HTTP response headers");
            return false;
        }

        size_t hdr_len  = (size_t)(hdr_end - raw.data);
        char *body_ptr  = hdr_end + sep_len;
        size_t body_len = raw.len - hdr_len - sep_len;

        /* Parse status line & headers */
        int status = 0;
        const char *sp = memchr(raw.data, ' ', hdr_len);
        if (sp) status = atoi(sp + 1);
        resp->status = status;

        char location[1024] = "";
        char encoding[64]   = "";
        bool chunked        = false;
        strcpy(resp->content_type, "text/html");

        size_t hpos = 0;
        const char *line_end = memchr(raw.data, '\n', hdr_len);
        hpos = line_end ? (size_t)(line_end - raw.data) + 1 : hdr_len;

        while (hpos < hdr_len) {
            const char *nl = memchr(raw.data + hpos, '\n', hdr_len - hpos);
            size_t llen = nl ? (size_t)(nl - (raw.data + hpos)) : (hdr_len - hpos);
            if (llen > 0 && raw.data[hpos + llen - 1] == '\r') llen--;
            const char *line = raw.data + hpos;
            const char *colon = memchr(line, ':', llen);
            if (colon) {
                size_t klen = (size_t)(colon - line);
                const char *val = colon + 1;
                size_t vlen = llen - klen - 1;
                while (vlen > 0 && tb_isspace(*val)) { val++; vlen--; }
                while (vlen > 0 && tb_isspace(val[vlen - 1])) vlen--;

                if (klen == 12 && tb_strncasecmp(line, "Content-Type", 12) == 0) {
                    snprintf(resp->content_type, sizeof(resp->content_type), "%.*s", (int)vlen, val);
                } else if (klen == 8 && tb_strncasecmp(line, "Location", 8) == 0) {
                    snprintf(location, sizeof(location), "%.*s", (int)vlen, val);
                } else if (klen == 16 && tb_strncasecmp(line, "Content-Encoding", 16) == 0) {
                    snprintf(encoding, sizeof(encoding), "%.*s", (int)vlen, val);
                } else if (klen == 17 && tb_strncasecmp(line, "Transfer-Encoding", 17) == 0) {
                    if (vlen >= 7 && tb_strncasecmp(val, "chunked", 7) == 0) chunked = true;
                }
            }
            hpos = nl ? (size_t)(nl - raw.data) + 1 : hdr_len;
        }

        /* Follow redirects */
        if ((status == 301 || status == 302 || status == 303 || status == 307 || status == 308) &&
            location[0] != '\0' && hop < 5) {
            tb_url_resolve(&u, location, curr_url, sizeof(curr_url));
            if (status == 303 || ((status == 301 || status == 302) && strcmp(method, "POST") == 0)) {
                method    = "GET";
                post_body = NULL;
            }
            tb_buf_free(&raw);
            continue;
        }

        char *decoded = NULL;
        size_t decoded_len = 0;
        if (chunked) {
            if (!decode_chunked(body_ptr, body_len, &decoded, &decoded_len)) {
                tb_buf_free(&raw);
                snprintf(resp->error, sizeof(resp->error), "Chunked transfer decode failed");
                return false;
            }
        } else {
            if (body_len > TB_MAX_BODY_BYTES) body_len = TB_MAX_BODY_BYTES;
            decoded = (char *)tb_malloc(body_len + 1);
            if (!decoded) {
                tb_buf_free(&raw);
                snprintf(resp->error, sizeof(resp->error), "Memory cap reached storing response");
                return false;
            }
            memcpy(decoded, body_ptr, body_len);
            decoded[body_len] = '\0';
            decoded_len = body_len;
        }
        tb_buf_free(&raw);

        if (tb_strncasecmp(encoding, "gzip", 4) == 0 || tb_strncasecmp(encoding, "x-gzip", 6) == 0) {
            char *unpacked = NULL;
            size_t unpacked_len = 0;
            if (tb_decompress((const uint8_t *)decoded, decoded_len, TB_DECOMP_GZIP,
                              TB_MAX_BODY_BYTES, &unpacked, &unpacked_len)) {
                tb_free(decoded);
                decoded     = unpacked;
                decoded_len = unpacked_len;
            }
        } else if (tb_strncasecmp(encoding, "deflate", 7) == 0) {
            char *unpacked = NULL;
            size_t unpacked_len = 0;
            if (tb_decompress((const uint8_t *)decoded, decoded_len, TB_DECOMP_ZLIB,
                              TB_MAX_BODY_BYTES, &unpacked, &unpacked_len)) {
                tb_free(decoded);
                decoded     = unpacked;
                decoded_len = unpacked_len;
            }
        }

        resp->body     = decoded;
        resp->body_len = decoded_len;
        return true;
    }

    snprintf(resp->error, sizeof(resp->error), "Too many redirects");
    return false;
}
