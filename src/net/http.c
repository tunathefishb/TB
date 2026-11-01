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

void tb_response_free(TbResponse *resp) {
    if (!resp) return;
    tb_free(resp->body);
    resp->body     = NULL;
    resp->body_len = 0;
}

static int connect_with_timeout(const char *host, int port, int timeout_ms,
                                char *err, size_t err_cap) {
    TbIpAddr addrs[8];
    size_t naddrs = tb_dns_resolve(host, timeout_ms, addrs, 8, err, err_cap);
    if (naddrs == 0) return -1;

    int fd = -1;
    for (size_t i = 0; i < naddrs; i++) {
        fd = tb_net_connect_ip(&addrs[i], port, timeout_ms);
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

static void build_http_request(TbBuf *req, const TbUrl *u, bool is_https,
                               const char *method, const char *post_body,
                               const char *post_ctype) {
    tb_buf_init(req);
    bool is_v6 = (strchr(u->host, ':') != NULL);
    const char *lb = is_v6 ? "[" : "";
    const char *rb = is_v6 ? "]" : "";
    bool default_port = (!is_https && u->port == 80) || (is_https && u->port == 443);
    tb_buf_printf(req, "%s %s HTTP/1.1\r\n", method, u->path[0] ? u->path : "/");
    if (default_port) tb_buf_printf(req, "Host: %s%s%s\r\n", lb, u->host, rb);
    else              tb_buf_printf(req, "Host: %s%s%s:%d\r\n", lb, u->host, rb, u->port);
    tb_buf_append_cstr(req,
                       "User-Agent: TB/2.0 (Linux; TUI; TinyJS; Zero-Deps)\r\n"
                       "Accept: text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.8\r\n"
                       "Accept-Encoding: gzip, deflate\r\n"
                       "Connection: close\r\n");
    size_t blen = post_body ? strlen(post_body) : 0;
    if (blen > 0 || strcmp(method, "POST") == 0) {
        tb_buf_printf(req, "Content-Type: %s\r\nContent-Length: %zu\r\n",
                      post_ctype ? post_ctype : "application/x-www-form-urlencoded", blen);
    }
    tb_buf_append_cstr(req, "\r\n");
    if (blen > 0) tb_buf_append(req, post_body, blen);
}

static void parse_http_headers(const char *hdr_data, size_t hdr_len,
                               TbResponse *resp, char *location, size_t loc_cap,
                               char *encoding, size_t enc_cap, bool *out_chunked) {
    int status = 0;
    const char *sp = memchr(hdr_data, ' ', hdr_len);
    if (sp) status = atoi(sp + 1);
    resp->status = status;

    location[0]  = '\0';
    encoding[0]  = '\0';
    *out_chunked = false;
    strcpy(resp->content_type, "text/html");

    const char *line_end = memchr(hdr_data, '\n', hdr_len);
    size_t hpos = line_end ? (size_t)(line_end - hdr_data) + 1 : hdr_len;

    while (hpos < hdr_len) {
        const char *nl = memchr(hdr_data + hpos, '\n', hdr_len - hpos);
        size_t llen = nl ? (size_t)(nl - (hdr_data + hpos)) : (hdr_len - hpos);
        if (llen > 0 && hdr_data[hpos + llen - 1] == '\r') llen--;
        const char *line = hdr_data + hpos;
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
                snprintf(location, loc_cap, "%.*s", (int)vlen, val);
            } else if (klen == 16 && tb_strncasecmp(line, "Content-Encoding", 16) == 0) {
                snprintf(encoding, enc_cap, "%.*s", (int)vlen, val);
            } else if (klen == 17 && tb_strncasecmp(line, "Transfer-Encoding", 17) == 0) {
                if (vlen >= 7 && tb_strncasecmp(val, "chunked", 7) == 0) *out_chunked = true;
            }
        }
        hpos = nl ? (size_t)(nl - hdr_data) + 1 : hdr_len;
    }
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

        if (strcmp(u.scheme, "about") == 0 ||
            strcmp(u.scheme, "data") == 0  ||
            strcmp(u.scheme, "file") == 0) {
            return tb_net_load_local_scheme(&u, resp);
        }

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
            bool is_ip_lit = tb_host_is_ip_literal(u.host);
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
        build_http_request(&req, &u, is_https, method, post_body, post_ctype);

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

        char location[1024];
        char encoding[64];
        bool chunked = false;
        parse_http_headers(raw.data, hdr_len, resp,
                           location, sizeof(location),
                           encoding, sizeof(encoding), &chunked);

        int status = resp->status;
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
