#include "test_harness.h"
#include "browser.h"
#include "dom.h"
#include "layout.h"
#include "mem.h"
#include "net.h"

/* ── Test 3: URL Parser, Relative Resolver, & Omnibar Normalizer ── */
void test_url_subsystem(void) {
    printf("[3/14] Testing URL parser, relative resolver, & omnibar normalizer...\n");
    TbUrl base;
    ASSERT_TRUE(tb_url_parse("https://example.com:8443/docs/guide/index.html?v=2#intro", &base),
                "Parse full HTTPS URL");
    ASSERT_STR_EQ(base.scheme, "https", "Parsed scheme");
    ASSERT_STR_EQ(base.host, "example.com", "Parsed host");
    ASSERT_TRUE(base.port == 8443, "Parsed custom port");
    ASSERT_STR_EQ(base.fragment, "intro", "Parsed fragment");

    char resolved[1536];
    tb_url_resolve(&base, "../assets/app.js", resolved, sizeof(resolved));
    ASSERT_STR_EQ(resolved, "https://example.com:8443/docs/assets/app.js", "Resolve ../ path");

    tb_url_resolve(&base, "//cdn.example.org/lib.js", resolved, sizeof(resolved));
    ASSERT_STR_EQ(resolved, "https://cdn.example.org/lib.js", "Resolve scheme-relative URL");

    tb_url_normalize_input("news.ycombinator.com", resolved, sizeof(resolved));
    ASSERT_STR_EQ(resolved, "https://news.ycombinator.com", "Normalize bare domain to https://");
}

/* ── Test 8: Ephemeral Loopback HTTP/1.1 Server (302 + Chunked Gzip + External JS + fetch + POST) ── */
static void send_str(int fd, const char *s) {
    (void)send(fd, s, strlen(s), MSG_NOSIGNAL);
}

static void serve_loopback_http(int listen_fd) {
    for (int req_no = 0; req_no < 5; req_no++) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) break;
        char req[4096];
        ssize_t n = recv(cfd, req, sizeof(req) - 1, 0);
        if (n <= 0) { close(cfd); continue; }
        req[n] = '\0';

        if (strncmp(req, "GET /start ", 11) == 0) {
            send_str(cfd, "HTTP/1.1 302 Found\r\nLocation: /app\r\nConnection: close\r\n\r\n");
        } else if (strncmp(req, "GET /app ", 9) == 0) {
            /* Serve GZIP_HTML_FIXTURE split across two HTTP/1.1 chunks! */
            send_str(cfd,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/html; charset=utf-8\r\n"
                     "Content-Encoding: gzip\r\n"
                     "Transfer-Encoding: chunked\r\n"
                     "Connection: close\r\n\r\n");
            size_t half = 100;
            size_t rest = sizeof(GZIP_HTML_FIXTURE) - half;
            char chdr[32];
            snprintf(chdr, sizeof(chdr), "%zx\r\n", half);
            send_str(cfd, chdr);
            (void)send(cfd, GZIP_HTML_FIXTURE, half, MSG_NOSIGNAL);
            send_str(cfd, "\r\n");
            snprintf(chdr, sizeof(chdr), "%zx\r\n", rest);
            send_str(cfd, chdr);
            (void)send(cfd, GZIP_HTML_FIXTURE + half, rest, MSG_NOSIGNAL);
            send_str(cfd, "\r\n0\r\n\r\n");
        } else if (strncmp(req, "GET /ext.js ", 12) == 0) {
            const char *js = "document.getElementById('gz').textContent += '+ExtJS';";
            char hdr[256];
            snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     strlen(js), js);
            send_str(cfd, hdr);
        } else if (strncmp(req, "GET /api/data.json ", 19) == 0) {
            const char *json = "{\"engine\":\"TinyJS\",\"ok\":true}";
            char hdr[256];
            snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     strlen(json), json);
            send_str(cfd, hdr);
        } else if (strncmp(req, "POST /submit ", 13) == 0) {
            const char *body = strstr(req, "\r\n\r\n");
            body = body ? body + 4 : "";
            char html[512];
            snprintf(html, sizeof(html), "<html><body><p id='post-echo'>POSTED:%s</p></body></html>", body);
            char hdr[768];
            snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     strlen(html), html);
            send_str(cfd, hdr);
        }
        close(cfd);
    }
    close(listen_fd);
}

void test_http_end_to_end(void) {
    printf("[8/14] Testing live loopback HTTP/1.1 (302, chunked+gzip, external JS, fetch, POST)...\n");
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        printf("  [SKIP] Loopback socket unavailable in environment\n");
        return;
    }
    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(lfd, 8) < 0) {
        close(lfd);
        printf("  [SKIP] Loopback bind unavailable in environment\n");
        return;
    }
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (struct sockaddr *)&addr, &alen);
    int port = ntohs(addr.sin_port);

    pid_t pid = fork();
    if (pid == 0) {
        serve_loopback_http(lfd);
        _exit(0);
    }
    close(lfd);

    TbBrowser b;
    tb_browser_init(&b, 88, 24, false);
    char start_url[128];
    snprintf(start_url, sizeof(start_url), "http://127.0.0.1:%d/start", port);
    ASSERT_TRUE(tb_browser_navigate(&b, start_url, true), "Navigate via 302 redirect to /app");

    TbBuf rendered;
    tb_buf_init(&rendered);
    layout_render_document(&b.layout, false, &rendered);
    ASSERT_TRUE(rendered.data && strstr(rendered.data, "GzipChunkedOK+ExtJS") != NULL,
                "Chunked gzip HTML + external <script src='/ext.js'> rendered");
    ASSERT_TRUE(rendered.data && strstr(rendered.data, "TinyJS:true") != NULL,
                "JS fetch('/api/data.json').then(r => r.json()) updated DOM");
    tb_buf_free(&rendered);

    /* Submit POST <form> via button HitBox */
    DomNode *sub_btn = dom_get_element_by_id(b.doc->root, "sub");
    int sub_hit = layout_find_node_hit(&b.layout, sub_btn);
    ASSERT_TRUE(sub_hit >= 0, "Locate submit button HitBox");
    tb_browser_activate_hit(&b, sub_hit);

    DomNode *echo = b.doc ? dom_get_element_by_id(b.doc->root, "post-echo") : NULL;
    char *echo_txt = dom_get_text_content(echo);
    ASSERT_STR_EQ(echo_txt, "POSTED:msg=sub10mb", "Form POST URL-encoded body round-trip");
    tb_free(echo_txt);

    tb_browser_free(&b);
    int wstatus = 0;
    waitpid(pid, &wstatus, 0);
}

/* ── Test 12: Direct RFC 1035 DNS Parser, Pointer-Loop Guard, & Live UDP->TCP Fallback ── */
static void serve_mock_dns(int udp_fd, int tcp_fd) {
    /* 1. Handle two UDP queries:
     *    - "udp.tb.test" -> direct A record 127.0.0.42
     *    - "big.tb.test" -> TC=1 truncated header triggering client TCP retry! */
    for (int i = 0; i < 2; i++) {
        uint8_t q[512];
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        ssize_t n = recvfrom(udp_fd, q, sizeof(q), 0, (struct sockaddr *)&cli, &clen);
        if (n < 18) continue;

        bool is_big = (n > 16 && memcmp(q + 13, "big", 3) == 0);
        uint8_t r[256];
        memset(r, 0, sizeof(r));
        r[0] = q[0];
        r[1] = q[1];
        if (is_big) {
            /* QR=1, RD=1, RA=1, TC=1 (0x8380) */
            r[2] = 0x83;
            r[3] = 0x80;
            r[4] = 0x00; r[5] = 0x01;
            memcpy(r + 12, q + 12, (size_t)(n - 12));
            (void)sendto(udp_fd, r, (size_t)n, MSG_NOSIGNAL, (struct sockaddr *)&cli, clen);
        } else {
            /* QR=1, RD=1, RA=1 (0x8180), QDCOUNT=1, ANCOUNT=1 */
            r[2] = 0x81; r[3] = 0x80;
            r[4] = 0x00; r[5] = 0x01;
            r[6] = 0x00; r[7] = 0x01;
            size_t p = 12;
            size_t qbody = (size_t)(n - 12);
            memcpy(r + p, q + 12, qbody);
            p += qbody;
            /* Answer: pointer 0xC00C -> TYPE A (1), CLASS IN (1), TTL 60, RDLEN 4, 127.0.0.42 */
            uint8_t ans[16] = {
                0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
                127, 0, 0, 42
            };
            memcpy(r + p, ans, sizeof(ans));
            p += sizeof(ans);
            (void)sendto(udp_fd, r, p, MSG_NOSIGNAL, (struct sockaddr *)&cli, clen);
        }
    }

    /* 2. Accept TCP fallback connection for "big.tb.test" and return CNAME -> A (127.0.0.99) */
    struct pollfd pfd = { .fd = tcp_fd, .events = POLLIN, .revents = 0 };
    if (poll(&pfd, 1, 3000) > 0) {
        int cfd = accept(tcp_fd, NULL, NULL);
        if (cfd >= 0) {
            uint8_t tq[516];
            ssize_t tn = recv(cfd, tq, sizeof(tq), 0);
            if (tn >= 14) {
                size_t qlen = ((size_t)tq[0] << 8) | tq[1];
                if (2 + qlen <= (size_t)tn && qlen >= 16) {
                    uint8_t tr[256];
                    size_t p = 2; /* Reserve 2 bytes for TCP length prefix */
                    memset(tr, 0, sizeof(tr));
                    tr[p + 0] = tq[2]; tr[p + 1] = tq[3]; /* TXID */
                    tr[p + 2] = 0x81;  tr[p + 3] = 0x80;  /* Standard response */
                    tr[p + 4] = 0x00;  tr[p + 5] = 0x01;  /* QDCOUNT = 1 */
                    tr[p + 6] = 0x00;  tr[p + 7] = 0x02;  /* ANCOUNT = 2 (CNAME + A) */
                    size_t off = p + 12;
                    memcpy(tr + off, tq + 2 + 12, qlen - 12);
                    off += (qlen - 12);

                    /* RR 1: big.tb.test (0xC00C) CNAME real.tb.test */
                    const uint8_t cname_rdata[] = { 4,'r','e','a','l', 2,'t','b', 4,'t','e','s','t', 0 };
                    tr[off++] = 0xC0; tr[off++] = 0x0C;
                    tr[off++] = 0x00; tr[off++] = 0x05; /* CNAME */
                    tr[off++] = 0x00; tr[off++] = 0x01; /* IN */
                    tr[off++] = 0x00; tr[off++] = 0x00; tr[off++] = 0x00; tr[off++] = 0x3C;
                    tr[off++] = 0x00; tr[off++] = (uint8_t)sizeof(cname_rdata);
                    size_t real_name_pkt_off = off - p;
                    memcpy(tr + off, cname_rdata, sizeof(cname_rdata));
                    off += sizeof(cname_rdata);

                    /* RR 2: real.tb.test (compressed pointer) A 127.0.0.99 */
                    tr[off++] = (uint8_t)(0xC0U | (real_name_pkt_off >> 8));
                    tr[off++] = (uint8_t)(real_name_pkt_off & 0xFFU);
                    tr[off++] = 0x00; tr[off++] = 0x01; /* A */
                    tr[off++] = 0x00; tr[off++] = 0x01; /* IN */
                    tr[off++] = 0x00; tr[off++] = 0x00; tr[off++] = 0x00; tr[off++] = 0x3C;
                    tr[off++] = 0x00; tr[off++] = 0x04;
                    tr[off++] = 127; tr[off++] = 0; tr[off++] = 0; tr[off++] = 99;

                    size_t dns_len = off - 2;
                    tr[0] = (uint8_t)(dns_len >> 8);
                    tr[1] = (uint8_t)(dns_len & 0xFFU);
                    (void)send(cfd, tr, off, MSG_NOSIGNAL);
                }
            }
            close(cfd);
        }
    }
    close(udp_fd);
    close(tcp_fd);
}

void test_direct_dns_subsystem(void) {
    printf("[12/14] Testing direct IPv4/IPv6 parser, RFC 1035 DNS loop guard, & UDP->TCP fallback...\n");

    TbIpAddr ip;
    ASSERT_TRUE(tb_parse_ip_literal("127.0.0.1", &ip) && ip.family == AF_INET &&
                ip.addr[0] == 127 && ip.addr[3] == 1, "Parse valid IPv4 literal");
    ASSERT_TRUE(!tb_parse_ip_literal("256.0.0.1", &ip) &&
                !tb_parse_ip_literal("1.2.3", &ip) &&
                !tb_parse_ip_literal("01.2.3.4", &ip), "Reject malformed/octal IPv4 literals");
    ASSERT_TRUE(tb_parse_ip_literal("[::1]", &ip) && ip.family == AF_INET6 && ip.addr[15] == 1,
                "Parse bracketed IPv6 [::1]");
    ASSERT_TRUE(tb_parse_ip_literal("2001:db8::ff00:42:8329", &ip) && ip.family == AF_INET6 &&
                ip.addr[0] == 0x20 && ip.addr[1] == 0x01 && ip.addr[15] == 0x29,
                "Parse compressed IPv6 literal");
    ASSERT_TRUE(!tb_parse_ip_literal("2001::db8::1", &ip) && !tb_parse_ip_literal("[::1", &ip),
                "Reject double-:: and unclosed-[ IPv6 literals");

    /* Malicious DNS compression pointer self-loop (0xC0 0x0C) & mutual loop (12 <-> 14) */
    const uint8_t evil_self_loop[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01
    };
    const uint8_t evil_mutual_loop[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0E, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01
    };
    bool tc = false;
    TbIpAddr out[4];
    ASSERT_TRUE(tb_dns_parse_response(evil_self_loop, sizeof(evil_self_loop), 0x1234, 1, &tc, out, 4) == 0,
                "Reject DNS self-pointing compression pointer");
    ASSERT_TRUE(tb_dns_parse_response(evil_mutual_loop, sizeof(evil_mutual_loop), 0x1234, 1, &tc, out, 4) == 0,
                "Reject DNS mutual compression pointer loop within 32 hops");
    ASSERT_TRUE(tb_dns_parse_response(evil_self_loop, 8, 0x1234, 1, &tc, out, 4) == 0,
                "Reject truncated <12-byte DNS packet");

    /* /etc/hosts + RFC 6761 localhost resolution */
    char err[128] = "";
    size_t n_lh = tb_dns_resolve("localhost", 1000, out, 4, err, sizeof(err));
    ASSERT_TRUE(n_lh >= 1 && ((out[0].family == AF_INET && out[0].addr[0] == 127) ||
                              (out[0].family == AF_INET6 && out[0].addr[15] == 1)),
                "Direct resolve 'localhost' without getaddrinfo");

    /* Live loopback UDP + TC=1 TCP fallback DNS server on same port */
    int tfd = socket(AF_INET, SOCK_STREAM, 0);
    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    if (tfd >= 0 && ufd >= 0) {
        int opt = 1;
        setsockopt(tfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(ufd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = 0;
        if (bind(tfd, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(tfd, 4) == 0) {
            socklen_t alen = sizeof(addr);
            getsockname(tfd, (struct sockaddr *)&addr, &alen);
            if (bind(ufd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                int port = ntohs(addr.sin_port);
                pid_t pid = fork();
                if (pid == 0) {
                    serve_mock_dns(ufd, tfd);
                    _exit(0);
                }
                close(ufd);
                close(tfd);

                tb_dns_set_override_server("127.0.0.1", port);

                size_t n1 = tb_dns_resolve("udp.tb.test", 2000, out, 4, err, sizeof(err));
                ASSERT_TRUE(n1 == 1 && out[0].family == AF_INET &&
                            out[0].addr[0] == 127 && out[0].addr[3] == 42,
                            "Live UDP RFC 1035 DNS resolution -> 127.0.0.42");

                size_t n2 = tb_dns_resolve("big.tb.test", 2000, out, 4, err, sizeof(err));
                ASSERT_TRUE(n2 == 1 && out[0].family == AF_INET &&
                            out[0].addr[0] == 127 && out[0].addr[3] == 99,
                            "Live TC=1 truncated UDP -> automatic TCP DNS fallback + CNAME -> 127.0.0.99");

                tb_dns_set_override_server(NULL, 0);
                int wst = 0;
                waitpid(pid, &wst, 0);
                return;
            }
        }
    }
    if (tfd >= 0) close(tfd);
    if (ufd >= 0) close(ufd);
}
