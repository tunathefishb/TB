#include "net.h"
#include "common.h"

/* ============================================================================
 * Direct IPv4/IPv6 Literal Parser + RFC 1035 UDP/TCP DNS Resolver
 * ============================================================================ */

enum {
    DNS_TYPE_A      = 1,
    DNS_TYPE_CNAME  = 5,
    DNS_TYPE_AAAA   = 28,
    DNS_CLASS_IN    = 1,
    DNS_FLAG_QR     = 0x8000U,
    DNS_FLAG_TC     = 0x0200U,
    DNS_RCODE_MASK  = 0x000FU,
    DNS_RCODE_NXDOM = 3
};

bool tb_parse_ip_literal(const char *host, TbIpAddr *out) {
    if (!host || !out) return false;
    memset(out, 0, sizeof(*out));
    if (tb_parse_ipv4_bytes(host, out->addr)) {
        out->family = AF_INET;
        return true;
    }
    if (tb_parse_ipv6_bytes(host, out->addr)) {
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
    tb_store16_be(buf, txid);
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
    tb_store16_be(buf + pos, qtype);
    pos += 2;
    tb_store16_be(buf + pos, DNS_CLASS_IN);
    pos += 2;
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
            return false; /* Reserved label encoding bits */
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

    uint16_t txid  = tb_load16_be(pkt);
    uint16_t flags = tb_load16_be(pkt + 2);
    if (txid != expected_txid) return 0;
    if ((flags & DNS_FLAG_QR) == 0) return 0;

    if ((flags & DNS_FLAG_TC) != 0) {
        if (out_truncated) *out_truncated = true;
    }
    if ((flags & DNS_RCODE_MASK) != 0) return 0;

    uint16_t qdcount = tb_load16_be(pkt + 4);
    uint16_t ancount = tb_load16_be(pkt + 6);
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

        uint16_t rtype  = tb_load16_be(pkt + next);
        uint16_t rclass = tb_load16_be(pkt + next + 2);
        uint16_t rdlen  = tb_load16_be(pkt + next + 8);
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
            if (rrs[i].rclass == DNS_CLASS_IN && rrs[i].rtype == DNS_TYPE_CNAME &&
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
        if (rrs[i].rclass != DNS_CLASS_IN || rrs[i].rtype != qtype) continue;
        if (target_name[0] != '\0' && tb_strcasecmp(rrs[i].owner, target_name) != 0) continue;

        TbIpAddr ip;
        memset(&ip, 0, sizeof(ip));
        if (qtype == DNS_TYPE_A && rrs[i].rdlen == 4) {
            ip.family = AF_INET;
            memcpy(ip.addr, pkt + rrs[i].rdata_off, 4);
            add_unique_addr(out_addrs, &count, max_addrs, &ip);
        } else if (qtype == DNS_TYPE_AAAA && rrs[i].rdlen == 16) {
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

int tb_net_connect_ip(const TbIpAddr *ip, int port, int timeout_ms) {
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
        if (n >= 12 && tb_load16_be(resp) == txid) {
            close(fd);
            return n;
        }
    }
    close(fd);
    return -1;
}

static bool tcp_read_exact(int fd, uint8_t *buf, size_t target, int64_t deadline) {
    size_t got = 0;
    while (got < target) {
        int64_t rem = deadline - net_now_ms();
        if (rem <= 0) return false;
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int prc = poll(&pfd, 1, (int)rem);
        if (prc < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (prc == 0) return false;
        ssize_t r = recv(fd, buf + got, target - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0) return false;
        got += (size_t)r;
    }
    return true;
}

static ssize_t dns_exchange_tcp(const DnsServer *srv, const uint8_t *query, size_t qlen,
                                uint8_t *resp, size_t rcap, int timeout_ms) {
    int fd = tb_net_connect_ip(&srv->ip, srv->port, timeout_ms);
    if (fd < 0) return -1;

    /* RFC 1035 §4.2.2: 2-byte big-endian message length prefix over TCP */
    uint8_t tcp_q[516];
    if (2 + qlen > sizeof(tcp_q)) {
        close(fd);
        return -1;
    }
    tb_store16_be(tcp_q, (uint16_t)qlen);
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
    if (!tcp_read_exact(fd, len_hdr, 2, deadline)) {
        close(fd);
        return -1;
    }

    size_t msg_len = tb_load16_be(len_hdr);
    if (msg_len < 12 || msg_len > rcap || !tcp_read_exact(fd, resp, msg_len, deadline)) {
        close(fd);
        return -1;
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
            uint8_t rcode = udp_resp[3] & DNS_RCODE_MASK;
            if (n > 0 || rcode == 0 || rcode == DNS_RCODE_NXDOM) {
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
    size_t count = dns_query_rrtype(servers, nservers, clean_host, DNS_TYPE_A,
                                    timeout_ms, out_addrs, max_addrs, &got_reply);
    if (count == 0) {
        count = dns_query_rrtype(servers, nservers, clean_host, DNS_TYPE_AAAA,
                                 timeout_ms, out_addrs, max_addrs, &got_reply);
    }
    if (count == 0 && err && err_cap > 0) {
        snprintf(err, err_cap, "DNS lookup failed for %.150s (%s)",
                 host, got_reply ? "no A/AAAA records" : "nameserver timeout");
    }
    return count;
}
