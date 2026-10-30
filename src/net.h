#ifndef TB_NET_H
#define TB_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TB_MAX_BODY_BYTES (2UL * 1024UL * 1024UL) /* 2 MB max single response payload */

typedef struct {
    char scheme[16];
    char host[256];
    int  port;
    char path[1024];
    char fragment[128];
} TbUrl;

typedef struct {
    int    status;
    char   final_url[1536];
    char   content_type[128];
    char   error[256];
    char  *body;
    size_t body_len;
} TbResponse;

typedef struct {
    int     family; /* AF_INET or AF_INET6 */
    uint8_t addr[16];
} TbIpAddr;

bool tb_url_parse(const char *raw, TbUrl *out);
void tb_url_format(const TbUrl *u, char *out, size_t cap, bool include_frag);
void tb_url_resolve(const TbUrl *base, const char *rel, char *out, size_t cap);
void tb_url_normalize_input(const char *input, char *out, size_t cap);

/* Direct RFC 1035 DNS + /etc/hosts + /etc/resolv.conf resolver */
bool   tb_parse_ip_literal(const char *host, TbIpAddr *out);
size_t tb_dns_build_query(const char *host, uint16_t qtype, uint16_t txid,
                          uint8_t *buf, size_t cap);
size_t tb_dns_parse_response(const uint8_t *pkt, size_t pkt_len,
                             uint16_t expected_txid, uint16_t qtype,
                             bool *out_truncated,
                             TbIpAddr *out_addrs, size_t max_addrs);
void   tb_dns_set_override_server(const char *ip, int port);
size_t tb_dns_resolve(const char *host, int timeout_ms,
                      TbIpAddr *out_addrs, size_t max_addrs,
                      char *err, size_t err_cap);

bool tb_fetch(const char *url, const char *method, const char *post_body,
              const char *post_ctype, bool insecure_tls, TbResponse *resp);
void tb_response_free(TbResponse *resp);
void tb_net_cleanup(void);

#endif /* TB_NET_H */
