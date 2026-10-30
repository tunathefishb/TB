#ifndef TB_NET_H
#define TB_NET_H

#include <stdbool.h>
#include <stddef.h>

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

bool tb_url_parse(const char *raw, TbUrl *out);
void tb_url_format(const TbUrl *u, char *out, size_t cap, bool include_frag);
void tb_url_resolve(const TbUrl *base, const char *rel, char *out, size_t cap);
void tb_url_normalize_input(const char *input, char *out, size_t cap);

bool tb_fetch(const char *url, const char *method, const char *post_body,
              const char *post_ctype, bool insecure_tls, TbResponse *resp);
void tb_response_free(TbResponse *resp);
void tb_net_cleanup(void);

#endif /* TB_NET_H */
