#ifndef TB_REGEX_H
#define TB_REGEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TB_REGEX_MAX_GROUPS 16 /* Group 0 = full match, Groups 1..15 = captures */

#define TB_RX_GLOBAL    (1U << 0) /* g */
#define TB_RX_ICASE     (1U << 1) /* i */
#define TB_RX_MULTILINE (1U << 2) /* m */
#define TB_RX_DOTALL    (1U << 3) /* s */
#define TB_RX_STICKY    (1U << 4) /* y */
#define TB_RX_UNICODE   (1U << 5) /* u */

typedef struct TbRegex TbRegex;

typedef struct {
    uint32_t group_count; /* Total groups including group 0 (>= 1) */
    size_t   starts[TB_REGEX_MAX_GROUPS]; /* SIZE_MAX if unmatched */
    size_t   ends[TB_REGEX_MAX_GROUPS];   /* SIZE_MAX if unmatched */
} TbRegexMatch;

TbRegex *tb_regex_compile(const char *pattern, const char *flags,
                          char *err_buf, size_t err_cap);
void     tb_regex_free(TbRegex *rx);
size_t   tb_regex_mem_size(const TbRegex *rx);
uint32_t tb_regex_flags(const TbRegex *rx);
uint32_t tb_regex_group_count(const TbRegex *rx);

bool     tb_regex_exec(const TbRegex *rx, const char *subj, size_t subj_len,
                       size_t start_offset, TbRegexMatch *out_match);

#endif /* TB_REGEX_H */
