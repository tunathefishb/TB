#ifndef TB_INFLATE_H
#define TB_INFLATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    TB_DECOMP_AUTO = 0,
    TB_DECOMP_GZIP,
    TB_DECOMP_ZLIB,
    TB_DECOMP_DEFLATE
} TbDecompFmt;

/* Decompresses gzip, zlib, or raw DEFLATE data using tb_malloc.
 * Strictly refuses to output more than max_out bytes (anti-zip-bomb).
 * Returns true on success and sets *out (NUL-terminated) and *out_len. */
bool tb_decompress(const uint8_t *in, size_t in_len, TbDecompFmt fmt,
                   size_t max_out, char **out, size_t *out_len);

#endif /* TB_INFLATE_H */
