#include "inflate.h"
#include "common.h"

#define MAX_BITS 15
#define MAX_SYMS 288

typedef struct {
    const uint8_t *in;
    size_t         len;
    size_t         pos;
    uint32_t       bitbuf;
    int            bitcnt;
} BitStream;

typedef struct {
    uint16_t count[MAX_BITS + 1];
    uint16_t symbol[MAX_SYMS];
} HuffTable;

static bool bs_ensure(BitStream *bs, int n) {
    while (bs->bitcnt < n) {
        if (bs->pos >= bs->len) return false;
        bs->bitbuf |= (uint32_t)bs->in[bs->pos++] << bs->bitcnt;
        bs->bitcnt += 8;
    }
    return true;
}

static bool bs_read(BitStream *bs, int n, uint32_t *out) {
    if (n == 0) {
        *out = 0;
        return true;
    }
    if (!bs_ensure(bs, n)) return false;
    *out = bs->bitbuf & ((1U << n) - 1U);
    bs->bitbuf >>= n;
    bs->bitcnt -= n;
    return true;
}

static void bs_align_byte(BitStream *bs) {
    int drop = bs->bitcnt & 7;
    bs->bitbuf >>= drop;
    bs->bitcnt -= drop;
}

static bool huff_build(HuffTable *ht, const uint8_t *lengths, int num_syms) {
    memset(ht->count, 0, sizeof(ht->count));
    for (int i = 0; i < num_syms; i++) {
        if (lengths[i] > MAX_BITS) return false;
        ht->count[lengths[i]]++;
    }
    if (ht->count[0] == num_syms) {
        return true; /* Empty alphabet allowed for unused distance tree */
    }
    int left = 1;
    for (int len = 1; len <= MAX_BITS; len++) {
        left <<= 1;
        left -= ht->count[len];
        if (left < 0) return false; /* Over-subscribed */
    }
    uint16_t offs[MAX_BITS + 1];
    offs[1] = 0;
    for (int len = 1; len < MAX_BITS; len++) {
        offs[len + 1] = offs[len] + ht->count[len];
    }
    for (int sym = 0; sym < num_syms; sym++) {
        if (lengths[sym] != 0) {
            ht->symbol[offs[lengths[sym]]++] = (uint16_t)sym;
        }
    }
    return true;
}

static int huff_decode(BitStream *bs, const HuffTable *ht) {
    int code  = 0;
    int first = 0;
    int index = 0;
    for (int len = 1; len <= MAX_BITS; len++) {
        uint32_t bit = 0;
        if (!bs_read(bs, 1, &bit)) return -1;
        code |= (int)bit;
        int cnt = ht->count[len];
        if (code - cnt < first) {
            return ht->symbol[index + (code - first)];
        }
        index += cnt;
        first += cnt;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

static bool inflate_huff_block(BitStream *bs, const HuffTable *litlen,
                               const HuffTable *dist_ht, TbBuf *out, size_t max_out) {
    static const uint16_t len_base[29] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
    };
    static const uint8_t len_ext[29] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
    };
    static const uint16_t dist_base[30] = {
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
        8193, 12289, 16385, 24577
    };
    static const uint8_t dist_ext[30] = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
    };

    for (;;) {
        int sym = huff_decode(bs, litlen);
        if (sym < 0) return false;
        if (sym < 256) {
            if (out->len + 1 > max_out) return false;
            if (!tb_buf_append_char(out, (char)sym)) return false;
        } else if (sym == 256) {
            return true; /* End of block */
        } else {
            sym -= 257;
            if (sym >= 29) return false;
            uint32_t extra = 0;
            if (!bs_read(bs, len_ext[sym], &extra)) return false;
            size_t match_len = (size_t)len_base[sym] + extra;

            int dsym = huff_decode(bs, dist_ht);
            if (dsym < 0 || dsym >= 30) return false;
            uint32_t dextra = 0;
            if (!bs_read(bs, dist_ext[dsym], &dextra)) return false;
            size_t dist = (size_t)dist_base[dsym] + dextra;

            if (dist > out->len || out->len + match_len > max_out) return false;
            if (!tb_buf_reserve(out, match_len)) return false;
            for (size_t i = 0; i < match_len; i++) {
                out->data[out->len] = out->data[out->len - dist];
                out->len++;
            }
            out->data[out->len] = '\0';
        }
    }
}

static bool inflate_raw(const uint8_t *in, size_t in_len, size_t max_out, TbBuf *out) {
    BitStream bs = { in, in_len, 0, 0, 0 };
    uint32_t bfinal = 0;

    do {
        uint32_t btype = 0;
        if (!bs_read(&bs, 1, &bfinal)) return false;
        if (!bs_read(&bs, 2, &btype)) return false;

        if (btype == 0) {
            /* Stored uncompressed block */
            bs_align_byte(&bs);
            uint32_t blen = 0, bnlen = 0;
            if (!bs_read(&bs, 16, &blen)) return false;
            if (!bs_read(&bs, 16, &bnlen)) return false;
            if (blen != (~bnlen & 0xFFFFU)) return false;
            if (out->len + blen > max_out) return false;
            /* Drain any buffered bytes first */
            while (blen > 0 && bs.bitcnt >= 8) {
                uint32_t b = 0;
                bs_read(&bs, 8, &b);
                if (!tb_buf_append_char(out, (char)b)) return false;
                blen--;
            }
            if (bs.pos + blen > bs.len) return false;
            if (!tb_buf_append(out, (const char *)(bs.in + bs.pos), blen)) return false;
            bs.pos += blen;
        } else if (btype == 1) {
            /* Fixed Huffman */
            uint8_t lengths[288];
            for (int i = 0; i <= 143; i++) lengths[i] = 8;
            for (int i = 144; i <= 255; i++) lengths[i] = 9;
            for (int i = 256; i <= 279; i++) lengths[i] = 7;
            for (int i = 280; i <= 287; i++) lengths[i] = 8;
            uint8_t dlengths[30];
            for (int i = 0; i < 30; i++) dlengths[i] = 5;

            HuffTable litlen, dist_ht;
            if (!huff_build(&litlen, lengths, 288)) return false;
            if (!huff_build(&dist_ht, dlengths, 30)) return false;
            if (!inflate_huff_block(&bs, &litlen, &dist_ht, out, max_out)) return false;
        } else if (btype == 2) {
            /* Dynamic Huffman */
            static const uint8_t cl_order[19] = {
                16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
            };
            uint32_t hlit = 0, hdist = 0, hclen = 0;
            if (!bs_read(&bs, 5, &hlit)) return false;
            if (!bs_read(&bs, 5, &hdist)) return false;
            if (!bs_read(&bs, 4, &hclen)) return false;
            int nlit  = (int)hlit + 257;
            int ndist = (int)hdist + 1;
            int nclen = (int)hclen + 4;
            if (nlit > 286 || ndist > 30) return false;

            uint8_t cl_lens[19] = {0};
            for (int i = 0; i < nclen; i++) {
                uint32_t v = 0;
                if (!bs_read(&bs, 3, &v)) return false;
                cl_lens[cl_order[i]] = (uint8_t)v;
            }
            HuffTable cl_ht;
            if (!huff_build(&cl_ht, cl_lens, 19)) return false;

            uint8_t lengths[288 + 32] = {0};
            int total = nlit + ndist;
            int idx   = 0;
            while (idx < total) {
                int sym = huff_decode(&bs, &cl_ht);
                if (sym < 0) return false;
                if (sym < 16) {
                    lengths[idx++] = (uint8_t)sym;
                } else {
                    int rep = 0;
                    uint8_t val = 0;
                    uint32_t ext = 0;
                    if (sym == 16) {
                        if (idx == 0) return false;
                        if (!bs_read(&bs, 2, &ext)) return false;
                        rep = 3 + (int)ext;
                        val = lengths[idx - 1];
                    } else if (sym == 17) {
                        if (!bs_read(&bs, 3, &ext)) return false;
                        rep = 3 + (int)ext;
                    } else if (sym == 18) {
                        if (!bs_read(&bs, 7, &ext)) return false;
                        rep = 11 + (int)ext;
                    } else {
                        return false;
                    }
                    if (idx + rep > total) return false;
                    while (rep-- > 0) lengths[idx++] = val;
                }
            }
            HuffTable litlen, dist_ht;
            if (!huff_build(&litlen, lengths, nlit)) return false;
            if (!huff_build(&dist_ht, lengths + nlit, ndist)) return false;
            if (!inflate_huff_block(&bs, &litlen, &dist_ht, out, max_out)) return false;
        } else {
            return false;
        }
    } while (!bfinal);

    return true;
}

bool tb_decompress(const uint8_t *in, size_t in_len, TbDecompFmt fmt,
                   size_t max_out, char **out, size_t *out_len) {
    if (!in || !out || !out_len) return false;
    *out     = NULL;
    *out_len = 0;

    if (fmt == TB_DECOMP_AUTO) {
        if (in_len >= 10 && in[0] == 0x1F && in[1] == 0x8B) {
            fmt = TB_DECOMP_GZIP;
        } else if (in_len >= 2 && (in[0] & 0x0F) == 8 && ((in[0] & 0xF0) >> 4) <= 7 &&
                   (((uint16_t)in[0] << 8 | in[1]) % 31 == 0)) {
            fmt = TB_DECOMP_ZLIB;
        } else {
            fmt = TB_DECOMP_DEFLATE;
        }
    }

    size_t offset = 0;
    if (fmt == TB_DECOMP_GZIP) {
        if (in_len < 18 || in[0] != 0x1F || in[1] != 0x8B || in[2] != 8) return false;
        uint8_t flg = in[3];
        offset = 10;
        if (flg & 0x04) { /* FEXTRA */
            if (offset + 2 > in_len) return false;
            size_t xlen = (size_t)in[offset] | ((size_t)in[offset + 1] << 8);
            offset += 2 + xlen;
        }
        if (flg & 0x08) { /* FNAME */
            while (offset < in_len && in[offset] != 0) offset++;
            offset++;
        }
        if (flg & 0x10) { /* FCOMMENT */
            while (offset < in_len && in[offset] != 0) offset++;
            offset++;
        }
        if (flg & 0x02) { /* FHCRC */
            offset += 2;
        }
        if (offset >= in_len) return false;
    } else if (fmt == TB_DECOMP_ZLIB) {
        if (in_len < 6) return false;
        offset = 2;
        if (in[1] & 0x20) offset += 4; /* FDICT */
        if (offset >= in_len) return false;
    }

    TbBuf buf;
    tb_buf_init(&buf);
    if (!tb_buf_reserve(&buf, in_len < 4096 ? 4096 : (in_len < max_out ? in_len : max_out))) {
        tb_buf_free(&buf);
        return false;
    }

    bool ok = inflate_raw(in + offset, in_len - offset, max_out, &buf);
    if (!ok && fmt == TB_DECOMP_ZLIB) {
        /* HTTP "Content-Encoding: deflate" is sometimes raw RFC 1951 without zlib header */
        tb_buf_clear(&buf);
        ok = inflate_raw(in, in_len, max_out, &buf);
    }
    if (!ok) {
        tb_buf_free(&buf);
        return false;
    }
    *out = tb_buf_detach(&buf, out_len);
    return *out != NULL;
}
