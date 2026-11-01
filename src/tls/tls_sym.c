#include "tls.h"

/* ============================================================================
 * Constant-Time & Bit Rotation Helpers
 * ============================================================================ */

void tb_crypto_wipe(void *p, size_t n) {
    if (!p || n == 0) return;
    volatile uint8_t *vp = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++) vp[i] = 0;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : : "r"(p) : "memory");
#endif
}

int tb_crypto_ct_memcmp(const void *a, const void *b, size_t n) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(pa[i] ^ pb[i]);
    return (int)diff;
}

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

/* ============================================================================
 * SHA-1 (FIPS 180-4 — used strictly for OpenSSL X509_NAME subject hash lookup)
 * ============================================================================ */

static void sha1_compress(uint32_t h[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) w[i] = tb_load32_be(block + i * 4);
    for (int i = 16; i < 80; i++) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }
        uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void tb_sha1_init(TbSha1Ctx *ctx) {
    ctx->h[0] = 0x67452301U;
    ctx->h[1] = 0xEFCDAB89U;
    ctx->h[2] = 0x98BADCFEU;
    ctx->h[3] = 0x10325476U;
    ctx->h[4] = 0xC3D2E1F0U;
    ctx->total_bytes = 0;
    ctx->buf_len     = 0;
}

void tb_sha1_update(TbSha1Ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    ctx->total_bytes += len;
    if (ctx->buf_len > 0) {
        size_t take = 64 - ctx->buf_len;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->buf_len, p, take);
        ctx->buf_len += take;
        p   += take;
        len -= take;
        if (ctx->buf_len == 64) {
            sha1_compress(ctx->h, ctx->buf);
            ctx->buf_len = 0;
        }
    }
    while (len >= 64) {
        sha1_compress(ctx->h, p);
        p   += 64;
        len -= 64;
    }
    if (len > 0) {
        memcpy(ctx->buf, p, len);
        ctx->buf_len = len;
    }
}

void tb_sha1_final(TbSha1Ctx *ctx, uint8_t out[20]) {
    uint64_t bits = ctx->total_bytes * 8ULL;
    ctx->buf[ctx->buf_len++] = 0x80;
    if (ctx->buf_len > 56) {
        memset(ctx->buf + ctx->buf_len, 0, 64 - ctx->buf_len);
        sha1_compress(ctx->h, ctx->buf);
        ctx->buf_len = 0;
    }
    memset(ctx->buf + ctx->buf_len, 0, 56 - ctx->buf_len);
    tb_store64_be(ctx->buf + 56, bits);
    sha1_compress(ctx->h, ctx->buf);
    for (int i = 0; i < 5; i++) tb_store32_be(out + i * 4, ctx->h[i]);
    tb_crypto_wipe(ctx, sizeof(*ctx));
}

void tb_sha1(const void *data, size_t len, uint8_t out[20]) {
    TbSha1Ctx ctx;
    tb_sha1_init(&ctx);
    tb_sha1_update(&ctx, data, len);
    tb_sha1_final(&ctx, out);
}

/* ============================================================================
 * SHA-256 (FIPS 180-4)
 * ============================================================================ */

static const uint32_t K256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = tb_load32_be(block + i * 4);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1  = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch  = (e & f) ^ ((~e) & g);
        uint32_t t1  = hh + S1 + ch + K256[i] + w[i];
        uint32_t S0  = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2  = S0 + maj;

        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void tb_sha256_init(TbSha256Ctx *ctx) {
    ctx->h[0] = 0x6a09e667U; ctx->h[1] = 0xbb67ae85U;
    ctx->h[2] = 0x3c6ef372U; ctx->h[3] = 0xa54ff53aU;
    ctx->h[4] = 0x510e527fU; ctx->h[5] = 0x9b05688cU;
    ctx->h[6] = 0x1f83d9abU; ctx->h[7] = 0x5be0cd19U;
    ctx->total_bytes = 0;
    ctx->buf_len     = 0;
}

void tb_sha256_update(TbSha256Ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    ctx->total_bytes += len;
    if (ctx->buf_len > 0) {
        size_t take = 64 - ctx->buf_len;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->buf_len, p, take);
        ctx->buf_len += take;
        p   += take;
        len -= take;
        if (ctx->buf_len == 64) {
            sha256_compress(ctx->h, ctx->buf);
            ctx->buf_len = 0;
        }
    }
    while (len >= 64) {
        sha256_compress(ctx->h, p);
        p   += 64;
        len -= 64;
    }
    if (len > 0) {
        memcpy(ctx->buf, p, len);
        ctx->buf_len = len;
    }
}

void tb_sha256_final(TbSha256Ctx *ctx, uint8_t out[32]) {
    uint64_t bits = ctx->total_bytes * 8ULL;
    ctx->buf[ctx->buf_len++] = 0x80;
    if (ctx->buf_len > 56) {
        memset(ctx->buf + ctx->buf_len, 0, 64 - ctx->buf_len);
        sha256_compress(ctx->h, ctx->buf);
        ctx->buf_len = 0;
    }
    memset(ctx->buf + ctx->buf_len, 0, 56 - ctx->buf_len);
    tb_store64_be(ctx->buf + 56, bits);
    sha256_compress(ctx->h, ctx->buf);
    for (int i = 0; i < 8; i++) tb_store32_be(out + i * 4, ctx->h[i]);
    tb_crypto_wipe(ctx, sizeof(*ctx));
}

void tb_sha256(const void *data, size_t len, uint8_t out[32]) {
    TbSha256Ctx ctx;
    tb_sha256_init(&ctx);
    tb_sha256_update(&ctx, data, len);
    tb_sha256_final(&ctx, out);
}

/* ============================================================================
 * SHA-384 & SHA-512 (FIPS 180-4)
 * ============================================================================ */

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void sha512_compress(uint64_t h[8], const uint8_t block[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) w[i] = tb_load64_be(block + i * 8);
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 80; i++) {
        uint64_t S1  = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch  = (e & f) ^ ((~e) & g);
        uint64_t t1  = hh + S1 + ch + K512[i] + w[i];
        uint64_t S0  = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2  = S0 + maj;

        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void tb_sha384_init(TbSha512Ctx *ctx) {
    ctx->h[0] = 0xcbbb9d5dc1059ed8ULL; ctx->h[1] = 0x629a292a367cd507ULL;
    ctx->h[2] = 0x9159015a3070dd17ULL; ctx->h[3] = 0x152fecd8f70e5939ULL;
    ctx->h[4] = 0x67332667ffc00b31ULL; ctx->h[5] = 0x8eb44a8768581511ULL;
    ctx->h[6] = 0xdb0c2e0d64f98fa7ULL; ctx->h[7] = 0x47b5481dbefa4fa4ULL;
    ctx->total_lo = 0;
    ctx->total_hi = 0;
    ctx->buf_len  = 0;
}

void tb_sha512_init(TbSha512Ctx *ctx) {
    ctx->h[0] = 0x6a09e667f3bcc908ULL; ctx->h[1] = 0xbb67ae8584caa73bULL;
    ctx->h[2] = 0x3c6ef372fe94f82bULL; ctx->h[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->h[4] = 0x510e527fade682d1ULL; ctx->h[5] = 0x9b05688c2b3e6c1fULL;
    ctx->h[6] = 0x1f83d9abfb41bd6bULL; ctx->h[7] = 0x5be0cd19137e2179ULL;
    ctx->total_lo = 0;
    ctx->total_hi = 0;
    ctx->buf_len  = 0;
}

void tb_sha512_update(TbSha512Ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t prev = ctx->total_lo;
    ctx->total_lo += (uint64_t)len;
    if (ctx->total_lo < prev) ctx->total_hi++;

    if (ctx->buf_len > 0) {
        size_t take = 128 - ctx->buf_len;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->buf_len, p, take);
        ctx->buf_len += take;
        p   += take;
        len -= take;
        if (ctx->buf_len == 128) {
            sha512_compress(ctx->h, ctx->buf);
            ctx->buf_len = 0;
        }
    }
    while (len >= 128) {
        sha512_compress(ctx->h, p);
        p   += 128;
        len -= 128;
    }
    if (len > 0) {
        memcpy(ctx->buf, p, len);
        ctx->buf_len = len;
    }
}

static void sha512_pad_finish(TbSha512Ctx *ctx) {
    uint64_t bits_lo = ctx->total_lo << 3;
    uint64_t bits_hi = (ctx->total_hi << 3) | (ctx->total_lo >> 61);
    ctx->buf[ctx->buf_len++] = 0x80;
    if (ctx->buf_len > 112) {
        memset(ctx->buf + ctx->buf_len, 0, 128 - ctx->buf_len);
        sha512_compress(ctx->h, ctx->buf);
        ctx->buf_len = 0;
    }
    memset(ctx->buf + ctx->buf_len, 0, 112 - ctx->buf_len);
    tb_store64_be(ctx->buf + 112, bits_hi);
    tb_store64_be(ctx->buf + 120, bits_lo);
    sha512_compress(ctx->h, ctx->buf);
}

void tb_sha384_final(TbSha512Ctx *ctx, uint8_t out[48]) {
    sha512_pad_finish(ctx);
    for (int i = 0; i < 6; i++) tb_store64_be(out + i * 8, ctx->h[i]);
    tb_crypto_wipe(ctx, sizeof(*ctx));
}

void tb_sha512_final(TbSha512Ctx *ctx, uint8_t out[64]) {
    sha512_pad_finish(ctx);
    for (int i = 0; i < 8; i++) tb_store64_be(out + i * 8, ctx->h[i]);
    tb_crypto_wipe(ctx, sizeof(*ctx));
}

void tb_sha384(const void *data, size_t len, uint8_t out[48]) {
    TbSha512Ctx ctx;
    tb_sha384_init(&ctx);
    tb_sha512_update(&ctx, data, len);
    tb_sha384_final(&ctx, out);
}

void tb_sha512(const void *data, size_t len, uint8_t out[64]) {
    TbSha512Ctx ctx;
    tb_sha512_init(&ctx);
    tb_sha512_update(&ctx, data, len);
    tb_sha512_final(&ctx, out);
}

/* ============================================================================
 * HMAC & TLS 1.3 HKDF (RFC 2104, RFC 5869, RFC 8446 §7.1)
 * ============================================================================ */

void tb_hmac(size_t hash_len, const uint8_t *key, size_t key_len,
             const uint8_t *data, size_t data_len, uint8_t *out) {
    size_t block_len = (hash_len == 48) ? 128 : 64;
    uint8_t k_pad[128];
    uint8_t k_hash[64];
    memset(k_pad, 0, block_len);

    if (key_len > block_len) {
        if (hash_len == 48) tb_sha384(key, key_len, k_hash);
        else                tb_sha256(key, key_len, k_hash);
        memcpy(k_pad, k_hash, hash_len);
    } else if (key_len > 0) {
        memcpy(k_pad, key, key_len);
    }

    uint8_t ipad[128], opad[128], inner[64];
    for (size_t i = 0; i < block_len; i++) {
        ipad[i] = (uint8_t)(k_pad[i] ^ 0x36U);
        opad[i] = (uint8_t)(k_pad[i] ^ 0x5cU);
    }

    if (hash_len == 48) {
        TbSha512Ctx c;
        tb_sha384_init(&c);
        tb_sha512_update(&c, ipad, block_len);
        if (data_len > 0) tb_sha512_update(&c, data, data_len);
        tb_sha384_final(&c, inner);

        tb_sha384_init(&c);
        tb_sha512_update(&c, opad, block_len);
        tb_sha512_update(&c, inner, 48);
        tb_sha384_final(&c, out);
    } else {
        TbSha256Ctx c;
        tb_sha256_init(&c);
        tb_sha256_update(&c, ipad, block_len);
        if (data_len > 0) tb_sha256_update(&c, data, data_len);
        tb_sha256_final(&c, inner);

        tb_sha256_init(&c);
        tb_sha256_update(&c, opad, block_len);
        tb_sha256_update(&c, inner, 32);
        tb_sha256_final(&c, out);
    }

    tb_crypto_wipe(k_pad, sizeof(k_pad));
    tb_crypto_wipe(k_hash, sizeof(k_hash));
    tb_crypto_wipe(ipad, sizeof(ipad));
    tb_crypto_wipe(opad, sizeof(opad));
    tb_crypto_wipe(inner, sizeof(inner));
}

void tb_hkdf_extract(size_t hash_len, const uint8_t *salt, size_t salt_len,
                     const uint8_t *ikm, size_t ikm_len, uint8_t *prk_out) {
    uint8_t zeros[48] = {0};
    if (!salt || salt_len == 0) {
        salt     = zeros;
        salt_len = hash_len;
    }
    tb_hmac(hash_len, salt, salt_len, ikm, ikm_len, prk_out);
}

void tb_hkdf_expand(size_t hash_len, const uint8_t *prk,
                    const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len) {
    uint8_t t[48];
    uint8_t msg[48 + 512 + 1];
    size_t  t_len = 0;
    size_t  pos   = 0;
    uint8_t ctr   = 1;

    if (info_len > 512) info_len = 512;
    while (pos < okm_len) {
        size_t mlen = 0;
        if (t_len > 0) {
            memcpy(msg, t, t_len);
            mlen += t_len;
        }
        if (info_len > 0) {
            memcpy(msg + mlen, info, info_len);
            mlen += info_len;
        }
        msg[mlen++] = ctr++;
        tb_hmac(hash_len, prk, hash_len, msg, mlen, t);
        t_len = hash_len;

        size_t take = okm_len - pos;
        if (take > hash_len) take = hash_len;
        memcpy(okm + pos, t, take);
        pos += take;
    }
    tb_crypto_wipe(t, sizeof(t));
    tb_crypto_wipe(msg, sizeof(msg));
}

void tb_tls13_hkdf_expand_label(size_t hash_len, const uint8_t *secret,
                                const char *label,
                                const uint8_t *context, size_t context_len,
                                uint8_t *out, size_t out_len) {
    size_t  lbl_len = strlen(label);
    uint8_t info[512];
    size_t  p = 0;
    tb_store16_be(info + p, (uint16_t)out_len);
    p += 2;
    info[p++] = (uint8_t)(6 + lbl_len);
    memcpy(info + p, "tls13 ", 6);
    p += 6;
    memcpy(info + p, label, lbl_len);
    p += lbl_len;
    info[p++] = (uint8_t)context_len;
    if (context_len > 0) {
        memcpy(info + p, context, context_len);
        p += context_len;
    }
    tb_hkdf_expand(hash_len, secret, info, p, out, out_len);
    tb_crypto_wipe(info, sizeof(info));
}

/* ============================================================================
 * ChaCha20-Poly1305 AEAD (RFC 8439)
 * ============================================================================ */

#define CHACHA_QR(a, b, c, d) do { \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 16); \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 12); \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 8);  \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 7);  \
} while (0)

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t st[16] = {
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U,
        tb_load32_le(key +  0), tb_load32_le(key +  4), tb_load32_le(key +  8), tb_load32_le(key + 12),
        tb_load32_le(key + 16), tb_load32_le(key + 20), tb_load32_le(key + 24), tb_load32_le(key + 28),
        counter,
        tb_load32_le(nonce + 0), tb_load32_le(nonce + 4), tb_load32_le(nonce + 8)
    };
    uint32_t x[16];
    memcpy(x, st, sizeof(st));
    for (int i = 0; i < 10; i++) {
        CHACHA_QR(x[0], x[4], x[ 8], x[12]);
        CHACHA_QR(x[1], x[5], x[ 9], x[13]);
        CHACHA_QR(x[2], x[6], x[10], x[14]);
        CHACHA_QR(x[3], x[7], x[11], x[15]);
        CHACHA_QR(x[0], x[5], x[10], x[15]);
        CHACHA_QR(x[1], x[6], x[11], x[12]);
        CHACHA_QR(x[2], x[7], x[ 8], x[13]);
        CHACHA_QR(x[3], x[4], x[ 9], x[14]);
    }
    for (int i = 0; i < 16; i++) tb_store32_le(out + i * 4, x[i] + st[i]);
    tb_crypto_wipe(x, sizeof(x));
    tb_crypto_wipe(st, sizeof(st));
}

static void chacha20_xor(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12], const uint8_t *in,
                         uint8_t *out, size_t len) {
    uint8_t block[64];
    size_t  off = 0;
    while (off < len) {
        chacha20_block(key, counter++, nonce, block);
        size_t take = len - off;
        if (take > 64) take = 64;
        for (size_t i = 0; i < take; i++) out[off + i] = (uint8_t)(in[off + i] ^ block[i]);
        off += take;
    }
    tb_crypto_wipe(block, sizeof(block));
}

typedef struct {
    uint32_t r[5];
    uint32_t s[4];
    uint32_t h[5];
} Poly1305Ctx;

static void poly1305_init(Poly1305Ctx *ctx, const uint8_t key[32]) {
    ctx->r[0] = (tb_load32_le(key +  0)     ) & 0x3ffffffU;
    ctx->r[1] = (tb_load32_le(key +  3) >> 2) & 0x3ffff03U;
    ctx->r[2] = (tb_load32_le(key +  6) >> 4) & 0x3ffc0ffU;
    ctx->r[3] = (tb_load32_le(key +  9) >> 6) & 0x3f03fffU;
    ctx->r[4] = (tb_load32_le(key + 12) >> 8) & 0x00fffffU;

    ctx->s[0] = tb_load32_le(key + 16);
    ctx->s[1] = tb_load32_le(key + 20);
    ctx->s[2] = tb_load32_le(key + 24);
    ctx->s[3] = tb_load32_le(key + 28);

    memset(ctx->h, 0, sizeof(ctx->h));
}

static void poly1305_blocks(Poly1305Ctx *ctx, const uint8_t *m, size_t bytes, uint32_t hibit) {
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5U, s2 = r2 * 5U, s3 = r3 * 5U, s4 = r4 * 5U;
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];

    while (bytes >= 16) {
        h0 += (tb_load32_le(m +  0)     ) & 0x3ffffffU;
        h1 += (tb_load32_le(m +  3) >> 2) & 0x3ffffffU;
        h2 += (tb_load32_le(m +  6) >> 4) & 0x3ffffffU;
        h3 += (tb_load32_le(m +  9) >> 6) & 0x3ffffffU;
        h4 += (tb_load32_le(m + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint64_t c;
        c = d0 >> 26; h0 = (uint32_t)d0 & 0x3ffffffU; d1 += c;
        c = d1 >> 26; h1 = (uint32_t)d1 & 0x3ffffffU; d2 += c;
        c = d2 >> 26; h2 = (uint32_t)d2 & 0x3ffffffU; d3 += c;
        c = d3 >> 26; h3 = (uint32_t)d3 & 0x3ffffffU; d4 += c;
        c = d4 >> 26; h4 = (uint32_t)d4 & 0x3ffffffU;
        uint64_t h0_64 = (uint64_t)h0 + c * 5ULL;
        h0 = (uint32_t)h0_64 & 0x3ffffffU;
        h1 += (uint32_t)(h0_64 >> 26);

        m     += 16;
        bytes -= 16;
    }
    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2; ctx->h[3] = h3; ctx->h[4] = h4;
}

static void poly1305_padded(Poly1305Ctx *ctx, const uint8_t *data, size_t len) {
    size_t full = len & ~(size_t)15U;
    if (full > 0) poly1305_blocks(ctx, data, full, 1U << 24);
    size_t rem = len - full;
    if (rem > 0) {
        uint8_t blk[16] = {0};
        memcpy(blk, data + full, rem);
        poly1305_blocks(ctx, blk, 16, 1U << 24);
        tb_crypto_wipe(blk, sizeof(blk));
    }
}

static void poly1305_finish(Poly1305Ctx *ctx, uint8_t tag[16]) {
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffffU; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffffU; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffffU; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffffU; h0 += c * 5U;
    c = h0 >> 26; h0 &= 0x3ffffffU; h1 += c;

    uint32_t g0 = h0 + 5U; c = g0 >> 26; g0 &= 0x3ffffffU;
    uint32_t g1 = h1 + c;  c = g1 >> 26; g1 &= 0x3ffffffU;
    uint32_t g2 = h2 + c;  c = g2 >> 26; g2 &= 0x3ffffffU;
    uint32_t g3 = h3 + c;  c = g3 >> 26; g3 &= 0x3ffffffU;
    uint32_t g4 = h4 + c - (1U << 26);

    uint32_t mask = (g4 >> 31) - 1U;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    uint64_t f;
    f = (uint64_t)(h0 | (h1 << 26)) + ctx->s[0];
    tb_store32_le(tag + 0, (uint32_t)f);
    f = (uint64_t)((h1 >> 6) | (h2 << 20)) + ctx->s[1] + (f >> 32);
    tb_store32_le(tag + 4, (uint32_t)f);
    f = (uint64_t)((h2 >> 12) | (h3 << 14)) + ctx->s[2] + (f >> 32);
    tb_store32_le(tag + 8, (uint32_t)f);
    f = (uint64_t)((h3 >> 18) | (h4 << 8)) + ctx->s[3] + (f >> 32);
    tb_store32_le(tag + 12, (uint32_t)f);

    tb_crypto_wipe(ctx, sizeof(*ctx));
}

static void chacha20_poly1305_mac(const uint8_t poly_key[32],
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *ct, size_t ct_len,
                                  uint8_t tag[16]) {
    Poly1305Ctx pc;
    poly1305_init(&pc, poly_key);
    if (aad_len > 0) poly1305_padded(&pc, aad, aad_len);
    if (ct_len > 0)  poly1305_padded(&pc, ct, ct_len);
    uint8_t lens[16];
    tb_store64_le(lens + 0, (uint64_t)aad_len);
    tb_store64_le(lens + 8, (uint64_t)ct_len);
    poly1305_blocks(&pc, lens, 16, 1U << 24);
    poly1305_finish(&pc, tag);
}

void tb_chacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *pt, size_t pt_len,
                               uint8_t *ct, uint8_t tag[16]) {
    uint8_t block0[64];
    chacha20_block(key, 0, nonce, block0);
    if (pt_len > 0) chacha20_xor(key, 1, nonce, pt, ct, pt_len);
    chacha20_poly1305_mac(block0, aad, aad_len, ct, pt_len, tag);
    tb_crypto_wipe(block0, sizeof(block0));
}

bool tb_chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t tag[16], uint8_t *pt) {
    uint8_t block0[64];
    uint8_t calc_tag[16];
    chacha20_block(key, 0, nonce, block0);
    chacha20_poly1305_mac(block0, aad, aad_len, ct, ct_len, calc_tag);
    tb_crypto_wipe(block0, sizeof(block0));

    int diff = tb_crypto_ct_memcmp(calc_tag, tag, 16);
    tb_crypto_wipe(calc_tag, sizeof(calc_tag));
    if (diff != 0) return false;

    if (ct_len > 0) chacha20_xor(key, 1, nonce, ct, pt, ct_len);
    return true;
}

/* ============================================================================
 * AES-128-GCM & AES-256-GCM AEAD (FIPS 197 + NIST SP 800-38D)
 * ============================================================================ */

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t AES_RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

typedef struct {
    uint8_t rk[240];
    int     rounds;
} AesCtx;

static void aes_init(AesCtx *ctx, const uint8_t *key, size_t key_len) {
    int nk = (key_len == 32) ? 8 : 4;
    int nr = (key_len == 32) ? 14 : 10;
    ctx->rounds = nr;
    memcpy(ctx->rk, key, (size_t)nk * 4);

    int total_words = 4 * (nr + 1);
    for (int i = nk; i < total_words; i++) {
        uint8_t t[4];
        memcpy(t, ctx->rk + (i - 1) * 4, 4);
        if (i % nk == 0) {
            uint8_t u = t[0];
            t[0] = AES_SBOX[t[1]] ^ AES_RCON[i / nk];
            t[1] = AES_SBOX[t[2]];
            t[2] = AES_SBOX[t[3]];
            t[3] = AES_SBOX[u];
        } else if (nk == 8 && (i % 8) == 4) {
            t[0] = AES_SBOX[t[0]];
            t[1] = AES_SBOX[t[1]];
            t[2] = AES_SBOX[t[2]];
            t[3] = AES_SBOX[t[3]];
        }
        for (int j = 0; j < 4; j++) {
            ctx->rk[i * 4 + j] = (uint8_t)(ctx->rk[(i - nk) * 4 + j] ^ t[j]);
        }
    }
}

static inline uint8_t aes_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1U) * 0x1bU));
}

static void aes_encrypt_block(const AesCtx *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = (uint8_t)(in[i] ^ ctx->rk[i]);

    for (int r = 1; r <= ctx->rounds; r++) {
        uint8_t t[16];
        /* SubBytes + ShiftRows */
        t[ 0] = AES_SBOX[s[ 0]]; t[ 4] = AES_SBOX[s[ 4]]; t[ 8] = AES_SBOX[s[ 8]]; t[12] = AES_SBOX[s[12]];
        t[ 1] = AES_SBOX[s[ 5]]; t[ 5] = AES_SBOX[s[ 9]]; t[ 9] = AES_SBOX[s[13]]; t[13] = AES_SBOX[s[ 1]];
        t[ 2] = AES_SBOX[s[10]]; t[ 6] = AES_SBOX[s[14]]; t[10] = AES_SBOX[s[ 2]]; t[14] = AES_SBOX[s[ 6]];
        t[ 3] = AES_SBOX[s[15]]; t[ 7] = AES_SBOX[s[ 3]]; t[11] = AES_SBOX[s[ 7]]; t[15] = AES_SBOX[s[11]];

        const uint8_t *rk = ctx->rk + r * 16;
        if (r < ctx->rounds) {
            /* MixColumns + AddRoundKey */
            for (int c = 0; c < 4; c++) {
                uint8_t *col = t + c * 4;
                uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                uint8_t xr = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                s[c * 4 + 0] = (uint8_t)(a0 ^ xr ^ aes_xtime((uint8_t)(a0 ^ a1)) ^ rk[c * 4 + 0]);
                s[c * 4 + 1] = (uint8_t)(a1 ^ xr ^ aes_xtime((uint8_t)(a1 ^ a2)) ^ rk[c * 4 + 1]);
                s[c * 4 + 2] = (uint8_t)(a2 ^ xr ^ aes_xtime((uint8_t)(a2 ^ a3)) ^ rk[c * 4 + 2]);
                s[c * 4 + 3] = (uint8_t)(a3 ^ xr ^ aes_xtime((uint8_t)(a3 ^ a0)) ^ rk[c * 4 + 3]);
            }
        } else {
            for (int i = 0; i < 16; i++) s[i] = (uint8_t)(t[i] ^ rk[i]);
        }
    }
    memcpy(out, s, 16);
}

static void ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    uint64_t v_hi = tb_load64_be(h);
    uint64_t v_lo = tb_load64_be(h + 8);
    uint64_t z_hi = 0, z_lo = 0;

    for (int i = 0; i < 128; i++) {
        uint8_t  xb   = x[i >> 3];
        uint64_t bit  = (uint64_t)((xb >> (7 - (i & 7))) & 1U);
        uint64_t mask = 0ULL - bit;
        z_hi ^= v_hi & mask;
        z_lo ^= v_lo & mask;

        uint64_t lsb = v_lo & 1ULL;
        v_lo = (v_lo >> 1) | (v_hi << 63);
        v_hi = (v_hi >> 1) ^ (0xE100000000000000ULL & (0ULL - lsb));
    }
    tb_store64_be(x, z_hi);
    tb_store64_be(x + 8, z_lo);
}

static void ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len) {
    size_t off = 0;
    while (off + 16 <= len) {
        for (int i = 0; i < 16; i++) y[i] ^= data[off + i];
        ghash_mul(y, h);
        off += 16;
    }
    if (off < len) {
        for (size_t i = 0; i < len - off; i++) y[i] ^= data[off + i];
        ghash_mul(y, h);
    }
}

static void aes_gcm_compute_tag(const AesCtx *aes, const uint8_t nonce[12],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *ct, size_t ct_len,
                                uint8_t tag[16]) {
    uint8_t h[16] = {0};
    aes_encrypt_block(aes, h, h);

    uint8_t y[16] = {0};
    if (aad_len > 0) ghash_update(y, h, aad, aad_len);
    if (ct_len > 0)  ghash_update(y, h, ct, ct_len);

    uint8_t lens[16];
    tb_store64_be(lens + 0, (uint64_t)aad_len * 8ULL);
    tb_store64_be(lens + 8, (uint64_t)ct_len * 8ULL);
    ghash_update(y, h, lens, 16);

    uint8_t j0[16];
    memcpy(j0, nonce, 12);
    tb_store32_be(j0 + 12, 1U);
    uint8_t ej0[16];
    aes_encrypt_block(aes, j0, ej0);
    for (int i = 0; i < 16; i++) tag[i] = (uint8_t)(y[i] ^ ej0[i]);

    tb_crypto_wipe(h, sizeof(h));
    tb_crypto_wipe(y, sizeof(y));
    tb_crypto_wipe(ej0, sizeof(ej0));
}

static void aes_gcm_ctr(const AesCtx *aes, const uint8_t nonce[12],
                        const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t cb[16], ks[16];
    memcpy(cb, nonce, 12);
    uint32_t ctr = 2U;
    size_t   off = 0;
    while (off < len) {
        tb_store32_be(cb + 12, ctr++);
        aes_encrypt_block(aes, cb, ks);
        size_t take = len - off;
        if (take > 16) take = 16;
        for (size_t i = 0; i < take; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        off += take;
    }
    tb_crypto_wipe(cb, sizeof(cb));
    tb_crypto_wipe(ks, sizeof(ks));
}

void tb_aes_gcm_seal(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t pt_len,
                     uint8_t *ct, uint8_t tag[16]) {
    AesCtx aes;
    aes_init(&aes, key, key_len);
    if (pt_len > 0) aes_gcm_ctr(&aes, nonce, pt, ct, pt_len);
    aes_gcm_compute_tag(&aes, nonce, aad, aad_len, ct, pt_len, tag);
    tb_crypto_wipe(&aes, sizeof(aes));
}

bool tb_aes_gcm_open(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len,
                     const uint8_t tag[16], uint8_t *pt) {
    AesCtx aes;
    uint8_t calc_tag[16];
    aes_init(&aes, key, key_len);
    aes_gcm_compute_tag(&aes, nonce, aad, aad_len, ct, ct_len, calc_tag);
    int diff = tb_crypto_ct_memcmp(calc_tag, tag, 16);
    tb_crypto_wipe(calc_tag, sizeof(calc_tag));
    if (diff != 0) {
        tb_crypto_wipe(&aes, sizeof(aes));
        return false;
    }
    if (ct_len > 0) aes_gcm_ctr(&aes, nonce, ct, pt, ct_len);
    tb_crypto_wipe(&aes, sizeof(aes));
    return true;
}
