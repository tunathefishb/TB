#include "tls.h"

/* ============================================================================
 * Constant-Time & Endian Helpers
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

static inline uint32_t load32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static inline void store32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint64_t load64_be(const uint8_t *p) {
    return ((uint64_t)load32_be(p) << 32) | (uint64_t)load32_be(p + 4);
}

static inline void store64_be(uint8_t *p, uint64_t v) {
    store32_be(p, (uint32_t)(v >> 32));
    store32_be(p + 4, (uint32_t)v);
}

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint64_t load64_le(const uint8_t *p) {
    return (uint64_t)load32_le(p) | ((uint64_t)load32_le(p + 4) << 32);
}

static inline void store64_le(uint8_t *p, uint64_t v) {
    store32_le(p, (uint32_t)v);
    store32_le(p + 4, (uint32_t)(v >> 32));
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
    for (int i = 0; i < 16; i++) w[i] = load32_be(block + i * 4);
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
    store64_be(ctx->buf + 56, bits);
    sha1_compress(ctx->h, ctx->buf);
    for (int i = 0; i < 5; i++) store32_be(out + i * 4, ctx->h[i]);
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
    for (int i = 0; i < 16; i++) w[i] = load32_be(block + i * 4);
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
    store64_be(ctx->buf + 56, bits);
    sha256_compress(ctx->h, ctx->buf);
    for (int i = 0; i < 8; i++) store32_be(out + i * 4, ctx->h[i]);
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
    for (int i = 0; i < 16; i++) w[i] = load64_be(block + i * 8);
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
    store64_be(ctx->buf + 112, bits_hi);
    store64_be(ctx->buf + 120, bits_lo);
    sha512_compress(ctx->h, ctx->buf);
}

void tb_sha384_final(TbSha512Ctx *ctx, uint8_t out[48]) {
    sha512_pad_finish(ctx);
    for (int i = 0; i < 6; i++) store64_be(out + i * 8, ctx->h[i]);
    tb_crypto_wipe(ctx, sizeof(*ctx));
}

void tb_sha512_final(TbSha512Ctx *ctx, uint8_t out[64]) {
    sha512_pad_finish(ctx);
    for (int i = 0; i < 8; i++) store64_be(out + i * 8, ctx->h[i]);
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
    info[p++] = (uint8_t)(out_len >> 8);
    info[p++] = (uint8_t)out_len;
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
        load32_le(key +  0), load32_le(key +  4), load32_le(key +  8), load32_le(key + 12),
        load32_le(key + 16), load32_le(key + 20), load32_le(key + 24), load32_le(key + 28),
        counter,
        load32_le(nonce + 0), load32_le(nonce + 4), load32_le(nonce + 8)
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
    for (int i = 0; i < 16; i++) store32_le(out + i * 4, x[i] + st[i]);
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
    ctx->r[0] = (load32_le(key +  0)     ) & 0x3ffffffU;
    ctx->r[1] = (load32_le(key +  3) >> 2) & 0x3ffff03U;
    ctx->r[2] = (load32_le(key +  6) >> 4) & 0x3ffc0ffU;
    ctx->r[3] = (load32_le(key +  9) >> 6) & 0x3f03fffU;
    ctx->r[4] = (load32_le(key + 12) >> 8) & 0x00fffffU;

    ctx->s[0] = load32_le(key + 16);
    ctx->s[1] = load32_le(key + 20);
    ctx->s[2] = load32_le(key + 24);
    ctx->s[3] = load32_le(key + 28);

    memset(ctx->h, 0, sizeof(ctx->h));
}

static void poly1305_blocks(Poly1305Ctx *ctx, const uint8_t *m, size_t bytes, uint32_t hibit) {
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5U, s2 = r2 * 5U, s3 = r3 * 5U, s4 = r4 * 5U;
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];

    while (bytes >= 16) {
        h0 += (load32_le(m +  0)     ) & 0x3ffffffU;
        h1 += (load32_le(m +  3) >> 2) & 0x3ffffffU;
        h2 += (load32_le(m +  6) >> 4) & 0x3ffffffU;
        h3 += (load32_le(m +  9) >> 6) & 0x3ffffffU;
        h4 += (load32_le(m + 12) >> 8) | hibit;

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
    store32_le(tag + 0, (uint32_t)f);
    f = (uint64_t)((h1 >> 6) | (h2 << 20)) + ctx->s[1] + (f >> 32);
    store32_le(tag + 4, (uint32_t)f);
    f = (uint64_t)((h2 >> 12) | (h3 << 14)) + ctx->s[2] + (f >> 32);
    store32_le(tag + 8, (uint32_t)f);
    f = (uint64_t)((h3 >> 18) | (h4 << 8)) + ctx->s[3] + (f >> 32);
    store32_le(tag + 12, (uint32_t)f);

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
    store64_le(lens + 0, (uint64_t)aad_len);
    store64_le(lens + 8, (uint64_t)ct_len);
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
    uint64_t v_hi = load64_be(h);
    uint64_t v_lo = load64_be(h + 8);
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
    store64_be(x, z_hi);
    store64_be(x + 8, z_lo);
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
    store64_be(lens + 0, (uint64_t)aad_len * 8ULL);
    store64_be(lens + 8, (uint64_t)ct_len * 8ULL);
    ghash_update(y, h, lens, 16);

    uint8_t j0[16];
    memcpy(j0, nonce, 12);
    store32_be(j0 + 12, 1U);
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
        store32_be(cb + 12, ctr++);
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

/* ============================================================================
 * X25519 Elliptic Curve Diffie-Hellman (RFC 7748, 5x51-bit GF(2^255 - 19))
 * ============================================================================ */

#define FE51_MASK 0x0007FFFFFFFFFFFFULL

typedef struct {
    uint64_t v[5];
} Fe25519;

static void fe25519_load(Fe25519 *o, const uint8_t in[32]) {
    o->v[0] =  load64_le(in +  0)        & FE51_MASK;
    o->v[1] = (load64_le(in +  6) >>  3) & FE51_MASK;
    o->v[2] = (load64_le(in + 12) >>  6) & FE51_MASK;
    o->v[3] = (load64_le(in + 19) >>  1) & FE51_MASK;
    o->v[4] = ((load64_le(in + 24) & 0x7FFFFFFFFFFFFFFFULL) >> 12) & FE51_MASK;
}

static void fe25519_store(uint8_t out[32], const Fe25519 *a) {
    uint64_t t0 = a->v[0], t1 = a->v[1], t2 = a->v[2], t3 = a->v[3], t4 = a->v[4];
    uint64_t c;
    for (int pass = 0; pass < 2; pass++) {
        c = t0 >> 51; t0 &= FE51_MASK; t1 += c;
        c = t1 >> 51; t1 &= FE51_MASK; t2 += c;
        c = t2 >> 51; t2 &= FE51_MASK; t3 += c;
        c = t3 >> 51; t3 &= FE51_MASK; t4 += c;
        c = t4 >> 51; t4 &= FE51_MASK; t0 += c * 19ULL;
    }

    /* Canonical reduction modulo p = 2^255 - 19 */
    uint64_t u0 = t0 + 19ULL; c = u0 >> 51; u0 &= FE51_MASK;
    uint64_t u1 = t1 + c;     c = u1 >> 51; u1 &= FE51_MASK;
    uint64_t u2 = t2 + c;     c = u2 >> 51; u2 &= FE51_MASK;
    uint64_t u3 = t3 + c;     c = u3 >> 51; u3 &= FE51_MASK;
    uint64_t u4 = t4 + c;     c = u4 >> 51; u4 &= FE51_MASK;

    uint64_t mask = 0ULL - c; /* all 1s if t >= 2^255 - 19 */
    t0 = (t0 & ~mask) | (u0 & mask);
    t1 = (t1 & ~mask) | (u1 & mask);
    t2 = (t2 & ~mask) | (u2 & mask);
    t3 = (t3 & ~mask) | (u3 & mask);
    t4 = (t4 & ~mask) | (u4 & mask);

    store64_le(out +  0,  t0        | (t1 << 51));
    store64_le(out +  8, (t1 >> 13) | (t2 << 38));
    store64_le(out + 16, (t2 >> 26) | (t3 << 25));
    store64_le(out + 24, (t3 >> 39) | (t4 << 12));
}

static void fe25519_add(Fe25519 *o, const Fe25519 *a, const Fe25519 *b) {
    for (int i = 0; i < 5; i++) o->v[i] = a->v[i] + b->v[i];
}

static void fe25519_sub(Fe25519 *o, const Fe25519 *a, const Fe25519 *b) {
    /* Add 4*p bias so limbs stay strictly unsigned */
    static const uint64_t BIAS[5] = {
        0x001FFFFFFFFFFFB4ULL, 0x001FFFFFFFFFFFFCULL, 0x001FFFFFFFFFFFFCULL,
        0x001FFFFFFFFFFFFCULL, 0x001FFFFFFFFFFFFCULL
    };
    uint64_t c = 0;
    for (int i = 0; i < 5; i++) {
        uint64_t s = a->v[i] + BIAS[i] - b->v[i] + c;
        o->v[i] = s & FE51_MASK;
        c = s >> 51;
    }
    o->v[0] += c * 19ULL;
}

static void fe25519_mul(Fe25519 *o, const Fe25519 *a, const Fe25519 *b) {
    uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];
    uint64_t b0 = b->v[0], b1 = b->v[1], b2 = b->v[2], b3 = b->v[3], b4 = b->v[4];
    uint64_t b1_19 = b1 * 19ULL, b2_19 = b2 * 19ULL, b3_19 = b3 * 19ULL, b4_19 = b4 * 19ULL;

    __uint128_t r0 = (__uint128_t)a0 * b0    + (__uint128_t)a1 * b4_19 + (__uint128_t)a2 * b3_19 + (__uint128_t)a3 * b2_19 + (__uint128_t)a4 * b1_19;
    __uint128_t r1 = (__uint128_t)a0 * b1    + (__uint128_t)a1 * b0    + (__uint128_t)a2 * b4_19 + (__uint128_t)a3 * b3_19 + (__uint128_t)a4 * b2_19;
    __uint128_t r2 = (__uint128_t)a0 * b2    + (__uint128_t)a1 * b1    + (__uint128_t)a2 * b0    + (__uint128_t)a3 * b4_19 + (__uint128_t)a4 * b3_19;
    __uint128_t r3 = (__uint128_t)a0 * b3    + (__uint128_t)a1 * b2    + (__uint128_t)a2 * b1    + (__uint128_t)a3 * b0    + (__uint128_t)a4 * b4_19;
    __uint128_t r4 = (__uint128_t)a0 * b4    + (__uint128_t)a1 * b3    + (__uint128_t)a2 * b2    + (__uint128_t)a3 * b1    + (__uint128_t)a4 * b0;

    uint64_t c;
    c = (uint64_t)(r0 >> 51); o->v[0] = (uint64_t)r0 & FE51_MASK; r1 += c;
    c = (uint64_t)(r1 >> 51); o->v[1] = (uint64_t)r1 & FE51_MASK; r2 += c;
    c = (uint64_t)(r2 >> 51); o->v[2] = (uint64_t)r2 & FE51_MASK; r3 += c;
    c = (uint64_t)(r3 >> 51); o->v[3] = (uint64_t)r3 & FE51_MASK; r4 += c;
    c = (uint64_t)(r4 >> 51); o->v[4] = (uint64_t)r4 & FE51_MASK; o->v[0] += c * 19ULL;
    c = o->v[0] >> 51;        o->v[0] &= FE51_MASK;               o->v[1] += c;
}

static void fe25519_sq(Fe25519 *o, const Fe25519 *a) {
    fe25519_mul(o, a, a);
}

static void fe25519_mul_u32(Fe25519 *o, const Fe25519 *a, uint32_t m) {
    __uint128_t c = 0;
    for (int i = 0; i < 5; i++) {
        __uint128_t p = (__uint128_t)a->v[i] * m + c;
        o->v[i] = (uint64_t)p & FE51_MASK;
        c = p >> 51;
    }
    o->v[0] += (uint64_t)c * 19ULL;
    uint64_t c0 = o->v[0] >> 51;
    o->v[0] &= FE51_MASK;
    o->v[1] += c0;
}

static void fe25519_cswap(Fe25519 *a, Fe25519 *b, uint64_t swap) {
    uint64_t mask = 0ULL - swap;
    for (int i = 0; i < 5; i++) {
        uint64_t x = mask & (a->v[i] ^ b->v[i]);
        a->v[i] ^= x;
        b->v[i] ^= x;
    }
}

static void fe25519_inv(Fe25519 *o, const Fe25519 *x) {
    /* Fermat's Little Theorem: x^(p - 2) = x^(2^255 - 21) */
    Fe25519 r = { { 1, 0, 0, 0, 0 } };
    for (int i = 254; i >= 0; i--) {
        fe25519_sq(&r, &r);
        if (i >= 5 || i == 3 || i == 1 || i == 0) {
            fe25519_mul(&r, &r, x);
        }
    }
    *o = r;
}

static void x25519_raw(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t k[32];
    memcpy(k, scalar, 32);
    k[0]  &= 248U;
    k[31] &= 127U;
    k[31] |= 64U;

    Fe25519 x1, x2 = { { 1, 0, 0, 0, 0 } }, z2 = { { 0, 0, 0, 0, 0 } };
    Fe25519 x3, z3 = { { 1, 0, 0, 0, 0 } };
    fe25519_load(&x1, point);
    x3 = x1;

    uint64_t swap = 0;
    for (int t = 254; t >= 0; t--) {
        uint64_t kt = (uint64_t)((k[t >> 3] >> (t & 7)) & 1U);
        swap ^= kt;
        fe25519_cswap(&x2, &x3, swap);
        fe25519_cswap(&z2, &z3, swap);
        swap = kt;

        Fe25519 A, AA, B, BB, E, C, D, DA, CB, tmp;
        fe25519_add(&A, &x2, &z2);
        fe25519_sq(&AA, &A);
        fe25519_sub(&B, &x2, &z2);
        fe25519_sq(&BB, &B);
        fe25519_sub(&E, &AA, &BB);
        fe25519_add(&C, &x3, &z3);
        fe25519_sub(&D, &x3, &z3);
        fe25519_mul(&DA, &D, &A);
        fe25519_mul(&CB, &C, &B);

        fe25519_add(&tmp, &DA, &CB);
        fe25519_sq(&x3, &tmp);
        fe25519_sub(&tmp, &DA, &CB);
        fe25519_sq(&tmp, &tmp);
        fe25519_mul(&z3, &x1, &tmp);

        fe25519_mul(&x2, &AA, &BB);
        fe25519_mul_u32(&tmp, &E, 121665U);
        fe25519_add(&tmp, &AA, &tmp);
        fe25519_mul(&z2, &E, &tmp);
    }
    fe25519_cswap(&x2, &x3, swap);
    fe25519_cswap(&z2, &z3, swap);

    fe25519_inv(&z2, &z2);
    fe25519_mul(&x2, &x2, &z2);
    fe25519_store(out, &x2);
    tb_crypto_wipe(k, sizeof(k));
}

void tb_x25519_base(uint8_t pub[32], const uint8_t priv[32]) {
    static const uint8_t BASE[32] = { 9 };
    x25519_raw(pub, priv, BASE);
}

bool tb_x25519(uint8_t shared[32], const uint8_t priv[32], const uint8_t peer_pub[32]) {
    static const uint8_t ZEROS[32] = { 0 };
    x25519_raw(shared, priv, peer_pub);
    return tb_crypto_ct_memcmp(shared, ZEROS, 32) != 0;
}

/* ============================================================================
 * Unified 64-bit Montgomery BigInt (up to 4096-bit RSA + P-256 / P-384 ECDSA)
 * ============================================================================ */

#define BIG_MAX_LIMBS 64 /* 64 * 64 = 4096 bits */

static int big_cmp(const uint64_t *a, const uint64_t *b, size_t n) {
    for (size_t i = n; i > 0; i--) {
        if (a[i - 1] > b[i - 1]) return 1;
        if (a[i - 1] < b[i - 1]) return -1;
    }
    return 0;
}

static bool big_is_zero(const uint64_t *a, size_t n) {
    uint64_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= a[i];
    return acc == 0;
}

static uint64_t big_add(uint64_t *r, const uint64_t *a, const uint64_t *b, size_t n) {
    __uint128_t c = 0;
    for (size_t i = 0; i < n; i++) {
        __uint128_t s = (__uint128_t)a[i] + b[i] + c;
        r[i] = (uint64_t)s;
        c    = s >> 64;
    }
    return (uint64_t)c;
}

static uint64_t big_sub(uint64_t *r, const uint64_t *a, const uint64_t *b, size_t n) {
    __uint128_t borrow = 0;
    for (size_t i = 0; i < n; i++) {
        __uint128_t ai = a[i];
        __uint128_t bi = (__uint128_t)b[i] + borrow;
        r[i]   = (uint64_t)(ai - bi);
        borrow = (ai < bi) ? 1 : 0;
    }
    return (uint64_t)borrow;
}

static void big_mod_add(uint64_t *r, const uint64_t *a, const uint64_t *b,
                        const uint64_t *mod, size_t n) {
    uint64_t c = big_add(r, a, b, n);
    if (c || big_cmp(r, mod, n) >= 0) {
        big_sub(r, r, mod, n);
    }
}

static void big_mod_sub(uint64_t *r, const uint64_t *a, const uint64_t *b,
                        const uint64_t *mod, size_t n) {
    uint64_t tmp[BIG_MAX_LIMBS];
    if (big_sub(tmp, a, b, n)) {
        big_add(r, tmp, mod, n);
    } else {
        memcpy(r, tmp, n * sizeof(uint64_t));
    }
}

static void big_from_be(uint64_t *out, size_t n_limbs, const uint8_t *be, size_t be_len) {
    memset(out, 0, n_limbs * sizeof(uint64_t));
    size_t max_bytes = n_limbs * 8;
    if (be_len > max_bytes) {
        be     += (be_len - max_bytes);
        be_len  = max_bytes;
    }
    for (size_t i = 0; i < be_len; i++) {
        size_t rev = be_len - 1 - i;
        out[rev >> 3] |= (uint64_t)be[i] << ((rev & 7) * 8);
    }
}

static void big_to_be(uint8_t *be, size_t be_len, const uint64_t *a, size_t n_limbs) {
    memset(be, 0, be_len);
    for (size_t i = 0; i < be_len; i++) {
        size_t rev  = be_len - 1 - i;
        size_t limb = rev >> 3;
        if (limb < n_limbs) {
            be[i] = (uint8_t)(a[limb] >> ((rev & 7) * 8));
        }
    }
}

static uint64_t mont_n0_inv(uint64_t m0) {
    uint64_t inv = 1;
    for (int i = 0; i < 6; i++) inv *= 2ULL - m0 * inv;
    return ~inv + 1ULL;
}

static void mont_compute_rr(uint64_t *rr, const uint64_t *mod, size_t n) {
    memset(rr, 0, n * sizeof(uint64_t));
    rr[0] = 1ULL;
    if (big_cmp(rr, mod, n) >= 0) big_sub(rr, rr, mod, n);
    size_t bits = 128 * n;
    for (size_t i = 0; i < bits; i++) {
        big_mod_add(rr, rr, rr, mod, n);
    }
}

static void mont_mul(uint64_t *r, const uint64_t *a, const uint64_t *b,
                     const uint64_t *mod, size_t n, uint64_t n0_inv) {
    uint64_t t[BIG_MAX_LIMBS + 2];
    memset(t, 0, (n + 2) * sizeof(uint64_t));

    for (size_t i = 0; i < n; i++) {
        __uint128_t carry = 0;
        uint64_t ai = a[i];
        for (size_t j = 0; j < n; j++) {
            __uint128_t cur = (__uint128_t)t[j] + (__uint128_t)ai * b[j] + carry;
            t[j]  = (uint64_t)cur;
            carry = cur >> 64;
        }
        __uint128_t sum = (__uint128_t)t[n] + carry;
        t[n]     = (uint64_t)sum;
        t[n + 1] += (uint64_t)(sum >> 64);

        uint64_t u = t[0] * n0_inv;
        carry = ((__uint128_t)t[0] + (__uint128_t)u * mod[0]) >> 64;
        for (size_t j = 1; j < n; j++) {
            __uint128_t cur = (__uint128_t)t[j] + (__uint128_t)u * mod[j] + carry;
            t[j - 1] = (uint64_t)cur;
            carry    = cur >> 64;
        }
        sum      = (__uint128_t)t[n] + carry;
        t[n - 1] = (uint64_t)sum;
        t[n]     = t[n + 1] + (uint64_t)(sum >> 64);
        t[n + 1] = 0;
    }

    if (t[n] > 0 || big_cmp(t, mod, n) >= 0) {
        big_sub(r, t, mod, n);
    } else {
        memcpy(r, t, n * sizeof(uint64_t));
    }
}

static void mont_from(uint64_t *r, const uint64_t *a_mont,
                      const uint64_t *mod, size_t n, uint64_t n0_inv) {
    uint64_t one[BIG_MAX_LIMBS] = { 1ULL };
    mont_mul(r, a_mont, one, mod, n, n0_inv);
}

/* ============================================================================
 * RSA Signature Verification (PKCS#1 v1.5 & RSASSA-PSS, 1024..4096-bit)
 * ============================================================================ */

static size_t strip_leading_zeros(const uint8_t **p, size_t len) {
    while (len > 0 && (*p)[0] == 0) {
        (*p)++;
        len--;
    }
    return len;
}

static bool rsa_public_op(const uint8_t *mod, size_t mod_len,
                          const uint8_t *exp, size_t exp_len,
                          const uint8_t *sig, size_t sig_len,
                          uint8_t *em_out, size_t *out_mod_len,
                          size_t *out_mod_bits) {
    mod_len = strip_leading_zeros(&mod, mod_len);
    exp_len = strip_leading_zeros(&exp, exp_len);
    if (mod_len < 128 || mod_len > 512 || exp_len == 0 || exp_len > mod_len) return false;
    if (sig_len != mod_len) return false;
    if ((mod[mod_len - 1] & 1U) == 0 || (exp[exp_len - 1] & 1U) == 0) return false;
    if (exp_len == 1 && exp[0] < 3) return false;

    size_t n = (mod_len + 7) / 8;
    uint64_t m_big[BIG_MAX_LIMBS], s_big[BIG_MAX_LIMBS];
    big_from_be(m_big, n, mod, mod_len);
    big_from_be(s_big, n, sig, sig_len);
    if (big_cmp(s_big, m_big, n) >= 0) return false;

    uint64_t n0 = mont_n0_inv(m_big[0]);
    uint64_t rr[BIG_MAX_LIMBS];
    mont_compute_rr(rr, m_big, n);

    uint64_t s_mont[BIG_MAX_LIMBS], acc[BIG_MAX_LIMBS];
    uint64_t one[BIG_MAX_LIMBS] = { 1ULL };
    mont_mul(s_mont, s_big, rr, m_big, n, n0);
    mont_mul(acc, one, rr, m_big, n, n0);

    bool started = false;
    for (size_t bi = 0; bi < exp_len; bi++) {
        uint8_t eb = exp[bi];
        for (int bit = 7; bit >= 0; bit--) {
            int b = (eb >> bit) & 1;
            if (!started) {
                if (b) {
                    memcpy(acc, s_mont, n * sizeof(uint64_t));
                    started = true;
                }
                continue;
            }
            mont_mul(acc, acc, acc, m_big, n, n0);
            if (b) mont_mul(acc, acc, s_mont, m_big, n, n0);
        }
    }

    uint64_t res_big[BIG_MAX_LIMBS];
    mont_from(res_big, acc, m_big, n, n0);
    big_to_be(em_out, mod_len, res_big, n);

    int top_bits = 8;
    uint8_t msb = mod[0];
    while (top_bits > 0 && ((msb >> (top_bits - 1)) & 1U) == 0) top_bits--;
    *out_mod_len  = mod_len;
    *out_mod_bits = (mod_len - 1) * 8 + (size_t)top_bits;
    return true;
}

static size_t hash_alg_len(TbHashAlg alg) {
    switch (alg) {
        case TB_HASH_SHA256: return 32;
        case TB_HASH_SHA384: return 48;
        case TB_HASH_SHA512: return 64;
    }
    return 0;
}

static void hash_compute(TbHashAlg alg, const void *data, size_t len, uint8_t *out) {
    switch (alg) {
        case TB_HASH_SHA256: tb_sha256(data, len, out); break;
        case TB_HASH_SHA384: tb_sha384(data, len, out); break;
        case TB_HASH_SHA512: tb_sha512(data, len, out); break;
    }
}

bool tb_rsa_verify_pkcs1(const uint8_t *mod, size_t mod_len,
                         const uint8_t *exp, size_t exp_len,
                         TbHashAlg alg, const uint8_t *digest, size_t digest_len,
                         const uint8_t *sig, size_t sig_len) {
    /* Exact DER DigestInfo prefixes (RFC 8017 §9.2 Notes 1) */
    static const uint8_t DI_SHA256[19] = {
        0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
    };
    static const uint8_t DI_SHA384[19] = {
        0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30
    };
    static const uint8_t DI_SHA512[19] = {
        0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40
    };
    size_t hlen = hash_alg_len(alg);
    if (hlen == 0 || digest_len != hlen) return false;
    const uint8_t *di = (alg == TB_HASH_SHA256) ? DI_SHA256 :
                        (alg == TB_HASH_SHA384) ? DI_SHA384 : DI_SHA512;

    uint8_t em[512];
    size_t  k = 0, mod_bits = 0;
    if (!rsa_public_op(mod, mod_len, exp, exp_len, sig, sig_len, em, &k, &mod_bits)) return false;

    size_t t_len = 19 + hlen;
    if (k < t_len + 11) return false;
    size_t ps_len = k - t_len - 3;

    uint8_t bad = 0;
    bad |= em[0] ^ 0x00U;
    bad |= em[1] ^ 0x01U;
    for (size_t i = 0; i < ps_len; i++) bad |= em[2 + i] ^ 0xFFU;
    bad |= em[2 + ps_len] ^ 0x00U;
    for (size_t i = 0; i < 19; i++) bad |= em[3 + ps_len + i] ^ di[i];
    for (size_t i = 0; i < hlen; i++) bad |= em[3 + ps_len + 19 + i] ^ digest[i];
    return bad == 0;
}

static void mgf1_xor(TbHashAlg alg, const uint8_t *seed, size_t seed_len,
                     uint8_t *dst, size_t dst_len) {
    size_t  hlen = hash_alg_len(alg);
    uint8_t in[68];
    uint8_t md[64];
    memcpy(in, seed, seed_len);
    size_t   pos = 0;
    uint32_t ctr = 0;
    while (pos < dst_len) {
        store32_be(in + seed_len, ctr++);
        hash_compute(alg, in, seed_len + 4, md);
        size_t take = dst_len - pos;
        if (take > hlen) take = hlen;
        for (size_t i = 0; i < take; i++) dst[pos + i] ^= md[i];
        pos += take;
    }
}

bool tb_rsa_verify_pss(const uint8_t *mod, size_t mod_len,
                       const uint8_t *exp, size_t exp_len,
                       TbHashAlg alg, const uint8_t *digest, size_t digest_len,
                       int expected_salt_len,
                       const uint8_t *sig, size_t sig_len) {
    size_t hlen = hash_alg_len(alg);
    if (hlen == 0 || digest_len != hlen) return false;

    uint8_t raw_em[512];
    size_t  k = 0, mod_bits = 0;
    if (!rsa_public_op(mod, mod_len, exp, exp_len, sig, sig_len, raw_em, &k, &mod_bits))
        return false;

    size_t em_bits = mod_bits - 1;
    size_t em_len  = (em_bits + 7) / 8;
    if (em_len < k) {
        for (size_t i = 0; i < k - em_len; i++) {
            if (raw_em[i] != 0) return false;
        }
    }
    uint8_t *em = raw_em + (k - em_len);
    if (em_len < hlen + 2) return false;
    if (em[em_len - 1] != 0xBCU) return false;

    size_t top_zero_bits = 8 * em_len - em_bits;
    uint8_t top_mask = (uint8_t)(0xFFU >> top_zero_bits);
    if ((em[0] & ~top_mask) != 0) return false;

    size_t db_len = em_len - hlen - 1;
    const uint8_t *H = em + db_len;
    mgf1_xor(alg, H, hlen, em, db_len);
    em[0] &= top_mask;

    size_t salt_off = 0;
    if (expected_salt_len >= 0) {
        size_t slen = (size_t)expected_salt_len;
        if (em_len < hlen + slen + 2) return false;
        size_t zero_cnt = db_len - slen - 1;
        for (size_t i = 0; i < zero_cnt; i++) {
            if (em[i] != 0x00U) return false;
        }
        if (em[zero_cnt] != 0x01U) return false;
        salt_off = zero_cnt + 1;
    } else {
        size_t i = 0;
        while (i < db_len && em[i] == 0x00U) i++;
        if (i >= db_len || em[i] != 0x01U) return false;
        salt_off = i + 1;
    }
    size_t salt_len = db_len - salt_off;

    uint8_t m_prime[8 + 64 + 512];
    if (salt_len > 512) return false;
    memset(m_prime, 0, 8);
    memcpy(m_prime + 8, digest, hlen);
    if (salt_len > 0) memcpy(m_prime + 8 + hlen, em + salt_off, salt_len);

    uint8_t h_prime[64];
    hash_compute(alg, m_prime, 8 + hlen + salt_len, h_prime);
    return tb_crypto_ct_memcmp(H, h_prime, hlen) == 0;
}

/* ============================================================================
 * NIST P-256 & P-384 Weierstrass Jacobian Arithmetic (ECDSA & P-256 ECDHE)
 * ============================================================================ */

typedef struct {
    size_t   limbs;      /* 4 for P-256, 6 for P-384 */
    size_t   coord_len;  /* 32 for P-256, 48 for P-384 */
    uint64_t p[6];
    uint64_t n[6];
    uint64_t b[6];
    uint64_t gx[6];
    uint64_t gy[6];
    uint64_t p_n0;
    uint64_t n_n0;
} EcCurve;

static const EcCurve CURVE_P256 = {
    .limbs = 4,
    .coord_len = 32,
    .p  = { 0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
            0x0000000000000000ULL, 0xFFFFFFFF00000001ULL, 0, 0 },
    .n  = { 0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL,
            0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL, 0, 0 },
    .b  = { 0x3BCE3C3E27D2604BULL, 0x651D06B0CC53B0F6ULL,
            0xB3EBBD55769886BCULL, 0x5AC635D8AA3A93E7ULL, 0, 0 },
    .gx = { 0xF4A13945D898C296ULL, 0x77037D812DEB33A0ULL,
            0xF8BCE6E563A440F2ULL, 0x6B17D1F2E12C4247ULL, 0, 0 },
    .gy = { 0xCBB6406837BF51F5ULL, 0x2BCE33576B315ECEULL,
            0x8EE7EB4A7C0F9E16ULL, 0x4FE342E2FE1A7F9BULL, 0, 0 },
    .p_n0 = 0x0000000000000001ULL, /* -(-1)^(-1) mod 2^64 = 1 */
    .n_n0 = 0xCCD1C8AAEE00BC4FULL
};

static const EcCurve CURVE_P384 = {
    .limbs = 6,
    .coord_len = 48,
    .p  = { 0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL,
            0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL,
            0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL },
    .n  = { 0xECEC196ACCC52973ULL, 0x581A0DB248B0A77AULL,
            0xC7634D81F4372DDFULL, 0xFFFFFFFFFFFFFFFFULL,
            0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL },
    .b  = { 0x2A85C8EDD3EC2AEFULL, 0xC656398D8A2ED19DULL,
            0x0314088F5013875AULL, 0x181D9C6EFE814112ULL,
            0x988E056BE3F82D19ULL, 0xB3312FA7E23EE7E4ULL },
    .gx = { 0x3A545E3872760AB7ULL, 0x5502F25DBF55296CULL,
            0x59F741E082542A38ULL, 0x6E1D3B628BA79B98ULL,
            0x8EB1C71EF320AD74ULL, 0xAA87CA22BE8B0537ULL },
    .gy = { 0x7A431D7C90EA0E5FULL, 0x0A60B1CE1D7E819DULL,
            0xE9DA3113B5F0B8C0ULL, 0xF8F41DBD289A147CULL,
            0x5D9E98BF9292DC29ULL, 0x3617DE4A96262C6FULL },
    .p_n0 = 0x0000000100000001ULL,
    .n_n0 = 0x6888EEC531C06D8DULL
};

typedef struct {
    uint64_t X[6];
    uint64_t Y[6];
    uint64_t Z[6]; /* All Montgomery-domain mod p; Z == 0 => point at infinity */
} EcJacPt;

static void ec_mod_exp(uint64_t *out_mont, const uint64_t *a_mont,
                       const uint64_t *exp_sub2, const uint64_t *mod,
                       size_t k, uint64_t n0, const uint64_t *one_mont) {
    uint64_t acc[6];
    memcpy(acc, one_mont, k * sizeof(uint64_t));
    bool started = false;
    for (size_t li = k; li > 0; li--) {
        uint64_t w = exp_sub2[li - 1];
        for (int bit = 63; bit >= 0; bit--) {
            int b = (int)((w >> bit) & 1ULL);
            if (!started) {
                if (b) {
                    memcpy(acc, a_mont, k * sizeof(uint64_t));
                    started = true;
                }
                continue;
            }
            mont_mul(acc, acc, acc, mod, k, n0);
            if (b) mont_mul(acc, acc, a_mont, mod, k, n0);
        }
    }
    memcpy(out_mont, acc, k * sizeof(uint64_t));
}

static bool ec_load_VerifyOnCurve(const EcCurve *cv, const uint8_t *xy,
                                  const uint64_t *rr_p, EcJacPt *out_pt) {
    size_t k = cv->limbs;
    uint64_t x[6], y[6];
    big_from_be(x, k, xy, cv->coord_len);
    big_from_be(y, k, xy + cv->coord_len, cv->coord_len);
    if (big_cmp(x, cv->p, k) >= 0 || big_cmp(y, cv->p, k) >= 0) return false;

    uint64_t n0 = mont_n0_inv(cv->p[0]);
    uint64_t xm[6], ym[6], bm[6], lhs[6], rhs[6], t[6];
    mont_mul(xm, x, rr_p, cv->p, k, n0);
    mont_mul(ym, y, rr_p, cv->p, k, n0);
    mont_mul(bm, cv->b, rr_p, cv->p, k, n0);

    /* Check y^2 == x^3 - 3*x + b (mod p) */
    mont_mul(lhs, ym, ym, cv->p, k, n0);
    mont_mul(t, xm, xm, cv->p, k, n0);
    mont_mul(rhs, t, xm, cv->p, k, n0);
    big_mod_sub(rhs, rhs, xm, cv->p, k);
    big_mod_sub(rhs, rhs, xm, cv->p, k);
    big_mod_sub(rhs, rhs, xm, cv->p, k);
    big_mod_add(rhs, rhs, bm, cv->p, k);
    if (big_cmp(lhs, rhs, k) != 0) return false;

    uint64_t one[6] = { 1ULL };
    memcpy(out_pt->X, xm, k * sizeof(uint64_t));
    memcpy(out_pt->Y, ym, k * sizeof(uint64_t));
    mont_mul(out_pt->Z, one, rr_p, cv->p, k, n0);
    return true;
}

static void ec_double(const EcCurve *cv, uint64_t p_n0, EcJacPt *R, const EcJacPt *P) {
    size_t k = cv->limbs;
    if (big_is_zero(P->Z, k) || big_is_zero(P->Y, k)) {
        memset(R, 0, sizeof(*R));
        return;
    }
    const uint64_t *p = cv->p;
    uint64_t delta[6], gamma[6], beta[6], alpha[6], t1[6], t2[6];
    uint64_t X3[6], Y3[6], Z3[6];

    mont_mul(delta, P->Z, P->Z, p, k, p_n0);
    mont_mul(gamma, P->Y, P->Y, p, k, p_n0);
    mont_mul(beta, P->X, gamma, p, k, p_n0);

    big_mod_sub(t1, P->X, delta, p, k);
    big_mod_add(t2, P->X, delta, p, k);
    mont_mul(alpha, t1, t2, p, k, p_n0);
    big_mod_add(t1, alpha, alpha, p, k);
    big_mod_add(alpha, t1, alpha, p, k); /* alpha = 3*(X - Z^2)*(X + Z^2) */

    mont_mul(X3, alpha, alpha, p, k, p_n0);
    big_mod_add(t1, beta, beta, p, k);   /* 2*beta */
    big_mod_add(t1, t1, t1, p, k);       /* 4*beta */
    big_mod_add(t2, t1, t1, p, k);       /* 8*beta */
    big_mod_sub(X3, X3, t2, p, k);       /* X3 = alpha^2 - 8*beta */

    big_mod_add(Z3, P->Y, P->Z, p, k);
    mont_mul(Z3, Z3, Z3, p, k, p_n0);
    big_mod_sub(Z3, Z3, gamma, p, k);
    big_mod_sub(Z3, Z3, delta, p, k);    /* Z3 = (Y + Z)^2 - gamma - delta */

    big_mod_sub(t1, t1, X3, p, k);       /* 4*beta - X3 */
    mont_mul(Y3, alpha, t1, p, k, p_n0);
    mont_mul(t2, gamma, gamma, p, k, p_n0);
    big_mod_add(t2, t2, t2, p, k);
    big_mod_add(t2, t2, t2, p, k);
    big_mod_add(t2, t2, t2, p, k);       /* 8*gamma^2 */
    big_mod_sub(Y3, Y3, t2, p, k);

    memcpy(R->X, X3, k * sizeof(uint64_t));
    memcpy(R->Y, Y3, k * sizeof(uint64_t));
    memcpy(R->Z, Z3, k * sizeof(uint64_t));
}

static void ec_add(const EcCurve *cv, uint64_t p_n0, EcJacPt *R,
                   const EcJacPt *P, const EcJacPt *Q) {
    size_t k = cv->limbs;
    if (big_is_zero(P->Z, k)) { *R = *Q; return; }
    if (big_is_zero(Q->Z, k)) { *R = *P; return; }

    const uint64_t *p = cv->p;
    uint64_t Z1Z1[6], Z2Z2[6], U1[6], U2[6], S1[6], S2[6], t[6];
    mont_mul(Z1Z1, P->Z, P->Z, p, k, p_n0);
    mont_mul(Z2Z2, Q->Z, Q->Z, p, k, p_n0);
    mont_mul(U1, P->X, Z2Z2, p, k, p_n0);
    mont_mul(U2, Q->X, Z1Z1, p, k, p_n0);

    mont_mul(t, Q->Z, Z2Z2, p, k, p_n0);
    mont_mul(S1, P->Y, t, p, k, p_n0);
    mont_mul(t, P->Z, Z1Z1, p, k, p_n0);
    mont_mul(S2, Q->Y, t, p, k, p_n0);

    if (big_cmp(U1, U2, k) == 0) {
        if (big_cmp(S1, S2, k) == 0) {
            ec_double(cv, p_n0, R, P);
        } else {
            memset(R, 0, sizeof(*R));
        }
        return;
    }

    uint64_t H[6], I[6], J[6], r[6], V[6], X3[6], Y3[6], Z3[6];
    big_mod_sub(H, U2, U1, p, k);
    big_mod_add(I, H, H, p, k);
    mont_mul(I, I, I, p, k, p_n0);       /* I = (2*H)^2 */
    mont_mul(J, H, I, p, k, p_n0);       /* J = H*I */
    big_mod_sub(r, S2, S1, p, k);
    big_mod_add(r, r, r, p, k);          /* r = 2*(S2 - S1) */
    mont_mul(V, U1, I, p, k, p_n0);      /* V = U1*I */

    mont_mul(X3, r, r, p, k, p_n0);
    big_mod_sub(X3, X3, J, p, k);
    big_mod_sub(X3, X3, V, p, k);
    big_mod_sub(X3, X3, V, p, k);        /* X3 = r^2 - J - 2*V */

    big_mod_sub(t, V, X3, p, k);
    mont_mul(Y3, r, t, p, k, p_n0);
    mont_mul(t, S1, J, p, k, p_n0);
    big_mod_add(t, t, t, p, k);
    big_mod_sub(Y3, Y3, t, p, k);        /* Y3 = r*(V - X3) - 2*S1*J */

    big_mod_add(Z3, P->Z, Q->Z, p, k);
    mont_mul(Z3, Z3, Z3, p, k, p_n0);
    big_mod_sub(Z3, Z3, Z1Z1, p, k);
    big_mod_sub(Z3, Z3, Z2Z2, p, k);
    mont_mul(Z3, Z3, H, p, k, p_n0);

    memcpy(R->X, X3, k * sizeof(uint64_t));
    memcpy(R->Y, Y3, k * sizeof(uint64_t));
    memcpy(R->Z, Z3, k * sizeof(uint64_t));
}

static void ec_scalar_mul(const EcCurve *cv, uint64_t p_n0, EcJacPt *R,
                          const EcJacPt *P, const uint64_t *scalar) {
    size_t k = cv->limbs;
    EcJacPt acc;
    memset(&acc, 0, sizeof(acc));
    for (size_t li = k; li > 0; li--) {
        uint64_t w = scalar[li - 1];
        for (int bit = 63; bit >= 0; bit--) {
            ec_double(cv, p_n0, &acc, &acc);
            if ((w >> bit) & 1ULL) {
                ec_add(cv, p_n0, &acc, &acc, P);
            }
        }
    }
    *R = acc;
}

static bool ec_to_affine(const EcCurve *cv, uint64_t p_n0, const uint64_t *one_mont,
                         const EcJacPt *P, uint64_t *ax_out, uint64_t *ay_out) {
    size_t k = cv->limbs;
    if (big_is_zero(P->Z, k)) return false;

    uint64_t two[6] = { 2ULL };
    uint64_t p_minus_2[6];
    big_sub(p_minus_2, cv->p, two, k);

    uint64_t z_inv[6], z_inv2[6], z_inv3[6], xm[6], ym[6];
    ec_mod_exp(z_inv, P->Z, p_minus_2, cv->p, k, p_n0, one_mont);
    mont_mul(z_inv2, z_inv, z_inv, cv->p, k, p_n0);
    mont_mul(z_inv3, z_inv2, z_inv, cv->p, k, p_n0);
    mont_mul(xm, P->X, z_inv2, cv->p, k, p_n0);
    mont_mul(ym, P->Y, z_inv3, cv->p, k, p_n0);

    if (ax_out) mont_from(ax_out, xm, cv->p, k, p_n0);
    if (ay_out) mont_from(ay_out, ym, cv->p, k, p_n0);
    return true;
}

static bool ecdsa_verify_curve(const EcCurve *cv, const uint8_t *pub_xy,
                               const uint8_t *digest, size_t digest_len,
                               const uint8_t *sig_r, const uint8_t *sig_s) {
    size_t   k    = cv->limbs;
    uint64_t p_n0 = mont_n0_inv(cv->p[0]);
    uint64_t n_n0 = mont_n0_inv(cv->n[0]);

    uint64_t r[6], s[6];
    big_from_be(r, k, sig_r, cv->coord_len);
    big_from_be(s, k, sig_s, cv->coord_len);
    if (big_is_zero(r, k) || big_cmp(r, cv->n, k) >= 0) return false;
    if (big_is_zero(s, k) || big_cmp(s, cv->n, k) >= 0) return false;

    uint64_t rr_p[6], rr_n[6];
    mont_compute_rr(rr_p, cv->p, k);
    mont_compute_rr(rr_n, cv->n, k);

    EcJacPt Q, G;
    if (!ec_load_VerifyOnCurve(cv, pub_xy, rr_p, &Q)) return false;

    uint64_t one[6] = { 1ULL };
    uint64_t one_p[6], one_n[6];
    mont_mul(one_p, one, rr_p, cv->p, k, p_n0);
    mont_mul(one_n, one, rr_n, cv->n, k, n_n0);

    mont_mul(G.X, cv->gx, rr_p, cv->p, k, p_n0);
    mont_mul(G.Y, cv->gy, rr_p, cv->p, k, p_n0);
    memcpy(G.Z, one_p, k * sizeof(uint64_t));

    /* Leftmost bitlen(n) bits of digest (FIPS 186-4 §4.1.4) */
    uint64_t e[6];
    size_t use_len = (digest_len > cv->coord_len) ? cv->coord_len : digest_len;
    big_from_be(e, k, digest, use_len);
    while (big_cmp(e, cv->n, k) >= 0) big_sub(e, e, cv->n, k);

    /* w = s^(-1) mod n = s^(n - 2) mod n */
    uint64_t two[6] = { 2ULL }, n_minus_2[6];
    big_sub(n_minus_2, cv->n, two, k);
    uint64_t sm[6], wm[6], em[6], rm[6], u1m[6], u2m[6], u1[6], u2[6];
    mont_mul(sm, s, rr_n, cv->n, k, n_n0);
    ec_mod_exp(wm, sm, n_minus_2, cv->n, k, n_n0, one_n);

    mont_mul(em, e, rr_n, cv->n, k, n_n0);
    mont_mul(rm, r, rr_n, cv->n, k, n_n0);
    mont_mul(u1m, em, wm, cv->n, k, n_n0);
    mont_mul(u2m, rm, wm, cv->n, k, n_n0);
    mont_from(u1, u1m, cv->n, k, n_n0);
    mont_from(u2, u2m, cv->n, k, n_n0);

    EcJacPt P1, P2, R;
    ec_scalar_mul(cv, p_n0, &P1, &G, u1);
    ec_scalar_mul(cv, p_n0, &P2, &Q, u2);
    ec_add(cv, p_n0, &R, &P1, &P2);

    uint64_t rx[6];
    if (!ec_to_affine(cv, p_n0, one_p, &R, rx, NULL)) return false;
    while (big_cmp(rx, cv->n, k) >= 0) big_sub(rx, rx, cv->n, k);
    return big_cmp(rx, r, k) == 0;
}

bool tb_ecdsa_p256_verify(const uint8_t pub_xy[64],
                          const uint8_t *digest, size_t digest_len,
                          const uint8_t sig_r[32], const uint8_t sig_s[32]) {
    return ecdsa_verify_curve(&CURVE_P256, pub_xy, digest, digest_len, sig_r, sig_s);
}

bool tb_ecdsa_p384_verify(const uint8_t pub_xy[96],
                          const uint8_t *digest, size_t digest_len,
                          const uint8_t sig_r[48], const uint8_t sig_s[48]) {
    return ecdsa_verify_curve(&CURVE_P384, pub_xy, digest, digest_len, sig_r, sig_s);
}

static bool ec_keygen_curve(const EcCurve *cv, uint8_t *priv, uint8_t *pub_uncompressed) {
    size_t k    = cv->limbs;
    size_t clen = cv->coord_len;
    uint64_t d[6];
    for (int tries = 0; tries < 16; tries++) {
        if (!tb_getrandom(priv, clen)) return false;
        big_from_be(d, k, priv, clen);
        if (!big_is_zero(d, k) && big_cmp(d, cv->n, k) < 0) {
            uint64_t p_n0 = mont_n0_inv(cv->p[0]);
            uint64_t rr_p[6], one[6] = { 1ULL }, one_p[6];
            mont_compute_rr(rr_p, cv->p, k);
            mont_mul(one_p, one, rr_p, cv->p, k, p_n0);

            EcJacPt G, Q;
            mont_mul(G.X, cv->gx, rr_p, cv->p, k, p_n0);
            mont_mul(G.Y, cv->gy, rr_p, cv->p, k, p_n0);
            memcpy(G.Z, one_p, k * sizeof(uint64_t));

            ec_scalar_mul(cv, p_n0, &Q, &G, d);
            uint64_t qx[6], qy[6];
            if (!ec_to_affine(cv, p_n0, one_p, &Q, qx, qy)) {
                tb_crypto_wipe(d, sizeof(d));
                return false;
            }
            pub_uncompressed[0] = 0x04U;
            big_to_be(pub_uncompressed + 1,        clen, qx, k);
            big_to_be(pub_uncompressed + 1 + clen, clen, qy, k);
            tb_crypto_wipe(d, sizeof(d));
            return true;
        }
    }
    tb_crypto_wipe(d, sizeof(d));
    return false;
}

static bool ec_ecdh_curve(const EcCurve *cv, uint8_t *shared_x, const uint8_t *priv,
                          const uint8_t *peer_pub, size_t peer_pub_len) {
    size_t k    = cv->limbs;
    size_t clen = cv->coord_len;
    if (!peer_pub || peer_pub_len != 1 + 2 * clen || peer_pub[0] != 0x04U) return false;
    uint64_t d[6];
    big_from_be(d, k, priv, clen);
    if (big_is_zero(d, k) || big_cmp(d, cv->n, k) >= 0) {
        tb_crypto_wipe(d, sizeof(d));
        return false;
    }

    uint64_t p_n0 = mont_n0_inv(cv->p[0]);
    uint64_t rr_p[6], one[6] = { 1ULL }, one_p[6];
    mont_compute_rr(rr_p, cv->p, k);
    mont_mul(one_p, one, rr_p, cv->p, k, p_n0);

    EcJacPt P, S;
    if (!ec_load_VerifyOnCurve(cv, peer_pub + 1, rr_p, &P)) {
        tb_crypto_wipe(d, sizeof(d));
        return false;
    }
    ec_scalar_mul(cv, p_n0, &S, &P, d);
    tb_crypto_wipe(d, sizeof(d));

    uint64_t sx[6];
    if (!ec_to_affine(cv, p_n0, one_p, &S, sx, NULL)) return false;
    big_to_be(shared_x, clen, sx, k);
    tb_crypto_wipe(sx, sizeof(sx));
    return true;
}

bool tb_p256_keygen(uint8_t priv[32], uint8_t pub_uncompressed[65]) {
    return ec_keygen_curve(&CURVE_P256, priv, pub_uncompressed);
}

bool tb_p256_ecdh(uint8_t shared_x[32], const uint8_t priv[32],
                  const uint8_t *peer_pub, size_t peer_pub_len) {
    return ec_ecdh_curve(&CURVE_P256, shared_x, priv, peer_pub, peer_pub_len);
}

bool tb_p384_keygen(uint8_t priv[48], uint8_t pub_uncompressed[97]) {
    return ec_keygen_curve(&CURVE_P384, priv, pub_uncompressed);
}

bool tb_p384_ecdh(uint8_t shared_x[48], const uint8_t priv[48],
                  const uint8_t *peer_pub, size_t peer_pub_len) {
    return ec_ecdh_curve(&CURVE_P384, shared_x, priv, peer_pub, peer_pub_len);
}

bool tb_ec_self_test(void) {
    /* Verify generator G lies on curve and n * G == O for both P-256 and P-384 */
    const EcCurve *curves[2] = { &CURVE_P256, &CURVE_P384 };
    for (int i = 0; i < 2; i++) {
        const EcCurve *cv = curves[i];
        size_t   k    = cv->limbs;
        uint64_t p_n0 = mont_n0_inv(cv->p[0]);
        uint64_t rr_p[6];
        mont_compute_rr(rr_p, cv->p, k);

        uint8_t g_xy[96];
        big_to_be(g_xy, cv->coord_len, cv->gx, k);
        big_to_be(g_xy + cv->coord_len, cv->coord_len, cv->gy, k);

        EcJacPt G, Inf;
        if (!ec_load_VerifyOnCurve(cv, g_xy, rr_p, &G)) return false;
        ec_scalar_mul(cv, p_n0, &Inf, &G, cv->n);
        if (!big_is_zero(Inf.Z, k)) return false;
    }
    return true;
}
