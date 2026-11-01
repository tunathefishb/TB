#include "tls.h"

/* ============================================================================
 * X25519 Elliptic Curve Diffie-Hellman (RFC 7748, 5x51-bit GF(2^255 - 19))
 * ============================================================================ */

#define FE51_MASK 0x0007FFFFFFFFFFFFULL

typedef struct {
    uint64_t v[5];
} Fe25519;

static void fe25519_load(Fe25519 *o, const uint8_t in[32]) {
    o->v[0] =  tb_load64_le(in +  0)        & FE51_MASK;
    o->v[1] = (tb_load64_le(in +  6) >>  3) & FE51_MASK;
    o->v[2] = (tb_load64_le(in + 12) >>  6) & FE51_MASK;
    o->v[3] = (tb_load64_le(in + 19) >>  1) & FE51_MASK;
    o->v[4] = ((tb_load64_le(in + 24) & 0x7FFFFFFFFFFFFFFFULL) >> 12) & FE51_MASK;
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

    tb_store64_le(out +  0,  t0        | (t1 << 51));
    tb_store64_le(out +  8, (t1 >> 13) | (t2 << 38));
    tb_store64_le(out + 16, (t2 >> 26) | (t3 << 25));
    tb_store64_le(out + 24, (t3 >> 39) | (t4 << 12));
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
        tb_store32_be(in + seed_len, ctr++);
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
