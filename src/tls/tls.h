#ifndef TB_TLS_H
#define TB_TLS_H

#include "common.h"

/* ============================================================================
 * Public TLS 1.3 Connection API
 * ============================================================================ */

typedef struct TbTlsConn TbTlsConn;

void        tb_tls_set_ca_file(const char *pem_path);
const char *tb_tls_get_ca_file(void);

TbTlsConn  *tb_tls_connect(int fd, const char *host, bool insecure,
                           int timeout_ms, char *err_buf, size_t err_cap);
ssize_t     tb_tls_read(TbTlsConn *c, void *buf, size_t len, int timeout_ms);
bool        tb_tls_write(TbTlsConn *c, const void *buf, size_t len, int timeout_ms);
void        tb_tls_close(TbTlsConn *c);

/* ============================================================================
 * Cryptographic Primitives (tls_crypto.c)
 * ============================================================================ */

void tb_crypto_wipe(void *p, size_t n);
int  tb_crypto_ct_memcmp(const void *a, const void *b, size_t n);

/* SHA-1 (used strictly for OpenSSL /etc/ssl/certs/<hash>.0 lookup) */
typedef struct {
    uint32_t h[5];
    uint64_t total_bytes;
    uint8_t  buf[64];
    size_t   buf_len;
} TbSha1Ctx;

void tb_sha1_init(TbSha1Ctx *ctx);
void tb_sha1_update(TbSha1Ctx *ctx, const void *data, size_t len);
void tb_sha1_final(TbSha1Ctx *ctx, uint8_t out[20]);
void tb_sha1(const void *data, size_t len, uint8_t out[20]);

/* SHA-256 */
typedef struct {
    uint32_t h[8];
    uint64_t total_bytes;
    uint8_t  buf[64];
    size_t   buf_len;
} TbSha256Ctx;

void tb_sha256_init(TbSha256Ctx *ctx);
void tb_sha256_update(TbSha256Ctx *ctx, const void *data, size_t len);
void tb_sha256_final(TbSha256Ctx *ctx, uint8_t out[32]);
void tb_sha256(const void *data, size_t len, uint8_t out[32]);

/* SHA-384 & SHA-512 */
typedef struct {
    uint64_t h[8];
    uint64_t total_lo;
    uint64_t total_hi;
    uint8_t  buf[128];
    size_t   buf_len;
} TbSha512Ctx;

void tb_sha384_init(TbSha512Ctx *ctx);
void tb_sha512_init(TbSha512Ctx *ctx);
void tb_sha512_update(TbSha512Ctx *ctx, const void *data, size_t len);
void tb_sha384_final(TbSha512Ctx *ctx, uint8_t out[48]);
void tb_sha512_final(TbSha512Ctx *ctx, uint8_t out[64]);
void tb_sha384(const void *data, size_t len, uint8_t out[48]);
void tb_sha512(const void *data, size_t len, uint8_t out[64]);

typedef enum {
    TB_HASH_SHA256 = 1,
    TB_HASH_SHA384 = 2,
    TB_HASH_SHA512 = 3
} TbHashAlg;

/* HMAC & TLS 1.3 HKDF (hash_len = 32 for SHA-256, 48 for SHA-384) */
void tb_hmac(size_t hash_len, const uint8_t *key, size_t key_len,
             const uint8_t *data, size_t data_len, uint8_t *out);
void tb_hkdf_extract(size_t hash_len, const uint8_t *salt, size_t salt_len,
                     const uint8_t *ikm, size_t ikm_len, uint8_t *prk_out);
void tb_hkdf_expand(size_t hash_len, const uint8_t *prk,
                    const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len);
void tb_tls13_hkdf_expand_label(size_t hash_len, const uint8_t *secret,
                                const char *label,
                                const uint8_t *context, size_t context_len,
                                uint8_t *out, size_t out_len);

/* AEAD: ChaCha20-Poly1305 (RFC 8439) & AES-128/256-GCM (NIST SP 800-38D) */
void tb_chacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *pt, size_t pt_len,
                               uint8_t *ct, uint8_t tag[16]);
bool tb_chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t tag[16], uint8_t *pt);

void tb_aes_gcm_seal(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t pt_len,
                     uint8_t *ct, uint8_t tag[16]);
bool tb_aes_gcm_open(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len,
                     const uint8_t tag[16], uint8_t *pt);

/* Key Exchange: X25519 (RFC 7748) & ECDHE P-256 / P-384 */
void tb_x25519_base(uint8_t pub[32], const uint8_t priv[32]);
bool tb_x25519(uint8_t shared[32], const uint8_t priv[32], const uint8_t peer_pub[32]);

bool tb_p256_keygen(uint8_t priv[32], uint8_t pub_uncompressed[65]);
bool tb_p256_ecdh(uint8_t shared_x[32], const uint8_t priv[32],
                  const uint8_t *peer_pub, size_t peer_pub_len);
bool tb_p384_keygen(uint8_t priv[48], uint8_t pub_uncompressed[97]);
bool tb_p384_ecdh(uint8_t shared_x[48], const uint8_t priv[48],
                  const uint8_t *peer_pub, size_t peer_pub_len);

/* Public-Key Signature Verification: RSA (PKCS#1 v1.5 & PSS) + ECDSA (P-256 & P-384) */
bool tb_rsa_verify_pkcs1(const uint8_t *mod, size_t mod_len,
                         const uint8_t *exp, size_t exp_len,
                         TbHashAlg alg, const uint8_t *digest, size_t digest_len,
                         const uint8_t *sig, size_t sig_len);
bool tb_rsa_verify_pss(const uint8_t *mod, size_t mod_len,
                       const uint8_t *exp, size_t exp_len,
                       TbHashAlg alg, const uint8_t *digest, size_t digest_len,
                       int expected_salt_len,
                       const uint8_t *sig, size_t sig_len);

bool tb_ecdsa_p256_verify(const uint8_t pub_xy[64],
                          const uint8_t *digest, size_t digest_len,
                          const uint8_t sig_r[32], const uint8_t sig_s[32]);
bool tb_ecdsa_p384_verify(const uint8_t pub_xy[96],
                          const uint8_t *digest, size_t digest_len,
                          const uint8_t sig_r[48], const uint8_t sig_s[48]);
bool tb_ec_self_test(void);

/* ============================================================================
 * X.509 DER/PEM Parsing & Chain Verification (tls_x509.c)
 * ============================================================================ */

typedef enum {
    TB_PUBKEY_NONE = 0,
    TB_PUBKEY_RSA,
    TB_PUBKEY_EC_P256,
    TB_PUBKEY_EC_P384
} TbX509PubKeyType;

typedef enum {
    TB_SIG_NONE = 0,
    TB_SIG_RSA_PKCS1_SHA256,
    TB_SIG_RSA_PKCS1_SHA384,
    TB_SIG_RSA_PKCS1_SHA512,
    TB_SIG_RSA_PSS_SHA256,
    TB_SIG_RSA_PSS_SHA384,
    TB_SIG_RSA_PSS_SHA512,
    TB_SIG_ECDSA_SHA256,
    TB_SIG_ECDSA_SHA384,
    TB_SIG_ECDSA_SHA512
} TbX509SigAlg;

typedef struct {
    const uint8_t   *tbs_der;
    size_t           tbs_len;
    const uint8_t   *issuer_der;
    size_t           issuer_len;
    const uint8_t   *subject_der;
    size_t           subject_len;
    const char      *cn_ptr;
    size_t           cn_len;
    const uint8_t   *san_der;
    size_t           san_len;
    const uint8_t   *ski_ptr;
    size_t           ski_len;
    const uint8_t   *aki_ptr;
    size_t           aki_len;

    int64_t          not_before;
    int64_t          not_after;
    int              version; /* 1, 2, or 3 */

    bool             has_basic_constraints;
    bool             is_ca;
    bool             has_path_len;
    int              path_len;

    bool             has_key_usage;
    uint16_t         key_usage;

    bool             has_eku;
    bool             eku_server_auth;

    TbX509PubKeyType pubkey_type;
    const uint8_t   *rsa_n;
    size_t           rsa_n_len;
    const uint8_t   *rsa_e;
    size_t           rsa_e_len;
    uint8_t          ec_xy[96]; /* 64 bytes for P-256, 96 bytes for P-384 */

    TbX509SigAlg     sig_alg;
    int              pss_salt_len; /* -1 if unspecified / default */
    const uint8_t   *sig_bytes;
    size_t           sig_len;
} TbX509Cert;

bool     tb_x509_parse_der(const uint8_t *der, size_t der_len, TbX509Cert *out,
                           char *err, size_t err_cap);
bool     tb_x509_wildcard_match(const char *pattern, size_t pat_len,
                                const char *host, size_t host_len);
bool     tb_x509_match_hostname(const TbX509Cert *cert, const char *host);
bool     tb_x509_verify_cert_sig(const TbX509Cert *child, const TbX509Cert *issuer);
uint32_t tb_x509_subject_hash_openssl(const uint8_t *name_der, size_t name_len);
bool     tb_x509_verify_chain(const uint8_t *const *cert_ders, const size_t *cert_lens,
                              size_t cert_count, const char *host, int64_t now_unix,
                              const char *ca_file_override, char *err, size_t err_cap);
bool     tb_x509_verify_tls13_sig(const TbX509Cert *leaf, uint16_t sig_scheme,
                                  const uint8_t *transcript_hash, size_t th_len,
                                  const uint8_t *sig, size_t sig_len);

#endif /* TB_TLS_H */
