#include "tls.h"

/* ============================================================================
 * RFC 8446 TLS 1.3 Client Engine
 * ============================================================================ */

#define TLS_MAX_PLAINTEXT   16384U
#define TLS_MAX_CIPHERTEXT  (TLS_MAX_PLAINTEXT + 256U)
#define TLS_MAX_HS_BUF      262144U
#define TLS_MAX_CERTS       16U

/* Cipher suites */
#define TLS_AES_128_GCM_SHA256       0x1301U
#define TLS_AES_256_GCM_SHA384       0x1302U
#define TLS_CHACHA20_POLY1305_SHA256 0x1303U

/* Named groups */
#define TLS_GROUP_SECP256R1 0x0017U
#define TLS_GROUP_SECP384R1 0x0018U
#define TLS_GROUP_X25519    0x001dU

/* Handshake message types */
#define TLS_HS_CLIENT_HELLO         1U
#define TLS_HS_SERVER_HELLO         2U
#define TLS_HS_NEW_SESSION_TICKET   4U
#define TLS_HS_ENCRYPTED_EXTENSIONS 8U
#define TLS_HS_CERTIFICATE          11U
#define TLS_HS_CERTIFICATE_REQUEST  13U
#define TLS_HS_CERTIFICATE_VERIFY   15U
#define TLS_HS_FINISHED             20U
#define TLS_HS_KEY_UPDATE           24U
#define TLS_HS_MESSAGE_HASH         254U

/* RFC 8446 §4.1.3 magic ServerHello.random for HelloRetryRequest */
static const uint8_t TLS_HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

static char g_tls_ca_file[PATH_MAX];

void tb_tls_set_ca_file(const char *pem_path) {
    if (!pem_path || !*pem_path) {
        g_tls_ca_file[0] = '\0';
        return;
    }
    snprintf(g_tls_ca_file, sizeof(g_tls_ca_file), "%s", pem_path);
}

const char *tb_tls_get_ca_file(void) {
    return g_tls_ca_file[0] ? g_tls_ca_file : NULL;
}

struct TbTlsConn {
    int      fd;
    uint16_t cipher_suite;
    size_t   hash_len;
    size_t   key_len;
    bool     is_chacha;
    bool     app_ready;
    bool     eof;
    bool     fatal;

    uint8_t  read_secret[48];
    uint8_t  read_key[32];
    uint8_t  read_iv[12];
    uint64_t read_seq;

    uint8_t  write_secret[48];
    uint8_t  write_key[32];
    uint8_t  write_iv[12];
    uint64_t write_seq;

    /* Single reusable record / decrypted plaintext buffer */
    uint8_t *rec_buf;
    size_t   app_off;
    size_t   app_len;

    /* Post-handshake message reassembly buffer (only allocated if fragmented) */
    TbBuf    ph_buf;
};

static void tls_err(char *buf, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void tls_err(char *buf, size_t cap, const char *fmt, ...) {
    if (!buf || cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
}

/* ============================================================================
 * Poll-Bounded Socket I/O
 * ============================================================================ */

static int64_t tls_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000LL + (int64_t)(ts.tv_nsec / 1000000LL);
}

static ssize_t tls_raw_read_exact(int fd, uint8_t *buf, size_t len, int timeout_ms) {
    size_t  got      = 0;
    int64_t deadline = (timeout_ms > 0) ? (tls_now_ms() + timeout_ms) : 0;

    while (got < len) {
        if (timeout_ms > 0) {
            int64_t rem = deadline - tls_now_ms();
            if (rem <= 0) {
                errno = ETIMEDOUT;
                return -1;
            }
            struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
            int prc = poll(&pfd, 1, (int)rem);
            if (prc < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (prc == 0) {
                errno = ETIMEDOUT;
                return -1;
            }
        }
        ssize_t r = recv(fd, buf + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        if (r == 0) {
            return (got == 0) ? 0 : -1;
        }
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static bool tls_raw_write_all(int fd, const uint8_t *buf, size_t len, int timeout_ms) {
    size_t  sent     = 0;
    int64_t deadline = (timeout_ms > 0) ? (tls_now_ms() + timeout_ms) : 0;

    while (sent < len) {
        if (timeout_ms > 0) {
            int64_t rem = deadline - tls_now_ms();
            if (rem <= 0) {
                errno = ETIMEDOUT;
                return false;
            }
            struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
            int prc = poll(&pfd, 1, (int)rem);
            if (prc < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (prc == 0) {
                errno = ETIMEDOUT;
                return false;
            }
        }
        ssize_t w = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return false;
        }
        if (w == 0) return false;
        sent += (size_t)w;
    }
    return true;
}

/* ============================================================================
 * Dual SHA-256 / SHA-384 Transcript Hash
 * ============================================================================ */

typedef struct {
    TbSha256Ctx sha256;
    TbSha512Ctx sha384;
} TlsTranscript;

static void th_init(TlsTranscript *th) {
    tb_sha256_init(&th->sha256);
    tb_sha384_init(&th->sha384);
}

static void th_update(TlsTranscript *th, const uint8_t *data, size_t len) {
    tb_sha256_update(&th->sha256, data, len);
    tb_sha512_update(&th->sha384, data, len);
}

static void th_snapshot(const TlsTranscript *th, size_t hash_len, uint8_t out[48]) {
    if (hash_len == 48) {
        TbSha512Ctx tmp = th->sha384;
        tb_sha384_final(&tmp, out);
        tb_crypto_wipe(&tmp, sizeof(tmp));
    } else {
        TbSha256Ctx tmp = th->sha256;
        tb_sha256_final(&tmp, out);
        tb_crypto_wipe(&tmp, sizeof(tmp));
    }
}

/* RFC 8446 §4.4.1 synthetic message_hash replacement for HelloRetryRequest */
static void th_replace_with_message_hash(TlsTranscript *th, size_t hash_len) {
    uint8_t ch1_hash[48];
    th_snapshot(th, hash_len, ch1_hash);

    uint8_t synth[4 + 48];
    synth[0] = (uint8_t)TLS_HS_MESSAGE_HASH;
    synth[1] = 0;
    synth[2] = 0;
    synth[3] = (uint8_t)hash_len;
    memcpy(synth + 4, ch1_hash, hash_len);

    th_init(th);
    th_update(th, synth, 4 + hash_len);
    tb_crypto_wipe(ch1_hash, sizeof(ch1_hash));
    tb_crypto_wipe(synth, sizeof(synth));
}

/* ============================================================================
 * Traffic Key Derivation & Record AEAD Encryption/Decryption
 * ============================================================================ */

static void tls_derive_traffic_keys(size_t hash_len, size_t key_len,
                                    const uint8_t *secret,
                                    uint8_t key_out[32], uint8_t iv_out[12]) {
    tb_tls13_hkdf_expand_label(hash_len, secret, "key", NULL, 0, key_out, key_len);
    tb_tls13_hkdf_expand_label(hash_len, secret, "iv",  NULL, 0, iv_out,  12);
}

static void tls_build_nonce(const uint8_t iv[12], uint64_t seq, uint8_t nonce[12]) {
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[11 - i] ^= (uint8_t)(seq >> (i * 8));
    }
}

static bool tls_encrypt_and_send(TbTlsConn *c, uint8_t inner_type,
                                 const uint8_t *pt, size_t pt_len, int timeout_ms) {
    if (pt_len > TLS_MAX_PLAINTEXT) return false;

    uint8_t stack_buf[5 + 2048 + 1 + 16];
    size_t  enc_len   = pt_len + 1 + 16;
    size_t  total_len = 5 + enc_len;
    uint8_t *wire     = (total_len <= sizeof(stack_buf))
                            ? stack_buf
                            : (uint8_t *)tb_malloc(total_len);
    if (!wire) return false;

    wire[0] = 0x17; /* application_data outer wrapper */
    wire[1] = 0x03;
    wire[2] = 0x03;
    wire[3] = (uint8_t)(enc_len >> 8);
    wire[4] = (uint8_t)enc_len;

    if (pt_len > 0) memcpy(wire + 5, pt, pt_len);
    wire[5 + pt_len] = inner_type;

    uint8_t nonce[12];
    tls_build_nonce(c->write_iv, c->write_seq++, nonce);

    uint8_t *tag = wire + 5 + pt_len + 1;
    if (c->is_chacha) {
        tb_chacha20_poly1305_seal(c->write_key, nonce, wire, 5,
                                  wire + 5, pt_len + 1, wire + 5, tag);
    } else {
        tb_aes_gcm_seal(c->write_key, c->key_len, nonce, wire, 5,
                        wire + 5, pt_len + 1, wire + 5, tag);
    }
    tb_crypto_wipe(nonce, sizeof(nonce));

    bool ok = tls_raw_write_all(c->fd, wire, total_len, timeout_ms);
    if (wire != stack_buf) tb_free(wire);
    return ok;
}

/* Reads one TLS outer record into c->rec_buf (capacity TLS_MAX_CIPHERTEXT).
 * Returns record length (>= 0) on success, -2 on clean socket EOF before header, -1 on error. */
static ssize_t tls_read_outer_record(TbTlsConn *c, uint8_t hdr_out[5], int timeout_ms) {
    ssize_t hr = tls_raw_read_exact(c->fd, hdr_out, 5, timeout_ms);
    if (hr == 0) return -2;
    if (hr < 0)  return -1;

    size_t rlen = ((size_t)hdr_out[3] << 8) | hdr_out[4];
    if (rlen > TLS_MAX_CIPHERTEXT) return -1;
    if (rlen > 0) {
        if (tls_raw_read_exact(c->fd, c->rec_buf, rlen, timeout_ms) != (ssize_t)rlen) {
            return -1;
        }
    }
    return (ssize_t)rlen;
}

/* Decrypts an already-read 0x17 outer record in c->rec_buf in-place. */
static bool tls_decrypt_record_inplace(TbTlsConn *c, const uint8_t hdr[5], size_t rlen,
                                       uint8_t *inner_type_out, size_t *pt_len_out) {
    if (rlen < 17) return false; /* At least 1 byte inner content type + 16 byte AEAD tag */
    size_t ct_len = rlen - 16;
    const uint8_t *tag = c->rec_buf + ct_len;

    uint8_t nonce[12];
    tls_build_nonce(c->read_iv, c->read_seq++, nonce);

    bool ok;
    if (c->is_chacha) {
        ok = tb_chacha20_poly1305_open(c->read_key, nonce, hdr, 5,
                                       c->rec_buf, ct_len, tag, c->rec_buf);
    } else {
        ok = tb_aes_gcm_open(c->read_key, c->key_len, nonce, hdr, 5,
                             c->rec_buf, ct_len, tag, c->rec_buf);
    }
    tb_crypto_wipe(nonce, sizeof(nonce));
    if (!ok) return false;

    /* Strip trailing zero padding and extract inner content type (RFC 8446 §5.4) */
    size_t i = ct_len;
    while (i > 0 && c->rec_buf[i - 1] == 0x00) i--;
    if (i == 0) return false;

    *inner_type_out = c->rec_buf[i - 1];
    *pt_len_out     = i - 1;
    if (*pt_len_out > TLS_MAX_PLAINTEXT) return false;
    return true;
}

/* ============================================================================
 * ClientHello Construction & ServerHello Parsing
 * ============================================================================ */

static bool host_is_ip_literal(const char *host) {
    if (!host || !*host) return true;
    /* Any colon or bracket indicates an IPv6 literal */
    if (strchr(host, ':') || host[0] == '[') return true;

    /* Check if pure IPv4 dotted decimal */
    int dots = 0;
    bool all_num_dot = true;
    for (const char *p = host; *p; p++) {
        if (*p == '.') dots++;
        else if (!tb_isdigit(*p)) { all_num_dot = false; break; }
    }
    if (all_num_dot && dots == 3) return true;
    return false;
}

static void buf_put_u8(TbBuf *b, uint8_t v) {
    tb_buf_append(b, (const char *)&v, 1);
}

static void buf_put_u16(TbBuf *b, uint16_t v) {
    uint8_t tmp[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    tb_buf_append(b, (const char *)tmp, 2);
}

static void buf_put_u24(TbBuf *b, uint32_t v) {
    uint8_t tmp[3] = { (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    tb_buf_append(b, (const char *)tmp, 3);
}

static bool tls_build_client_hello(TbBuf *hs_msg, const char *host,
                                   const uint8_t client_random[32],
                                   const uint8_t session_id[32],
                                   uint16_t only_group,
                                   const uint8_t x25519_pub[32],
                                   const uint8_t p256_pub[65],
                                   const uint8_t p384_pub[97],
                                   const uint8_t *cookie, size_t cookie_len) {
    TbBuf ext;
    tb_buf_init(&ext);

    /* 1. server_name (0x0000) — omitted for IPv4/IPv6 literals per RFC 6066 §3 */
    if (host && *host && !host_is_ip_literal(host)) {
        size_t hlen = strlen(host);
        if (hlen <= 253) {
            buf_put_u16(&ext, 0x0000);
            buf_put_u16(&ext, (uint16_t)(hlen + 5));
            buf_put_u16(&ext, (uint16_t)(hlen + 3));
            buf_put_u8(&ext, 0x00); /* host_name */
            buf_put_u16(&ext, (uint16_t)hlen);
            tb_buf_append(&ext, host, hlen);
        }
    }

    /* 2. application_layer_protocol_negotiation (0x0010) -> "http/1.1" (RFC 7301) */
    buf_put_u16(&ext, 0x0010);
    buf_put_u16(&ext, 11);
    buf_put_u16(&ext, 9);
    buf_put_u8(&ext, 8);
    tb_buf_append(&ext, "http/1.1", 8);

    /* 3. supported_versions (0x002b) -> TLS 1.3 (0x0304) */
    buf_put_u16(&ext, 0x002b);
    buf_put_u16(&ext, 3);
    buf_put_u8(&ext, 2);
    buf_put_u16(&ext, 0x0304);

    /* 4. supported_groups (0x000a) -> x25519 (0x001d), secp256r1 (0x0017), secp384r1 (0x0018) */
    buf_put_u16(&ext, 0x000a);
    buf_put_u16(&ext, 8);
    buf_put_u16(&ext, 6);
    buf_put_u16(&ext, TLS_GROUP_X25519);
    buf_put_u16(&ext, TLS_GROUP_SECP256R1);
    buf_put_u16(&ext, TLS_GROUP_SECP384R1);

    /* 5. signature_algorithms (0x000d) */
    static const uint16_t sig_algs[] = {
        0x0403, /* ecdsa_secp256r1_sha256 */
        0x0503, /* ecdsa_secp384r1_sha384 */
        0x0804, /* rsa_pss_rsae_sha256 */
        0x0805, /* rsa_pss_rsae_sha384 */
        0x0806, /* rsa_pss_rsae_sha512 */
        0x0809, /* rsa_pss_pss_sha256 */
        0x080a, /* rsa_pss_pss_sha384 */
        0x080b, /* rsa_pss_pss_sha512 */
        0x0401, /* rsa_pkcs1_sha256 (for X.509 chain sigs) */
        0x0501, /* rsa_pkcs1_sha384 */
        0x0601  /* rsa_pkcs1_sha512 */
    };
    uint16_t sig_bytes = (uint16_t)(sizeof(sig_algs));
    buf_put_u16(&ext, 0x000d);
    buf_put_u16(&ext, (uint16_t)(2 + sig_bytes));
    buf_put_u16(&ext, sig_bytes);
    for (size_t i = 0; i < sizeof(sig_algs) / sizeof(sig_algs[0]); i++) {
        buf_put_u16(&ext, sig_algs[i]);
    }

    /* 6. cookie (0x002c) — echoed if server sent HelloRetryRequest with cookie */
    if (cookie && cookie_len > 0) {
        buf_put_u16(&ext, 0x002c);
        buf_put_u16(&ext, (uint16_t)(2 + cookie_len));
        buf_put_u16(&ext, (uint16_t)cookie_len);
        tb_buf_append(&ext, (const char *)cookie, cookie_len);
    }

    /* 7. key_share (0x0033) — offer x25519 & P-256 initially, or selected HRR group (inc. P-384) */
    TbBuf ks;
    tb_buf_init(&ks);
    if (only_group == 0 || only_group == TLS_GROUP_X25519) {
        buf_put_u16(&ks, TLS_GROUP_X25519);
        buf_put_u16(&ks, 32);
        tb_buf_append(&ks, (const char *)x25519_pub, 32);
    }
    if (only_group == 0 || only_group == TLS_GROUP_SECP256R1) {
        buf_put_u16(&ks, TLS_GROUP_SECP256R1);
        buf_put_u16(&ks, 65);
        tb_buf_append(&ks, (const char *)p256_pub, 65);
    }
    if (only_group == TLS_GROUP_SECP384R1 && p384_pub) {
        buf_put_u16(&ks, TLS_GROUP_SECP384R1);
        buf_put_u16(&ks, 97);
        tb_buf_append(&ks, (const char *)p384_pub, 97);
    }
    buf_put_u16(&ext, 0x0033);
    buf_put_u16(&ext, (uint16_t)(2 + ks.len));
    buf_put_u16(&ext, (uint16_t)ks.len);
    if (ks.len > 0) tb_buf_append(&ext, ks.data, ks.len);
    tb_buf_free(&ks);

    /* Assemble ClientHello body */
    TbBuf body;
    tb_buf_init(&body);
    buf_put_u16(&body, 0x0303); /* legacy_version = TLS 1.2 */
    tb_buf_append(&body, (const char *)client_random, 32);
    buf_put_u8(&body, 32);
    tb_buf_append(&body, (const char *)session_id, 32);

    /* Cipher suites: AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM */
    buf_put_u16(&body, 6);
    buf_put_u16(&body, TLS_AES_128_GCM_SHA256);
    buf_put_u16(&body, TLS_CHACHA20_POLY1305_SHA256);
    buf_put_u16(&body, TLS_AES_256_GCM_SHA384);

    /* legacy_compression_methods = { 0x00 } */
    buf_put_u8(&body, 1);
    buf_put_u8(&body, 0);

    /* Extensions block */
    buf_put_u16(&body, (uint16_t)ext.len);
    if (ext.len > 0) tb_buf_append(&body, ext.data, ext.len);
    tb_buf_free(&ext);

    /* Wrap in 4-byte Handshake header */
    tb_buf_init(hs_msg);
    buf_put_u8(hs_msg, (uint8_t)TLS_HS_CLIENT_HELLO);
    buf_put_u24(hs_msg, (uint32_t)body.len);
    if (body.len > 0) tb_buf_append(hs_msg, body.data, body.len);
    tb_buf_free(&body);

    return hs_msg->data != NULL;
}

static bool tls_send_plaintext_record(int fd, uint8_t content_type, uint16_t legacy_ver,
                                      const uint8_t *payload, size_t len, int timeout_ms) {
    uint8_t hdr[5] = {
        content_type,
        (uint8_t)(legacy_ver >> 8),
        (uint8_t)legacy_ver,
        (uint8_t)(len >> 8),
        (uint8_t)len
    };
    if (!tls_raw_write_all(fd, hdr, 5, timeout_ms)) return false;
    if (len > 0 && !tls_raw_write_all(fd, payload, len, timeout_ms)) return false;
    return true;
}

typedef struct {
    bool           is_hrr;
    uint16_t       cipher_suite;
    uint16_t       selected_group;
    const uint8_t *peer_key;
    size_t         peer_key_len;
    const uint8_t *cookie;
    size_t         cookie_len;
} ParsedServerHello;

static bool tls_parse_server_hello(const uint8_t *body, size_t len,
                                   const uint8_t expected_sid[32],
                                   ParsedServerHello *out,
                                   char *err, size_t err_cap) {
    memset(out, 0, sizeof(*out));
    if (len < 38) {
        tls_err(err, err_cap, "TLS ServerHello truncated");
        return false;
    }
    uint16_t legacy_ver = ((uint16_t)body[0] << 8) | body[1];
    if (legacy_ver != 0x0303) {
        tls_err(err, err_cap, "TLS ServerHello unsupported legacy version 0x%04x", legacy_ver);
        return false;
    }
    const uint8_t *srv_random = body + 2;
    out->is_hrr = (memcmp(srv_random, TLS_HRR_RANDOM, 32) == 0);

    size_t p = 34;
    uint8_t sid_len = body[p++];
    if (sid_len != 32 || p + sid_len + 3 > len ||
        memcmp(body + p, expected_sid, 32) != 0) {
        tls_err(err, err_cap, "TLS ServerHello session ID mismatch (server may only support TLS 1.2)");
        return false;
    }
    p += sid_len;

    out->cipher_suite = ((uint16_t)body[p] << 8) | body[p + 1];
    p += 2;
    uint8_t comp = body[p++];
    if (comp != 0) {
        tls_err(err, err_cap, "TLS ServerHello invalid compression method");
        return false;
    }

    if (out->cipher_suite != TLS_AES_128_GCM_SHA256 &&
        out->cipher_suite != TLS_CHACHA20_POLY1305_SHA256 &&
        out->cipher_suite != TLS_AES_256_GCM_SHA384) {
        tls_err(err, err_cap, "TLS server selected unsupported cipher suite 0x%04x", out->cipher_suite);
        return false;
    }

    if (p + 2 > len) {
        tls_err(err, err_cap, "TLS ServerHello missing TLS 1.3 extensions");
        return false;
    }
    size_t ext_total = ((size_t)body[p] << 8) | body[p + 1];
    p += 2;
    if (p + ext_total != len) {
        tls_err(err, err_cap, "TLS ServerHello malformed extensions length");
        return false;
    }

    bool got_ver = false;
    bool got_ks  = false;
    while (p < len) {
        if (p + 4 > len) return false;
        uint16_t etype = ((uint16_t)body[p] << 8) | body[p + 1];
        size_t   elen  = ((size_t)body[p + 2] << 8) | body[p + 3];
        p += 4;
        if (p + elen > len) return false;
        const uint8_t *ed = body + p;

        if (etype == 0x002b) { /* supported_versions */
            if (elen != 2 || (((uint16_t)ed[0] << 8) | ed[1]) != 0x0304) {
                tls_err(err, err_cap, "TLS server did not negotiate TLS 1.3");
                return false;
            }
            got_ver = true;
        } else if (etype == 0x0033) { /* key_share */
            if (out->is_hrr) {
                if (elen != 2) return false;
                out->selected_group = ((uint16_t)ed[0] << 8) | ed[1];
                got_ks = true;
            } else {
                if (elen < 4) return false;
                out->selected_group = ((uint16_t)ed[0] << 8) | ed[1];
                size_t klen         = ((size_t)ed[2] << 8) | ed[3];
                if (4 + klen != elen) return false;
                out->peer_key     = ed + 4;
                out->peer_key_len = klen;
                got_ks = true;
            }
        } else if (etype == 0x002c) { /* cookie */
            if (elen < 2) return false;
            size_t clen = ((size_t)ed[0] << 8) | ed[1];
            if (2 + clen != elen) return false;
            out->cookie     = ed + 2;
            out->cookie_len = clen;
        }
        p += elen;
    }

    if (!got_ver) {
        tls_err(err, err_cap, "TLS server negotiated TLS 1.2 instead of TLS 1.3");
        return false;
    }
    if (!out->is_hrr && !got_ks) {
        tls_err(err, err_cap, "TLS ServerHello missing key_share extension");
        return false;
    }
    return true;
}

/* Reads plaintext ServerHello handshake record (ignoring any middlebox CCS). */
static bool tls_read_plaintext_server_hello(TbTlsConn *c, TbBuf *sh_buf, int timeout_ms,
                                            char *err, size_t err_cap) {
    tb_buf_init(sh_buf);
    for (;;) {
        if (sh_buf->len >= 4) {
            size_t mlen = ((size_t)(uint8_t)sh_buf->data[1] << 16) |
                          ((size_t)(uint8_t)sh_buf->data[2] << 8)  |
                          (size_t)(uint8_t)sh_buf->data[3];
            if ((uint8_t)sh_buf->data[0] != TLS_HS_SERVER_HELLO) {
                tls_err(err, err_cap, "TLS expected ServerHello, got msg %u",
                        (unsigned)(uint8_t)sh_buf->data[0]);
                tb_buf_free(sh_buf);
                return false;
            }
            if (sh_buf->len == 4 + mlen) return true;
            if (sh_buf->len > 4 + mlen) {
                /* Plaintext ServerHello must align on record boundary before encrypted flight */
                tls_err(err, err_cap, "TLS extra bytes trailing plaintext ServerHello");
                tb_buf_free(sh_buf);
                return false;
            }
        }

        uint8_t hdr[5];
        ssize_t rlen = tls_read_outer_record(c, hdr, timeout_ms);
        if (rlen < 0) {
            tls_err(err, err_cap, "TLS connection closed waiting for ServerHello");
            tb_buf_free(sh_buf);
            return false;
        }
        if (hdr[0] == 0x14) {
            /* Middlebox ChangeCipherSpec */
            continue;
        }
        if (hdr[0] == 0x15) {
            uint8_t desc = (rlen >= 2) ? c->rec_buf[1] : 0;
            tls_err(err, err_cap, "TLS alert %u from server during ServerHello", (unsigned)desc);
            tb_buf_free(sh_buf);
            return false;
        }
        if (hdr[0] != 0x16 || sh_buf->len + (size_t)rlen > TLS_MAX_HS_BUF) {
            tls_err(err, err_cap, "TLS unexpected outer record 0x%02x before ServerHello", hdr[0]);
            tb_buf_free(sh_buf);
            return false;
        }
        if (!tb_buf_append(sh_buf, (const char *)c->rec_buf, (size_t)rlen)) {
            tls_err(err, err_cap, "TLS out of memory buffering ServerHello");
            tb_buf_free(sh_buf);
            return false;
        }
    }
}

/* Pulls the next complete decrypted handshake message into hs_buf[hs_off .. hs_off + 4 + msg_len]. */
static bool tls_next_encrypted_hs(TbTlsConn *c, TbBuf *hs_buf, size_t *hs_off,
                                  int timeout_ms, uint8_t *msg_type,
                                  const uint8_t **full_msg, size_t *full_len,
                                  const uint8_t **body_out, size_t *body_len,
                                  char *err, size_t err_cap) {
    for (;;) {
        size_t avail = hs_buf->len - *hs_off;
        if (avail >= 4) {
            const uint8_t *p = (const uint8_t *)hs_buf->data + *hs_off;
            size_t mlen = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | (size_t)p[3];
            if (4 + mlen > TLS_MAX_HS_BUF) {
                tls_err(err, err_cap, "TLS handshake message exceeds 256 KB limit");
                return false;
            }
            if (avail >= 4 + mlen) {
                *msg_type = p[0];
                *full_msg = p;
                *full_len = 4 + mlen;
                *body_out = p + 4;
                *body_len = mlen;
                *hs_off  += 4 + mlen;
                return true;
            }
        }

        /* Compact consumed prefix before appending a new decrypted record */
        if (*hs_off > 0) {
            size_t rem = hs_buf->len - *hs_off;
            if (rem > 0) memmove(hs_buf->data, hs_buf->data + *hs_off, rem);
            hs_buf->len = rem;
            *hs_off = 0;
        }

        uint8_t hdr[5];
        ssize_t rlen = tls_read_outer_record(c, hdr, timeout_ms);
        if (rlen < 0) {
            tls_err(err, err_cap, "TLS connection closed during encrypted handshake");
            return false;
        }
        if (hdr[0] == 0x14) {
            /* Ignore middlebox plaintext ChangeCipherSpec */
            continue;
        }
        if (hdr[0] == 0x15) {
            uint8_t desc = (rlen >= 2) ? c->rec_buf[1] : 0;
            tls_err(err, err_cap, "TLS plaintext alert %u during handshake", (unsigned)desc);
            return false;
        }
        if (hdr[0] != 0x17) {
            tls_err(err, err_cap, "TLS unexpected record type 0x%02x during encrypted handshake", hdr[0]);
            return false;
        }

        uint8_t inner_type = 0;
        size_t  pt_len     = 0;
        if (!tls_decrypt_record_inplace(c, hdr, (size_t)rlen, &inner_type, &pt_len)) {
            tls_err(err, err_cap, "TLS handshake AEAD decryption failed");
            return false;
        }
        if (inner_type == 0x15) {
            uint8_t desc = (pt_len >= 2) ? c->rec_buf[1] : 0;
            tls_err(err, err_cap, "TLS encrypted alert %u during handshake", (unsigned)desc);
            return false;
        }
        if (inner_type != 0x16) {
            tls_err(err, err_cap, "TLS unexpected inner content type 0x%02x during handshake", inner_type);
            return false;
        }
        if (hs_buf->len + pt_len > TLS_MAX_HS_BUF) {
            tls_err(err, err_cap, "TLS handshake buffer overflow");
            return false;
        }
        if (pt_len > 0 && !tb_buf_append(hs_buf, (const char *)c->rec_buf, pt_len)) {
            tls_err(err, err_cap, "TLS out of memory buffering handshake");
            return false;
        }
    }
}

/* ============================================================================
 * Public Handshake Entry Point: tb_tls_connect
 * ============================================================================ */

TbTlsConn *tb_tls_connect(int fd, const char *host, bool insecure,
                          int timeout_ms, char *err_buf, size_t err_cap) {
    if (err_buf && err_cap > 0) err_buf[0] = '\0';
    if (fd < 0) {
        tls_err(err_buf, err_cap, "Invalid socket fd");
        return NULL;
    }

    TbTlsConn *c = (TbTlsConn *)tb_calloc(1, sizeof(TbTlsConn));
    if (!c) {
        tls_err(err_buf, err_cap, "Out of memory allocating TLS connection");
        return NULL;
    }
    c->fd      = fd;
    c->rec_buf = (uint8_t *)tb_malloc(TLS_MAX_CIPHERTEXT);
    if (!c->rec_buf) {
        tb_free(c);
        tls_err(err_buf, err_cap, "Out of memory allocating TLS record buffer");
        return NULL;
    }

    /* Generate client random, legacy session ID, X25519 keypair, and P-256 keypair */
    uint8_t client_random[32];
    uint8_t session_id[32];
    uint8_t x25519_priv[32], x25519_pub[32];
    uint8_t p256_priv[32],   p256_pub[65];
    uint8_t p384_priv[48]  = {0};
    uint8_t p384_pub[97]   = {0};

    TbBuf sh_buf   = {0};
    TbBuf hs_buf   = {0};
    TbBuf cert_req_ctx = {0};

    if (!tb_getrandom(client_random, 32) ||
        !tb_getrandom(session_id, 32) ||
        !tb_getrandom(x25519_priv, 32) ||
        !tb_p256_keygen(p256_priv, p256_pub)) {
        tls_err(err_buf, err_cap, "CSPRNG failure generating TLS ephemeral keys");
        goto fail;
    }
    tb_x25519_base(x25519_pub, x25519_priv);

    TlsTranscript th;
    th_init(&th);

    /* Send ClientHello1 */
    {
        TbBuf ch1 = {0};
        if (!tls_build_client_hello(&ch1, host, client_random, session_id, 0,
                                    x25519_pub, p256_pub, NULL, NULL, 0)) {
            tb_buf_free(&ch1);
            tls_err(err_buf, err_cap, "Out of memory building TLS ClientHello");
            goto fail;
        }
        th_update(&th, (const uint8_t *)ch1.data, ch1.len);
        bool sent = tls_send_plaintext_record(fd, 0x16, 0x0301,
                                              (const uint8_t *)ch1.data, ch1.len, timeout_ms);
        tb_buf_free(&ch1);
        if (!sent) {
            tls_err(err_buf, err_cap, "Failed sending TLS ClientHello");
            goto fail;
        }
    }

    /* Read ServerHello (or HelloRetryRequest) */
    if (!tls_read_plaintext_server_hello(c, &sh_buf, timeout_ms, err_buf, err_cap)) {
        goto fail;
    }

    ParsedServerHello psh;
    if (!tls_parse_server_hello((const uint8_t *)sh_buf.data + 4, sh_buf.len - 4,
                                session_id, &psh, err_buf, err_cap)) {
        goto fail;
    }

    /* Configure cipher suite parameters */
    c->cipher_suite = psh.cipher_suite;
    if (c->cipher_suite == TLS_AES_256_GCM_SHA384) {
        c->hash_len  = 48;
        c->key_len   = 32;
        c->is_chacha = false;
    } else if (c->cipher_suite == TLS_CHACHA20_POLY1305_SHA256) {
        c->hash_len  = 32;
        c->key_len   = 32;
        c->is_chacha = true;
    } else {
        c->hash_len  = 32;
        c->key_len   = 16;
        c->is_chacha = false;
    }

    /* Handle HelloRetryRequest if server requested a cookie or specific group */
    bool did_hrr = false;
    if (psh.is_hrr) {
        did_hrr = true;
        uint16_t req_group = psh.selected_group;
        if (req_group == 0 && psh.cookie_len == 0) {
            tls_err(err_buf, err_cap, "TLS HelloRetryRequest contained no group or cookie change");
            goto fail;
        }
        if (req_group != 0 &&
            req_group != TLS_GROUP_X25519 &&
            req_group != TLS_GROUP_SECP256R1 &&
            req_group != TLS_GROUP_SECP384R1) {
            tls_err(err_buf, err_cap, "TLS HelloRetryRequest unsupported group 0x%04x", req_group);
            goto fail;
        }
        if (req_group == TLS_GROUP_SECP384R1 && !tb_p384_keygen(p384_priv, p384_pub)) {
            tls_err(err_buf, err_cap, "CSPRNG failure generating TLS P-384 ephemeral key");
            goto fail;
        }
        th_replace_with_message_hash(&th, c->hash_len);
        th_update(&th, (const uint8_t *)sh_buf.data, sh_buf.len);

        /* Middlebox compatibility CCS before ClientHello2 (must NOT send a second CCS later!) */
        uint8_t ccs = 0x01;
        if (!tls_send_plaintext_record(fd, 0x14, 0x0303, &ccs, 1, timeout_ms)) {
            tls_err(err_buf, err_cap, "Failed sending TLS middlebox CCS");
            goto fail;
        }

        TbBuf ch2 = {0};
        if (!tls_build_client_hello(&ch2, host, client_random, session_id, req_group,
                                    x25519_pub, p256_pub, p384_pub, psh.cookie, psh.cookie_len)) {
            tb_buf_free(&ch2);
            tls_err(err_buf, err_cap, "Out of memory building TLS ClientHello2");
            goto fail;
        }
        tb_buf_free(&sh_buf);

        th_update(&th, (const uint8_t *)ch2.data, ch2.len);
        bool sent = tls_send_plaintext_record(fd, 0x16, 0x0303,
                                              (const uint8_t *)ch2.data, ch2.len, timeout_ms);
        tb_buf_free(&ch2);
        if (!sent) {
            tls_err(err_buf, err_cap, "Failed sending TLS ClientHello2");
            goto fail;
        }

        if (!tls_read_plaintext_server_hello(c, &sh_buf, timeout_ms, err_buf, err_cap)) {
            goto fail;
        }
        if (!tls_parse_server_hello((const uint8_t *)sh_buf.data + 4, sh_buf.len - 4,
                                    session_id, &psh, err_buf, err_cap) ||
            psh.is_hrr || psh.cipher_suite != c->cipher_suite ||
            (req_group != 0 && psh.selected_group != req_group)) {
            tls_err(err_buf, err_cap, "Invalid second TLS ServerHello after HRR");
            goto fail;
        }
    }

    /* Update transcript with ServerHello */
    th_update(&th, (const uint8_t *)sh_buf.data, sh_buf.len);

    /* Compute ECDHE shared secret */
    uint8_t shared_secret[48];
    size_t  shared_secret_len = 32;
    if (psh.selected_group == TLS_GROUP_X25519) {
        if (psh.peer_key_len != 32 || !tb_x25519(shared_secret, x25519_priv, psh.peer_key)) {
            tls_err(err_buf, err_cap, "TLS X25519 key exchange failed");
            goto fail;
        }
    } else if (psh.selected_group == TLS_GROUP_SECP256R1) {
        if (!tb_p256_ecdh(shared_secret, p256_priv, psh.peer_key, psh.peer_key_len)) {
            tls_err(err_buf, err_cap, "TLS P-256 ECDHE key exchange failed");
            goto fail;
        }
    } else if (psh.selected_group == TLS_GROUP_SECP384R1 && did_hrr) {
        shared_secret_len = 48;
        if (!tb_p384_ecdh(shared_secret, p384_priv, psh.peer_key, psh.peer_key_len)) {
            tls_err(err_buf, err_cap, "TLS P-384 ECDHE key exchange failed");
            goto fail;
        }
    } else {
        tls_err(err_buf, err_cap, "TLS ServerHello selected unoffered group 0x%04x", psh.selected_group);
        goto fail;
    }
    tb_buf_free(&sh_buf);
    tb_crypto_wipe(x25519_priv, sizeof(x25519_priv));
    tb_crypto_wipe(p256_priv, sizeof(p256_priv));
    tb_crypto_wipe(p384_priv, sizeof(p384_priv));

    /* Derive TLS 1.3 Handshake Secrets (RFC 8446 §7.1) */
    uint8_t zeros[48]      = {0};
    uint8_t empty_hash[48] = {0};
    if (c->hash_len == 48) tb_sha384("", 0, empty_hash);
    else                   tb_sha256("", 0, empty_hash);

    uint8_t early_secret[48];
    uint8_t derived_secret[48];
    uint8_t handshake_secret[48];
    uint8_t c_hs_traffic[48];
    uint8_t s_hs_traffic[48];
    uint8_t th_sh[48];

    tb_hkdf_extract(c->hash_len, zeros, c->hash_len, zeros, c->hash_len, early_secret);
    tb_tls13_hkdf_expand_label(c->hash_len, early_secret, "derived",
                               empty_hash, c->hash_len, derived_secret, c->hash_len);
    tb_hkdf_extract(c->hash_len, derived_secret, c->hash_len,
                    shared_secret, shared_secret_len, handshake_secret);
    tb_crypto_wipe(shared_secret, sizeof(shared_secret));

    th_snapshot(&th, c->hash_len, th_sh);
    tb_tls13_hkdf_expand_label(c->hash_len, handshake_secret, "c hs traffic",
                               th_sh, c->hash_len, c_hs_traffic, c->hash_len);
    tb_tls13_hkdf_expand_label(c->hash_len, handshake_secret, "s hs traffic",
                               th_sh, c->hash_len, s_hs_traffic, c->hash_len);

    /* Activate handshake keys */
    memcpy(c->read_secret,  s_hs_traffic, c->hash_len);
    memcpy(c->write_secret, c_hs_traffic, c->hash_len);
    tls_derive_traffic_keys(c->hash_len, c->key_len, c->read_secret,  c->read_key,  c->read_iv);
    tls_derive_traffic_keys(c->hash_len, c->key_len, c->write_secret, c->write_key, c->write_iv);
    c->read_seq  = 0;
    c->write_seq = 0;

    /* Process encrypted server handshake flight:
     * 1. EncryptedExtensions (8)
     * 2. [Optional] CertificateRequest (13)
     * 3. Certificate (11)
     * 4. CertificateVerify (15)
     * 5. Finished (20) */
    tb_buf_init(&hs_buf);
    size_t hs_off = 0;

    uint8_t        mtype = 0;
    const uint8_t *mfull = NULL, *mbody = NULL;
    size_t         mflen = 0,     mblen = 0;

    /* 1. EncryptedExtensions */
    if (!tls_next_encrypted_hs(c, &hs_buf, &hs_off, timeout_ms,
                               &mtype, &mfull, &mflen, &mbody, &mblen, err_buf, err_cap)) {
        goto fail_wipe;
    }
    if (mtype != TLS_HS_ENCRYPTED_EXTENSIONS || mblen < 2) {
        tls_err(err_buf, err_cap, "TLS expected EncryptedExtensions, got %u", (unsigned)mtype);
        goto fail_wipe;
    }
    {
        size_t ee_len = ((size_t)mbody[0] << 8) | mbody[1];
        if (2 + ee_len != mblen) {
            tls_err(err_buf, err_cap, "TLS malformed EncryptedExtensions");
            goto fail_wipe;
        }
        size_t ep = 2;
        while (ep < mblen) {
            if (ep + 4 > mblen) {
                tls_err(err_buf, err_cap, "TLS truncated EncryptedExtensions entry");
                goto fail_wipe;
            }
            uint16_t etype = ((uint16_t)mbody[ep] << 8) | mbody[ep + 1];
            size_t   elen  = ((size_t)mbody[ep + 2] << 8) | mbody[ep + 3];
            ep += 4;
            if (ep + elen > mblen) {
                tls_err(err_buf, err_cap, "TLS EncryptedExtensions entry overflow");
                goto fail_wipe;
            }
            if (etype == 0x0010U) { /* ALPN */
                const uint8_t *ed = mbody + ep;
                if (elen != 11 || (((size_t)ed[0] << 8) | ed[1]) != 9 ||
                    ed[2] != 8 || memcmp(ed + 3, "http/1.1", 8) != 0) {
                    tls_err(err_buf, err_cap, "TLS server negotiated unsupported ALPN protocol");
                    goto fail_wipe;
                }
            }
            ep += elen;
        }
    }
    th_update(&th, mfull, mflen);

    /* 2. Optional CertificateRequest or Certificate */
    bool got_cert_req = false;
    if (!tls_next_encrypted_hs(c, &hs_buf, &hs_off, timeout_ms,
                               &mtype, &mfull, &mflen, &mbody, &mblen, err_buf, err_cap)) {
        goto fail_wipe;
    }
    if (mtype == TLS_HS_CERTIFICATE_REQUEST) {
        if (mblen < 3) {
            tls_err(err_buf, err_cap, "TLS malformed CertificateRequest");
            goto fail_wipe;
        }
        size_t ctx_len = mbody[0];
        if (1 + ctx_len + 2 > mblen) {
            tls_err(err_buf, err_cap, "TLS truncated CertificateRequest context");
            goto fail_wipe;
        }
        got_cert_req = true;
        tb_buf_init(&cert_req_ctx);
        if (ctx_len > 0) tb_buf_append(&cert_req_ctx, (const char *)(mbody + 1), ctx_len);
        th_update(&th, mfull, mflen);

        if (!tls_next_encrypted_hs(c, &hs_buf, &hs_off, timeout_ms,
                                   &mtype, &mfull, &mflen, &mbody, &mblen, err_buf, err_cap)) {
            goto fail_wipe;
        }
    }

    /* 3. Certificate */
    if (mtype != TLS_HS_CERTIFICATE || mblen < 4) {
        tls_err(err_buf, err_cap, "TLS expected Certificate, got %u", (unsigned)mtype);
        goto fail_wipe;
    }
    TbX509Cert leaf_cert;
    memset(&leaf_cert, 0, sizeof(leaf_cert));
    uint8_t *leaf_der_copy = NULL;
    size_t   leaf_der_len  = 0;
    {
        size_t ctx_len = mbody[0];
        if (ctx_len != 0 || 1 + ctx_len + 3 > mblen) {
            tls_err(err_buf, err_cap, "TLS invalid server Certificate context");
            goto fail_wipe;
        }
        size_t p = 1 + ctx_len;
        size_t list_len = ((size_t)mbody[p] << 16) | ((size_t)mbody[p + 1] << 8) | mbody[p + 2];
        p += 3;
        if (p + list_len != mblen || list_len == 0) {
            tls_err(err_buf, err_cap, "TLS empty or malformed server Certificate list");
            goto fail_wipe;
        }

        const uint8_t *cert_ders[TLS_MAX_CERTS];
        size_t         cert_lens[TLS_MAX_CERTS];
        size_t         cert_count = 0;

        while (p < mblen) {
            if (p + 3 > mblen) {
                tls_err(err_buf, err_cap, "TLS truncated CertificateEntry");
                goto fail_wipe;
            }
            size_t clen = ((size_t)mbody[p] << 16) | ((size_t)mbody[p + 1] << 8) | mbody[p + 2];
            p += 3;
            if (clen == 0 || p + clen + 2 > mblen) {
                tls_err(err_buf, err_cap, "TLS invalid CertificateEntry DER length");
                goto fail_wipe;
            }
            const uint8_t *cder = mbody + p;
            p += clen;

            size_t ext_len = ((size_t)mbody[p] << 8) | mbody[p + 1];
            p += 2;
            if (p + ext_len > mblen) {
                tls_err(err_buf, err_cap, "TLS invalid CertificateEntry extensions");
                goto fail_wipe;
            }
            p += ext_len;

            if (cert_count < TLS_MAX_CERTS) {
                cert_ders[cert_count] = cder;
                cert_lens[cert_count] = clen;
                cert_count++;
            }
        }

        if (cert_count == 0) {
            tls_err(err_buf, err_cap, "TLS server sent zero certificates");
            goto fail_wipe;
        }

        /* Copy leaf DER before hs_buf can be compacted by subsequent reads */
        leaf_der_len  = cert_lens[0];
        leaf_der_copy = (uint8_t *)tb_malloc(leaf_der_len);
        if (!leaf_der_copy) {
            tls_err(err_buf, err_cap, "Out of memory copying leaf certificate");
            goto fail_wipe;
        }
        memcpy(leaf_der_copy, cert_ders[0], leaf_der_len);

        if (!tb_x509_parse_der(leaf_der_copy, leaf_der_len, &leaf_cert, err_buf, err_cap)) {
            tb_free(leaf_der_copy);
            goto fail_wipe;
        }

        if (!insecure) {
            struct timespec ts_real = {0, 0};
            clock_gettime(CLOCK_REALTIME, &ts_real);
            int64_t now_unix = (int64_t)ts_real.tv_sec;
            if (!tb_x509_verify_chain(cert_ders, cert_lens, cert_count, host, now_unix,
                                      tb_tls_get_ca_file(), err_buf, err_cap)) {
                tb_free(leaf_der_copy);
                goto fail_wipe;
            }
        }
    }
    th_update(&th, mfull, mflen);

    /* 4. CertificateVerify */
    uint8_t th_cv[48];
    th_snapshot(&th, c->hash_len, th_cv);

    if (!tls_next_encrypted_hs(c, &hs_buf, &hs_off, timeout_ms,
                               &mtype, &mfull, &mflen, &mbody, &mblen, err_buf, err_cap)) {
        tb_free(leaf_der_copy);
        goto fail_wipe;
    }
    if (mtype != TLS_HS_CERTIFICATE_VERIFY || mblen < 4) {
        tb_free(leaf_der_copy);
        tls_err(err_buf, err_cap, "TLS expected CertificateVerify, got %u", (unsigned)mtype);
        goto fail_wipe;
    }
    {
        uint16_t sig_scheme = ((uint16_t)mbody[0] << 8) | mbody[1];
        size_t   sig_len    = ((size_t)mbody[2] << 8) | mbody[3];
        if (4 + sig_len != mblen) {
            tb_free(leaf_der_copy);
            tls_err(err_buf, err_cap, "TLS malformed CertificateVerify signature length");
            goto fail_wipe;
        }
        if (!tb_x509_verify_tls13_sig(&leaf_cert, sig_scheme, th_cv, c->hash_len,
                                      mbody + 4, sig_len)) {
            tb_free(leaf_der_copy);
            tls_err(err_buf, err_cap, "TLS 1.3 CertificateVerify signature verification failed");
            goto fail_wipe;
        }
    }
    tb_free(leaf_der_copy);
    leaf_der_copy = NULL;
    th_update(&th, mfull, mflen);

    /* 5. Server Finished */
    uint8_t th_before_sfin[48];
    th_snapshot(&th, c->hash_len, th_before_sfin);

    if (!tls_next_encrypted_hs(c, &hs_buf, &hs_off, timeout_ms,
                               &mtype, &mfull, &mflen, &mbody, &mblen, err_buf, err_cap)) {
        goto fail_wipe;
    }
    if (mtype != TLS_HS_FINISHED || mblen != c->hash_len) {
        tls_err(err_buf, err_cap, "TLS expected server Finished (%zu B), got type %u (%zu B)",
                c->hash_len, (unsigned)mtype, mblen);
        goto fail_wipe;
    }
    /* RFC 8446 §5.1: Key change after Finished MUST align with record boundary */
    if (hs_off != hs_buf.len) {
        tls_err(err_buf, err_cap, "TLS server Finished did not align with record boundary");
        goto fail_wipe;
    }
    {
        uint8_t s_fin_key[48];
        uint8_t expected_sfin[48];
        tb_tls13_hkdf_expand_label(c->hash_len, s_hs_traffic, "finished",
                                   NULL, 0, s_fin_key, c->hash_len);
        tb_hmac(c->hash_len, s_fin_key, c->hash_len,
                th_before_sfin, c->hash_len, expected_sfin);
        int diff = tb_crypto_ct_memcmp(expected_sfin, mbody, c->hash_len);
        tb_crypto_wipe(s_fin_key, sizeof(s_fin_key));
        tb_crypto_wipe(expected_sfin, sizeof(expected_sfin));
        if (diff != 0) {
            tls_err(err_buf, err_cap, "TLS server Finished MAC mismatch");
            goto fail_wipe;
        }
    }
    th_update(&th, mfull, mflen);
    tb_buf_free(&hs_buf);

    /* Derive Master Secret & Application Traffic Secrets over ClientHello..server Finished */
    uint8_t th_sfin[48];
    uint8_t master_secret[48];
    uint8_t c_ap_traffic[48];
    uint8_t s_ap_traffic[48];

    th_snapshot(&th, c->hash_len, th_sfin);
    tb_tls13_hkdf_expand_label(c->hash_len, handshake_secret, "derived",
                               empty_hash, c->hash_len, derived_secret, c->hash_len);
    tb_hkdf_extract(c->hash_len, derived_secret, c->hash_len,
                    zeros, c->hash_len, master_secret);
    tb_tls13_hkdf_expand_label(c->hash_len, master_secret, "c ap traffic",
                               th_sfin, c->hash_len, c_ap_traffic, c->hash_len);
    tb_tls13_hkdf_expand_label(c->hash_len, master_secret, "s ap traffic",
                               th_sfin, c->hash_len, s_ap_traffic, c->hash_len);

    /* Send client ChangeCipherSpec (middlebox compat, if HRR didn't already send it) + Finished */
    if (!did_hrr) {
        uint8_t ccs = 0x01;
        if (!tls_send_plaintext_record(fd, 0x14, 0x0303, &ccs, 1, timeout_ms)) {
            tls_err(err_buf, err_cap, "Failed sending TLS client CCS");
            goto fail_wipe_ap;
        }
    }

    /* If server sent CertificateRequest, reply with an empty client Certificate message */
    if (got_cert_req) {
        TbBuf ccert;
        tb_buf_init(&ccert);
        buf_put_u8(&ccert, (uint8_t)TLS_HS_CERTIFICATE);
        buf_put_u24(&ccert, (uint32_t)(1 + cert_req_ctx.len + 3));
        buf_put_u8(&ccert, (uint8_t)cert_req_ctx.len);
        if (cert_req_ctx.len > 0) tb_buf_append(&ccert, cert_req_ctx.data, cert_req_ctx.len);
        buf_put_u24(&ccert, 0); /* empty certificate_list */

        th_update(&th, (const uint8_t *)ccert.data, ccert.len);
        bool ok = tls_encrypt_and_send(c, 0x16, (const uint8_t *)ccert.data, ccert.len, timeout_ms);
        tb_buf_free(&ccert);
        tb_buf_free(&cert_req_ctx);
        if (!ok) {
            tls_err(err_buf, err_cap, "Failed sending empty client Certificate");
            goto fail_wipe_ap;
        }
    }

    /* Compute & send client Finished under c_hs_traffic */
    {
        uint8_t th_cfin[48];
        uint8_t c_fin_key[48];
        uint8_t c_fin_msg[4 + 48];

        th_snapshot(&th, c->hash_len, th_cfin);
        tb_tls13_hkdf_expand_label(c->hash_len, c_hs_traffic, "finished",
                                   NULL, 0, c_fin_key, c->hash_len);
        c_fin_msg[0] = (uint8_t)TLS_HS_FINISHED;
        c_fin_msg[1] = 0;
        c_fin_msg[2] = 0;
        c_fin_msg[3] = (uint8_t)c->hash_len;
        tb_hmac(c->hash_len, c_fin_key, c->hash_len, th_cfin, c->hash_len, c_fin_msg + 4);

        bool ok = tls_encrypt_and_send(c, 0x16, c_fin_msg, 4 + c->hash_len, timeout_ms);
        tb_crypto_wipe(th_cfin, sizeof(th_cfin));
        tb_crypto_wipe(c_fin_key, sizeof(c_fin_key));
        tb_crypto_wipe(c_fin_msg, sizeof(c_fin_msg));
        if (!ok) {
            tls_err(err_buf, err_cap, "Failed sending TLS client Finished");
            goto fail_wipe_ap;
        }
    }

    /* Switch active read/write traffic keys to Application Traffic Secrets */
    memcpy(c->read_secret,  s_ap_traffic, c->hash_len);
    memcpy(c->write_secret, c_ap_traffic, c->hash_len);
    tls_derive_traffic_keys(c->hash_len, c->key_len, c->read_secret,  c->read_key,  c->read_iv);
    tls_derive_traffic_keys(c->hash_len, c->key_len, c->write_secret, c->write_key, c->write_iv);
    c->read_seq  = 0;
    c->write_seq = 0;
    c->app_ready = true;

    /* Wipe all transient handshake secrets */
    tb_crypto_wipe(&th, sizeof(th));
    tb_crypto_wipe(early_secret, sizeof(early_secret));
    tb_crypto_wipe(derived_secret, sizeof(derived_secret));
    tb_crypto_wipe(handshake_secret, sizeof(handshake_secret));
    tb_crypto_wipe(c_hs_traffic, sizeof(c_hs_traffic));
    tb_crypto_wipe(s_hs_traffic, sizeof(s_hs_traffic));
    tb_crypto_wipe(master_secret, sizeof(master_secret));
    tb_crypto_wipe(c_ap_traffic, sizeof(c_ap_traffic));
    tb_crypto_wipe(s_ap_traffic, sizeof(s_ap_traffic));
    tb_crypto_wipe(th_sh, sizeof(th_sh));
    tb_crypto_wipe(th_sfin, sizeof(th_sfin));
    return c;

fail_wipe_ap:
    tb_crypto_wipe(master_secret, sizeof(master_secret));
    tb_crypto_wipe(c_ap_traffic, sizeof(c_ap_traffic));
    tb_crypto_wipe(s_ap_traffic, sizeof(s_ap_traffic));
fail_wipe:
    tb_crypto_wipe(&th, sizeof(th));
    tb_crypto_wipe(early_secret, sizeof(early_secret));
    tb_crypto_wipe(derived_secret, sizeof(derived_secret));
    tb_crypto_wipe(handshake_secret, sizeof(handshake_secret));
    tb_crypto_wipe(c_hs_traffic, sizeof(c_hs_traffic));
    tb_crypto_wipe(s_hs_traffic, sizeof(s_hs_traffic));
fail:
    c->fatal = true;
    tb_crypto_wipe(x25519_priv, sizeof(x25519_priv));
    tb_crypto_wipe(p256_priv, sizeof(p256_priv));
    tb_crypto_wipe(p384_priv, sizeof(p384_priv));
    tb_buf_free(&sh_buf);
    tb_buf_free(&hs_buf);
    tb_buf_free(&cert_req_ctx);
    tb_tls_close(c);
    return NULL;
}

/* ============================================================================
 * Post-Handshake Handling & Application Data Read / Write / Close
 * ============================================================================ */

static bool tls_handle_post_handshake(TbTlsConn *c, const uint8_t *data, size_t len, int timeout_ms) {
    if (len == 0) return true;
    if (c->ph_buf.len + len > TLS_MAX_HS_BUF) return false;
    if (!tb_buf_append(&c->ph_buf, (const char *)data, len)) return false;

    size_t off = 0;
    while (c->ph_buf.len - off >= 4) {
        const uint8_t *p = (const uint8_t *)c->ph_buf.data + off;
        uint8_t mtype = p[0];
        size_t  mlen  = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
        if (4 + mlen > TLS_MAX_HS_BUF) return false;
        if (c->ph_buf.len - off < 4 + mlen) break;

        if (mtype == TLS_HS_NEW_SESSION_TICKET) {
            /* Stateless client ignores session tickets */
        } else if (mtype == TLS_HS_KEY_UPDATE) {
            if (mlen != 1 || (p[4] != 0 && p[4] != 1)) return false;
            /* RFC 8446 §5.1: KeyUpdate must align with record boundary */
            if (off + 4 + mlen != c->ph_buf.len) return false;

            uint8_t next_sec[48];
            tb_tls13_hkdf_expand_label(c->hash_len, c->read_secret, "traffic upd",
                                       NULL, 0, next_sec, c->hash_len);
            memcpy(c->read_secret, next_sec, c->hash_len);
            tls_derive_traffic_keys(c->hash_len, c->key_len, c->read_secret,
                                    c->read_key, c->read_iv);
            c->read_seq = 0;

            if (p[4] == 1) { /* update_requested */
                uint8_t ku_reply[5] = { (uint8_t)TLS_HS_KEY_UPDATE, 0, 0, 1, 0 };
                if (!tls_encrypt_and_send(c, 0x16, ku_reply, 5, timeout_ms)) {
                    tb_crypto_wipe(next_sec, sizeof(next_sec));
                    return false;
                }
                tb_tls13_hkdf_expand_label(c->hash_len, c->write_secret, "traffic upd",
                                           NULL, 0, next_sec, c->hash_len);
                memcpy(c->write_secret, next_sec, c->hash_len);
                tls_derive_traffic_keys(c->hash_len, c->key_len, c->write_secret,
                                        c->write_key, c->write_iv);
                c->write_seq = 0;
            }
            tb_crypto_wipe(next_sec, sizeof(next_sec));
        } else {
            return false;
        }
        off += 4 + mlen;
    }

    if (off == c->ph_buf.len) {
        tb_buf_free(&c->ph_buf);
    } else if (off > 0) {
        size_t rem = c->ph_buf.len - off;
        memmove(c->ph_buf.data, c->ph_buf.data + off, rem);
        c->ph_buf.len = rem;
    }
    return true;
}

ssize_t tb_tls_read(TbTlsConn *c, void *buf, size_t len, int timeout_ms) {
    if (!c || !buf || c->fatal) return -1;
    if (len == 0 || c->eof) return 0;

    if (c->app_len > 0) {
        size_t take = (len < c->app_len) ? len : c->app_len;
        memcpy(buf, c->rec_buf + c->app_off, take);
        c->app_off += take;
        c->app_len -= take;
        return (ssize_t)take;
    }

    for (;;) {
        uint8_t hdr[5];
        ssize_t rlen = tls_read_outer_record(c, hdr, timeout_ms);
        if (rlen == -2) {
            /* Clean TCP EOF (Connection: close servers sometimes omit close_notify) */
            c->eof = true;
            return 0;
        }
        if (rlen < 0) {
            c->fatal = true;
            return -1;
        }
        if (hdr[0] == 0x14) {
            continue;
        }
        if (hdr[0] != 0x17) {
            c->fatal = true;
            return -1;
        }

        uint8_t inner_type = 0;
        size_t  pt_len     = 0;
        if (!tls_decrypt_record_inplace(c, hdr, (size_t)rlen, &inner_type, &pt_len)) {
            c->fatal = true;
            return -1;
        }

        if (inner_type == 0x17) {
            if (pt_len == 0) continue; /* RFC 8446 permits empty app-data keepalive records */
            size_t take = (len < pt_len) ? len : pt_len;
            memcpy(buf, c->rec_buf, take);
            c->app_off = take;
            c->app_len = pt_len - take;
            return (ssize_t)take;
        } else if (inner_type == 0x16) {
            if (!tls_handle_post_handshake(c, c->rec_buf, pt_len, timeout_ms)) {
                c->fatal = true;
                return -1;
            }
        } else if (inner_type == 0x15) {
            if (pt_len >= 2 && c->rec_buf[1] == 0) { /* close_notify */
                c->eof = true;
                return 0;
            }
            if (pt_len >= 2 && c->rec_buf[0] == 1 && c->rec_buf[1] == 90) {
                /* RFC 8446 §6.1 user_canceled warning alert preceding close_notify */
                continue;
            }
            c->fatal = true;
            return -1;
        } else {
            c->fatal = true;
            return -1;
        }
    }
}

bool tb_tls_write(TbTlsConn *c, const void *buf, size_t len, int timeout_ms) {
    if (!c || (!buf && len > 0) || c->fatal || c->eof) return false;
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        size_t chunk = len - sent;
        if (chunk > TLS_MAX_PLAINTEXT) chunk = TLS_MAX_PLAINTEXT;
        if (!tls_encrypt_and_send(c, 0x17, p + sent, chunk, timeout_ms)) {
            c->fatal = true;
            return false;
        }
        sent += chunk;
    }
    return true;
}

void tb_tls_close(TbTlsConn *c) {
    if (!c) return;
    if (!c->fatal && !c->eof && c->app_ready && c->fd >= 0) {
        /* Best-effort close_notify alert (non-blocking / short timeout) */
        uint8_t alert[2] = { 1, 0 };
        tls_encrypt_and_send(c, 0x15, alert, 2, 200);
    }
    if (c->rec_buf) {
        tb_crypto_wipe(c->rec_buf, TLS_MAX_CIPHERTEXT);
        tb_free(c->rec_buf);
    }
    tb_buf_free(&c->ph_buf);
    tb_crypto_wipe(c, sizeof(*c));
    tb_free(c);
}
