#include "tls.h"
#include "math_tb.h"

/* ============================================================================
 * Strict Bounds-Checked ASN.1 DER Reader
 * ============================================================================ */

typedef struct {
    const uint8_t *p;
    size_t         len;
    size_t         pos;
} DerCur;

static void der_init(DerCur *c, const uint8_t *p, size_t len) {
    c->p   = p;
    c->len = len;
    c->pos = 0;
}

static bool der_eof(const DerCur *c) {
    return c->pos >= c->len;
}

static bool der_next(DerCur *c, uint8_t *out_tag, DerCur *out_val,
                     const uint8_t **out_tlv, size_t *out_tlv_len) {
    if (c->pos + 2 > c->len) return false;
    size_t start = c->pos;
    uint8_t tag  = c->p[c->pos++];
    uint8_t lb   = c->p[c->pos++];
    size_t  vlen = 0;

    if ((lb & 0x80U) == 0) {
        vlen = lb;
    } else {
        size_t nbytes = lb & 0x7FU;
        if (nbytes == 0 || nbytes > 4 || c->pos + nbytes > c->len) return false;
        for (size_t i = 0; i < nbytes; i++) {
            vlen = (vlen << 8) | c->p[c->pos++];
        }
    }
    if (c->pos + vlen > c->len) return false;

    if (out_tag) *out_tag = tag;
    if (out_val) der_init(out_val, c->p + c->pos, vlen);
    c->pos += vlen;
    if (out_tlv)     *out_tlv     = c->p + start;
    if (out_tlv_len) *out_tlv_len = c->pos - start;
    return true;
}

static bool der_peek_tag(const DerCur *c, uint8_t *out_tag) {
    if (c->pos >= c->len) return false;
    *out_tag = c->p[c->pos];
    return true;
}

/* ============================================================================
 * Known OIDs
 * ============================================================================ */

static bool oid_eq(const DerCur *oid, const uint8_t *ref, size_t ref_len) {
    return oid->len == ref_len && memcmp(oid->p, ref, ref_len) == 0;
}

#define OID_MATCH(cur, arr) oid_eq((cur), (arr), sizeof(arr))

static const uint8_t OID_RSA_ENC[]        = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01 };
static const uint8_t OID_RSASSA_PSS[]     = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0a };
static const uint8_t OID_RSA_SHA256[]     = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
static const uint8_t OID_RSA_SHA384[]     = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0c };
static const uint8_t OID_RSA_SHA512[]     = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0d };

static const uint8_t OID_EC_PUBKEY[]      = { 0x2a,0x86,0x48,0xce,0x3d,0x02,0x01 };
static const uint8_t OID_SECP256R1[]      = { 0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 };
static const uint8_t OID_SECP384R1[]      = { 0x2b,0x81,0x04,0x00,0x22 };

static const uint8_t OID_ECDSA_SHA256[]   = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02 };
static const uint8_t OID_ECDSA_SHA384[]   = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03 };
static const uint8_t OID_ECDSA_SHA512[]   = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x04 };

static const uint8_t OID_SHA256[]         = { 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01 };
static const uint8_t OID_SHA384[]         = { 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02 };
static const uint8_t OID_SHA512[]         = { 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03 };

static const uint8_t OID_COMMON_NAME[]    = { 0x55,0x04,0x03 };
static const uint8_t OID_EXT_SKI[]        = { 0x55,0x1d,0x0e };
static const uint8_t OID_EXT_KEY_USAGE[]  = { 0x55,0x1d,0x0f };
static const uint8_t OID_EXT_SAN[]        = { 0x55,0x1d,0x11 };
static const uint8_t OID_EXT_BASIC_CON[]  = { 0x55,0x1d,0x13 };
static const uint8_t OID_EXT_AKI[]        = { 0x55,0x1d,0x23 };
static const uint8_t OID_EXT_EKU[]        = { 0x55,0x1d,0x25 };
static const uint8_t OID_KP_SERVER_AUTH[] = { 0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x01 };
static const uint8_t OID_ANY_EKU[]        = { 0x55,0x1d,0x25,0x00 };

/* ============================================================================
 * ASN.1 Time, Algorithm, Name, SPKI, and Extension Parsers
 * ============================================================================ */

static int parse_2dig(const uint8_t *p) {
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') return -1;
    return (p[0] - '0') * 10 + (p[1] - '0');
}

static bool parse_asn1_time(uint8_t tag, const DerCur *val, int64_t *out_unix) {
    int year, mon, day, hour, min, sec = 0;
    const uint8_t *p = val->p;
    size_t n = val->len;
    if (n < 11 || p[n - 1] != 'Z') return false;

    size_t off = 0;
    if (tag == 0x17U) { /* UTCTime: YYMMDDHHMM[SS]Z */
        if (n != 13 && n != 11) return false;
        int yy = parse_2dig(p);
        if (yy < 0) return false;
        year = (yy >= 50) ? (1900 + yy) : (2000 + yy);
        off = 2;
    } else if (tag == 0x18U) { /* GeneralizedTime: YYYYMMDDHHMM[SS[.fff]]Z */
        if (n < 13) return false;
        int c1 = parse_2dig(p), c2 = parse_2dig(p + 2);
        if (c1 < 0 || c2 < 0) return false;
        year = c1 * 100 + c2;
        off = 4;
    } else {
        return false;
    }

    mon  = parse_2dig(p + off);
    day  = parse_2dig(p + off + 2);
    hour = parse_2dig(p + off + 4);
    min  = parse_2dig(p + off + 6);
    if (mon < 1 || mon > 12 || day < 1 || day > 31 ||
        hour < 0 || hour > 23 || min < 0 || min > 59) return false;
    off += 8;

    if (off + 2 <= n - 1) {
        sec = parse_2dig(p + off);
        if (sec < 0 || sec > 60) return false;
        if (sec == 60) sec = 59;
    }
    *out_unix = tb_unix_from_civil(year, mon, day, hour, min, sec);
    return true;
}

static bool parse_der_int_small(const DerCur *val, int *out) {
    if (val->len == 0 || val->len > 4) return false;
    if ((val->p[0] & 0x80U) != 0) return false; /* negative */
    uint32_t v = 0;
    for (size_t i = 0; i < val->len; i++) v = (v << 8) | val->p[i];
    if (v > 0x7FFFFFFFU) return false;
    *out = (int)v;
    return true;
}

static bool parse_sig_alg(DerCur *alg_seq, TbX509SigAlg *out_alg, int *out_pss_salt) {
    uint8_t tag;
    DerCur  oid;
    if (!der_next(alg_seq, &tag, &oid, NULL, NULL) || tag != 0x06U) return false;
    *out_pss_salt = -1;

    if (OID_MATCH(&oid, OID_RSA_SHA256))   { *out_alg = TB_SIG_RSA_PKCS1_SHA256; return true; }
    if (OID_MATCH(&oid, OID_RSA_SHA384))   { *out_alg = TB_SIG_RSA_PKCS1_SHA384; return true; }
    if (OID_MATCH(&oid, OID_RSA_SHA512))   { *out_alg = TB_SIG_RSA_PKCS1_SHA512; return true; }
    if (OID_MATCH(&oid, OID_ECDSA_SHA256)) { *out_alg = TB_SIG_ECDSA_SHA256;     return true; }
    if (OID_MATCH(&oid, OID_ECDSA_SHA384)) { *out_alg = TB_SIG_ECDSA_SHA384;     return true; }
    if (OID_MATCH(&oid, OID_ECDSA_SHA512)) { *out_alg = TB_SIG_ECDSA_SHA512;     return true; }

    if (OID_MATCH(&oid, OID_RSASSA_PSS)) {
        /* RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm, [1] maskGenAlgorithm, [2] saltLength ... } */
        TbX509SigAlg pss_alg = TB_SIG_NONE;
        if (!der_eof(alg_seq)) {
            DerCur params;
            if (!der_next(alg_seq, &tag, &params, NULL, NULL) || tag != 0x30U) return false;
            while (!der_eof(&params)) {
                uint8_t ptag;
                DerCur  pval;
                if (!der_next(&params, &ptag, &pval, NULL, NULL)) return false;
                if (ptag == 0xA0U) { /* [0] EXPLICIT AlgorithmIdentifier */
                    uint8_t st, ot;
                    DerCur  hseq, hoid;
                    if (!der_next(&pval, &st, &hseq, NULL, NULL) || st != 0x30U) return false;
                    if (!der_next(&hseq, &ot, &hoid, NULL, NULL) || ot != 0x06U) return false;
                    if (OID_MATCH(&hoid, OID_SHA256))      pss_alg = TB_SIG_RSA_PSS_SHA256;
                    else if (OID_MATCH(&hoid, OID_SHA384)) pss_alg = TB_SIG_RSA_PSS_SHA384;
                    else if (OID_MATCH(&hoid, OID_SHA512)) pss_alg = TB_SIG_RSA_PSS_SHA512;
                } else if (ptag == 0xA2U) { /* [2] EXPLICIT INTEGER saltLength */
                    uint8_t it;
                    DerCur  ival;
                    if (der_next(&pval, &it, &ival, NULL, NULL) && it == 0x02U) {
                        int sl = -1;
                        if (parse_der_int_small(&ival, &sl)) *out_pss_salt = sl;
                    }
                }
            }
        }
        *out_alg = pss_alg;
        return pss_alg != TB_SIG_NONE;
    }

    *out_alg = TB_SIG_NONE;
    return true;
}

static void extract_common_name(DerCur name_seq, const char **out_cn, size_t *out_len) {
    *out_cn  = NULL;
    *out_len = 0;
    while (!der_eof(&name_seq)) {
        uint8_t stag;
        DerCur  rdn_set;
        if (!der_next(&name_seq, &stag, &rdn_set, NULL, NULL) || stag != 0x31U) break;
        while (!der_eof(&rdn_set)) {
            uint8_t atag, otag, vtag;
            DerCur  atv, oid, val;
            if (!der_next(&rdn_set, &atag, &atv, NULL, NULL) || atag != 0x30U) break;
            if (!der_next(&atv, &otag, &oid, NULL, NULL) || otag != 0x06U) continue;
            if (!der_next(&atv, &vtag, &val, NULL, NULL)) continue;
            if (OID_MATCH(&oid, OID_COMMON_NAME)) {
                *out_cn  = (const char *)val.p;
                *out_len = val.len;
            }
        }
    }
}

static bool parse_spki(DerCur *spki, TbX509Cert *out) {
    uint8_t tag;
    DerCur  alg_seq, bit_str, oid;
    if (!der_next(spki, &tag, &alg_seq, NULL, NULL) || tag != 0x30U) return false;
    if (!der_next(spki, &tag, &bit_str, NULL, NULL) || tag != 0x03U) return false;
    if (bit_str.len < 2 || bit_str.p[0] != 0x00U) return false;
    const uint8_t *key_bytes = bit_str.p + 1;
    size_t         key_len   = bit_str.len - 1;

    if (!der_next(&alg_seq, &tag, &oid, NULL, NULL) || tag != 0x06U) return false;

    if (OID_MATCH(&oid, OID_RSA_ENC) || OID_MATCH(&oid, OID_RSASSA_PSS)) {
        DerCur kcur, rsa_seq, n_val, e_val;
        der_init(&kcur, key_bytes, key_len);
        if (!der_next(&kcur, &tag, &rsa_seq, NULL, NULL) || tag != 0x30U) return false;
        if (!der_next(&rsa_seq, &tag, &n_val, NULL, NULL) || tag != 0x02U || n_val.len == 0) return false;
        if (!der_next(&rsa_seq, &tag, &e_val, NULL, NULL) || tag != 0x02U || e_val.len == 0) return false;
        if ((n_val.p[0] & 0x80U) || (e_val.p[0] & 0x80U)) return false;

        out->pubkey_type = TB_PUBKEY_RSA;
        out->rsa_n       = n_val.p;
        out->rsa_n_len   = n_val.len;
        out->rsa_e       = e_val.p;
        out->rsa_e_len   = e_val.len;
        return true;
    }

    if (OID_MATCH(&oid, OID_EC_PUBKEY)) {
        DerCur curve_oid;
        if (!der_next(&alg_seq, &tag, &curve_oid, NULL, NULL) || tag != 0x06U) return false;
        if (OID_MATCH(&curve_oid, OID_SECP256R1)) {
            if (key_len != 65 || key_bytes[0] != 0x04U) return false;
            out->pubkey_type = TB_PUBKEY_EC_P256;
            memcpy(out->ec_xy, key_bytes + 1, 64);
            return true;
        }
        if (OID_MATCH(&curve_oid, OID_SECP384R1)) {
            if (key_len != 97 || key_bytes[0] != 0x04U) return false;
            out->pubkey_type = TB_PUBKEY_EC_P384;
            memcpy(out->ec_xy, key_bytes + 1, 96);
            return true;
        }
    }

    out->pubkey_type = TB_PUBKEY_NONE;
    return true;
}

static bool parse_extensions(DerCur *ext_list, TbX509Cert *out, char *err, size_t err_cap) {
    while (!der_eof(ext_list)) {
        uint8_t tag;
        DerCur  ext_seq, oid, oct;
        if (!der_next(ext_list, &tag, &ext_seq, NULL, NULL) || tag != 0x30U) return false;
        if (!der_next(&ext_seq, &tag, &oid, NULL, NULL) || tag != 0x06U) return false;

        bool critical = false;
        if (!der_peek_tag(&ext_seq, &tag)) return false;
        if (tag == 0x01U) {
            DerCur bval;
            if (!der_next(&ext_seq, &tag, &bval, NULL, NULL) || bval.len != 1) return false;
            critical = (bval.p[0] != 0);
        }
        if (!der_next(&ext_seq, &tag, &oct, NULL, NULL) || tag != 0x04U) return false;

        if (OID_MATCH(&oid, OID_EXT_BASIC_CON)) {
            out->has_basic_constraints = true;
            DerCur bc_seq;
            if (!der_next(&oct, &tag, &bc_seq, NULL, NULL) || tag != 0x30U) return false;
            if (!der_eof(&bc_seq)) {
                uint8_t ftag;
                if (!der_peek_tag(&bc_seq, &ftag)) return false;
                if (ftag == 0x01U) {
                    DerCur bval;
                    if (!der_next(&bc_seq, &ftag, &bval, NULL, NULL) || bval.len != 1) return false;
                    out->is_ca = (bval.p[0] != 0);
                }
            }
            if (!der_eof(&bc_seq)) {
                uint8_t itag;
                DerCur  ival;
                if (!der_next(&bc_seq, &itag, &ival, NULL, NULL) || itag != 0x02U) return false;
                int pl = 0;
                if (!parse_der_int_small(&ival, &pl)) return false;
                out->has_path_len = true;
                out->path_len     = pl;
            }
        } else if (OID_MATCH(&oid, OID_EXT_KEY_USAGE)) {
            DerCur bs;
            if (!der_next(&oct, &tag, &bs, NULL, NULL) || tag != 0x03U || bs.len < 2) return false;
            uint8_t unused = bs.p[0];
            if (unused > 7) return false;
            uint16_t ku = (uint16_t)bs.p[1] << 8;
            if (bs.len >= 3) ku |= bs.p[2];
            out->has_key_usage = true;
            out->key_usage     = ku;
        } else if (OID_MATCH(&oid, OID_EXT_SAN)) {
            out->san_der = oct.p;
            out->san_len = oct.len;
        } else if (OID_MATCH(&oid, OID_EXT_SKI)) {
            DerCur ski;
            if (der_next(&oct, &tag, &ski, NULL, NULL) && tag == 0x04U) {
                out->ski_ptr = ski.p;
                out->ski_len = ski.len;
            }
        } else if (OID_MATCH(&oid, OID_EXT_AKI)) {
            DerCur aki_seq;
            if (der_next(&oct, &tag, &aki_seq, NULL, NULL) && tag == 0x30U) {
                while (!der_eof(&aki_seq)) {
                    uint8_t atag;
                    DerCur  aval;
                    if (!der_next(&aki_seq, &atag, &aval, NULL, NULL)) break;
                    if (atag == 0x80U) { /* [0] IMPLICIT KeyIdentifier */
                        out->aki_ptr = aval.p;
                        out->aki_len = aval.len;
                    }
                }
            }
        } else if (OID_MATCH(&oid, OID_EXT_EKU)) {
            DerCur eku_seq;
            if (!der_next(&oct, &tag, &eku_seq, NULL, NULL) || tag != 0x30U) return false;
            bool ok_eku = false;
            while (!der_eof(&eku_seq)) {
                uint8_t etag;
                DerCur  eoid;
                if (!der_next(&eku_seq, &etag, &eoid, NULL, NULL) || etag != 0x06U) return false;
                if (OID_MATCH(&eoid, OID_KP_SERVER_AUTH) || OID_MATCH(&eoid, OID_ANY_EKU)) {
                    ok_eku = true;
                }
            }
            out->has_eku         = true;
            out->eku_server_auth = ok_eku;
            if (!ok_eku && critical) {
                if (err && err_cap) snprintf(err, err_cap, "X.509 critical EKU excludes serverAuth");
                return false;
            }
        } else if (critical) {
            if (err && err_cap) snprintf(err, err_cap, "X.509 unsupported critical extension");
            return false;
        }
    }
    return true;
}

bool tb_x509_parse_der(const uint8_t *der, size_t der_len, TbX509Cert *out,
                       char *err, size_t err_cap) {
    memset(out, 0, sizeof(*out));
    out->version      = 1;
    out->pss_salt_len = -1;

    DerCur root, cert_seq, tbs, sig_alg_seq, sig_bs;
    uint8_t tag;
    der_init(&root, der, der_len);
    if (!der_next(&root, &tag, &cert_seq, NULL, NULL) || tag != 0x30U || !der_eof(&root)) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 outer DER sequence invalid");
        return false;
    }

    if (!der_next(&cert_seq, &tag, &tbs, &out->tbs_der, &out->tbs_len) || tag != 0x30U) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 TBSCertificate invalid");
        return false;
    }
    if (!der_next(&cert_seq, &tag, &sig_alg_seq, NULL, NULL) || tag != 0x30U) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 signatureAlgorithm invalid");
        return false;
    }
    if (!der_next(&cert_seq, &tag, &sig_bs, NULL, NULL) || tag != 0x03U ||
        sig_bs.len < 2 || sig_bs.p[0] != 0x00U || !der_eof(&cert_seq)) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 signatureValue invalid");
        return false;
    }
    out->sig_bytes = sig_bs.p + 1;
    out->sig_len   = sig_bs.len - 1;

    int outer_salt = -1;
    if (!parse_sig_alg(&sig_alg_seq, &out->sig_alg, &outer_salt)) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 signatureAlgorithm malformed");
        return false;
    }
    out->pss_salt_len = outer_salt;

    /* TBSCertificate fields */
    if (!der_peek_tag(&tbs, &tag)) return false;
    if (tag == 0xA0U) { /* [0] EXPLICIT Version */
        DerCur vwrap, vint;
        if (!der_next(&tbs, &tag, &vwrap, NULL, NULL)) return false;
        if (!der_next(&vwrap, &tag, &vint, NULL, NULL) || tag != 0x02U) return false;
        int v = 0;
        if (!parse_der_int_small(&vint, &v) || v < 0 || v > 2) return false;
        out->version = v + 1;
    }

    DerCur serial, inner_alg, issuer_val, validity, subject_val, spki;
    if (!der_next(&tbs, &tag, &serial, NULL, NULL) || tag != 0x02U || serial.len == 0) return false;
    if (!der_next(&tbs, &tag, &inner_alg, NULL, NULL) || tag != 0x30U) return false;

    TbX509SigAlg tbs_sig_alg = TB_SIG_NONE;
    int inner_salt = -1;
    if (!parse_sig_alg(&inner_alg, &tbs_sig_alg, &inner_salt) || tbs_sig_alg != out->sig_alg) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 inner/outer signatureAlgorithm mismatch");
        return false;
    }

    if (!der_next(&tbs, &tag, &issuer_val, &out->issuer_der, &out->issuer_len) || tag != 0x30U)
        return false;
    if (!der_next(&tbs, &tag, &validity, NULL, NULL) || tag != 0x30U) return false;

    uint8_t nb_tag, na_tag;
    DerCur  nb_val, na_val;
    if (!der_next(&validity, &nb_tag, &nb_val, NULL, NULL) ||
        !parse_asn1_time(nb_tag, &nb_val, &out->not_before)) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 notBefore invalid");
        return false;
    }
    if (!der_next(&validity, &na_tag, &na_val, NULL, NULL) ||
        !parse_asn1_time(na_tag, &na_val, &out->not_after)) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 notAfter invalid");
        return false;
    }

    if (!der_next(&tbs, &tag, &subject_val, &out->subject_der, &out->subject_len) || tag != 0x30U)
        return false;
    extract_common_name(subject_val, &out->cn_ptr, &out->cn_len);

    if (!der_next(&tbs, &tag, &spki, NULL, NULL) || tag != 0x30U || !parse_spki(&spki, out)) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 SubjectPublicKeyInfo invalid");
        return false;
    }

    while (!der_eof(&tbs)) {
        DerCur opt;
        if (!der_next(&tbs, &tag, &opt, NULL, NULL)) return false;
        if (tag == 0x81U || tag == 0x82U) {
            continue; /* issuerUniqueID / subjectUniqueID */
        }
        if (tag == 0xA3U) { /* [3] EXPLICIT Extensions */
            DerCur ext_seq;
            if (!der_next(&opt, &tag, &ext_seq, NULL, NULL) || tag != 0x30U) return false;
            if (!parse_extensions(&ext_seq, out, err, err_cap)) return false;
        }
    }
    return true;
}

/* ============================================================================
 * Hostname, IP Literal, and RFC 6125 Wildcard Matching
 * ============================================================================ */

static bool mem_case_eq(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (tb_tolower(a[i]) != tb_tolower(b[i])) return false;
    }
    return true;
}

bool tb_x509_wildcard_match(const char *pattern, size_t pat_len,
                            const char *host, size_t host_len) {
    if (!pattern || !host) return false;
    /* Strip optional trailing DNS root dot */
    if (pat_len > 0 && pattern[pat_len - 1] == '.') pat_len--;
    if (host_len > 0 && host[host_len - 1] == '.') host_len--;
    if (pat_len == 0 || host_len == 0) return false;

    /* Reject embedded NULs or spaces in SAN pattern */
    for (size_t i = 0; i < pat_len; i++) {
        if (pattern[i] == '\0' || pattern[i] == ' ') return false;
    }
    for (size_t i = 0; i < host_len; i++) {
        if (host[i] == '\0' || host[i] == ' ') return false;
    }

    const char *star = (const char *)memchr(pattern, '*', pat_len);
    if (!star) {
        return pat_len == host_len && mem_case_eq(pattern, host, pat_len);
    }

    /* RFC 6125 §6.4.3: '*' only allowed as complete leftmost label ("*.domain.tld") */
    if (star != pattern || pat_len < 4 || pattern[1] != '.') return false;
    const char *suffix     = pattern + 2;
    size_t      suffix_len = pat_len - 2;

    /* Reject additional wildcards or single-label TLD wildcards like "*.com" */
    if (memchr(suffix, '*', suffix_len) != NULL) return false;
    const char *suf_dot = (const char *)memchr(suffix, '.', suffix_len);
    if (!suf_dot || suf_dot == suffix || suffix[suffix_len - 1] == '.') return false;

    /* Match exactly one non-empty leftmost label in host (and reject IDN xn-- wildcard) */
    const char *host_dot = (const char *)memchr(host, '.', host_len);
    if (!host_dot || host_dot == host) return false;
    size_t label_len = (size_t)(host_dot - host);
    if (label_len >= 4 && mem_case_eq(host, "xn--", 4)) return false;

    size_t host_rem_len = host_len - label_len - 1;
    if (host_rem_len != suffix_len) return false;
    return mem_case_eq(host_dot + 1, suffix, suffix_len);
}

static bool parse_ipv4_bytes(const char *s, uint8_t out[4]) {
    int parts = 0;
    const char *p = s;
    while (*p) {
        if (parts >= 4 || !tb_isdigit(*p)) return false;
        int val = 0, digits = 0;
        if (*p == '0' && tb_isdigit(p[1])) return false;
        while (tb_isdigit(*p)) {
            val = val * 10 + (*p - '0');
            if (val > 255) return false;
            p++;
            digits++;
        }
        if (digits == 0) return false;
        out[parts++] = (uint8_t)val;
        if (*p == '.') {
            p++;
            if (!*p) return false;
        } else if (*p != '\0') {
            return false;
        }
    }
    return parts == 4;
}

static bool parse_ipv6_bytes(const char *s, uint8_t out[16]) {
    if (s[0] == '[') {
        size_t sl = strlen(s);
        if (sl < 4 || s[sl - 1] != ']') return false;
        char tmp[64];
        if (sl - 2 >= sizeof(tmp)) return false;
        memcpy(tmp, s + 1, sl - 2);
        tmp[sl - 2] = '\0';
        return parse_ipv6_bytes(tmp, out);
    }
    uint16_t groups[8] = {0};
    int ng = 0, gap = -1;
    const char *p = s;
    if (*p == ':') {
        if (p[1] != ':') return false;
        gap = 0;
        p += 2;
        if (!*p) {
            memset(out, 0, 16);
            return true;
        }
    }
    while (*p) {
        if (ng >= 8) return false;
        /* Check trailing IPv4 dotted quad (e.g. ::ffff:127.0.0.1) */
        const char *dot_chk = p;
        while (*dot_chk && *dot_chk != ':' && *dot_chk != '.') dot_chk++;
        if (*dot_chk == '.') {
            if (ng > 6) return false;
            uint8_t v4[4];
            if (!parse_ipv4_bytes(p, v4)) return false;
            groups[ng++] = (uint16_t)(((uint16_t)v4[0] << 8) | v4[1]);
            groups[ng++] = (uint16_t)(((uint16_t)v4[2] << 8) | v4[3]);
            break;
        }
        uint32_t v = 0;
        int hd = 0;
        while (tb_isxdigit(*p)) {
            int d = tb_isdigit(*p) ? (*p - '0') : (10 + tb_tolower(*p) - 'a');
            v = (v << 4) | (uint32_t)d;
            p++;
            if (++hd > 4) return false;
        }
        if (hd == 0) return false;
        groups[ng++] = (uint16_t)v;
        if (!*p) break;
        if (*p != ':') return false;
        p++;
        if (*p == ':') {
            if (gap >= 0) return false;
            gap = ng;
            p++;
            if (!*p) break;
        } else if (!*p) {
            return false;
        }
    }
    if (gap >= 0) {
        int zeros = 8 - ng;
        if (zeros < 1) return false;
        for (int i = ng - 1; i >= gap; i--) groups[i + zeros] = groups[i];
        for (int i = 0; i < zeros; i++) groups[gap + i] = 0;
        ng = 8;
    }
    if (ng != 8) return false;
    for (int i = 0; i < 8; i++) {
        out[i * 2 + 0] = (uint8_t)(groups[i] >> 8);
        out[i * 2 + 1] = (uint8_t)groups[i];
    }
    return true;
}

bool tb_x509_match_hostname(const TbX509Cert *cert, const char *host) {
    if (!cert || !host || !host[0]) return false;

    uint8_t ip_bin[16];
    size_t  ip_len = 0;
    if (parse_ipv4_bytes(host, ip_bin)) {
        ip_len = 4;
    } else if (strchr(host, ':') != NULL && parse_ipv6_bytes(host, ip_bin)) {
        ip_len = 16;
    }

    size_t host_len = strlen(host);
    bool   saw_dns_san = false;

    if (cert->san_der && cert->san_len > 0) {
        DerCur san_oct, san_seq;
        uint8_t tag;
        der_init(&san_oct, cert->san_der, cert->san_len);
        if (!der_next(&san_oct, &tag, &san_seq, NULL, NULL) || tag != 0x30U) return false;
        while (!der_eof(&san_seq)) {
            uint8_t gtag;
            DerCur  gval;
            if (!der_next(&san_seq, &gtag, &gval, NULL, NULL)) return false;
            if (gtag == 0x82U) { /* dNSName [2] IMPLICIT IA5String */
                saw_dns_san = true;
                if (ip_len == 0 &&
                    tb_x509_wildcard_match((const char *)gval.p, gval.len, host, host_len)) {
                    return true;
                }
            } else if (gtag == 0x87U) { /* iPAddress [7] IMPLICIT OCTET STRING */
                if (ip_len > 0 && gval.len == ip_len && memcmp(gval.p, ip_bin, ip_len) == 0) {
                    return true;
                }
            }
        }
    }

    if (ip_len > 0 || saw_dns_san) return false;
    if (cert->cn_ptr && cert->cn_len > 0) {
        return tb_x509_wildcard_match(cert->cn_ptr, cert->cn_len, host, host_len);
    }
    return false;
}

/* ============================================================================
 * Signature Verification (X.509 Certificate & TLS 1.3 CertificateVerify)
 * ============================================================================ */

static bool parse_ecdsa_der_sig(const uint8_t *sig, size_t sig_len,
                                size_t coord_len, uint8_t *r_out, uint8_t *s_out) {
    DerCur top, seq, rv, sv;
    uint8_t tag;
    der_init(&top, sig, sig_len);
    if (!der_next(&top, &tag, &seq, NULL, NULL) || tag != 0x30U || !der_eof(&top)) return false;
    if (!der_next(&seq, &tag, &rv, NULL, NULL) || tag != 0x02U || rv.len == 0) return false;
    if (!der_next(&seq, &tag, &sv, NULL, NULL) || tag != 0x02U || sv.len == 0 || !der_eof(&seq))
        return false;
    if ((rv.p[0] & 0x80U) || (sv.p[0] & 0x80U)) return false;

    const uint8_t *rp = rv.p; size_t rl = rv.len;
    const uint8_t *sp = sv.p; size_t sl = sv.len;
    while (rl > 0 && *rp == 0) { rp++; rl--; }
    while (sl > 0 && *sp == 0) { sp++; sl--; }
    if (rl == 0 || rl > coord_len || sl == 0 || sl > coord_len) return false;

    memset(r_out, 0, coord_len);
    memset(s_out, 0, coord_len);
    memcpy(r_out + (coord_len - rl), rp, rl);
    memcpy(s_out + (coord_len - sl), sp, sl);
    return true;
}

bool tb_x509_verify_cert_sig(const TbX509Cert *child, const TbX509Cert *issuer) {
    if (!child || !issuer || issuer->pubkey_type == TB_PUBKEY_NONE) return false;
    if (issuer->has_key_usage && (issuer->key_usage & 0x0400U) == 0) {
        /* keyCertSign is bit 5 from MSB => 0x8000 >> 5 = 0x0400 */
        return false;
    }

    uint8_t digest[64];
    size_t  dlen = 0;
    TbHashAlg halg = TB_HASH_SHA256;

    switch (child->sig_alg) {
        case TB_SIG_RSA_PKCS1_SHA256:
        case TB_SIG_RSA_PSS_SHA256:
        case TB_SIG_ECDSA_SHA256:
            tb_sha256(child->tbs_der, child->tbs_len, digest);
            dlen = 32;
            halg = TB_HASH_SHA256;
            break;
        case TB_SIG_RSA_PKCS1_SHA384:
        case TB_SIG_RSA_PSS_SHA384:
        case TB_SIG_ECDSA_SHA384:
            tb_sha384(child->tbs_der, child->tbs_len, digest);
            dlen = 48;
            halg = TB_HASH_SHA384;
            break;
        case TB_SIG_RSA_PKCS1_SHA512:
        case TB_SIG_RSA_PSS_SHA512:
        case TB_SIG_ECDSA_SHA512:
            tb_sha512(child->tbs_der, child->tbs_len, digest);
            dlen = 64;
            halg = TB_HASH_SHA512;
            break;
        default:
            return false;
    }

    if (child->sig_alg >= TB_SIG_RSA_PKCS1_SHA256 &&
        child->sig_alg <= TB_SIG_RSA_PKCS1_SHA512) {
        if (issuer->pubkey_type != TB_PUBKEY_RSA) return false;
        return tb_rsa_verify_pkcs1(issuer->rsa_n, issuer->rsa_n_len,
                                   issuer->rsa_e, issuer->rsa_e_len,
                                   halg, digest, dlen,
                                   child->sig_bytes, child->sig_len);
    }

    if (child->sig_alg >= TB_SIG_RSA_PSS_SHA256 &&
        child->sig_alg <= TB_SIG_RSA_PSS_SHA512) {
        if (issuer->pubkey_type != TB_PUBKEY_RSA) return false;
        return tb_rsa_verify_pss(issuer->rsa_n, issuer->rsa_n_len,
                                 issuer->rsa_e, issuer->rsa_e_len,
                                 halg, digest, dlen, child->pss_salt_len,
                                 child->sig_bytes, child->sig_len);
    }

    if (issuer->pubkey_type == TB_PUBKEY_EC_P256) {
        uint8_t r[32], s[32];
        if (!parse_ecdsa_der_sig(child->sig_bytes, child->sig_len, 32, r, s)) return false;
        return tb_ecdsa_p256_verify(issuer->ec_xy, digest, dlen, r, s);
    }
    if (issuer->pubkey_type == TB_PUBKEY_EC_P384) {
        uint8_t r[48], s[48];
        if (!parse_ecdsa_der_sig(child->sig_bytes, child->sig_len, 48, r, s)) return false;
        return tb_ecdsa_p384_verify(issuer->ec_xy, digest, dlen, r, s);
    }
    return false;
}

bool tb_x509_verify_tls13_sig(const TbX509Cert *leaf, uint16_t sig_scheme,
                              const uint8_t *transcript_hash, size_t th_len,
                              const uint8_t *sig, size_t sig_len) {
    if (!leaf || !transcript_hash || (th_len != 32 && th_len != 48)) return false;
    if (leaf->has_key_usage && (leaf->key_usage & 0x8000U) == 0) {
        /* digitalSignature is bit 0 from MSB => 0x8000 */
        return false;
    }

    static const char CTX_STR[] = "TLS 1.3, server CertificateVerify";
    uint8_t msg[64 + 33 + 1 + 48];
    memset(msg, 0x20, 64);
    memcpy(msg + 64, CTX_STR, 33);
    msg[64 + 33] = 0x00U;
    memcpy(msg + 98, transcript_hash, th_len);
    size_t msg_len = 98 + th_len;

    uint8_t digest[64];
    switch (sig_scheme) {
        case 0x0403U: { /* ecdsa_secp256r1_sha256 */
            if (leaf->pubkey_type != TB_PUBKEY_EC_P256) return false;
            uint8_t r[32], s[32];
            if (!parse_ecdsa_der_sig(sig, sig_len, 32, r, s)) return false;
            tb_sha256(msg, msg_len, digest);
            return tb_ecdsa_p256_verify(leaf->ec_xy, digest, 32, r, s);
        }
        case 0x0503U: { /* ecdsa_secp384r1_sha384 */
            if (leaf->pubkey_type != TB_PUBKEY_EC_P384) return false;
            uint8_t r[48], s[48];
            if (!parse_ecdsa_der_sig(sig, sig_len, 48, r, s)) return false;
            tb_sha384(msg, msg_len, digest);
            return tb_ecdsa_p384_verify(leaf->ec_xy, digest, 48, r, s);
        }
        case 0x0804U:   /* rsa_pss_rsae_sha256 */
        case 0x0809U: { /* rsa_pss_pss_sha256 */
            if (leaf->pubkey_type != TB_PUBKEY_RSA) return false;
            tb_sha256(msg, msg_len, digest);
            return tb_rsa_verify_pss(leaf->rsa_n, leaf->rsa_n_len,
                                     leaf->rsa_e, leaf->rsa_e_len,
                                     TB_HASH_SHA256, digest, 32, 32, sig, sig_len);
        }
        case 0x0805U:   /* rsa_pss_rsae_sha384 */
        case 0x080aU: { /* rsa_pss_pss_sha384 */
            if (leaf->pubkey_type != TB_PUBKEY_RSA) return false;
            tb_sha384(msg, msg_len, digest);
            return tb_rsa_verify_pss(leaf->rsa_n, leaf->rsa_n_len,
                                     leaf->rsa_e, leaf->rsa_e_len,
                                     TB_HASH_SHA384, digest, 48, 48, sig, sig_len);
        }
        case 0x0806U:   /* rsa_pss_rsae_sha512 */
        case 0x080bU: { /* rsa_pss_pss_sha512 */
            if (leaf->pubkey_type != TB_PUBKEY_RSA) return false;
            tb_sha512(msg, msg_len, digest);
            return tb_rsa_verify_pss(leaf->rsa_n, leaf->rsa_n_len,
                                     leaf->rsa_e, leaf->rsa_e_len,
                                     TB_HASH_SHA512, digest, 64, 64, sig, sig_len);
        }
        default:
            return false;
    }
}

/* ============================================================================
 * OpenSSL X509_NAME Canonical Subject Hash + Streaming PEM CA Store Verifier
 * ============================================================================ */

static void der_append_tlv(TbBuf *b, uint8_t tag, const uint8_t *val, size_t len) {
    tb_buf_append_char(b, (char)tag);
    if (len < 128) {
        tb_buf_append_char(b, (char)len);
    } else if (len < 256) {
        tb_buf_append_char(b, (char)0x81);
        tb_buf_append_char(b, (char)len);
    } else {
        tb_buf_append_char(b, (char)0x82);
        tb_buf_append_char(b, (char)(len >> 8));
        tb_buf_append_char(b, (char)len);
    }
    if (len > 0) tb_buf_append(b, (const char *)val, len);
}

static bool is_asn1_canon_str_tag(uint8_t tag) {
    return tag == 0x0CU || tag == 0x13U || tag == 0x16U ||
           tag == 0x14U || tag == 0x1CU || tag == 0x1EU || tag == 0x12U;
}

static void asn1_str_to_utf8(uint8_t tag, const uint8_t *p, size_t len, TbBuf *u8) {
    if (tag == 0x1EU && (len & 1U) == 0) { /* BMPString: UTF-16BE */
        for (size_t i = 0; i + 1 < len; i += 2) {
            uint32_t cp = ((uint32_t)p[i] << 8) | p[i + 1];
            char tmp[4];
            tb_buf_append(u8, tmp, tb_utf8_encode(cp, tmp));
        }
    } else if (tag == 0x1CU && (len & 3U) == 0) { /* UniversalString: UTF-32BE */
        for (size_t i = 0; i + 3 < len; i += 4) {
            uint32_t cp = ((uint32_t)p[i] << 24) | ((uint32_t)p[i + 1] << 16) |
                          ((uint32_t)p[i + 2] << 8) | p[i + 3];
            char tmp[4];
            tb_buf_append(u8, tmp, tb_utf8_encode(cp, tmp));
        }
    } else if (tag == 0x14U) { /* TeletexString / T61String: treated as Latin-1 by OpenSSL */
        for (size_t i = 0; i < len; i++) {
            char tmp[4];
            tb_buf_append(u8, tmp, tb_utf8_encode(p[i], tmp));
        }
    } else {
        if (len > 0) tb_buf_append(u8, (const char *)p, len);
    }
}

uint32_t tb_x509_subject_hash_openssl(const uint8_t *name_der, size_t name_len) {
    DerCur top, seq;
    uint8_t tag;
    der_init(&top, name_der, name_len);
    if (!der_next(&top, &tag, &seq, NULL, NULL) || tag != 0x30U) return 0;

    TbBuf canon;
    tb_buf_init(&canon);

    while (!der_eof(&seq)) {
        uint8_t stag;
        DerCur  rdn_set;
        if (!der_next(&seq, &stag, &rdn_set, NULL, NULL) || stag != 0x31U) break;

        TbBuf  atv_tlvs[16];
        size_t atv_cnt = 0;

        while (!der_eof(&rdn_set) && atv_cnt < 16) {
            uint8_t atag, otag, vtag;
            DerCur  atv, oid, val;
            const uint8_t *oid_tlv = NULL, *val_tlv = NULL;
            size_t oid_tlv_len = 0, val_tlv_len = 0;
            if (!der_next(&rdn_set, &atag, &atv, NULL, NULL) || atag != 0x30U) break;
            if (!der_next(&atv, &otag, &oid, &oid_tlv, &oid_tlv_len) || otag != 0x06U) continue;
            if (!der_next(&atv, &vtag, &val, &val_tlv, &val_tlv_len)) continue;

            TbBuf atv_body;
            tb_buf_init(&atv_body);
            tb_buf_append(&atv_body, (const char *)oid_tlv, oid_tlv_len);

            if (is_asn1_canon_str_tag(vtag)) {
                TbBuf u8buf, sbuf;
                tb_buf_init(&u8buf);
                tb_buf_init(&sbuf);
                asn1_str_to_utf8(vtag, val.p, val.len, &u8buf);

                const uint8_t *up = (const uint8_t *)(u8buf.data ? u8buf.data : "");
                size_t i = 0, end = u8buf.len;
                while (i < end && (up[i] == ' ' || up[i] == '\t' ||
                                   up[i] == '\r' || up[i] == '\n')) i++;
                while (end > i && (up[end - 1] == ' ' || up[end - 1] == '\t' ||
                                   up[end - 1] == '\r' || up[end - 1] == '\n')) end--;
                bool in_ws = false;
                for (; i < end; i++) {
                    uint8_t ch = up[i];
                    if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                        if (!in_ws) {
                            tb_buf_append_char(&sbuf, ' ');
                            in_ws = true;
                        }
                    } else {
                        in_ws = false;
                        if (ch >= 'A' && ch <= 'Z') ch = (uint8_t)(ch + 32);
                        tb_buf_append_char(&sbuf, (char)ch);
                    }
                }
                der_append_tlv(&atv_body, 0x0CU, (const uint8_t *)(sbuf.data ? sbuf.data : ""), sbuf.len);
                tb_buf_free(&sbuf);
                tb_buf_free(&u8buf);
            } else {
                tb_buf_append(&atv_body, (const char *)val_tlv, val_tlv_len);
            }

            tb_buf_init(&atv_tlvs[atv_cnt]);
            der_append_tlv(&atv_tlvs[atv_cnt], 0x30U,
                           (const uint8_t *)(atv_body.data ? atv_body.data : ""), atv_body.len);
            tb_buf_free(&atv_body);
            atv_cnt++;
        }

        /* DER SET OF canonical ordering: sort multi-valued RDN elements lexicographically */
        for (size_t a = 1; a < atv_cnt; a++) {
            TbBuf key = atv_tlvs[a];
            size_t b = a;
            while (b > 0) {
                size_t min_len = atv_tlvs[b - 1].len < key.len ? atv_tlvs[b - 1].len : key.len;
                int cmp = (min_len > 0) ? memcmp(atv_tlvs[b - 1].data, key.data, min_len) : 0;
                if (cmp > 0 || (cmp == 0 && atv_tlvs[b - 1].len > key.len)) {
                    atv_tlvs[b] = atv_tlvs[b - 1];
                    b--;
                } else {
                    break;
                }
            }
            atv_tlvs[b] = key;
        }

        TbBuf set_body;
        tb_buf_init(&set_body);
        for (size_t a = 0; a < atv_cnt; a++) {
            if (atv_tlvs[a].len > 0) tb_buf_append(&set_body, atv_tlvs[a].data, atv_tlvs[a].len);
            tb_buf_free(&atv_tlvs[a]);
        }
        der_append_tlv(&canon, 0x31U, (const uint8_t *)(set_body.data ? set_body.data : ""), set_body.len);
        tb_buf_free(&set_body);
    }

    uint8_t md[20];
    tb_sha1(canon.data ? canon.data : "", canon.len, md);
    tb_buf_free(&canon);
    return (uint32_t)md[0] | ((uint32_t)md[1] << 8) |
           ((uint32_t)md[2] << 16) | ((uint32_t)md[3] << 24);
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool check_ca_candidate(const uint8_t *ca_der, size_t ca_len,
                               const TbX509Cert *target, int inter_depth,
                               int64_t now_unix) {
    TbX509Cert ca;
    if (!tb_x509_parse_der(ca_der, ca_len, &ca, NULL, 0)) return false;

    /* Subject of CA must match Issuer of target */
    if (ca.subject_len != target->issuer_len ||
        memcmp(ca.subject_der, target->issuer_der, ca.subject_len) != 0) {
        return false;
    }
    /* Root / trusted CA validity & RFC 5280 constraints */
    if (ca.version >= 3 && (!ca.has_basic_constraints || !ca.is_ca)) return false;
    if (ca.has_basic_constraints && !ca.is_ca) return false;
    if (ca.has_key_usage && (ca.key_usage & 0x0400U) == 0) return false; /* keyCertSign */
    if (ca.has_eku && !ca.eku_server_auth) return false;
    if (ca.has_path_len && ca.path_len < inter_depth) return false;
    if (now_unix > 0 && (now_unix < ca.not_before || now_unix > ca.not_after)) return false;
    if (target->aki_ptr && ca.ski_ptr &&
        (target->aki_len != ca.ski_len ||
         memcmp(target->aki_ptr, ca.ski_ptr, ca.ski_len) != 0)) {
        return false;
    }
    return tb_x509_verify_cert_sig(target, &ca);
}

/* Stream a PEM file using an 8 KB stack buffer + 6 KB DER buffer (zero large heap footprint,
 * supports arbitrary Base64 line lengths including single-line PEM payloads). */
static bool verify_against_pem_file(const char *pem_path, const TbX509Cert *target,
                                    int inter_depth, int64_t now_unix) {
    int fd = open(pem_path, O_RDONLY);
    if (fd < 0) return false;

    static const char BEGIN_MARK[] = "-----BEGIN CERTIFICATE-----";
    static const char END_MARK[]   = "-----END CERTIFICATE-----";

    char     io_buf[8192];
    char     hdr_buf[256];
    size_t   hdr_len      = 0;

    uint8_t  der_buf[6144];
    size_t   der_len      = 0;
    uint32_t b64_acc      = 0;
    int      b64_cnt      = 0;
    bool     in_cert      = false;
    bool     line_started = false;
    bool     line_is_hdr  = false;
    bool     der_overflow = false;

    for (;;) {
        ssize_t n = read(fd, io_buf, sizeof(io_buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        size_t chunk = (size_t)n;
        for (size_t i = 0; i <= chunk; i++) {
            if (i == chunk && (chunk > 0 || (!line_started && hdr_len == 0))) break;
            char c = (i < chunk) ? io_buf[i] : '\n';
            if (c == '\r') continue;

            if (c != '\n') {
                if (!in_cert) {
                    if (hdr_len + 1 < sizeof(hdr_buf)) hdr_buf[hdr_len++] = c;
                } else {
                    if (!line_started) {
                        if (c == ' ' || c == '\t') continue;
                        line_started = true;
                        line_is_hdr  = (c == '-');
                    }
                    if (line_is_hdr) {
                        if (hdr_len + 1 < sizeof(hdr_buf)) hdr_buf[hdr_len++] = c;
                    } else if (!der_overflow && c != '=' && c != ' ' && c != '\t') {
                        int v = b64_val(c);
                        if (v >= 0) {
                            b64_acc = (b64_acc << 6) | (uint32_t)v;
                            b64_cnt++;
                            if (b64_cnt == 4) {
                                if (der_len + 3 > sizeof(der_buf)) {
                                    der_overflow = true;
                                } else {
                                    der_buf[der_len++] = (uint8_t)(b64_acc >> 16);
                                    der_buf[der_len++] = (uint8_t)(b64_acc >> 8);
                                    der_buf[der_len++] = (uint8_t)b64_acc;
                                }
                                b64_acc = 0;
                                b64_cnt = 0;
                            }
                        }
                    }
                }
                continue;
            }

            /* End of line */
            hdr_buf[hdr_len] = '\0';
            if (!in_cert) {
                if (strstr(hdr_buf, BEGIN_MARK) != NULL) {
                    in_cert      = true;
                    der_len      = 0;
                    b64_acc      = 0;
                    b64_cnt      = 0;
                    der_overflow = false;
                }
            } else if (line_is_hdr && strstr(hdr_buf, END_MARK) != NULL) {
                if (!der_overflow && b64_cnt > 0) {
                    if (b64_cnt == 2 && der_len + 1 <= sizeof(der_buf)) {
                        der_buf[der_len++] = (uint8_t)(b64_acc >> 4);
                    } else if (b64_cnt == 3 && der_len + 2 <= sizeof(der_buf)) {
                        der_buf[der_len++] = (uint8_t)(b64_acc >> 10);
                        der_buf[der_len++] = (uint8_t)(b64_acc >> 2);
                    } else {
                        der_overflow = true;
                    }
                }
                in_cert = false;
                if (!der_overflow && der_len > 0 &&
                    check_ca_candidate(der_buf, der_len, target, inter_depth, now_unix)) {
                    close(fd);
                    return true;
                }
            }
            hdr_len      = 0;
            line_started = false;
            line_is_hdr  = false;
        }
        if (n == 0) break;
    }

    close(fd);
    return false;
}

static bool verify_against_trust_store(const TbX509Cert *target, int inter_depth,
                                       int64_t now_unix, const char *ca_file_override) {
    if (ca_file_override && ca_file_override[0]) {
        return verify_against_pem_file(ca_file_override, target, inter_depth, now_unix);
    }

    /* Tier 1: O(1) OpenSSL /etc/ssl/certs/<8-hex-hash>.<idx> lookup (~1.5 KB read) */
    uint32_t h = tb_x509_subject_hash_openssl(target->issuer_der, target->issuer_len);
    for (int idx = 0; idx < 4; idx++) {
        char path[64];
        snprintf(path, sizeof(path), "/etc/ssl/certs/%08x.%d", h, idx);
        struct stat st;
        if (stat(path, &st) != 0) break;
        if (verify_against_pem_file(path, target, inter_depth, now_unix)) return true;
    }

    /* Tier 2: 8 KB streaming scan of system PEM bundle */
    static const char *const BUNDLES[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem"
    };
    for (size_t i = 0; i < sizeof(BUNDLES) / sizeof(BUNDLES[0]); i++) {
        struct stat st;
        if (stat(BUNDLES[i], &st) == 0) {
            return verify_against_pem_file(BUNDLES[i], target, inter_depth, now_unix);
        }
    }
    return false;
}

static bool verify_chain_dfs(const TbX509Cert *certs, const bool *cand_ok,
                             size_t cert_count, size_t cur_idx,
                             int inter_depth, bool used[10],
                             int64_t now_unix, const char *ca_file_override,
                             bool *saw_expired_issuer) {
    if (inter_depth >= 10) return false;
    const TbX509Cert *cur = &certs[cur_idx];

    /* 1. Can `cur` be verified directly by a trusted Root CA in our trust store? */
    if (verify_against_trust_store(cur, inter_depth, now_unix, ca_file_override)) {
        return true;
    }

    /* 2. Explore all candidate intermediate CAs in certs[1..cert_count-1] that issued `cur` */
    for (size_t j = 1; j < cert_count; j++) {
        if (used[j] || !cand_ok[j]) continue;
        const TbX509Cert *cand = &certs[j];
        if (cand->subject_len != cur->issuer_len ||
            memcmp(cand->subject_der, cur->issuer_der, cand->subject_len) != 0) {
            continue;
        }
        if (cand->version >= 3 && (!cand->has_basic_constraints || !cand->is_ca)) continue;
        if (!cand->has_basic_constraints || !cand->is_ca) continue;
        if (cand->has_key_usage && (cand->key_usage & 0x0400U) == 0) continue; /* keyCertSign */
        if (cand->has_eku && !cand->eku_server_auth) continue;
        if (cand->has_path_len && cand->path_len < inter_depth) continue;
        if (cur->aki_ptr && cand->ski_ptr &&
            (cur->aki_len != cand->ski_len ||
             memcmp(cur->aki_ptr, cand->ski_ptr, cand->ski_len) != 0)) {
            continue;
        }
        if (now_unix > 0 && (now_unix < cand->not_before || now_unix > cand->not_after)) {
            if (saw_expired_issuer) *saw_expired_issuer = true;
            continue;
        }
        if (!tb_x509_verify_cert_sig(cur, cand)) continue;

        used[j] = true;
        if (verify_chain_dfs(certs, cand_ok, cert_count, j, inter_depth + 1,
                             used, now_unix, ca_file_override, saw_expired_issuer)) {
            return true;
        }
        used[j] = false;
    }
    return false;
}

bool tb_x509_verify_chain(const uint8_t *const *cert_ders, const size_t *cert_lens,
                          size_t cert_count, const char *host, int64_t now_unix,
                          const char *ca_file_override, char *err, size_t err_cap) {
    if (!cert_ders || !cert_lens || cert_count == 0) {
        if (err && err_cap) snprintf(err, err_cap, "TLS server sent empty certificate chain");
        return false;
    }
    if (cert_count > 10) cert_count = 10;

    TbX509Cert certs[10];
    bool       cand_ok[10] = { false };

    /* 1. Strictly parse and validate leaf certificate (certs[0]) */
    if (!tb_x509_parse_der(cert_ders[0], cert_lens[0], &certs[0], err, err_cap)) {
        return false;
    }
    if (now_unix > 0 && (now_unix < certs[0].not_before || now_unix > certs[0].not_after)) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 certificate expired or not yet valid");
        return false;
    }
    if (certs[0].has_eku && !certs[0].eku_server_auth) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 leaf ExtendedKeyUsage excludes serverAuth");
        return false;
    }
    if (host && host[0] && !tb_x509_match_hostname(&certs[0], host)) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 hostname/SAN mismatch for '%s'", host);
        return false;
    }
    cand_ok[0] = true;

    /* 2. Parse candidate intermediates tolerantly so unused/expired cross-signs don't block valid paths */
    for (size_t i = 1; i < cert_count; i++) {
        cand_ok[i] = tb_x509_parse_der(cert_ders[i], cert_lens[i], &certs[i], NULL, 0);
    }

    /* 3. Bounded DFS trust-path discovery across out-of-order & cross-signed intermediates */
    bool used[10] = { false };
    used[0] = true;
    bool saw_expired_issuer = false;
    if (verify_chain_dfs(certs, cand_ok, cert_count, 0, 0, used,
                         now_unix, ca_file_override, &saw_expired_issuer)) {
        return true;
    }

    if (saw_expired_issuer) {
        if (err && err_cap) snprintf(err, err_cap, "X.509 intermediate certificate expired or not yet valid");
    } else {
        if (err && err_cap) snprintf(err, err_cap, "X.509 certificate chain not signed by trusted CA");
    }
    return false;
}
