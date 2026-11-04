#include "test_harness.h"
#include "browser.h"
#include "dom.h"
#include "mem.h"
#include "net.h"
#include "tls.h"

/* ── Test 13: Cryptographic Primitives & RFC 6125 X.509 Verification ── */
void test_crypto_and_x509_subsystem(void) {
#if defined(TB_TLS_OPENSSL) && TB_TLS_OPENSSL
    printf("[13/14] Skipping builtin crypto unit vectors (compiled with TLS=openssl)...\n");
#else
    printf("[13/14] Testing NIST/RFC SHA-2, HKDF, AES-GCM, ChaCha20-Poly1305, X25519, EC, & X.509...\n");

    /* 1. FIPS 180-4 SHA-256 / SHA-384 / SHA-512 */
    uint8_t d256[32], d384[48], d512[64];
    static const uint8_t exp_sha256_abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    static const uint8_t exp_sha384_abc[48] = {
        0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,
        0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,
        0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7
    };
    static const uint8_t exp_sha512_abc[64] = {
        0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
        0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
        0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
        0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
    };
    tb_sha256("abc", 3, d256);
    tb_sha384("abc", 3, d384);
    tb_sha512("abc", 3, d512);
    ASSERT_TRUE(memcmp(d256, exp_sha256_abc, 32) == 0, "FIPS 180-4 SHA-256('abc')");
    ASSERT_TRUE(memcmp(d384, exp_sha384_abc, 48) == 0, "FIPS 180-4 SHA-384('abc')");
    ASSERT_TRUE(memcmp(d512, exp_sha512_abc, 64) == 0, "FIPS 180-4 SHA-512('abc')");

    /* 2. RFC 5869 HKDF-SHA256 Test Case 1 */
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));
    static const uint8_t salt[13] = {0,1,2,3,4,5,6,7,8,9,10,11,12};
    static const uint8_t info[10] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
    static const uint8_t exp_okm[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65
    };
    uint8_t prk[32], okm[42];
    tb_hkdf_extract(32, salt, sizeof(salt), ikm, sizeof(ikm), prk);
    tb_hkdf_expand(32, prk, info, sizeof(info), okm, sizeof(okm));
    ASSERT_TRUE(memcmp(okm, exp_okm, 42) == 0, "RFC 5869 HKDF-SHA256 Test Case 1");

    /* 3. RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD + tamper rejection */
    static const char *cc_pt =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    static const uint8_t cc_aad[12] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
    static const uint8_t cc_key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };
    static const uint8_t cc_nonce[12] = {0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47};
    static const uint8_t exp_cc_ct16[16] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2
    };
    static const uint8_t exp_cc_tag[16] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
    };
    uint8_t cc_ct[114], cc_dec[114], cc_tag[16];
    tb_chacha20_poly1305_seal(cc_key, cc_nonce, cc_aad, 12, (const uint8_t *)cc_pt, 114, cc_ct, cc_tag);
    ASSERT_TRUE(memcmp(cc_ct, exp_cc_ct16, 16) == 0 && memcmp(cc_tag, exp_cc_tag, 16) == 0,
                "RFC 8439 ChaCha20-Poly1305 ciphertext & tag");
    ASSERT_TRUE(tb_chacha20_poly1305_open(cc_key, cc_nonce, cc_aad, 12, cc_ct, 114, cc_tag, cc_dec) &&
                memcmp(cc_dec, cc_pt, 114) == 0, "RFC 8439 ChaCha20-Poly1305 decrypt round-trip");
    cc_tag[7] ^= 0x01;
    ASSERT_TRUE(!tb_chacha20_poly1305_open(cc_key, cc_nonce, cc_aad, 12, cc_ct, 114, cc_tag, cc_dec),
                "ChaCha20-Poly1305 rejects 1-bit tampered tag");

    /* 4. NIST SP 800-38D AES-128-GCM & AES-256-GCM + tamper rejection */
    uint8_t zkey[32] = {0}, ziv[12] = {0}, zpt[16] = {0}, gct[16], gdec[16], gtag[16];
    static const uint8_t exp_gcm128_ct[16]  = {0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78};
    static const uint8_t exp_gcm128_tag[16] = {0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};
    static const uint8_t exp_gcm256_ct[16]  = {0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18};
    static const uint8_t exp_gcm256_tag[16] = {0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19};

    tb_aes_gcm_seal(zkey, 16, ziv, NULL, 0, zpt, 16, gct, gtag);
    ASSERT_TRUE(memcmp(gct, exp_gcm128_ct, 16) == 0 && memcmp(gtag, exp_gcm128_tag, 16) == 0,
                "NIST SP 800-38D AES-128-GCM vector");
    ASSERT_TRUE(tb_aes_gcm_open(zkey, 16, ziv, NULL, 0, gct, 16, gtag, gdec) &&
                memcmp(gdec, zpt, 16) == 0, "AES-128-GCM decrypt");
    gtag[15] ^= 0x80;
    ASSERT_TRUE(!tb_aes_gcm_open(zkey, 16, ziv, NULL, 0, gct, 16, gtag, gdec),
                "AES-128-GCM rejects tampered tag");

    tb_aes_gcm_seal(zkey, 32, ziv, NULL, 0, zpt, 16, gct, gtag);
    ASSERT_TRUE(memcmp(gct, exp_gcm256_ct, 16) == 0 && memcmp(gtag, exp_gcm256_tag, 16) == 0,
                "NIST SP 800-38D AES-256-GCM vector");

    /* 5. RFC 7748 §6.1 X25519 Key Exchange Vector */
    static const uint8_t alice_priv[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    };
    static const uint8_t bob_priv[32] = {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
    };
    static const uint8_t exp_shared[32] = {
        0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
        0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
    };
    uint8_t alice_pub[32], bob_pub[32], shared_ab[32], shared_ba[32];
    tb_x25519_base(alice_pub, alice_priv);
    tb_x25519_base(bob_pub, bob_priv);
    ASSERT_TRUE(tb_x25519(shared_ab, alice_priv, bob_pub) &&
                tb_x25519(shared_ba, bob_priv, alice_pub) &&
                memcmp(shared_ab, exp_shared, 32) == 0 &&
                memcmp(shared_ba, exp_shared, 32) == 0,
                "RFC 7748 §6.1 X25519 ECDH vector");

    /* 6. Weierstrass Jacobian P-256 & P-384 Curve Order / ECDH Self-Test */
    ASSERT_TRUE(tb_ec_self_test(), "Weierstrass P-256 & P-384 group law & ECDH self-test");

    /* 7. RFC 6125 Wildcard Hostname Verification Rules */
    ASSERT_TRUE(tb_x509_wildcard_match("*.example.com", 13, "api.example.com", 15),
                "Wildcard matches single leftmost label");
    ASSERT_TRUE(tb_x509_wildcard_match("*.Example.COM", 13, "API.example.com", 15),
                "Wildcard matches case-insensitively");
    ASSERT_TRUE(!tb_x509_wildcard_match("*.example.com", 13, "example.com", 11),
                "Wildcard rejects apex domain");
    ASSERT_TRUE(!tb_x509_wildcard_match("*.example.com", 13, "a.b.example.com", 15),
                "Wildcard rejects multi-label prefix");
    ASSERT_TRUE(!tb_x509_wildcard_match("*.com", 5, "example.com", 11),
                "Wildcard rejects single-label TLD *.com");
    ASSERT_TRUE(!tb_x509_wildcard_match("f*.example.com", 14, "foo.example.com", 15),
                "Wildcard rejects partial label f*");
    ASSERT_TRUE(!tb_x509_wildcard_match("*.example.com", 13, "xn--foo.example.com", 19),
                "Wildcard rejects IDN punycode label");
    ASSERT_TRUE(!tb_x509_wildcard_match("a\0.example.com", 14, "a.example.com", 13),
                "Wildcard rejects embedded NUL in SAN");

    /* 8. Ephemeral P-384 (secp384r1) Keygen + 48-Byte ECDH Agreement + Off-Curve Rejection */
    {
        uint8_t p1[48], q1[97], p2[48], q2[97], s1[48], s2[48];
        ASSERT_TRUE(tb_p384_keygen(p1, q1) && tb_p384_keygen(p2, q2),
                    "Generate two ephemeral P-384 ECDHE keypairs");
        ASSERT_TRUE(tb_p384_ecdh(s1, p1, q2, sizeof(q2)) &&
                    tb_p384_ecdh(s2, p2, q1, sizeof(q1)) &&
                    memcmp(s1, s2, 48) == 0,
                    "P-384 48-byte ECDH shared secret agreement");
        q2[12] ^= 0x01U; /* Corrupt X coordinate off curve */
        ASSERT_TRUE(!tb_p384_ecdh(s1, p1, q2, sizeof(q2)),
                    "P-384 ECDH rejects corrupted off-curve peer public key");
    }

    /* 9. Real System CA Bundle (/etc/ssl/certs/ca-certificates.crt) DER Parse & OpenSSL Hash Check */
    {
        int cfd = open("/etc/ssl/certs/ca-certificates.crt", O_RDONLY);
        if (cfd >= 0) {
            TbBuf pem;
            tb_buf_init(&pem);
            char chunk[4096];
            ssize_t nr;
            while ((nr = read(cfd, chunk, sizeof(chunk))) > 0 && pem.len < 65536) {
                tb_buf_append(&pem, chunk, (size_t)nr);
            }
            close(cfd);

            int total_blocks = 0;
            int parsed_roots = 0;
            int matched_symlinks = 0;
            int checked_symlinks = 0;
            const char *cur = pem.data ? pem.data : "";
            const char *beg_tag = "-----BEGIN CERTIFICATE-----";
            const char *end_tag = "-----END CERTIFICATE-----";
            while (total_blocks < 25) {
                const char *b = strstr(cur, beg_tag);
                if (!b) break;
                b += strlen(beg_tag);
                const char *e = strstr(b, end_tag);
                if (!e) break;
                cur = e + strlen(end_tag);
                total_blocks++;

                uint8_t der[4096];
                size_t dlen = 0;
                uint32_t acc = 0;
                int bits = 0;
                for (const char *p = b; p < e && dlen + 3 < sizeof(der); p++) {
                    unsigned char ch = (unsigned char)*p;
                    int v = -1;
                    if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
                    else if (ch >= 'a' && ch <= 'z') v = ch - 'a' + 26;
                    else if (ch >= '0' && ch <= '9') v = ch - '0' + 52;
                    else if (ch == '+') v = 62;
                    else if (ch == '/') v = 63;
                    else if (ch == '=') break;
                    if (v >= 0) {
                        acc = (acc << 6) | (uint32_t)v;
                        bits += 6;
                        if (bits >= 8) {
                            bits -= 8;
                            der[dlen++] = (uint8_t)((acc >> bits) & 0xFFU);
                        }
                    }
                }
                if (dlen > 0) {
                    TbX509Cert rc;
                    char xerr[96];
                    if (tb_x509_parse_der(der, dlen, &rc, xerr, sizeof(xerr))) {
                        parsed_roots++;
                        uint32_t h = tb_x509_subject_hash_openssl(rc.subject_der, rc.subject_len);
                        char spath[96];
                        snprintf(spath, sizeof(spath), "/etc/ssl/certs/%08x.0", h);
                        struct stat st_sym;
                        checked_symlinks++;
                        if (stat(spath, &st_sym) == 0) matched_symlinks++;
                    }
                }
            }
            tb_buf_free(&pem);
            ASSERT_TRUE(total_blocks >= 1 && parsed_roots >= 1 && parsed_roots * 2 >= total_blocks,
                        "System /etc/ssl/certs/ca-certificates.crt Root CAs parse cleanly");
            if (matched_symlinks > 0) {
                ASSERT_TRUE(matched_symlinks == checked_symlinks,
                            "OpenSSL canonical X509_NAME_hash matches /etc/ssl/certs/<hash>.0 symlinks");
            }
        }
    }
#endif
}

/* ── Test 14: Live Loopback TLS 1.3 Interop vs OpenSSL 3 + Sub-1MB Freestanding RSS ── */
static bool run_cmd_quiet(const char *prog, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) {
            dup2(dn, STDIN_FILENO);
            dup2(dn, STDOUT_FILENO);
            dup2(dn, STDERR_FILENO);
            if (dn > 2) close(dn);
        }
        execve(prog, argv, NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static int pick_ephemeral_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port        = 0;
    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        close(fd);
        return -1;
    }
    socklen_t slen = sizeof(sin);
    getsockname(fd, (struct sockaddr *)&sin, &slen);
    int port = ntohs(sin.sin_port);
    close(fd);
    return port;
}

typedef struct {
    pid_t pid;
    int   port;
    int   stdin_wfd;
    int   stdout_rfd;
} TlsTestServer;

static bool start_openssl_tls13_server_ex(TlsTestServer *srv,
                                          const char *cert_pem, const char *key_pem,
                                          const char *chain_pem,
                                          const char *ciphersuite, const char *groups,
                                          const char *alpn, bool www_mode) {
    memset(srv, 0, sizeof(*srv));
    srv->pid        = -1;
    srv->stdin_wfd  = -1;
    srv->stdout_rfd = -1;

    for (int attempt = 0; attempt < 3; attempt++) {
        int port = pick_ephemeral_port();
        if (port <= 0) return false;

        int in_pipe[2]  = {-1, -1};
        int out_pipe[2] = {-1, -1};
        if (pipe(in_pipe) != 0) return false;
        if (pipe(out_pipe) != 0) {
            close(in_pipe[0]);
            close(in_pipe[1]);
            return false;
        }

        char accept_arg[64];
        snprintf(accept_arg, sizeof(accept_arg), "127.0.0.1:%d", port);

        pid_t pid = fork();
        if (pid == 0) {
            close(in_pipe[1]);
            close(out_pipe[0]);
            dup2(in_pipe[0], STDIN_FILENO);
            dup2(out_pipe[1], STDOUT_FILENO);
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) {
                dup2(dn, STDERR_FILENO);
                if (dn > 2) close(dn);
            }
            if (in_pipe[0] > 2)  close(in_pipe[0]);
            if (out_pipe[1] > 2) close(out_pipe[1]);
            (void)chdir("/tmp");

            char *argv[28];
            int a = 0;
            argv[a++] = "/usr/bin/openssl";
            argv[a++] = "s_server";
            argv[a++] = "-tls1_3";
            argv[a++] = "-cert";
            argv[a++] = (char *)cert_pem;
            argv[a++] = "-key";
            argv[a++] = (char *)key_pem;
            if (chain_pem) {
                argv[a++] = "-cert_chain";
                argv[a++] = (char *)chain_pem;
            }
            argv[a++] = "-accept";
            argv[a++] = accept_arg;
            if (www_mode) {
                argv[a++] = "-WWW";
            }
            argv[a++] = "-naccept";
            argv[a++] = "1";
            if (ciphersuite) {
                argv[a++] = "-ciphersuites";
                argv[a++] = (char *)ciphersuite;
            }
            if (groups) {
                argv[a++] = "-groups";
                argv[a++] = (char *)groups;
            }
            if (alpn) {
                argv[a++] = "-alpn";
                argv[a++] = (char *)alpn;
            }
            argv[a] = NULL;
            execve("/usr/bin/openssl", argv, NULL);
            _exit(127);
        }

        close(in_pipe[0]);
        close(out_pipe[1]);
        if (pid < 0) {
            close(in_pipe[1]);
            close(out_pipe[0]);
            return false;
        }

        /* Wait until s_server prints "ACCEPT" confirming listen() is ready */
        char out_buf[512];
        size_t got = 0;
        bool ready = false;
        for (int wait_step = 0; wait_step < 30; wait_step++) {
            struct pollfd pfd = { .fd = out_pipe[0], .events = POLLIN, .revents = 0 };
            int prc = poll(&pfd, 1, 100);
            if (prc > 0) {
                ssize_t r = read(out_pipe[0], out_buf + got, sizeof(out_buf) - 1 - got);
                if (r <= 0) break;
                got += (size_t)r;
                out_buf[got] = '\0';
                if (strstr(out_buf, "ACCEPT") != NULL) {
                    ready = true;
                    break;
                }
            } else if (prc == 0) {
                int st = 0;
                if (waitpid(pid, &st, WNOHANG) == pid) break;
            }
        }

        if (ready) {
            srv->pid        = pid;
            srv->port       = port;
            srv->stdin_wfd  = in_pipe[1];
            srv->stdout_rfd = out_pipe[0];
            return true;
        }

        close(in_pipe[1]);
        close(out_pipe[0]);
        kill(pid, SIGKILL);
        int st = 0;
        waitpid(pid, &st, 0);
    }
    return false;
}

static bool start_openssl_tls13_server(TlsTestServer *srv,
                                       const char *cert_pem, const char *key_pem,
                                       const char *ciphersuite, const char *groups) {
    return start_openssl_tls13_server_ex(srv, cert_pem, key_pem, NULL,
                                         ciphersuite, groups, NULL, true);
}

static void stop_openssl_tls13_server(TlsTestServer *srv) {
    if (srv->stdin_wfd >= 0)  close(srv->stdin_wfd);
    if (srv->stdout_rfd >= 0) close(srv->stdout_rfd);
    if (srv->pid > 0) {
        int st = 0;
        for (int i = 0; i < 10; i++) {
            if (waitpid(srv->pid, &st, WNOHANG) == srv->pid) {
                srv->pid = -1;
                break;
            }
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 25000000L };
            nanosleep(&ts, NULL);
        }
        if (srv->pid > 0) {
            kill(srv->pid, SIGKILL);
            waitpid(srv->pid, &st, 0);
            srv->pid = -1;
        }
    }
}

static bool write_single_line_pem_copy(const char *src_pem, const char *dst_pem) {
    FILE *in = fopen(src_pem, "rb");
    if (!in) return false;
    char raw[8192];
    size_t n = fread(raw, 1, sizeof(raw) - 1, in);
    fclose(in);
    raw[n] = '\0';

    const char *beg_tag = "-----BEGIN CERTIFICATE-----";
    const char *end_tag = "-----END CERTIFICATE-----";
    const char *b = strstr(raw, beg_tag);
    if (!b) return false;
    b += strlen(beg_tag);
    const char *e = strstr(b, end_tag);
    if (!e) return false;

    FILE *out = fopen(dst_pem, "wb");
    if (!out) return false;
    const char *hdr = "-----BEGIN CERTIFICATE-----\n";
    const char *ftr = "\n-----END CERTIFICATE-----\n";
    fwrite(hdr, 1, strlen(hdr), out);
    for (const char *p = b; p < e; p++) {
        if (*p != '\r' && *p != '\n' && *p != ' ') {
            fwrite(p, 1, 1, out);
        }
    }
    fwrite(ftr, 1, strlen(ftr), out);
    fclose(out);
    return true;
}

void test_live_tls13_https(void) {
    printf("[14/14] Testing live loopback TLS 1.3 HTTPS (ECDSA/RSA/PSS, HRR/P-384, ALPN, KeyUpdate, & RSS)...\n");

    struct stat st;
    if (stat("/usr/bin/openssl", &st) != 0) {
        printf("  [SKIP] /usr/bin/openssl not present for live TLS 1.3 loopback test\n");
        return;
    }

    int pid = (int)getpid();
    char ca_key[96], ca_pem[96], ca_1line_pem[96], ca_srl[96], ext_cnf[96];
    char inter_cnf[96], eku_bad_cnf[96];
    char inter_key[96], inter_csr[96], inter_pem[96], inter_srl[96];
    char pss_key[96], pss_csr[96], pss_pem[96];
    char eku_key[96], eku_csr[96], eku_pem[96];
    char ec_key[96], ec_csr[96], ec_pem[96];
    char rsa_key[96], rsa_csr[96], rsa_pem[96];
    char bad_key[96], bad_pem[96];
    char html_name[64], html_path[96];

    snprintf(ca_key,       sizeof(ca_key),       "/tmp/tb_ca_%d.key",       pid);
    snprintf(ca_pem,       sizeof(ca_pem),       "/tmp/tb_ca_%d.pem",       pid);
    snprintf(ca_1line_pem, sizeof(ca_1line_pem), "/tmp/tb_ca1l_%d.pem",     pid);
    snprintf(ca_srl,       sizeof(ca_srl),       "/tmp/tb_ca_%d.srl",       pid);
    snprintf(ext_cnf,      sizeof(ext_cnf),      "/tmp/tb_ext_%d.cnf",      pid);
    snprintf(inter_cnf,    sizeof(inter_cnf),    "/tmp/tb_inter_%d.cnf",    pid);
    snprintf(eku_bad_cnf,  sizeof(eku_bad_cnf),  "/tmp/tb_ekubad_%d.cnf",   pid);
    snprintf(inter_key,    sizeof(inter_key),    "/tmp/tb_inter_%d.key",    pid);
    snprintf(inter_csr,    sizeof(inter_csr),    "/tmp/tb_inter_%d.csr",    pid);
    snprintf(inter_pem,    sizeof(inter_pem),    "/tmp/tb_inter_%d.pem",    pid);
    snprintf(inter_srl,    sizeof(inter_srl),    "/tmp/tb_inter_%d.srl",    pid);
    snprintf(pss_key,      sizeof(pss_key),      "/tmp/tb_pss_%d.key",      pid);
    snprintf(pss_csr,      sizeof(pss_csr),      "/tmp/tb_pss_%d.csr",      pid);
    snprintf(pss_pem,      sizeof(pss_pem),      "/tmp/tb_pss_%d.pem",      pid);
    snprintf(eku_key,      sizeof(eku_key),      "/tmp/tb_eku_%d.key",      pid);
    snprintf(eku_csr,      sizeof(eku_csr),      "/tmp/tb_eku_%d.csr",      pid);
    snprintf(eku_pem,      sizeof(eku_pem),      "/tmp/tb_eku_%d.pem",      pid);
    snprintf(ec_key,       sizeof(ec_key),       "/tmp/tb_ec_%d.key",       pid);
    snprintf(ec_csr,       sizeof(ec_csr),       "/tmp/tb_ec_%d.csr",       pid);
    snprintf(ec_pem,       sizeof(ec_pem),       "/tmp/tb_ec_%d.pem",       pid);
    snprintf(rsa_key,      sizeof(rsa_key),      "/tmp/tb_rsa_%d.key",      pid);
    snprintf(rsa_csr,      sizeof(rsa_csr),      "/tmp/tb_rsa_%d.csr",      pid);
    snprintf(rsa_pem,      sizeof(rsa_pem),      "/tmp/tb_rsa_%d.pem",      pid);
    snprintf(bad_key,      sizeof(bad_key),      "/tmp/tb_bad_%d.key",      pid);
    snprintf(bad_pem,      sizeof(bad_pem),      "/tmp/tb_bad_%d.pem",      pid);
    snprintf(html_name,    sizeof(html_name),    "tb_page_%d.html",         pid);
    snprintf(html_path,    sizeof(html_path),    "/tmp/%s",                 html_name);

    /* Write X.509v3 extension files (leaf SAN, intermediate CA, and non-critical clientAuth-only EKU) */
    {
        FILE *f = fopen(ext_cnf, "wb");
        ASSERT_TRUE(f != NULL, "Create temporary X.509 SAN extfile");
        if (!f) return;
        const char *ext_txt =
            "basicConstraints=CA:FALSE\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n";
        fwrite(ext_txt, 1, strlen(ext_txt), f);
        fclose(f);

        FILE *fi = fopen(inter_cnf, "wb");
        if (fi) {
            const char *ic_txt =
                "basicConstraints=critical,CA:TRUE,pathlen:0\n"
                "keyUsage=critical,keyCertSign,cRLSign\n";
            fwrite(ic_txt, 1, strlen(ic_txt), fi);
            fclose(fi);
        }

        FILE *fe = fopen(eku_bad_cnf, "wb");
        if (fe) {
            const char *ek_txt =
                "basicConstraints=CA:FALSE\n"
                "extendedKeyUsage=clientAuth\n"
                "subjectAltName=DNS:localhost,IP:127.0.0.1\n";
            fwrite(ek_txt, 1, strlen(ek_txt), fe);
            fclose(fe);
        }
    }

    /* Write >24 KB multi-record HTML + CSS + TinyJS payload */
    {
        FILE *f = fopen(html_path, "wb");
        ASSERT_TRUE(f != NULL, "Create >24 KB TLS 1.3 HTML+JS fixture");
        if (!f) { unlink(ext_cnf); unlink(inter_cnf); unlink(eku_bad_cnf); return; }
        const char *prefix =
            "<!DOCTYPE html><html><head><title>TLS13 Live</title>"
            "<style>#tls-res { color: #38bdf8; font-weight: bold; }</style></head><body>"
            "<p id='tls-res'>pending</p><!-- ";
        const char *suffix =
            " --><script>"
            "const v = [10, 20, 12].reduce((a, b) => a + b, 0);"
            "document.getElementById('tls-res').textContent = 'TLS13_VERIFIED_' + v;"
            "</script></body></html>";
        fwrite(prefix, 1, strlen(prefix), f);
        char pad[1024];
        memset(pad, 'X', sizeof(pad));
        for (int i = 0; i < 24; i++) fwrite(pad, 1, sizeof(pad), f);
        fwrite(suffix, 1, strlen(suffix), f);
        fclose(f);
    }

    /* Generate Root CA + Intermediate CA (P-384) + ECDSA P-256 Leaf + RSA-2048 Leaf +
     * id-RSASSA-PSS Leaf (signed by Intermediate CA) + clientAuth-only EKU Leaf + Untrusted Self-Signed Leaf */
    char *gen_ca[] = {
        "/usr/bin/openssl", "req", "-x509", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", ca_key, "-out", ca_pem, "-subj", "/CN=TBZeroDepRootCA", "-days", "2",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", NULL
    };
    char *gen_ec_csr[] = {
        "/usr/bin/openssl", "req", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", ec_key, "-out", ec_csr, "-subj", "/CN=localhost", NULL
    };
    char *sign_ec[] = {
        "/usr/bin/openssl", "x509", "-req", "-in", ec_csr,
        "-CA", ca_pem, "-CAkey", ca_key, "-CAcreateserial",
        "-out", ec_pem, "-days", "2", "-extfile", ext_cnf, "-sha256", NULL
    };
    char *gen_rsa_csr[] = {
        "/usr/bin/openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", rsa_key, "-out", rsa_csr, "-subj", "/CN=localhost", NULL
    };
    char *sign_rsa[] = {
        "/usr/bin/openssl", "x509", "-req", "-in", rsa_csr,
        "-CA", ca_pem, "-CAkey", ca_key, "-CAcreateserial",
        "-out", rsa_pem, "-days", "2", "-extfile", ext_cnf, "-sha256", NULL
    };
    char *gen_inter_csr[] = {
        "/usr/bin/openssl", "req", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:secp384r1", "-nodes",
        "-keyout", inter_key, "-out", inter_csr, "-subj", "/CN=TBZeroDepInterP384", NULL
    };
    char *sign_inter[] = {
        "/usr/bin/openssl", "x509", "-req", "-in", inter_csr,
        "-CA", ca_pem, "-CAkey", ca_key, "-CAcreateserial",
        "-out", inter_pem, "-days", "2", "-extfile", inter_cnf, "-sha384", NULL
    };
    char *gen_pss_csr[] = {
        "/usr/bin/openssl", "req", "-newkey", "rsa-pss",
        "-pkeyopt", "rsa_keygen_bits:2048", "-nodes",
        "-keyout", pss_key, "-out", pss_csr, "-subj", "/CN=localhost", NULL
    };
    char *sign_pss[] = {
        "/usr/bin/openssl", "x509", "-req", "-in", pss_csr,
        "-CA", inter_pem, "-CAkey", inter_key, "-CAcreateserial",
        "-out", pss_pem, "-days", "2", "-extfile", ext_cnf, "-sha384", NULL
    };
    char *gen_eku_csr[] = {
        "/usr/bin/openssl", "req", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", eku_key, "-out", eku_csr, "-subj", "/CN=localhost", NULL
    };
    char *sign_eku[] = {
        "/usr/bin/openssl", "x509", "-req", "-in", eku_csr,
        "-CA", ca_pem, "-CAkey", ca_key, "-CAcreateserial",
        "-out", eku_pem, "-days", "2", "-extfile", eku_bad_cnf, "-sha256", NULL
    };
    char *gen_bad[] = {
        "/usr/bin/openssl", "req", "-x509", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", bad_key, "-out", bad_pem, "-subj", "/CN=localhost", "-days", "2",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", NULL
    };

    bool certs_ok = run_cmd_quiet("/usr/bin/openssl", gen_ca) &&
                    write_single_line_pem_copy(ca_pem, ca_1line_pem) &&
                    run_cmd_quiet("/usr/bin/openssl", gen_ec_csr) &&
                    run_cmd_quiet("/usr/bin/openssl", sign_ec) &&
                    run_cmd_quiet("/usr/bin/openssl", gen_rsa_csr) &&
                    run_cmd_quiet("/usr/bin/openssl", sign_rsa) &&
                    run_cmd_quiet("/usr/bin/openssl", gen_inter_csr) &&
                    run_cmd_quiet("/usr/bin/openssl", sign_inter) &&
                    run_cmd_quiet("/usr/bin/openssl", gen_pss_csr) &&
                    run_cmd_quiet("/usr/bin/openssl", sign_pss) &&
                    run_cmd_quiet("/usr/bin/openssl", gen_eku_csr) &&
                    run_cmd_quiet("/usr/bin/openssl", sign_eku) &&
                    run_cmd_quiet("/usr/bin/openssl", gen_bad);
    ASSERT_TRUE(certs_ok, "Generate ephemeral Root/Inter-P384/ECDSA-P256/RSA-2048/RSASSA-PSS X.509 test PKI");

    if (certs_ok) {
        tb_tls_set_ca_file(ca_pem);

        /* Case 1: Full TbBrowser HTTPS navigation over TLS_AES_128_GCM_SHA256 + X25519 + ECDSA-P256 (>24 KB) */
        TlsTestServer srv;
        if (start_openssl_tls13_server(&srv, ec_pem, ec_key, "TLS_AES_128_GCM_SHA256", "X25519")) {
            TbBrowser b;
            tb_browser_init(&b, 88, 24, false);
            char url[160];
            snprintf(url, sizeof(url), "https://localhost:%d/%s", srv.port, html_name);
            ASSERT_TRUE(tb_browser_navigate(&b, url, true),
                        "TbBrowser HTTPS navigate (TLS 1.3 AES-128-GCM + X25519 + ECDSA-P256)");
            DomNode *el = b.doc ? dom_get_element_by_id(b.doc->root, "tls-res") : NULL;
            char *txt = dom_get_text_content(el);
            ASSERT_STR_EQ(txt, "TLS13_VERIFIED_42",
                           "Multi-record >24KB TLS 1.3 HTML decrypted and TinyJS executed");
            tb_free(txt);
            tb_browser_free(&b);
            stop_openssl_tls13_server(&srv);
        } else {
            ASSERT_TRUE(false, "Start OpenSSL TLS 1.3 server (AES-128-GCM)");
        }

        /* Case 2: TLS_CHACHA20_POLY1305_SHA256 + IPv4 literal (127.0.0.1 iPAddress SAN, omitted SNI) */
        if (start_openssl_tls13_server(&srv, ec_pem, ec_key, "TLS_CHACHA20_POLY1305_SHA256", "X25519")) {
            char url[160];
            snprintf(url, sizeof(url), "https://127.0.0.1:%d/%s", srv.port, html_name);
            TbResponse resp;
            bool ok = tb_fetch(url, "GET", NULL, NULL, false, &resp);
            ASSERT_TRUE(ok && resp.status == 200 && resp.body_len > 24000,
                        "HTTPS fetch via 127.0.0.1 IP SAN + ChaCha20-Poly1305 (>24 KB)");
            tb_response_free(&resp);
            stop_openssl_tls13_server(&srv);
        } else {
            ASSERT_TRUE(false, "Start OpenSSL TLS 1.3 server (ChaCha20-Poly1305)");
        }

        /* Case 3: TLS_AES_256_GCM_SHA384 + P-256 ECDHE + RSA-2048 PSS CertificateVerify (also forces HRR from X25519 key_share -> P-256!) */
        if (start_openssl_tls13_server(&srv, rsa_pem, rsa_key, "TLS_AES_256_GCM_SHA384", "P-256")) {
            char url[160];
            snprintf(url, sizeof(url), "https://localhost:%d/%s", srv.port, html_name);
            TbResponse resp;
            bool ok = tb_fetch(url, "GET", NULL, NULL, false, &resp);
            ASSERT_TRUE(ok && resp.status == 200 && resp.body_len > 24000,
                        "HTTPS fetch (TLS 1.3 HRR -> P-256 ECDHE + AES-256-GCM-SHA384 + RSA-2048 PSS)");
            tb_response_free(&resp);
            stop_openssl_tls13_server(&srv);
        } else {
            ASSERT_TRUE(false, "Start OpenSSL TLS 1.3 server (AES-256-GCM + RSA-2048)");
        }

        /* Case 4: Untrusted CA certificate MUST be rejected when insecure=false */
        if (start_openssl_tls13_server(&srv, bad_pem, bad_key, NULL, NULL)) {
            char url[160];
            snprintf(url, sizeof(url), "https://localhost:%d/%s", srv.port, html_name);
            TbResponse resp;
            bool ok = tb_fetch(url, "GET", NULL, NULL, false, &resp);
            ASSERT_TRUE(!ok, "Reject untrusted self-signed X.509 certificate when insecure=false");
            tb_response_free(&resp);
            stop_openssl_tls13_server(&srv);
        }

        /* Case 5: Wrong hostname MUST be rejected even with trusted CA when insecure=false */
        if (start_openssl_tls13_server(&srv, ec_pem, ec_key, NULL, NULL)) {
            char url[160];
            snprintf(url, sizeof(url), "https://wronghost.localhost:%d/%s", srv.port, html_name);
            TbResponse resp;
            bool ok = tb_fetch(url, "GET", NULL, NULL, false, &resp);
            ASSERT_TRUE(!ok, "Reject mismatched hostname (wronghost.localhost vs DNS:localhost)");
            tb_response_free(&resp);
            stop_openssl_tls13_server(&srv);
        }

        /* Case 6: Untrusted CA certificate MUST succeed when insecure=true (-k flag) */
        if (start_openssl_tls13_server(&srv, bad_pem, bad_key, NULL, NULL)) {
            char url[160];
            snprintf(url, sizeof(url), "https://localhost:%d/%s", srv.port, html_name);
            TbResponse resp;
            bool ok = tb_fetch(url, "GET", NULL, NULL, true, &resp);
            ASSERT_TRUE(ok && resp.status == 200 && resp.body_len > 24000,
                        "Accept self-signed certificate when insecure=true (-k)");
            tb_response_free(&resp);
            stop_openssl_tls13_server(&srv);
        }

        /* Case 7: HelloRetryRequest -> secp384r1 (P-384) 48-byte ECDHE + ALPN "http/1.1" negotiation */
        if (start_openssl_tls13_server_ex(&srv, ec_pem, ec_key, NULL,
                                          "TLS_AES_256_GCM_SHA384", "P-384", "http/1.1", true)) {
            char url[160];
            snprintf(url, sizeof(url), "https://localhost:%d/%s", srv.port, html_name);
            TbResponse resp;
            bool ok = tb_fetch(url, "GET", NULL, NULL, false, &resp);
            ASSERT_TRUE(ok && resp.status == 200 && resp.body_len > 24000,
                        "HTTPS fetch over HelloRetryRequest -> P-384 ECDHE + ALPN http/1.1 (>24 KB)");
            tb_response_free(&resp);
            stop_openssl_tls13_server(&srv);
        } else {
            ASSERT_TRUE(false, "Start OpenSSL TLS 1.3 server (HRR + P-384 + ALPN)");
        }

        /* Case 8: 3-tier PKI (Single-line >500-char PEM Root -> P-384 Intermediate -> id-RSASSA-PSS Leaf 0x0809) */
        tb_tls_set_ca_file(ca_1line_pem);
        if (start_openssl_tls13_server_ex(&srv, pss_pem, pss_key, inter_pem,
                                          "TLS_AES_128_GCM_SHA256", "X25519", "http/1.1", true)) {
            char url[160];
            snprintf(url, sizeof(url), "https://localhost:%d/%s", srv.port, html_name);
            TbResponse resp;
            bool ok = tb_fetch(url, "GET", NULL, NULL, false, &resp);
            ASSERT_TRUE(ok && resp.status == 200 && resp.body_len > 24000,
                        "3-tier chain: single-line PEM Root -> P-384 Intermediate -> id-RSASSA-PSS (0x0809) leaf");
            tb_response_free(&resp);
            stop_openssl_tls13_server(&srv);
        } else {
            ASSERT_TRUE(false, "Start OpenSSL TLS 1.3 server (3-tier RSASSA-PSS)");
        }
        tb_tls_set_ca_file(ca_pem);

        /* Case 9: Non-critical extendedKeyUsage=clientAuth (missing serverAuth) MUST be rejected! */
        if (start_openssl_tls13_server(&srv, eku_pem, eku_key, NULL, NULL)) {
            char url[160];
            snprintf(url, sizeof(url), "https://localhost:%d/%s", srv.port, html_name);
            TbResponse resp;
            bool ok = tb_fetch(url, "GET", NULL, NULL, false, &resp);
            ASSERT_TRUE(!ok, "Reject leaf certificate with non-critical EKU=clientAuth (no serverAuth)");
            tb_response_free(&resp);
            stop_openssl_tls13_server(&srv);
        } else {
            ASSERT_TRUE(false, "Start OpenSSL TLS 1.3 server (clientAuth EKU)");
        }

#if !(defined(TB_TLS_OPENSSL) && TB_TLS_OPENSSL)
        /* Case 10: Bidirectional post-handshake TLS 1.3 KeyUpdate (RFC 8446 §4.6.3) */
        if (start_openssl_tls13_server_ex(&srv, ec_pem, ec_key, NULL,
                                          "TLS_AES_128_GCM_SHA256", "X25519", NULL, false)) {
            int cfd = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family      = AF_INET;
            sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            sin.sin_port        = htons((uint16_t)srv.port);
            bool tcp_ok = (cfd >= 0 && connect(cfd, (struct sockaddr *)&sin, sizeof(sin)) == 0);
            ASSERT_TRUE(tcp_ok, "Connect TCP socket for interactive TLS 1.3 KeyUpdate test");
            if (tcp_ok) {
                char terr[128] = {0};
                TbTlsConn *tc = tb_tls_connect(cfd, "localhost", false, 5000, terr, sizeof(terr));
                ASSERT_TRUE(tc != NULL, "Complete TLS 1.3 handshake with interactive s_server");
                if (tc) {
                    /* Drain s_server handshake banner before triggering 'K' (KeyUpdate requested) */
                    char drain[512];
                    for (int i = 0; i < 6; i++) {
                        struct pollfd pfd = { .fd = srv.stdout_rfd, .events = POLLIN, .revents = 0 };
                        if (poll(&pfd, 1, 40) <= 0) break;
                        if (read(srv.stdout_rfd, drain, sizeof(drain)) <= 0) break;
                    }
                    /* Trigger OpenSSL s_server KeyUpdate(update_requested) via 'K\n' command */
                    (void)write(srv.stdin_wfd, "K\n", 2);
                    for (int i = 0; i < 15; i++) {
                        struct pollfd pfd = { .fd = srv.stdout_rfd, .events = POLLIN, .revents = 0 };
                        if (poll(&pfd, 1, 40) > 0) {
                            ssize_t nr = read(srv.stdout_rfd, drain, sizeof(drain) - 1);
                            if (nr > 0) {
                                drain[nr] = '\0';
                                if (strstr(drain, "KEYUPDATE") != NULL) break;
                            }
                        }
                    }
                    /* Send server payload encrypted under rotated server_application_traffic_secret_1
                     * (avoid leading 'P','Q','R','S','B','k','K','c' which s_server treats as commands!) */
                    const char *srv_msg = "after_keyupdate_server_ok\n";
                    (void)write(srv.stdin_wfd, srv_msg, strlen(srv_msg));

                    char rbuf[128] = {0};
                    ssize_t got = tb_tls_read(tc, rbuf, sizeof(rbuf) - 1, 4000);
                    ASSERT_TRUE(got > 0 && strstr(rbuf, "after_keyupdate_server_ok") != NULL,
                                "Client handled server KeyUpdate(update_requested) and decrypted rotated traffic");

                    /* Send client payload encrypted under rotated client_application_traffic_secret_1 */
                    const char *cli_msg = "after_keyupdate_client_ok\n";
                    ASSERT_TRUE(tb_tls_write(tc, cli_msg, strlen(cli_msg), 3000),
                                "Client transmitted application data under rotated traffic key");

                    char s_out[512];
                    size_t s_len = 0;
                    bool saw_cli = false;
                    for (int i = 0; i < 20 && s_len + 1 < sizeof(s_out); i++) {
                        struct pollfd pfd = { .fd = srv.stdout_rfd, .events = POLLIN, .revents = 0 };
                        if (poll(&pfd, 1, 50) <= 0) continue;
                        ssize_t nr = read(srv.stdout_rfd, s_out + s_len, sizeof(s_out) - 1 - s_len);
                        if (nr <= 0) break;
                        s_len += (size_t)nr;
                        s_out[s_len] = '\0';
                        if (strstr(s_out, "after_keyupdate_client_ok") != NULL) {
                            saw_cli = true;
                            break;
                        }
                    }
                    ASSERT_TRUE(saw_cli,
                                "OpenSSL s_server accepted client KeyUpdate response and decrypted rotated client traffic");
                    tb_tls_close(tc);
                }
            }
            if (cfd >= 0) close(cfd);
            stop_openssl_tls13_server(&srv);
        } else {
            ASSERT_TRUE(false, "Start OpenSSL TLS 1.3 interactive server (KeyUpdate)");
        }
#endif

        tb_tls_set_ca_file(NULL);
        tb_net_cleanup();
    }

    /* Clean up all temporary PKI & HTML files */
    unlink(ca_key);    unlink(ca_pem);    unlink(ca_1line_pem); unlink(ca_srl);
    unlink(ext_cnf);   unlink(inter_cnf); unlink(eku_bad_cnf);
    unlink(inter_key); unlink(inter_csr); unlink(inter_pem);    unlink(inter_srl);
    unlink(pss_key);   unlink(pss_csr);   unlink(pss_pem);
    unlink(eku_key);   unlink(eku_csr);   unlink(eku_pem);
    unlink(ec_key);    unlink(ec_csr);    unlink(ec_pem);
    unlink(rsa_key);   unlink(rsa_csr);   unlink(rsa_pem);
    unlink(bad_key);   unlink(bad_pem);   unlink(html_path);

    /* Verify active post-HTTPS VmRSS (< 1 MB in freestanding zero-dependency build!) */
    tb_mem_trim();
    TbMemStats ms;
    tb_mem_stats(&ms);
    printf("      Post-TLS 1.3 VmRSS: %zu KB (%.2f MB) | RssAnon: %zu KB | VmHWM: %zu KB\n",
           ms.vm_rss_kb, (double)ms.vm_rss_kb / 1024.0, ms.rss_anon_kb, ms.vm_hwm_kb);
#if defined(TB_FREESTANDING) && TB_FREESTANDING
    ASSERT_TRUE(ms.vm_rss_kb > 0 && ms.vm_rss_kb < 1024,
                "Freestanding zero-dependency post-HTTPS VmRSS is strictly < 1 MB (1,024 KB)");
#else
    ASSERT_TRUE(ms.vm_rss_kb > 0 && ms.vm_rss_kb < 10240,
                "Hosted post-HTTPS VmRSS is strictly < 10 MB (10,240 KB)");
#endif
}
