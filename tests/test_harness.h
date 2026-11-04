#ifndef TB_TEST_HARNESS_H
#define TB_TEST_HARNESS_H

#include "common.h"

extern int g_pass;
extern int g_fail;

extern const uint8_t GZIP_HTML_FIXTURE[279];
extern const uint8_t ZLIB_FIXTURE[72];

void assert_str_eq_impl(const char *actual, const char *expected,
                        const char *msg, const char *file, int line);

#define ASSERT_TRUE(cond, msg)                                                           \
    do {                                                                                 \
        if (cond) {                                                                      \
            g_pass++;                                                                    \
        } else {                                                                         \
            g_fail++;                                                                    \
            fprintf(stderr, "  [FAIL] %s:%d — %s\n", __FILE__, __LINE__, (msg));         \
        }                                                                                \
    } while (0)

#define ASSERT_STR_EQ(actual, expected, msg) \
    assert_str_eq_impl((actual), (expected), (msg), __FILE__, __LINE__)

/* test_core.c */
void test_memory_subsystem(void);
void test_inflate_subsystem(void);
void test_strict_memory_budget(void);
void test_math_tb_subsystem(void);
void test_regex_tb_subsystem(void);

/* test_engine.c */
void test_dom_and_css(void);
void test_browser_lifecycle(void);

/* test_js.c */
void test_js_engine(void);
void test_gc_and_orphan_dom_stress(void);

/* test_net.c */
void test_url_subsystem(void);
void test_http_end_to_end(void);
void test_direct_dns_subsystem(void);

/* test_tls.c */
void test_crypto_and_x509_subsystem(void);
void test_live_tls13_https(void);

#endif /* TB_TEST_HARNESS_H */
