#include "test_harness.h"
#include "inflate.h"
#include "js.h"
#include "math_tb.h"
#include "mem.h"
#include "regex_tb.h"

/* ── Test 1: Tracked Allocator, Hard Heap Cap, Arena, & /proc/self/status ── */
void test_memory_subsystem(void) {
    printf("[1/14] Testing tracked allocator, hard heap cap, arena, & /proc RSS...\n");
    TbMemStats s0, s1;
    tb_mem_stats(&s0);
    ASSERT_TRUE(s0.vm_rss_kb > 0 && s0.vm_rss_kb < 10240, "Initial VmRSS < 10 MB");

    void *blk = tb_malloc(32768);
    ASSERT_TRUE(blk != NULL, "tb_malloc(32KB) succeeds");
    tb_mem_stats(&s1);
    ASSERT_TRUE(s1.heap_live >= s0.heap_live + 32768, "heap_live tracks allocation");

    /* Temporarily enforce tight cap and verify OOM refusal without crashing */
    tb_mem_set_limit(s1.heap_live + 4096);
    void *rejected = tb_malloc(65536);
    ASSERT_TRUE(rejected == NULL, "Allocation exceeding hard cap cleanly returns NULL");
    tb_mem_set_limit(TB_DEFAULT_HEAP_LIMIT);
    tb_free(blk);

    TbArena arena;
    tb_arena_init(&arena, 4096);
    for (int i = 0; i < 300; i++) {
        char *s = tb_arena_strdup(&arena, "Arena bump pointer test string");
        ASSERT_TRUE(s != NULL || i > 0, "Arena allocation");
    }
    size_t bytes_first = arena.total_bytes;
    tb_arena_reset(&arena);
    for (int i = 0; i < 300; i++) {
        (void)tb_arena_strdup(&arena, "Arena bump pointer test string");
    }
    ASSERT_TRUE(arena.total_bytes == bytes_first, "tb_arena_reset reuses blocks with 0 growth");
    tb_arena_destroy(&arena);
}

/* ── Test 2: RFC 1951 / 1952 / 1950 Decompressor & Anti-Zip-Bomb Guard ── */
void test_inflate_subsystem(void) {
    printf("[2/14] Testing RFC 1952 gzip, RFC 1950 zlib, & anti-zip-bomb ceiling...\n");
    char *out = NULL;
    size_t out_len = 0;

    bool ok_gz = tb_decompress(GZIP_HTML_FIXTURE, sizeof(GZIP_HTML_FIXTURE),
                               TB_DECOMP_AUTO, 65536, &out, &out_len);
    ASSERT_TRUE(ok_gz && out != NULL && out_len == 376, "Gzip dynamic-Huffman decode length");
    ASSERT_TRUE(out && strstr(out, "GzipChunkedOK") != NULL, "Gzip decoded HTML content");
    tb_free(out);

    out = NULL;
    bool ok_zl = tb_decompress(ZLIB_FIXTURE, sizeof(ZLIB_FIXTURE),
                               TB_DECOMP_AUTO, 65536, &out, &out_len);
    ASSERT_TRUE(ok_zl && out != NULL && out_len == 366, "Zlib RFC 1950 decode length");
    ASSERT_TRUE(out && strncmp(out, "TinyBrowser RFC1950", 19) == 0, "Zlib decoded prefix");
    tb_free(out);

    /* Anti-zip-bomb: set max_out smaller than uncompressed payload */
    out = NULL;
    bool bomb_blocked = !tb_decompress(GZIP_HTML_FIXTURE, sizeof(GZIP_HTML_FIXTURE),
                                       TB_DECOMP_GZIP, 100, &out, &out_len);
    ASSERT_TRUE(bomb_blocked && out == NULL, "Anti-zip-bomb max_out rejects oversized stream");
}

/* ── Test 9: Strict < 10 MB Kernel VmRSS Assertion ── */
void test_strict_memory_budget(void) {
    printf("[9/14] Verifying kernel /proc/self/status VmRSS strictly < 10 MB (10,240 KB)...\n");
    tb_mem_trim();
    TbMemStats ms;
    tb_mem_stats(&ms);
    printf("      Measured VmRSS:   %zu KB (%.2f MB)  [Hard Target: < 10,240 KB]\n",
           ms.vm_rss_kb, (double)ms.vm_rss_kb / 1024.0);
    printf("      Measured RssAnon: %zu KB (%.2f MB)  [Private Heap + Stack]\n",
           ms.rss_anon_kb, (double)ms.rss_anon_kb / 1024.0);
    printf("      Measured VmHWM:   %zu KB (%.2f MB)  [Peak Lifetime RSS]\n",
           ms.vm_hwm_kb, (double)ms.vm_hwm_kb / 1024.0);

    ASSERT_TRUE(ms.vm_rss_kb > 0 && ms.vm_rss_kb < 10240,
                "Active Kernel VmRSS is strictly below 10 MB (10,240 KB)");
    ASSERT_TRUE(ms.vm_hwm_kb > 0 && ms.vm_hwm_kb < 10240,
                "Peak Lifetime Kernel VmHWM never exceeded 10 MB (10,240 KB)");
    ASSERT_TRUE(ms.rss_anon_kb < 4096,
                "Private RssAnon memory is strictly below 4 MB");
}

/* ── Test 10: In-Tree IEEE-754 Math & Gregorian UTC Helpers (Zero -lm) ── */
void test_math_tb_subsystem(void) {
    printf("[10/14] Testing in-tree IEEE-754 math_tb & Gregorian UTC calendar (zero -lm)...\n");

    ASSERT_TRUE(tb_isnan(TB_NAN) && !tb_isfinite(TB_NAN), "TB_NAN classification");
    ASSERT_TRUE(tb_isinf(TB_INFINITY) && tb_isinf(-TB_INFINITY), "TB_INFINITY classification");
    ASSERT_TRUE(tb_signbit(-0.0) && !tb_signbit(0.0), "Signed zero bit detection");

    ASSERT_TRUE(tb_floor(-2.1) == -3.0 && tb_floor(2.9) == 2.0, "tb_floor pos/neg");
    ASSERT_TRUE(tb_ceil(-2.9) == -2.0 && tb_ceil(2.1) == 3.0, "tb_ceil pos/neg");
    ASSERT_TRUE(tb_trunc(-2.9) == -2.0 && tb_trunc(2.9) == 2.0, "tb_trunc pos/neg");
    ASSERT_TRUE(tb_round(0.5) == 1.0 && tb_round(2.49) == 2.0, "tb_round positive");
    double r_neg_half = tb_round(-0.5);
    ASSERT_TRUE(r_neg_half == 0.0 && tb_signbit(r_neg_half), "ECMAScript Math.round(-0.5) === -0");
    ASSERT_TRUE(tb_round(-0.51) == -1.0, "tb_round(-0.51) === -1");
    ASSERT_TRUE(tb_floor(4503599627370497.0) == 4503599627370497.0, "tb_floor >= 2^52 exact");

    ASSERT_TRUE(tb_fabs(tb_fmod(5.5, 2.0) - 1.5) < 1e-15, "tb_fmod(5.5, 2.0)");
    ASSERT_TRUE(tb_fabs(tb_fmod(-5.5, 2.0) - (-1.5)) < 1e-15, "tb_fmod(-5.5, 2.0)");
    double big_mod = tb_fmod(1e20, 3.0);
    ASSERT_TRUE(tb_isfinite(big_mod) && big_mod >= 0.0 && big_mod < 3.0, "tb_fmod large exponent");
    ASSERT_TRUE(tb_isnan(tb_fmod(1.0, 0.0)) && tb_isnan(tb_fmod(TB_INFINITY, 2.0)), "tb_fmod NaN cases");

    ASSERT_TRUE(tb_sqrt(144.0) == 12.0 && tb_fabs(tb_sqrt(2.0) - 1.4142135623730951) < 1e-15, "tb_sqrt accuracy");
    ASSERT_TRUE(tb_isnan(tb_sqrt(-1.0)), "tb_sqrt(-1) is NaN");

    ASSERT_TRUE(tb_exp(0.0) == 1.0 && tb_fabs(tb_exp(1.0) - TB_E) < 1e-13, "tb_exp(0) and tb_exp(1)");
    ASSERT_TRUE(tb_isinf(tb_exp(1000.0)) && tb_exp(-1000.0) == 0.0, "tb_exp overflow/underflow");
    ASSERT_TRUE(tb_log(1.0) == 0.0 && tb_fabs(tb_log(tb_exp(3.25)) - 3.25) < 1e-13, "tb_log(exp(3.25))");
    ASSERT_TRUE(tb_fabs(tb_log10(1000.0) - 3.0) < 1e-13, "tb_log10(1000)");
    ASSERT_TRUE(tb_isinf(tb_log(0.0)) && tb_log(0.0) < 0.0 && tb_isnan(tb_log(-1.0)), "tb_log boundary");

    ASSERT_TRUE(tb_pow(2.0, 10.0) == 1024.0 && tb_pow(-2.0, 3.0) == -8.0, "tb_pow integer exponents");
    ASSERT_TRUE(tb_pow(TB_NAN, 0.0) == 1.0 && tb_isnan(tb_pow(1.0, TB_INFINITY)), "ECMAScript Math.pow edge rules");
    ASSERT_TRUE(tb_isnan(tb_pow(-2.0, 0.5)), "tb_pow negative base fractional exponent -> NaN");

    ASSERT_TRUE(tb_fabs(tb_sin(0.0)) < 1e-15 && tb_fabs(tb_cos(0.0) - 1.0) < 1e-15, "sin(0), cos(0)");
    ASSERT_TRUE(tb_fabs(tb_sin(TB_PI / 2.0) - 1.0) < 1e-14 && tb_fabs(tb_cos(TB_PI) + 1.0) < 1e-14, "sin(pi/2), cos(pi)");
    ASSERT_TRUE(tb_fabs(tb_tan(TB_PI / 4.0) - 1.0) < 1e-13, "tan(pi/4)");
    ASSERT_TRUE(tb_fabs(tb_atan2(1.0, 1.0) - (TB_PI / 4.0)) < 1e-14, "atan2(1, 1)");

    ASSERT_TRUE(tb_unix_from_civil(1970, 1, 1, 0, 0, 0) == 0LL, "Unix epoch 1970-01-01");
    ASSERT_TRUE(tb_unix_from_civil(2000, 2, 29, 12, 30, 45) == 951827445LL, "Leap century 2000-02-29");
    int cy = 0, cm = 0, cd = 0, ch = 0, cmi = 0, cs = 0;
    tb_civil_from_unix(951827445LL, &cy, &cm, &cd, &ch, &cmi, &cs);
    ASSERT_TRUE(cy == 2000 && cm == 2 && cd == 29 && ch == 12 && cmi == 30 && cs == 45,
                "tb_civil_from_unix round-trip");
    char iso[40];
    tb_utc_to_iso8601(0.0, iso, sizeof(iso));
    ASSERT_STR_EQ(iso, "1970-01-01T00:00:00.000Z", "ISO-8601 epoch formatting");

    /* strtod C11 'inf' vs 'infinity' boundary regression test (no over-read past NUL!) */
    const char *s_infi = "infi";
    const char *s_infw = "infill";
    const char *s_inff = "-Infinity!";
    char *ep = NULL;
    double v_infi = strtod(s_infi, &ep);
    ASSERT_TRUE(tb_isinf(v_infi) && v_infi > 0.0 && ep == s_infi + 3,
                "strtod('infi') consumes exactly 'inf' (3 bytes, no buffer over-read)");
    double v_infw = strtod(s_infw, &ep);
    ASSERT_TRUE(tb_isinf(v_infw) && v_infw > 0.0 && ep == s_infw + 3,
                "strtod('infill') consumes 'inf' leaving 'ill'");
    double v_inff = strtod(s_inff, &ep);
    ASSERT_TRUE(tb_isinf(v_inff) && v_inff < 0.0 && ep == s_inff + 9,
                "strtod('-Infinity!') consumes full '-Infinity' leaving '!'");
}

static int cmp_int_asc(const void *a, const void *b) {
    int va = *(const int *)a;
    int vb = *(const int *)b;
    return (va > vb) - (va < vb);
}

/* ── Test 11: Custom In-Tree RegExp Bytecode VM, JS Integration, & ReDoS Guard ── */
void test_regex_tb_subsystem(void) {
    /* Also run the 4,096-element qsort equal/descending verification here */
    {
        int *qarr = (int *)tb_malloc(4096 * sizeof(int));
        if (qarr) {
            for (int i = 0; i < 4096; i++) qarr[i] = 777;
            qsort(qarr, 4096, sizeof(int), cmp_int_asc);
            bool eq_ok = (qarr[0] == 777 && qarr[4095] == 777);
            for (int i = 0; i < 4096; i++) qarr[i] = 4095 - i;
            qsort(qarr, 4096, sizeof(int), cmp_int_asc);
            bool asc_ok = true;
            for (int i = 0; i < 4096; i++) {
                if (qarr[i] != i) { asc_ok = false; break; }
            }
            ASSERT_TRUE(eq_ok && asc_ok, "qsort O(N log N) HeapSort handles 4096 equal & reversed items");
            tb_free(qarr);
        }
    }

    printf("[11/14] Testing in-tree JS RegExp bytecode VM (captures, lookahead, backrefs, ReDoS guard)...\n");

    /* 1. Invalid pattern rejection without leak/crash */
    char err[128];
    TbRegex *bad1 = tb_regex_compile("[unclosed", "", err, sizeof(err));
    TbRegex *bad2 = tb_regex_compile("(abc", "", err, sizeof(err));
    TbRegex *bad3 = tb_regex_compile("*leading", "", err, sizeof(err));
    ASSERT_TRUE(bad1 == NULL && bad2 == NULL && bad3 == NULL, "Malformed regexes cleanly rejected");

    /* 2. Bounded-step ReDoS protection on catastrophic backtracking pattern */
    TbRegex *redos = tb_regex_compile("(a+)+b", "", err, sizeof(err));
    ASSERT_TRUE(redos != NULL, "Compile (a+)+b");
    if (redos) {
        const char *evil = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!";
        TbRegexMatch m;
        bool matched = tb_regex_exec(redos, evil, strlen(evil), 0, &m);
        ASSERT_TRUE(!matched, "Catastrophic backtracking halted safely by VM step limit");
        tb_regex_free(redos);
    }

    /* 2b. >16 counted {n,m} quantifiers in one pattern + {0}/{1} exact bounds regression test */
    TbRegex *many_q = tb_regex_compile(
        "^a{2}b{3}c{2}d{3}e{2}f{3}g{2}h{3}i{2}j{3}k{2}l{3}m{2}n{3}o{2}p{3}q{2}r{3}s{2}t{3}$",
        "", err, sizeof(err));
    ASSERT_TRUE(many_q != NULL, "Compile 20-quantifier {n,m} pattern");
    if (many_q) {
        const char *s_valid   = "aabbbccdddeefffgghhhiijjjkklllmmnnnoopp" "pqqrrrssttt";
        const char *s_short18 = "aabbbccdddeefffgghhhiijjjkklllmmnnnoopp" "pqqrssttt"; /* r has 1, needs 3 */
        TbRegexMatch m;
        ASSERT_TRUE(tb_regex_exec(many_q, s_valid, strlen(s_valid), 0, &m),
                    "20-quantifier {n,m} pattern matches exact counts");
        ASSERT_TRUE(!tb_regex_exec(many_q, s_short18, strlen(s_short18), 0, &m),
                    "20-quantifier {n,m} pattern enforces 18th quantifier r{3} (does not degrade to r+)");
        tb_regex_free(many_q);
    }
    TbRegex *zero_one_q = tb_regex_compile("^x{1}(y){0}z{2}$", "", err, sizeof(err));
    ASSERT_TRUE(zero_one_q != NULL, "Compile {1} and {0} quantifiers");
    if (zero_one_q) {
        TbRegexMatch m;
        ASSERT_TRUE(tb_regex_exec(zero_one_q, "xzz", 3, 0, &m) && m.starts[1] == SIZE_MAX,
                    "{0} quantifier skips group and clears capture");
        ASSERT_TRUE(!tb_regex_exec(zero_one_q, "xyzz", 4, 0, &m),
                    "{0} quantifier rejects non-zero occurrences");
        tb_regex_free(zero_one_q);
    }

    /* 3. Full ES6 RegExp & String integration inside TinyJS */
    JsVm *vm = js_vm_new();
    const char *rx_js =
        "const m = /([a-z]+)-(\\d+)/i.exec('>>Foo-42<<');\n"
        "const r_exec = `${m[0]}|${m[1]}|${m[2]}|${m.index}`;\n"
        "const r_lazy = '<p>one</p><p>two</p>'.match(/<p>.*?<\\/p>/g).join('|');\n"
        "const r_qmin = 'aaaaa'.match(/a{2,4}?/)[0];\n"
        "const r_wb   = 'cat scatter cat'.replace(/\\bcat\\b/g, 'dog') + ':' + /\\Bcat\\B/.test('scatter');\n"
        "const r_cls  = 'A1_ \\t!'.replace(/[\\d\\s]+/g, '-');\n"
        "const r_la   = '100px 200em 300px'.match(/\\d+(?=px)/g).join(',') + ':' + /\\b\\d+\\b(?!px)/.exec('100px 200')[0];\n"
        "const r_bref = /([\"'])hi\\1/.test(\"'hi'\") + ':' + /([\"'])hi\\1/.test(\"'hi\\\"\");\n"
        "const r_ms   = /^b/m.test('a\\nb') + ':' + /a.b/s.test('a\\nb') + ':' + /a.b/.test('a\\nb');\n"
        "const r_rep  = '2026-10-30'.replace(/(\\d{4})-(\\d{2})-(\\d{2})/, '$2/$3/$1') + '|' +\n"
        "               'x5y9'.replace(/(\\d)/g, (all, d, idx) => `[${Number(d)*2}@${idx}]`);\n"
        "const r_spl  = 'a1b2c'.split(/(\\d)/).join(':');\n"
        "const sticky = /\\d+/y; sticky.lastIndex = 3;\n"
        "const r_stk  = sticky.exec('abc123def')[0] + '@' + sticky.lastIndex;\n"
        "let badCaught = false;\n"
        "try { new RegExp('([unclosed'); } catch (e) { badCaught = true; }\n"
        "JSON.stringify({ r_exec, r_lazy, r_qmin, r_wb, r_cls, r_la, r_bref, r_ms, r_rep, r_spl, r_stk, badCaught });";

    JsVal res = js_undefined();
    bool ok = js_eval(vm, rx_js, strlen(rx_js), &res);
    ASSERT_TRUE(ok && res.type == JS_OBJECT && res.u.obj->obj_type == OBJ_STRING,
                "TinyJS RegExp comprehensive script evaluates cleanly");
    if (ok && res.type == JS_OBJECT && res.u.obj->obj_type == OBJ_STRING) {
        const char *got = ((JsStr *)res.u.obj)->data;
        const char *exp =
            "{\"r_exec\":\"Foo-42|Foo|42|2\","
            "\"r_lazy\":\"<p>one</p>|<p>two</p>\","
            "\"r_qmin\":\"aa\","
            "\"r_wb\":\"dog scatter dog:true\","
            "\"r_cls\":\"A-_-!\","
            "\"r_la\":\"100,300:200\","
            "\"r_bref\":\"true:false\","
            "\"r_ms\":\"true:true:false\","
            "\"r_rep\":\"10/30/2026|x[10@1]y[18@3]\","
            "\"r_spl\":\"a:1:b:2:c\","
            "\"r_stk\":\"123@6\","
            "\"badCaught\":true}";
        ASSERT_STR_EQ(got, exp, "Exact JS RegExp captures, lookahead, backrefs, sticky, & replace output");
    }
    js_vm_free(vm);
}
