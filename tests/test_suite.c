#define _GNU_SOURCE
#include "browser.h"
#include "common.h"
#include "css.h"
#include "dom.h"
#include "inflate.h"
#include "js.h"
#include "layout.h"
#include "mem.h"
#include "net.h"

#include <arpa/inet.h>
#include <math.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_pass = 0;
static int g_fail = 0;

#define ASSERT_TRUE(cond, msg)                                                           \
    do {                                                                                 \
        if (cond) {                                                                      \
            g_pass++;                                                                    \
        } else {                                                                         \
            g_fail++;                                                                    \
            fprintf(stderr, "  [FAIL] %s:%d — %s\n", __FILE__, __LINE__, (msg));         \
        }                                                                                \
    } while (0)

static void assert_str_eq_impl(const char *actual, const char *expected,
                               const char *msg, const char *file, int line) {
    const char *_a = actual ? actual : "(null)";
    const char *_e = expected ? expected : "(null)";
    if (strcmp(_a, _e) == 0) {
        g_pass++;
    } else {
        g_fail++;
        fprintf(stderr, "  [FAIL] %s:%d — %s (got \"%s\", expected \"%s\")\n",
                file, line, msg, _a, _e);
    }
}

#define ASSERT_STR_EQ(actual, expected, msg) \
    assert_str_eq_impl((actual), (expected), (msg), __FILE__, __LINE__)

/* Real RFC 1952 gzipped HTML+JS payload (level 9 DEFLATE) */
static const uint8_t GZIP_HTML_FIXTURE[279] = {
    0x1f,0x8b,0x08,0x00,0x30,0x9c,0xe3,0x6a,0x02,0xff,0x45,0x90,0xc1,0x6e,0x83,0x30,
    0x10,0x44,0x7f,0xc5,0xda,0x13,0x28,0x12,0x2e,0xd7,0xc6,0xf8,0xd0,0xa8,0xaa,0xaa,
    0x1e,0x52,0x29,0xfd,0x01,0x83,0x1d,0xec,0x04,0xaf,0x11,0x2c,0x51,0x49,0xd5,0x7f,
    0xef,0x02,0xad,0x7a,0x5b,0x3d,0x8f,0x67,0x67,0x47,0x79,0x8a,0x9d,0x56,0x75,0xb2,
    0xb3,0x56,0xbe,0x14,0xc1,0x56,0xd0,0xde,0x41,0xbf,0xdc,0x43,0x7f,0xf0,0x13,0x5e,
    0x9d,0x3d,0xbe,0x29,0xe9,0x4b,0xad,0xc6,0x66,0x08,0x3d,0x89,0x71,0x68,0x2a,0x90,
    0xee,0x93,0x8a,0xcb,0x08,0x5a,0xc9,0x0d,0x6b,0x65,0xc3,0x6d,0xfd,0x6d,0xfa,0x00,
    0xba,0x77,0x68,0x03,0xb6,0x4a,0x32,0xd5,0xea,0x9c,0x86,0xb8,0xbe,0x9d,0x41,0x98,
    0x86,0x42,0x42,0x76,0x18,0xa7,0x3a,0x06,0x02,0x11,0x1d,0xf9,0xc4,0x6f,0xef,0xc7,
    0xd3,0x07,0xfb,0x05,0xec,0x27,0x12,0x68,0xa2,0xab,0x20,0x8e,0x2d,0x88,0x9b,0xe9,
    0x26,0x9e,0x59,0x5e,0x3e,0xc4,0x1a,0x24,0x87,0x9d,0x88,0x12,0xae,0x86,0x4c,0x41,
    0xd0,0xdc,0x6f,0x82,0xc5,0x4f,0x9f,0x78,0xb5,0x92,0x9b,0x86,0xe3,0x2d,0xbb,0xff,
    0xb2,0xeb,0xb3,0xa3,0xc6,0x67,0x20,0x39,0xa3,0xb4,0x86,0x0c,0x9f,0x90,0x10,0xf2,
    0x82,0xbc,0xc3,0x6c,0xa8,0xf4,0xb0,0x82,0x2c,0xff,0x25,0xb6,0xd2,0x5f,0x36,0x35,
    0x53,0x74,0x48,0x45,0xeb,0xe8,0xb9,0x73,0xcb,0xf8,0x34,0xbf,0xda,0x6c,0xbd,0x93,
    0x75,0x5c,0xc4,0x21,0x21,0x31,0xae,0x6c,0xe1,0xb0,0x0d,0xe8,0x76,0xf0,0x08,0x3b,
    0x5b,0xa4,0xeb,0xfe,0x3b,0xdf,0xff,0x17,0x24,0xb7,0x92,0xe5,0xda,0xf8,0x0f,0xc9,
    0x00,0xf9,0x2c,0x78,0x01,0x00,0x00
};

/* Real RFC 1950 zlib-compressed payload */
static const uint8_t ZLIB_FIXTURE[72] = {
    0x78,0xda,0x0b,0xc9,0xcc,0xab,0x74,0x2a,0xca,0x2f,0x2f,0x4e,0x2d,0x52,0x08,0x72,
    0x73,0x36,0xb4,0x34,0x35,0x50,0x88,0xca,0xc9,0x4c,0x52,0x70,0x49,0x4d,0xce,0xcf,
    0x2d,0x28,0x4a,0x2d,0x2e,0xce,0xcc,0xcf,0x53,0x08,0x4b,0x2d,0xca,0x4c,0xcb,0x4c,
    0x4e,0x2c,0x01,0x71,0x02,0x12,0x2b,0x73,0xf2,0x13,0x53,0x14,0x15,0x42,0x46,0x35,
    0x93,0xa6,0x19,0x00,0x27,0x6f,0x82,0x09
};

/* ── Test 1: Tracked Allocator, Hard Heap Cap, Arena, & /proc/self/status ── */
static void test_memory_subsystem(void) {
    printf("[1/9] Testing tracked allocator, hard heap cap, arena, & /proc RSS...\n");
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
static void test_inflate_subsystem(void) {
    printf("[2/9] Testing RFC 1952 gzip, RFC 1950 zlib, & anti-zip-bomb ceiling...\n");
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

/* ── Test 3: URL Parser, Relative Resolver, & Omnibar Normalizer ── */
static void test_url_subsystem(void) {
    printf("[3/9] Testing URL parser, relative resolver, & omnibar normalizer...\n");
    TbUrl base;
    ASSERT_TRUE(tb_url_parse("https://example.com:8443/docs/guide/index.html?v=2#intro", &base),
                "Parse full HTTPS URL");
    ASSERT_STR_EQ(base.scheme, "https", "Parsed scheme");
    ASSERT_STR_EQ(base.host, "example.com", "Parsed host");
    ASSERT_TRUE(base.port == 8443, "Parsed custom port");
    ASSERT_STR_EQ(base.fragment, "intro", "Parsed fragment");

    char resolved[1536];
    tb_url_resolve(&base, "../assets/app.js", resolved, sizeof(resolved));
    ASSERT_STR_EQ(resolved, "https://example.com:8443/docs/assets/app.js", "Resolve ../ path");

    tb_url_resolve(&base, "//cdn.example.org/lib.js", resolved, sizeof(resolved));
    ASSERT_STR_EQ(resolved, "https://cdn.example.org/lib.js", "Resolve scheme-relative URL");

    tb_url_normalize_input("news.ycombinator.com", resolved, sizeof(resolved));
    ASSERT_STR_EQ(resolved, "https://news.ycombinator.com", "Normalize bare domain to https://");
}

/* ── Test 4: HTML5 Parser, Entities, CSS Specificity Cascade, & Selectors ── */
static void test_dom_and_css(void) {
    printf("[4/9] Testing HTML5 parser, entities, CSS specificity cascade, & selectors...\n");
    const char *html =
        "<!DOCTYPE html><html><head><title>  DOM &amp; CSS &mdash; Test  </title>"
        "<style>"
        "  p { color: #112233; }"
        "  .highlight { color: #445566; font-weight: bold; }"
        "  #hero { color: #ff0088; }"
        "  .ghost { display: none; }"
        "</style></head><body>"
        "<div class='card'><p id='hero' class='highlight'>Alpha &copy; &#65;</p>"
        "<ul><li data-role='js-item' class='active'>One<li>Two</ul>"
        "<span class='ghost' style='display:block; color: rgb(10, 20, 30)'>Override</span>"
        "</div></body></html>";

    DomDocument *doc = dom_parse_html(html, strlen(html));
    ASSERT_TRUE(doc != NULL, "dom_parse_html succeeds");
    char *title = dom_get_title(doc);
    ASSERT_STR_EQ(title, "DOM & CSS \xe2\x80\x94 Test", "Entity decode + whitespace collapse in <title>");
    tb_free(title);

    css_compute_document(doc, NULL);
    DomNode *hero = dom_get_element_by_id(doc->root, "hero");
    ASSERT_TRUE(hero != NULL, "getElementById('hero')");
    ASSERT_TRUE(hero->style.fg.r == 0xff && hero->style.fg.g == 0x00 && hero->style.fg.b == 0x88,
                "#id specificity beats .class and tag");
    ASSERT_TRUE(hero->style.bold == 1, ".highlight font-weight cascades alongside #hero color");

    DomNode *ov = dom_query_selector(doc->root, "div.card span.ghost");
    ASSERT_TRUE(ov != NULL && ov->style.display == CSS_DISP_BLOCK && ov->style.fg.g == 20,
                "Inline style overrides stylesheet display:none and rgb()");

    DomNode *li = dom_query_selector(doc->root, "div.card > ul li.active[data-role^='js']:first-child");
    ASSERT_TRUE(li != NULL, "Complex combinator + attribute + :first-child selector");
    dom_doc_free(doc);
}

/* ── Test 5: TinyJS ES6+ Language, Closures, Prototypes, Regex, HOFs, JSON, Guard ── */
static void test_js_engine(void) {
    printf("[5/9] Testing TinyJS ES6+ closures, prototypes, destructuring, regex, JSON, & step guard...\n");
    JsVm *vm = js_vm_new();
    ASSERT_TRUE(vm != NULL, "js_vm_new succeeds");

    const char *suite_js =
        "/* 1. Lexical closures & block-scoped let vs hoisted var */\n"
        "function makeCounter(seed = 10) {\n"
        "  let n = seed;\n"
        "  return (step = 1) => { n += step; return n; };\n"
        "}\n"
        "const c1 = makeCounter(5), c2 = makeCounter();\n"
        "const r_closure = `${c1(3)}:${c1()}:${c2(2)}`; /* 8:9:12 */\n"
        "\n"
        "let fns = [];\n"
        "for (let i = 0; i < 4; i++) { let k = i * i; fns.push(() => k); }\n"
        "const r_let = fns.map(f => f()).join(','); /* 0,1,4,9 */\n"
        "\n"
        "/* 2. Prototypes, `new`, `instanceof`, & lexical arrow `this` */\n"
        "function Vec(x, y) { this.x = x; this.y = y; }\n"
        "Vec.prototype.scaleSum = function(factors) {\n"
        "  return factors.map(k => (this.x + this.y) * k).reduce((a, b) => a + b, 0);\n"
        "};\n"
        "const v = new Vec(3, 4);\n"
        "const r_proto = (v instanceof Vec) ? v.scaleSum([1, 2, 3]) : -1; /* 42 */\n"
        "\n"
        "/* 3. Destructuring (var + parameter), rest/spread, `?.` & `??` */\n"
        "const cfg = { meta: { port: 0, host: 'tb.local' }, tags: ['c11', 'es6', 'tui'] };\n"
        "const { host: hostAlias, missing = 99 } = cfg.meta;\n"
        "const [firstTag, , thirdTag] = cfg.tags;\n"
        "const fmtPair = ({ a, b = 7 }, ...extra) => `${a}-${b}-${extra.length}`;\n"
        "const portVal = cfg.meta?.port ?? 8080; /* 0 (nullish, not falsy!) */\n"
        "const deadChain = cfg.nope?.deep?.prop ?? 'fallback';\n"
        "const r_es6 = `${hostAlias}|${missing}|${firstTag}-${thirdTag}|${fmtPair({a:4}, 8, 9)}|${portVal}|${deadChain}`;\n"
        "\n"
        "/* 4. RegExp, String, Array sort, JSON, try/catch/finally */\n"
        "const cleaned = 'item_12 + item_305'.replace(/\\d+/g, '#');\n"
        "const rxOk = /^[a-z]+_\\d+$/i.test('Node_42');\n"
        "const nums = [10, 2, 33, 4].sort((a, b) => a - b);\n"
        "const obj = JSON.parse(JSON.stringify({ nums, rxOk, cleaned }));\n"
        "let fin = '';\n"
        "try { fin += 'A'; throw 'boom'; } catch (e) { fin += e; } finally { fin += 'Z'; }\n"
        "\n"
        "JSON.stringify({ r_closure, r_let, r_proto, r_es6, sorted: obj.nums.join('.'), cleaned: obj.cleaned, rxOk: obj.rxOk, fin });";

    JsVal res = js_undefined();
    bool ok = js_eval(vm, suite_js, strlen(suite_js), &res);
    ASSERT_TRUE(ok && res.type == JS_OBJECT && res.u.obj->obj_type == OBJ_STRING,
                "ES6+ suite evaluates without error");
    if (ok && res.type == JS_OBJECT && res.u.obj->obj_type == OBJ_STRING) {
        const char *got = ((JsStr *)res.u.obj)->data;
        const char *exp =
            "{\"r_closure\":\"8:9:12\",\"r_let\":\"0,1,4,9\",\"r_proto\":42,"
            "\"r_es6\":\"tb.local|99|c11-tui|4-7-2|0|fallback\","
            "\"sorted\":\"2.4.10.33\",\"cleaned\":\"item_# + item_#\",\"rxOk\":true,\"fin\":\"AboomZ\"}";
        ASSERT_STR_EQ(got, exp, "Exact ES6+ suite output verification");
    }

    /* Infinite-loop step guard verification */
    vm->step_limit = 50000;
    JsVal inf_res = js_undefined();
    bool inf_ok = js_eval(vm, "while (true) {}", 15, &inf_res);
    ASSERT_TRUE(!inf_ok && strstr(vm->last_error, "RangeError") != NULL,
                "Infinite while(true){} halted cleanly by AST step limit RangeError");
    vm->step_limit = JS_DEFAULT_STEP_LIMIT;

    /* VM still healthy after step-limit exception */
    ASSERT_TRUE(js_eval(vm, "21 * 2", 6, &res) && res.type == JS_NUMBER && res.u.num == 42.0,
                "VM recovers cleanly after step-limit RangeError");
    js_vm_free(vm);
}

/* ── Test 6: 50,000-Object + Orphan DOM Node Mark-and-Sweep GC Stress Test ── */
static void test_gc_and_orphan_dom_stress(void) {
    printf("[6/9] Running 50,000-object + 5,000-detached-DOM Mark-and-Sweep GC stress...\n");
    DomDocument *doc = dom_parse_html("<html><body><div id='keep'>Live</div></body></html>", 51);
    JsVm *vm = js_vm_new();
    js_bind_document(vm, doc, "about:blank");

    uint32_t initial_dom_nodes = doc->node_count;
    const char *stress_js =
        "let sum = 0;\n"
        "for (let i = 0; i < 50000; i++) {\n"
        "  const o = { id: i, tag: 'ephemeral_' + i, list: [i, i + 1, i + 2] };\n"
        "  sum += o.list[1];\n"
        "  if ((i % 10) === 0) {\n"
        "    const orphan = document.createElement('div');\n"
        "    orphan.setAttribute('data-i', String(i));\n"
        "    orphan.appendChild(document.createTextNode('temp'));\n"
        "  }\n"
        "}\n"
        "sum;";

    JsVal res = js_undefined();
    bool ok = js_eval(vm, stress_js, strlen(stress_js), &res);
    ASSERT_TRUE(ok && res.type == JS_NUMBER && fabs(res.u.num - 1250025000.0) < 0.5,
                "50,000-iteration allocation loop computed exact checksum");

    js_gc_collect(vm);
    tb_mem_trim();

    ASSERT_TRUE(vm->gc_bytes < 96 * 1024,
                "Mark-and-Sweep GC reclaimed churned objects (< 96 KB live JS heap)");
    ASSERT_TRUE(doc->node_count == initial_dom_nodes,
                "All 5,000 detached orphan DomNode subtrees were swept and freed");

    js_vm_free(vm);
    dom_doc_free(doc);
}

/* ── Test 7: Full Browser Controller, Interactive Widgets, History, & Demos ── */
static void test_browser_lifecycle(void) {
    printf("[7/9] Testing browser navigation, widget events, input editing, & history...\n");
    TbBrowser b;
    tb_browser_init(&b, 92, 28, false);

    /* 1. about:home interactive buttons */
    ASSERT_TRUE(tb_browser_navigate(&b, "about:home", true), "Navigate to about:home");
    bool ok = tb_browser_eval_repl(&b,
        "document.getElementById('btn-inc').click();"
        "document.getElementById('btn-inc').click();"
        "document.getElementById('btn-fib').click();");
    ASSERT_TRUE(ok, "Click #btn-inc x2 and #btn-fib on about:home");
    DomNode *cnt = dom_get_element_by_id(b.doc->root, "cnt");
    char *cnt_txt = dom_get_text_content(cnt);
    ASSERT_STR_EQ(cnt_txt, "2", "#cnt updated to 2");
    tb_free(cnt_txt);

    /* 2. about:demo reactive Todo input editing + expression calculator */
    ASSERT_TRUE(tb_browser_navigate(&b, "about:demo", true), "Navigate to about:demo");
    DomNode *todo_in = dom_get_element_by_id(b.doc->root, "todo-in");
    int in_hit = layout_find_node_hit(&b.layout, todo_in);
    ASSERT_TRUE(in_hit >= 0, "Locate #todo-in HitBox in layout");
    dom_input_set_value(todo_in, "Zero leak");
    tb_browser_activate_hit(&b, in_hit);
    tb_browser_edit_key(&b, '!', 0);
    tb_browser_stop_editing(&b);
    ASSERT_STR_EQ(dom_input_get_value(todo_in), "Zero leak!", "Live cursor typing updated <input>");

    DomNode *todo_add = dom_get_element_by_id(b.doc->root, "todo-add");
    int add_hit = layout_find_node_hit(&b.layout, todo_add);
    ASSERT_TRUE(add_hit >= 0, "Locate #todo-add HitBox");
    tb_browser_activate_hit(&b, add_hit);

    TbBuf dump;
    tb_buf_init(&dump);
    layout_render_document(&b.layout, false, &dump);
    ASSERT_TRUE(dump.data && strstr(dump.data, "Zero leak!") != NULL,
                "Newly added Todo item appears in rendered TUI layout");
    tb_buf_free(&dump);

    /* 3. about:memory churn button & demos/index.html external script + history back */
    ASSERT_TRUE(tb_browser_navigate(&b, "about:memory", true), "Navigate to about:memory");
    ASSERT_TRUE(tb_browser_eval_repl(&b, "document.getElementById('btn-churn').click()"),
                "Run 5,000-object churn button in about:memory");

    ASSERT_TRUE(tb_browser_navigate(&b, "demos/index.html", true), "Navigate to demos/index.html");
    JsVal ext_ok = js_undefined();
    ASSERT_TRUE(js_eval(b.vm, "Boolean(window.TBExternalWidgetLoaded)", 38, &ext_ok) &&
                ext_ok.type == JS_BOOL && ext_ok.u.boolean,
                "External <script src='widget.js'> executed on demos/index.html");

    ASSERT_TRUE(tb_browser_back(&b) && strcmp(b.current_url, "about:memory") == 0,
                "History Back restored about:memory");
    ASSERT_TRUE(tb_browser_forward(&b) && strstr(b.current_url, "demos/index.html") != NULL,
                "History Forward restored demos/index.html");

    tb_browser_free(&b);
}

/* ── Test 8: Ephemeral Loopback HTTP/1.1 Server (302 + Chunked Gzip + External JS + fetch + POST) ── */
static void send_str(int fd, const char *s) {
    (void)send(fd, s, strlen(s), MSG_NOSIGNAL);
}

static void serve_loopback_http(int listen_fd) {
    for (int req_no = 0; req_no < 5; req_no++) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) break;
        char req[4096];
        ssize_t n = recv(cfd, req, sizeof(req) - 1, 0);
        if (n <= 0) { close(cfd); continue; }
        req[n] = '\0';

        if (strncmp(req, "GET /start ", 11) == 0) {
            send_str(cfd, "HTTP/1.1 302 Found\r\nLocation: /app\r\nConnection: close\r\n\r\n");
        } else if (strncmp(req, "GET /app ", 9) == 0) {
            /* Serve GZIP_HTML_FIXTURE split across two HTTP/1.1 chunks! */
            send_str(cfd,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/html; charset=utf-8\r\n"
                     "Content-Encoding: gzip\r\n"
                     "Transfer-Encoding: chunked\r\n"
                     "Connection: close\r\n\r\n");
            size_t half = 100;
            size_t rest = sizeof(GZIP_HTML_FIXTURE) - half;
            char chdr[32];
            snprintf(chdr, sizeof(chdr), "%zx\r\n", half);
            send_str(cfd, chdr);
            (void)send(cfd, GZIP_HTML_FIXTURE, half, MSG_NOSIGNAL);
            send_str(cfd, "\r\n");
            snprintf(chdr, sizeof(chdr), "%zx\r\n", rest);
            send_str(cfd, chdr);
            (void)send(cfd, GZIP_HTML_FIXTURE + half, rest, MSG_NOSIGNAL);
            send_str(cfd, "\r\n0\r\n\r\n");
        } else if (strncmp(req, "GET /ext.js ", 12) == 0) {
            const char *js = "document.getElementById('gz').textContent += '+ExtJS';";
            char hdr[256];
            snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     strlen(js), js);
            send_str(cfd, hdr);
        } else if (strncmp(req, "GET /api/data.json ", 19) == 0) {
            const char *json = "{\"engine\":\"TinyJS\",\"ok\":true}";
            char hdr[256];
            snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     strlen(json), json);
            send_str(cfd, hdr);
        } else if (strncmp(req, "POST /submit ", 13) == 0) {
            const char *body = strstr(req, "\r\n\r\n");
            body = body ? body + 4 : "";
            char html[512];
            snprintf(html, sizeof(html), "<html><body><p id='post-echo'>POSTED:%s</p></body></html>", body);
            char hdr[768];
            snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     strlen(html), html);
            send_str(cfd, hdr);
        }
        close(cfd);
    }
    close(listen_fd);
}

static void test_http_end_to_end(void) {
    printf("[8/9] Testing live loopback HTTP/1.1 (302, chunked+gzip, external JS, fetch, POST)...\n");
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        printf("  [SKIP] Loopback socket unavailable in environment\n");
        return;
    }
    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(lfd, 8) < 0) {
        close(lfd);
        printf("  [SKIP] Loopback bind unavailable in environment\n");
        return;
    }
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (struct sockaddr *)&addr, &alen);
    int port = ntohs(addr.sin_port);

    pid_t pid = fork();
    if (pid == 0) {
        serve_loopback_http(lfd);
        _exit(0);
    }
    close(lfd);

    TbBrowser b;
    tb_browser_init(&b, 88, 24, false);
    char start_url[128];
    snprintf(start_url, sizeof(start_url), "http://127.0.0.1:%d/start", port);
    ASSERT_TRUE(tb_browser_navigate(&b, start_url, true), "Navigate via 302 redirect to /app");

    TbBuf rendered;
    tb_buf_init(&rendered);
    layout_render_document(&b.layout, false, &rendered);
    ASSERT_TRUE(rendered.data && strstr(rendered.data, "GzipChunkedOK+ExtJS") != NULL,
                "Chunked gzip HTML + external <script src='/ext.js'> rendered");
    ASSERT_TRUE(rendered.data && strstr(rendered.data, "TinyJS:true") != NULL,
                "JS fetch('/api/data.json').then(r => r.json()) updated DOM");
    tb_buf_free(&rendered);

    /* Submit POST <form> via button HitBox */
    DomNode *sub_btn = dom_get_element_by_id(b.doc->root, "sub");
    int sub_hit = layout_find_node_hit(&b.layout, sub_btn);
    ASSERT_TRUE(sub_hit >= 0, "Locate submit button HitBox");
    tb_browser_activate_hit(&b, sub_hit);

    DomNode *echo = b.doc ? dom_get_element_by_id(b.doc->root, "post-echo") : NULL;
    char *echo_txt = dom_get_text_content(echo);
    ASSERT_STR_EQ(echo_txt, "POSTED:msg=sub10mb", "Form POST URL-encoded body round-trip");
    tb_free(echo_txt);

    tb_browser_free(&b);
    int wstatus = 0;
    waitpid(pid, &wstatus, 0);
}

/* ── Test 9: Strict < 10 MB Kernel VmRSS Assertion ── */
static void test_strict_memory_budget(void) {
    printf("[9/9] Verifying kernel /proc/self/status VmRSS strictly < 10 MB (10,240 KB)...\n");
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

int main(void) {
    tb_mem_init(TB_DEFAULT_HEAP_LIMIT);
    printf("=== TB Verification & Sub-10MB Memory Stress Suite ===\n");

    test_memory_subsystem();
    test_inflate_subsystem();
    test_url_subsystem();
    test_dom_and_css();
    test_js_engine();
    test_gc_and_orphan_dom_stress();
    test_browser_lifecycle();
    test_http_end_to_end();
    test_strict_memory_budget();

    printf("======================================================\n");
    printf("Result: %d assertions passed, %d failed.\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
