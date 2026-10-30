#include "browser.h"
#include "common.h"
#include "css.h"
#include "dom.h"
#include "inflate.h"
#include "js.h"
#include "layout.h"
#include "math_tb.h"
#include "mem.h"
#include "net.h"
#include "regex_tb.h"
#include "tls.h"

#ifndef fabs
#define fabs tb_fabs
#endif

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

/* ── Test 10: In-Tree IEEE-754 Math & Gregorian UTC Helpers (Zero -lm) ── */
static void test_math_tb_subsystem(void) {
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
static void test_regex_tb_subsystem(void) {
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

/* ── Test 12: Direct RFC 1035 DNS Parser, Pointer-Loop Guard, & Live UDP->TCP Fallback ── */
static void serve_mock_dns(int udp_fd, int tcp_fd) {
    /* 1. Handle two UDP queries:
     *    - "udp.tb.test" -> direct A record 127.0.0.42
     *    - "big.tb.test" -> TC=1 truncated header triggering client TCP retry! */
    for (int i = 0; i < 2; i++) {
        uint8_t q[512];
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        ssize_t n = recvfrom(udp_fd, q, sizeof(q), 0, (struct sockaddr *)&cli, &clen);
        if (n < 18) continue;

        bool is_big = (n > 16 && memcmp(q + 13, "big", 3) == 0);
        uint8_t r[256];
        memset(r, 0, sizeof(r));
        r[0] = q[0];
        r[1] = q[1];
        if (is_big) {
            /* QR=1, RD=1, RA=1, TC=1 (0x8380) */
            r[2] = 0x83;
            r[3] = 0x80;
            r[4] = 0x00; r[5] = 0x01;
            memcpy(r + 12, q + 12, (size_t)(n - 12));
            (void)sendto(udp_fd, r, (size_t)n, MSG_NOSIGNAL, (struct sockaddr *)&cli, clen);
        } else {
            /* QR=1, RD=1, RA=1 (0x8180), QDCOUNT=1, ANCOUNT=1 */
            r[2] = 0x81; r[3] = 0x80;
            r[4] = 0x00; r[5] = 0x01;
            r[6] = 0x00; r[7] = 0x01;
            size_t p = 12;
            size_t qbody = (size_t)(n - 12);
            memcpy(r + p, q + 12, qbody);
            p += qbody;
            /* Answer: pointer 0xC00C -> TYPE A (1), CLASS IN (1), TTL 60, RDLEN 4, 127.0.0.42 */
            uint8_t ans[16] = {
                0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
                127, 0, 0, 42
            };
            memcpy(r + p, ans, sizeof(ans));
            p += sizeof(ans);
            (void)sendto(udp_fd, r, p, MSG_NOSIGNAL, (struct sockaddr *)&cli, clen);
        }
    }

    /* 2. Accept TCP fallback connection for "big.tb.test" and return CNAME -> A (127.0.0.99) */
    struct pollfd pfd = { .fd = tcp_fd, .events = POLLIN, .revents = 0 };
    if (poll(&pfd, 1, 3000) > 0) {
        int cfd = accept(tcp_fd, NULL, NULL);
        if (cfd >= 0) {
            uint8_t tq[516];
            ssize_t tn = recv(cfd, tq, sizeof(tq), 0);
            if (tn >= 14) {
                size_t qlen = ((size_t)tq[0] << 8) | tq[1];
                if (2 + qlen <= (size_t)tn && qlen >= 16) {
                    uint8_t tr[256];
                    size_t p = 2; /* Reserve 2 bytes for TCP length prefix */
                    memset(tr, 0, sizeof(tr));
                    tr[p + 0] = tq[2]; tr[p + 1] = tq[3]; /* TXID */
                    tr[p + 2] = 0x81;  tr[p + 3] = 0x80;  /* Standard response */
                    tr[p + 4] = 0x00;  tr[p + 5] = 0x01;  /* QDCOUNT = 1 */
                    tr[p + 6] = 0x00;  tr[p + 7] = 0x02;  /* ANCOUNT = 2 (CNAME + A) */
                    size_t off = p + 12;
                    memcpy(tr + off, tq + 2 + 12, qlen - 12);
                    off += (qlen - 12);

                    /* RR 1: big.tb.test (0xC00C) CNAME real.tb.test */
                    const uint8_t cname_rdata[] = { 4,'r','e','a','l', 2,'t','b', 4,'t','e','s','t', 0 };
                    tr[off++] = 0xC0; tr[off++] = 0x0C;
                    tr[off++] = 0x00; tr[off++] = 0x05; /* CNAME */
                    tr[off++] = 0x00; tr[off++] = 0x01; /* IN */
                    tr[off++] = 0x00; tr[off++] = 0x00; tr[off++] = 0x00; tr[off++] = 0x3C;
                    tr[off++] = 0x00; tr[off++] = (uint8_t)sizeof(cname_rdata);
                    size_t real_name_pkt_off = off - p;
                    memcpy(tr + off, cname_rdata, sizeof(cname_rdata));
                    off += sizeof(cname_rdata);

                    /* RR 2: real.tb.test (compressed pointer) A 127.0.0.99 */
                    tr[off++] = (uint8_t)(0xC0U | (real_name_pkt_off >> 8));
                    tr[off++] = (uint8_t)(real_name_pkt_off & 0xFFU);
                    tr[off++] = 0x00; tr[off++] = 0x01; /* A */
                    tr[off++] = 0x00; tr[off++] = 0x01; /* IN */
                    tr[off++] = 0x00; tr[off++] = 0x00; tr[off++] = 0x00; tr[off++] = 0x3C;
                    tr[off++] = 0x00; tr[off++] = 0x04;
                    tr[off++] = 127; tr[off++] = 0; tr[off++] = 0; tr[off++] = 99;

                    size_t dns_len = off - 2;
                    tr[0] = (uint8_t)(dns_len >> 8);
                    tr[1] = (uint8_t)(dns_len & 0xFFU);
                    (void)send(cfd, tr, off, MSG_NOSIGNAL);
                }
            }
            close(cfd);
        }
    }
    close(udp_fd);
    close(tcp_fd);
}

static void test_direct_dns_subsystem(void) {
    printf("[12/14] Testing direct IPv4/IPv6 parser, RFC 1035 DNS loop guard, & UDP->TCP fallback...\n");

    TbIpAddr ip;
    ASSERT_TRUE(tb_parse_ip_literal("127.0.0.1", &ip) && ip.family == AF_INET &&
                ip.addr[0] == 127 && ip.addr[3] == 1, "Parse valid IPv4 literal");
    ASSERT_TRUE(!tb_parse_ip_literal("256.0.0.1", &ip) &&
                !tb_parse_ip_literal("1.2.3", &ip) &&
                !tb_parse_ip_literal("01.2.3.4", &ip), "Reject malformed/octal IPv4 literals");
    ASSERT_TRUE(tb_parse_ip_literal("[::1]", &ip) && ip.family == AF_INET6 && ip.addr[15] == 1,
                "Parse bracketed IPv6 [::1]");
    ASSERT_TRUE(tb_parse_ip_literal("2001:db8::ff00:42:8329", &ip) && ip.family == AF_INET6 &&
                ip.addr[0] == 0x20 && ip.addr[1] == 0x01 && ip.addr[15] == 0x29,
                "Parse compressed IPv6 literal");
    ASSERT_TRUE(!tb_parse_ip_literal("2001::db8::1", &ip) && !tb_parse_ip_literal("[::1", &ip),
                "Reject double-:: and unclosed-[ IPv6 literals");

    /* Malicious DNS compression pointer self-loop (0xC0 0x0C) & mutual loop (12 <-> 14) */
    const uint8_t evil_self_loop[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01
    };
    const uint8_t evil_mutual_loop[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0E, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01
    };
    bool tc = false;
    TbIpAddr out[4];
    ASSERT_TRUE(tb_dns_parse_response(evil_self_loop, sizeof(evil_self_loop), 0x1234, 1, &tc, out, 4) == 0,
                "Reject DNS self-pointing compression pointer");
    ASSERT_TRUE(tb_dns_parse_response(evil_mutual_loop, sizeof(evil_mutual_loop), 0x1234, 1, &tc, out, 4) == 0,
                "Reject DNS mutual compression pointer loop within 32 hops");
    ASSERT_TRUE(tb_dns_parse_response(evil_self_loop, 8, 0x1234, 1, &tc, out, 4) == 0,
                "Reject truncated <12-byte DNS packet");

    /* /etc/hosts + RFC 6761 localhost resolution */
    char err[128] = "";
    size_t n_lh = tb_dns_resolve("localhost", 1000, out, 4, err, sizeof(err));
    ASSERT_TRUE(n_lh >= 1 && ((out[0].family == AF_INET && out[0].addr[0] == 127) ||
                              (out[0].family == AF_INET6 && out[0].addr[15] == 1)),
                "Direct resolve 'localhost' without getaddrinfo");

    /* Live loopback UDP + TC=1 TCP fallback DNS server on same port */
    int tfd = socket(AF_INET, SOCK_STREAM, 0);
    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    if (tfd >= 0 && ufd >= 0) {
        int opt = 1;
        setsockopt(tfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(ufd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = 0;
        if (bind(tfd, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(tfd, 4) == 0) {
            socklen_t alen = sizeof(addr);
            getsockname(tfd, (struct sockaddr *)&addr, &alen);
            if (bind(ufd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                int port = ntohs(addr.sin_port);
                pid_t pid = fork();
                if (pid == 0) {
                    serve_mock_dns(ufd, tfd);
                    _exit(0);
                }
                close(ufd);
                close(tfd);

                tb_dns_set_override_server("127.0.0.1", port);

                size_t n1 = tb_dns_resolve("udp.tb.test", 2000, out, 4, err, sizeof(err));
                ASSERT_TRUE(n1 == 1 && out[0].family == AF_INET &&
                            out[0].addr[0] == 127 && out[0].addr[3] == 42,
                            "Live UDP RFC 1035 DNS resolution -> 127.0.0.42");

                size_t n2 = tb_dns_resolve("big.tb.test", 2000, out, 4, err, sizeof(err));
                ASSERT_TRUE(n2 == 1 && out[0].family == AF_INET &&
                            out[0].addr[0] == 127 && out[0].addr[3] == 99,
                            "Live TC=1 truncated UDP -> automatic TCP DNS fallback + CNAME -> 127.0.0.99");

                tb_dns_set_override_server(NULL, 0);
                int wst = 0;
                waitpid(pid, &wst, 0);
                return;
            }
        }
    }
    if (tfd >= 0) close(tfd);
    if (ufd >= 0) close(ufd);
}

/* ── Test 13: Cryptographic Primitives & RFC 6125 X.509 Verification ── */
static void test_crypto_and_x509_subsystem(void) {
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

static void test_live_tls13_https(void) {
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
    test_math_tb_subsystem();
    test_regex_tb_subsystem();
    test_direct_dns_subsystem();
    test_crypto_and_x509_subsystem();
    test_live_tls13_https();

    printf("======================================================\n");
    printf("Result: %d assertions passed, %d failed.\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
