#include "test_harness.h"
#include "dom.h"
#include "js.h"
#include "math_tb.h"
#include "mem.h"

/* ── Test 5: TinyJS ES6+ Language, Closures, Prototypes, Regex, HOFs, JSON, Guard ── */
void test_js_engine(void) {
    printf("[5/14] Testing TinyJS ES6+ closures, prototypes, destructuring, regex, JSON, & step guard...\n");
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
void test_gc_and_orphan_dom_stress(void) {
    printf("[6/14] Running 50,000-object + 5,000-detached-DOM Mark-and-Sweep GC stress...\n");
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
    ASSERT_TRUE(ok && res.type == JS_NUMBER && tb_fabs(res.u.num - 1250025000.0) < 0.5,
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
