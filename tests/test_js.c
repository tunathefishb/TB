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

    /* Phase 1 & Phase 2: Classes, extends, super, static, async/await, Promises, Map/Set,
     * Accessors, Object.defineProperty/fromEntries/hasOwn/is, rest/nested destructuring,
     * computed keys, URL, URLSearchParams, localStorage/sessionStorage, atob/btoa, Headers,
     * and modern Array/String methods */
    const char *modern_js =
        "/* 1. ES6 Class, extends, super, static, getters/setters */\n"
        "class Shape {\n"
        "  static kind = 'geom';\n"
        "  constructor(name) { this.name = name; }\n"
        "  describe() { return `Shape:${this.name}`; }\n"
        "  static identify() { return this.kind; }\n"
        "}\n"
        "class Rect extends Shape {\n"
        "  static kind = 'rect';\n"
        "  constructor(w, h) { super('rect'); this.w = w; this.h = h; }\n"
        "  get area() { return this.w * this.h; }\n"
        "  set scale(f) { this.w *= f; this.h *= f; }\n"
        "  describe() { return `${super.describe()}=${this.area}`; }\n"
        "}\n"
        "const rc = new Rect(3, 4);\n"
        "rc.scale = 2;\n"
        "const r_class = `${rc.describe()}|${Rect.identify()}|${rc instanceof Shape}|${rc instanceof Rect}`;\n"
        "\n"
        "/* 2. Map, Set, for..of, spread, destructuring rest & nested, computed keys */\n"
        "const mp = new Map([['a', 10], ['b', 20]]);\n"
        "mp.set('c', 30);\n"
        "let mapSum = 0;\n"
        "for (const [k, v] of mp) { mapSum += v; }\n"
        "const st = new Set([1, 2, 2, 3, 1]);\n"
        "const stArr = [...st];\n"
        "const [head, ...tail] = [10, 20, 30, 40];\n"
        "const { x: { y: deepY }, ...restObj } = { x: { y: 77 }, p: 1, q: 2 };\n"
        "const dynKey = 'comp';\n"
        "const compObj = { [dynKey + '_1']: 42, get dbl() { return this.comp_1 * 2; } };\n"
        "const r_coll = `${mapSum}|${st.size}:${stArr.join(',')}|${head}:${tail.join(',')}|${deepY}:${Object.keys(restObj).join(',')}|${compObj.dbl}`;\n"
        "\n"
        "/* 3. Object.defineProperty, Object.fromEntries, Object.is, Object.hasOwn, Array & String methods */\n"
        "const defTarget = {};\n"
        "Object.defineProperty(defTarget, 'secret', { get() { return 123; } });\n"
        "const fromEnt = Object.fromEntries([['k1', 'v1'], ['k2', 'v2']]);\n"
        "const arrMod = [1, [2, [3]]].flat(2).flatMap(x => [x, x * 10]);\n"
        "const arrCopy = [3, 1, 2].toSorted((a, b) => a - b);\n"
        "const strMod = '  hello  '.trimStart().trimEnd() + ':' + 'abcdef'.at(-2) + ':' + [9, 8, 7].at(-1);\n"
        "const r_intr = `${defTarget.secret}|${fromEnt.k2}|${Object.hasOwn(fromEnt, 'k1')}|${Object.is(NaN, NaN)}:${Object.is(+0, -0)}|${arrMod.join(',')}|${arrCopy.join('')}|${strMod}`;\n"
        "\n"
        "/* 4. Promise, async/await, queueMicrotask */\n"
        "let order = [];\n"
        "queueMicrotask(() => order.push('mt'));\n"
        "async function computeAsync(v) {\n"
        "  const a = await Promise.resolve(v + 1);\n"
        "  const [b, c] = await Promise.all([Promise.resolve(a * 2), 10]);\n"
        "  return b + c;\n"
        "}\n"
        "let asyncOut = 0;\n"
        "computeAsync(4).then(v => { asyncOut = v; order.push('done'); });\n"
        "js_drain_check = 1;\n"
        "\n"
        "/* 5. Web Globals: URL, URLSearchParams, localStorage, atob/btoa, encodeURI, Headers */\n"
        "const u = new URL('/path/page?foo=1&bar=two#sec', 'https://example.com:8443/base/');\n"
        "u.searchParams.append('baz', '3');\n"
        "localStorage.setItem('theme', 'dark');\n"
        "localStorage.user = 'alice';\n"
        "const b64 = btoa('TinyBrowser!');\n"
        "const unb64 = atob(b64);\n"
        "const hdrs = new Headers({'X-Custom': 'val1', 'Content-Type': 'text/plain'});\n"
        "hdrs.append('X-Custom', 'val2');\n"
        "const r_web = `${u.origin}|${u.pathname}|${u.searchParams.get('bar')}|${u.searchParams.toString()}|${localStorage.getItem('theme')}:${localStorage.user}:${localStorage.length}|${unb64}|${hdrs.get('x-custom')}`;\n"
        "\n"
        "JSON.stringify({ r_class, r_coll, r_intr, r_web, asyncOut, order: order.join(',') });";

    JsVal mres = js_undefined();
    bool mok = js_eval(vm, modern_js, strlen(modern_js), &mres);
    ASSERT_TRUE(mok && mres.type == JS_OBJECT && mres.u.obj->obj_type == OBJ_STRING,
                "Modern ES6+ & Web APIs suite evaluates without error");
    if (mok && mres.type == JS_OBJECT && mres.u.obj->obj_type == OBJ_STRING) {
        const char *got = ((JsStr *)mres.u.obj)->data;
        const char *exp =
            "{\"r_class\":\"Shape:rect=48|rect|true|true\","
            "\"r_coll\":\"60|3:1,2,3|10:20,30,40|77:p,q|84\","
            "\"r_intr\":\"123|v2|true|true:false|1,10,2,20,3,30|123|hello:e:7\","
            "\"r_web\":\"https://example.com:8443|/path/page|two|foo=1&bar=two&baz=3|dark:alice:2|TinyBrowser!|val1, val2\","
            "\"asyncOut\":20,\"order\":\"mt,done\"}";
        ASSERT_STR_EQ(got, exp, "Exact modern ES6+ & Web APIs output verification");
    }

    const char *edge_js =
        "let timerPromVal = 0;\n"
        "new Promise(resolve => setTimeout(resolve, 0, 99)).then(v => { timerPromVal = v; });\n"
        "let timerAwaitVal = 0;\n"
        "(async () => {\n"
        "  const a = await new Promise(r => setTimeout(() => r(40), 5));\n"
        "  const b = await Promise.resolve(1).then(async x => {\n"
        "    const y = await Promise.resolve(x).then(v => v + 1);\n"
        "    return y;\n"
        "  });\n"
        "  timerAwaitVal = a + b;\n"
        "})();\n"
        "class BaseA {\n"
        "  static base = 10;\n"
        "  static calc() { return this.base; }\n"
        "  chain() { return 'A'; }\n"
        "}\n"
        "class MidB extends BaseA {\n"
        "  static extra = this.base + 5;\n"
        "  constructor() { super(); this.b = 2; }\n"
        "}\n"
        "class LeafC extends MidB {\n"
        "  static calc() { return super.calc() + this.extra; }\n"
        "  chain() { return super.chain() + '->C:' + this.b; }\n"
        "}\n"
        "const leafInst = new LeafC();\n"
        "const inhCheck = `${leafInst instanceof LeafC}:${leafInst instanceof BaseA}:${leafInst.chain()}:${LeafC.calc()}`;\n"
        "const redefObj = {};\n"
        "let setLog = 0;\n"
        "Object.defineProperty(redefObj, 'prop', { get: () => 10, set: v => { setLog = v; } });\n"
        "Object.defineProperty(redefObj, 'prop', { get: () => 20 });\n"
        "redefObj.prop = 77;\n"
        "const beforeValRedef = `${redefObj.prop}:${setLog}`;\n"
        "Object.defineProperty(redefObj, 'prop', { value: 55 });\n"
        "const afterValRedef = `${redefObj.prop}:${setLog}`;\n"
        "Object.defineProperty(redefObj, 'delMe', { get: () => 88 });\n"
        "delete redefObj.delMe;\n"
        "const createdObj = Object.create({ p: 1 }, { own: { value: 2 }, acc: { get: () => 3 } });\n"
        "const redefCheck = `${beforeValRedef}|${afterValRedef}|${redefObj.delMe === undefined}|${createdObj.p + createdObj.own + createdObj.acc}`;\n"
        "async function addAsync(a, b) { return this.base + a + b; }\n"
        "const boundAsync = addAsync.bind({ base: 100 }, 20);\n"
        "let boundAsyncVal = 0;\n"
        "boundAsync(3).then(v => { boundAsyncVal = v; });\n"
        "function mulAdd(a, b, c) { return this.k * (a * b + c); }\n"
        "const b1 = mulAdd.bind({ k: 2 }, 6);\n"
        "const b2 = b1.bind({ k: 999 }, 7);\n"
        "function hoistCheck(p) {\n"
        "  const pre = typeof h1 + ':' + typeof h2;\n"
        "  var [[h1], { k: h2 }] = [[11], { k: 22 }];\n"
        "  var [p] = [p + 5];\n"
        "  return `${pre}|${h1}:${h2}:${p}`;\n"
        "}\n"
        "const usp = new URLSearchParams('msg=hello%20world%21&plus=a+b');\n"
        "const uspObj = Object.fromEntries(usp);\n"
        "const uspKeys = [...usp.keys()].join(',');\n"
        "const emptySearch = new URL('https://example.com/?').search;\n";
    JsVal ejres = js_undefined();
    ASSERT_TRUE(js_eval(vm, edge_js, strlen(edge_js), &ejres),
                "Edge-case ES6+ regression setup evaluates cleanly");
    js_run_timers(vm);
    const char *edge_verify_js =
        "JSON.stringify({\n"
        "  timerPromVal,\n"
        "  timerAwaitVal,\n"
        "  inhCheck,\n"
        "  redefCheck,\n"
        "  boundAsyncVal,\n"
        "  b2Val: b2(8),\n"
        "  hoist: hoistCheck(10),\n"
        "  uspMsg: uspObj.msg,\n"
        "  uspPlus: uspObj.plus,\n"
        "  uspStr: usp.toString(),\n"
        "  uspKeys,\n"
        "  emptySearch\n"
        "});";
    ASSERT_TRUE(js_eval(vm, edge_verify_js, strlen(edge_verify_js), &ejres) &&
                ejres.type == JS_OBJECT && ejres.u.obj->obj_type == OBJ_STRING,
                "Edge-case ES6+ regression verification evaluates cleanly");
    if (ejres.type == JS_OBJECT && ejres.u.obj->obj_type == OBJ_STRING) {
        const char *got = ((JsStr *)ejres.u.obj)->data;
        const char *exp =
            "{\"timerPromVal\":99,\"timerAwaitVal\":42,"
            "\"inhCheck\":\"true:true:A->C:2:25\","
            "\"redefCheck\":\"20:77|55:77|true|6\","
            "\"boundAsyncVal\":123,\"b2Val\":100,"
            "\"hoist\":\"undefined:undefined|11:22:15\","
            "\"uspMsg\":\"hello world!\",\"uspPlus\":\"a b\","
            "\"uspStr\":\"msg=hello+world%21&plus=a+b\",\"uspKeys\":\"msg,plus\",\"emptySearch\":\"\"}";
        ASSERT_STR_EQ(got, exp, "setTimeout(resolve), timer-backed await, 3-level class/static super, Object.defineProperty redefinition, bound async, and URLSearchParams");
    }

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
