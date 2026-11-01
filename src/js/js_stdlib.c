#include "js.h"
#include "math_tb.h"
#include "regex_tb.h"

static JsVal make_str_val(JsVm *vm, const char *s, size_t len) {
    JsStr *st = js_str_new(vm, s, len);
    return st ? js_obj_val((JsObj *)st) : js_undefined();
}

static JsVal make_cstr_val(JsVm *vm, const char *s) {
    JsStr *st = js_str_cstr(vm, s);
    return st ? js_obj_val((JsObj *)st) : js_undefined();
}

static JsVal build_match_array(JsVm *vm, JsStr *subj, const TbRegexMatch *m) {
    JsObj *arr = js_arr_new(vm, m->group_count);
    if (!arr) return js_null();
    int saved_sp = vm->temp_sp;
    js_temp_push(vm, js_obj_val(arr));
    js_temp_push(vm, js_obj_val((JsObj *)subj));
    JsArrObj *a = (JsArrObj *)arr;
    a->match_index = (int32_t)m->starts[0];
    a->match_input = subj;
    for (uint32_t g = 0; g < m->group_count; g++) {
        if (m->starts[g] != SIZE_MAX && m->ends[g] >= m->starts[g]) {
            js_arr_push(vm, arr, make_str_val(vm, subj->data + m->starts[g],
                                              m->ends[g] - m->starts[g]));
        } else {
            js_arr_push(vm, arr, js_undefined());
        }
    }
    vm->temp_sp = saved_sp;
    return js_obj_val(arr);
}

static void append_regex_subst(TbBuf *out, const char *subj, size_t slen,
                               const TbRegexMatch *m, const char *rep, size_t rlen) {
    size_t ms = m->starts[0];
    size_t me = m->ends[0];
    for (size_t i = 0; i < rlen; i++) {
        if (rep[i] == '$' && i + 1 < rlen) {
            char nx = rep[i + 1];
            if (nx == '$') {
                tb_buf_append_char(out, '$');
                i++;
                continue;
            }
            if (nx == '&') {
                tb_buf_append(out, subj + ms, me - ms);
                i++;
                continue;
            }
            if (nx == '`') {
                tb_buf_append(out, subj, ms);
                i++;
                continue;
            }
            if (nx == '\'') {
                if (me < slen) tb_buf_append(out, subj + me, slen - me);
                i++;
                continue;
            }
            if (nx >= '1' && nx <= '9') {
                uint32_t g = (uint32_t)(nx - '0');
                size_t adv = 1;
                if (i + 2 < rlen && rep[i + 2] >= '0' && rep[i + 2] <= '9') {
                    uint32_t g2 = g * 10U + (uint32_t)(rep[i + 2] - '0');
                    if (g2 < m->group_count) {
                        g = g2;
                        adv = 2;
                    }
                }
                if (g < m->group_count) {
                    if (m->starts[g] != SIZE_MAX && m->ends[g] >= m->starts[g]) {
                        tb_buf_append(out, subj + m->starts[g], m->ends[g] - m->starts[g]);
                    }
                    i += adv;
                    continue;
                }
            }
        }
        tb_buf_append_char(out, rep[i]);
    }
}

static bool invoke_replace_cb(JsVm *vm, JsVal cb, JsStr *subj, const TbRegexMatch *m, TbBuf *out) {
    int saved_sp = vm->temp_sp;
    js_temp_push(vm, cb);
    js_temp_push(vm, js_obj_val((JsObj *)subj));
    int arg_base = vm->temp_sp;
    int argc = 0;
    for (uint32_t g = 0; g < m->group_count; g++) {
        JsVal gv = (m->starts[g] != SIZE_MAX && m->ends[g] >= m->starts[g])
                       ? make_str_val(vm, subj->data + m->starts[g], m->ends[g] - m->starts[g])
                       : js_undefined();
        if (!js_temp_push(vm, gv)) break;
        argc++;
    }
    if (js_temp_push(vm, js_num((double)m->starts[0]))) argc++;
    if (js_temp_push(vm, js_obj_val((JsObj *)subj))) argc++;

    JsVal rv = js_call(vm, cb, js_undefined(), argc, &vm->temp_roots[arg_base]);
    if (vm->has_thrown) {
        vm->temp_sp = saved_sp;
        return false;
    }
    JsStr *rs = js_to_str(vm, rv);
    if (rs) tb_buf_append(out, rs->data, rs->len);
    vm->temp_sp = saved_sp;
    return true;
}

/* Global & Number built-ins */
typedef enum {
    GM_PARSE_INT = 0,
    GM_PARSE_FLOAT,
    GM_IS_NAN,
    GM_IS_FINITE,
    GM_NUM_IS_NAN,
    GM_NUM_IS_INTEGER,
    GM_NUMBER_CTOR,
    GM_STRING_CTOR,
    GM_BOOLEAN_CTOR,
    GM_ERROR_CTOR,
    GM_EVAL,
    GM_ENCODE_URI_COMP,
    GM_DECODE_URI_COMP,
    GM_TB_GC
} JsGlobalMagic;

static JsVal fn_global_misc(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    JsVal a0 = argc > 0 ? argv[0] : js_undefined();
    switch (magic) {
        case GM_PARSE_INT: {
            JsStr *s = js_to_str(vm, a0);
            if (!s) return js_num(TB_NAN);
            const char *p = s->data;
            while (*p && tb_isspace(*p)) p++;
            int radix = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[1]) : 0;
            if (radix == 0) {
                if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) radix = 16;
                else radix = 10;
            }
            if (radix < 2 || radix > 36) return js_num(TB_NAN);
            char *endp = NULL;
            long long v = strtoll(p, &endp, radix);
            return (endp == p) ? js_num(TB_NAN) : js_num((double)v);
        }
        case GM_PARSE_FLOAT: {
            JsStr *s = js_to_str(vm, a0);
            if (!s) return js_num(TB_NAN);
            const char *p = s->data;
            while (*p && tb_isspace(*p)) p++;
            char *endp = NULL;
            double v   = strtod(p, &endp);
            return (endp == p) ? js_num(TB_NAN) : js_num(v);
        }
        case GM_IS_NAN:
            return js_bool(tb_isnan(js_to_num(vm, a0)));
        case GM_IS_FINITE: {
            double d = js_to_num(vm, a0);
            return js_bool(!tb_isnan(d) && !tb_isinf(d));
        }
        case GM_NUM_IS_NAN:
            return js_bool(a0.type == JS_NUMBER && tb_isnan(a0.u.num));
        case GM_NUM_IS_INTEGER:
            return js_bool(a0.type == JS_NUMBER && tb_isfinite(a0.u.num) && tb_floor(a0.u.num) == a0.u.num);
        case GM_NUMBER_CTOR:
            return js_num(argc > 0 ? js_to_num(vm, a0) : 0.0);
        case GM_STRING_CTOR:
            return argc > 0 ? js_obj_val((JsObj *)js_to_str(vm, a0)) : make_cstr_val(vm, "");
        case GM_BOOLEAN_CTOR:
            return js_bool(js_to_bool(a0));
        case GM_ERROR_CTOR: {
            JsObj *err = js_map_new(vm, vm->object_proto);
            JsStr *ms  = (argc > 0 && a0.type != JS_UNDEFINED) ? js_to_str(vm, a0) : js_str_cstr(vm, "");
            if (err && ms) {
                js_set_prop(vm, js_obj_val(err), "message", js_obj_val((JsObj *)ms));
                js_set_prop(vm, js_obj_val(err), "name", make_cstr_val(vm, "Error"));
            }
            return js_obj_val(err);
        }
        case GM_EVAL: {
            if (a0.type != JS_OBJECT || !a0.u.obj || a0.u.obj->obj_type != OBJ_STRING) return a0;
            JsStr *code = (JsStr *)a0.u.obj;
            char err_buf[256] = "";
            JsChunk *ch = js_parse(vm, code->data, code->len, false, err_buf, sizeof(err_buf));
            if (!ch) {
                js_throw_str(vm, err_buf);
                return js_undefined();
            }
            JsEnv *env = (vm->env_sp > 0) ? vm->env_stack[vm->env_sp - 1] : vm->global_env;
            JsVal ev = js_eval_chunk(vm, ch, env);
            if (ch->pinned > 0) ch->pinned--;
            return ev;
        }
        case GM_ENCODE_URI_COMP: {
            JsStr *s = js_to_str(vm, a0);
            if (!s) return make_cstr_val(vm, "");
            TbBuf b;
            tb_buf_init(&b);
            for (uint32_t i = 0; i < s->len; i++) {
                uint8_t c = (uint8_t)s->data[i];
                if (tb_isalnum((char)c) || c == '-' || c == '_' || c == '.' || c == '!' ||
                    c == '~' || c == '*' || c == '\'' || c == '(' || c == ')') {
                    tb_buf_append_char(&b, (char)c);
                } else {
                    tb_buf_printf(&b, "%%%02X", c);
                }
            }
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case GM_DECODE_URI_COMP: {
            JsStr *s = js_to_str(vm, a0);
            if (!s) return make_cstr_val(vm, "");
            TbBuf b;
            tb_buf_init(&b);
            for (uint32_t i = 0; i < s->len; i++) {
                if (s->data[i] == '%' && i + 2 < s->len &&
                    tb_isxdigit(s->data[i + 1]) && tb_isxdigit(s->data[i + 2])) {
                    int hi = tb_hex_val(s->data[i + 1]);
                    int lo = tb_hex_val(s->data[i + 2]);
                    tb_buf_append_char(&b, (char)((hi << 4) | lo));
                    i += 2;
                } else {
                    tb_buf_append_char(&b, s->data[i]);
                }
            }
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case GM_TB_GC: {
            int saved_pause = vm->gc_pause;
            vm->gc_pause = 0;
            size_t swept = js_gc_collect(vm);
            vm->gc_pause = saved_pause;
            tb_mem_trim();
            return js_num((double)swept);
        }
        default:
            return js_undefined();
    }
}

typedef enum {
    NUM_TO_FIXED = 0,
    NUM_TO_STRING
} JsNumProtoMagic;

static JsVal fn_num_proto(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    double n = js_to_num(vm, this_val);
    if (magic == NUM_TO_FIXED) {
        int digits = (argc > 0 && argv[0].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[0]) : 0;
        if (digits < 0) digits = 0;
        if (digits > 20) digits = 20;
        if (tb_isnan(n) || tb_isinf(n)) return js_obj_val((JsObj *)js_to_str(vm, js_num(n)));
        char buf[128];
        snprintf(buf, sizeof(buf), "%.*f", digits, n);
        return make_cstr_val(vm, buf);
    }
    /* NUM_TO_STRING */
    int radix = (argc > 0 && argv[0].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[0]) : 10;
    if (radix == 10 || radix < 2 || radix > 36 || !tb_isfinite(n)) {
        return js_obj_val((JsObj *)js_to_str(vm, js_num(n)));
    }
    long long iv = (long long)n;
    bool neg = iv < 0;
    unsigned long long u = neg ? (unsigned long long)(-iv) : (unsigned long long)iv;
    char buf[72];
    int pos = 70;
    buf[71] = '\0';
    const char *alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
    do {
        buf[pos--] = alphabet[u % (unsigned)radix];
        u /= (unsigned)radix;
    } while (u > 0 && pos > 1);
    if (neg) buf[pos--] = '-';
    return make_cstr_val(vm, buf + pos + 1);
}

/* Function.prototype: call, apply, bind */
typedef enum {
    FN_CALL = 0,
    FN_APPLY,
    FN_BIND
} JsFuncProtoMagic;

static JsVal fn_func_proto(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    JsVal bound_this = argc > 0 ? argv[0] : js_undefined();
    if (magic == FN_CALL) {
        return js_call(vm, this_val, bound_this, argc > 1 ? argc - 1 : 0, argc > 1 ? argv + 1 : NULL);
    }
    if (magic == FN_APPLY) {
        if (argc > 1 && argv[1].type == JS_OBJECT && argv[1].u.obj &&
            argv[1].u.obj->obj_type == OBJ_ARRAY) {
            JsArrObj *a = (JsArrObj *)argv[1].u.obj;
            return js_call(vm, this_val, bound_this, (int)a->len, a->items);
        }
        return js_call(vm, this_val, bound_this, 0, NULL);
    }
    /* FN_BIND */
    if (this_val.type == JS_OBJECT && this_val.u.obj && this_val.u.obj->obj_type == OBJ_FUNC) {
        JsFuncObj *orig = (JsFuncObj *)this_val.u.obj;
        JsFuncObj *copy = (JsFuncObj *)js_func_new(vm, orig->chunk, orig->ast_idx, orig->closure, orig->is_arrow);
        if (copy) {
            copy->bound_this     = bound_this;
            copy->has_bound_this = true;
            return js_obj_val((JsObj *)copy);
        }
    }
    return this_val;
}

/* Object methods */
typedef enum {
    OBJ_CTOR = 0,
    OBJ_KEYS,
    OBJ_VALUES,
    OBJ_ENTRIES,
    OBJ_ASSIGN,
    OBJ_CREATE,
    OBJ_HAS_OWN_PROP,
    OBJ_TO_STRING
} JsObjMagic;

static JsVal fn_object(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == OBJ_HAS_OWN_PROP) {
        if (this_val.type != JS_OBJECT || !this_val.u.obj || argc == 0) return js_bool(false);
        JsStr *k = js_to_str(vm, argv[0]);
        if (!k || this_val.u.obj->obj_type != OBJ_OBJECT) return js_bool(false);
        JsMapObj *m = (JsMapObj *)this_val.u.obj;
        for (uint32_t i = 0; i < m->count; i++) {
            if (m->props[i].key->len == k->len &&
                memcmp(m->props[i].key->data, k->data, k->len) == 0) return js_bool(true);
        }
        return js_bool(false);
    }
    if (magic == OBJ_TO_STRING) {
        return js_obj_val((JsObj *)js_to_str(vm, this_val));
    }

    JsVal a0 = argc > 0 ? argv[0] : js_undefined();
    if (magic == OBJ_CTOR) {
        if (a0.type == JS_OBJECT && a0.u.obj) return a0;
        return js_obj_val(js_map_new(vm, vm->object_proto));
    }
    if (magic == OBJ_KEYS || magic == OBJ_VALUES || magic == OBJ_ENTRIES) {
        JsObj *arr = js_arr_new(vm, 8);
        if (!arr || a0.type != JS_OBJECT || !a0.u.obj) return js_obj_val(arr);
        if (a0.u.obj->obj_type == OBJ_OBJECT) {
            JsMapObj *m = (JsMapObj *)a0.u.obj;
            for (uint32_t i = 0; i < m->count; i++) {
                if (magic == OBJ_KEYS) {
                    js_arr_push(vm, arr, js_obj_val((JsObj *)m->props[i].key));
                } else if (magic == OBJ_VALUES) {
                    js_arr_push(vm, arr, m->props[i].val);
                } else {
                    JsObj *pair = js_arr_new(vm, 2);
                    if (pair) {
                        js_arr_push(vm, pair, js_obj_val((JsObj *)m->props[i].key));
                        js_arr_push(vm, pair, m->props[i].val);
                        js_arr_push(vm, arr, js_obj_val(pair));
                    }
                }
            }
        }
        return js_obj_val(arr);
    }
    if (magic == OBJ_ASSIGN) {
        if (a0.type != JS_OBJECT || !a0.u.obj) return a0;
        for (int s = 1; s < argc; s++) {
            if (argv[s].type == JS_OBJECT && argv[s].u.obj &&
                argv[s].u.obj->obj_type == OBJ_OBJECT) {
                JsMapObj *src = (JsMapObj *)argv[s].u.obj;
                for (uint32_t i = 0; i < src->count; i++) {
                    js_set_prop_str(vm, a0, src->props[i].key, src->props[i].val);
                }
            }
        }
        return a0;
    }
    if (magic == OBJ_CREATE) {
        JsObj *proto = (a0.type == JS_OBJECT) ? a0.u.obj : NULL;
        return js_obj_val(js_map_new(vm, proto));
    }
    return js_undefined();
}

/* RegExp methods */
typedef enum {
    RX_CTOR = 0,
    RX_TEST,
    RX_EXEC
} JsRegexMagic;

static JsVal fn_regexp(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == RX_CTOR) {
        const char *pat_c = "";
        const char *flg_c = "";
        JsStr *p = NULL;
        JsStr *f = NULL;
        int saved_sp = vm->temp_sp;
        if (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj &&
            argv[0].u.obj->obj_type == OBJ_REGEX) {
            JsRegexObj *src_rx = (JsRegexObj *)argv[0].u.obj;
            pat_c = src_rx->pattern ? src_rx->pattern : "";
            flg_c = src_rx->flags ? src_rx->flags : "";
        } else if (argc > 0 && argv[0].type != JS_UNDEFINED) {
            p = js_to_str(vm, argv[0]);
            if (p) {
                js_temp_push(vm, js_obj_val((JsObj *)p));
                pat_c = p->data;
            }
        }
        if (argc > 1 && argv[1].type != JS_UNDEFINED) {
            f = js_to_str(vm, argv[1]);
            if (f) {
                js_temp_push(vm, js_obj_val((JsObj *)f));
                flg_c = f->data;
            }
        }
        JsObj *rxo = js_regex_new(vm, pat_c, flg_c);
        vm->temp_sp = saved_sp;
        return rxo ? js_obj_val(rxo) : js_undefined();
    }
    if (this_val.type != JS_OBJECT || !this_val.u.obj || this_val.u.obj->obj_type != OBJ_REGEX)
        return magic == RX_TEST ? js_bool(false) : js_null();
    JsRegexObj *rx = (JsRegexObj *)this_val.u.obj;
    JsStr *subj    = js_to_str(vm, argc > 0 ? argv[0] : js_undefined());
    if (!subj || !rx->compiled) return magic == RX_TEST ? js_bool(false) : js_null();

    uint32_t rf      = tb_regex_flags(rx->compiled);
    bool use_last    = (rf & (TB_RX_GLOBAL | TB_RX_STICKY)) != 0;
    size_t start_pos = use_last ? rx->last_index : 0;
    if (start_pos > subj->len) {
        if (use_last) rx->last_index = 0;
        return magic == RX_TEST ? js_bool(false) : js_null();
    }
    TbRegexMatch m;
    bool hit = tb_regex_exec(rx->compiled, subj->data, subj->len, start_pos, &m);
    if (!hit) {
        if (use_last) rx->last_index = 0;
        return magic == RX_TEST ? js_bool(false) : js_null();
    }
    if (use_last) rx->last_index = m.ends[0];
    if (magic == RX_TEST) return js_bool(true);
    return build_match_array(vm, subj, &m);
}

/* String & String.prototype */
static JsVal fn_str_from_char_code(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val; (void)magic;
    TbBuf b;
    tb_buf_init(&b);
    for (int i = 0; i < argc; i++) {
        uint32_t cp = (uint32_t)js_to_num(vm, argv[i]) & 0xFFFFU;
        char u8[4];
        size_t n = tb_utf8_encode(cp, u8);
        tb_buf_append(&b, u8, n);
    }
    JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
    tb_buf_free(&b);
    return r;
}

typedef enum {
    STR_TO_STRING = 0,
    STR_CHAR_AT,
    STR_CHAR_CODE_AT,
    STR_SLICE,
    STR_SUBSTRING,
    STR_SUBSTR,
    STR_INDEX_OF,
    STR_INCLUDES,
    STR_STARTS_WITH,
    STR_ENDS_WITH,
    STR_TO_LOWER_CASE,
    STR_TO_UPPER_CASE,
    STR_TRIM,
    STR_REPEAT,
    STR_PAD_START,
    STR_PAD_END,
    STR_SPLIT,
    STR_REPLACE,
    STR_REPLACE_ALL,
    STR_MATCH,
    STR_LAST_INDEX_OF,
    STR_SEARCH
} JsStrProtoMagic;

static JsVal fn_str_proto(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    JsStr *s = js_to_str(vm, this_val);
    if (!s) return make_cstr_val(vm, "");
    int slen = (int)s->len;

    switch (magic) {
        case STR_TO_STRING: return js_obj_val((JsObj *)s);
        case STR_CHAR_AT: {
            int idx = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (idx < 0 || idx >= slen) return make_cstr_val(vm, "");
            return make_str_val(vm, s->data + idx, 1);
        }
        case STR_CHAR_CODE_AT: {
            int idx = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (idx < 0 || idx >= slen) return js_num(TB_NAN);
            return js_num((double)(uint8_t)s->data[idx]);
        }
        case STR_SLICE: {
            int st = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            int en = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[1]) : slen;
            if (st < 0) st = slen + st;
            if (en < 0) en = slen + en;
            if (st < 0) st = 0;
            if (en > slen) en = slen;
            if (en <= st) return make_cstr_val(vm, "");
            return make_str_val(vm, s->data + st, (size_t)(en - st));
        }
        case STR_SUBSTRING: {
            int st = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            int en = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[1]) : slen;
            if (st < 0) st = 0;
            if (en < 0) en = 0;
            if (st > slen) st = slen;
            if (en > slen) en = slen;
            if (st > en) { int t = st; st = en; en = t; }
            return make_str_val(vm, s->data + st, (size_t)(en - st));
        }
        case STR_SUBSTR: {
            int st  = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            int cnt = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[1]) : slen;
            if (st < 0) st = slen + st;
            if (st < 0) st = 0;
            if (cnt <= 0 || st >= slen) return make_cstr_val(vm, "");
            if (st + cnt > slen) cnt = slen - st;
            return make_str_val(vm, s->data + st, (size_t)cnt);
        }
        case STR_INDEX_OF:
        case STR_INCLUDES:
        case STR_STARTS_WITH:
        case STR_ENDS_WITH: {
            JsStr *ndl = js_to_str(vm, argc > 0 ? argv[0] : js_undefined());
            if (!ndl) return magic == STR_INDEX_OF ? js_num(-1) : js_bool(false);
            int nlen = (int)ndl->len;
            if (magic == STR_STARTS_WITH) {
                int pos = argc > 1 ? (int)js_to_num(vm, argv[1]) : 0;
                if (pos < 0) pos = 0;
                return js_bool(pos + nlen <= slen && memcmp(s->data + pos, ndl->data, (size_t)nlen) == 0);
            }
            if (magic == STR_ENDS_WITH) {
                return js_bool(nlen <= slen && memcmp(s->data + slen - nlen, ndl->data, (size_t)nlen) == 0);
            }
            int from = argc > 1 ? (int)js_to_num(vm, argv[1]) : 0;
            if (from < 0) from = 0;
            if (from > slen) return magic == STR_INDEX_OF ? js_num(-1) : js_bool(false);
            const char *hit = strstr(s->data + from, ndl->data);
            if (!hit) return magic == STR_INDEX_OF ? js_num(-1) : js_bool(false);
            return magic == STR_INDEX_OF ? js_num((double)(hit - s->data)) : js_bool(true);
        }
        case STR_TO_LOWER_CASE:
        case STR_TO_UPPER_CASE: {
            char *tmp = tb_strndup(s->data, s->len);
            if (!tmp) return js_obj_val((JsObj *)s);
            for (uint32_t i = 0; i < s->len; i++) {
                tmp[i] = (magic == STR_TO_LOWER_CASE) ? tb_tolower(tmp[i]) : tb_toupper(tmp[i]);
            }
            JsVal r = make_str_val(vm, tmp, s->len);
            tb_free(tmp);
            return r;
        }
        case STR_TRIM: {
            size_t st = 0, en = s->len;
            while (st < en && tb_isspace(s->data[st])) st++;
            while (en > st && tb_isspace(s->data[en - 1])) en--;
            return make_str_val(vm, s->data + st, en - st);
        }
        case STR_REPEAT: {
            int cnt = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (cnt <= 0 || s->len == 0) return make_cstr_val(vm, "");
            if ((size_t)cnt * s->len > 262144) cnt = (int)(262144 / s->len);
            TbBuf b;
            tb_buf_init(&b);
            for (int i = 0; i < cnt; i++) tb_buf_append(&b, s->data, s->len);
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case STR_PAD_START:
        case STR_PAD_END: {
            int target_len = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (target_len <= slen || target_len > 65536) return js_obj_val((JsObj *)s);
            JsStr *pad = (argc > 1 && argv[1].type != JS_UNDEFINED)
                             ? js_to_str(vm, argv[1])
                             : js_str_cstr(vm, " ");
            if (!pad || pad->len == 0) return js_obj_val((JsObj *)s);
            int need = target_len - slen;
            TbBuf b;
            tb_buf_init(&b);
            if (magic == STR_PAD_END) tb_buf_append(&b, s->data, s->len);
            while (need > 0) {
                size_t take = (size_t)need < pad->len ? (size_t)need : pad->len;
                tb_buf_append(&b, pad->data, take);
                need -= (int)take;
            }
            if (magic == STR_PAD_START) tb_buf_append(&b, s->data, s->len);
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case STR_SPLIT: {
            JsObj *arr = js_arr_new(vm, 8);
            if (!arr) return js_undefined();
            uint32_t limit = 0xFFFFFFFFU;
            if (argc > 1 && argv[1].type != JS_UNDEFINED) {
                double lim_d = js_to_num(vm, argv[1]);
                limit = (lim_d >= 0.0 && !tb_isnan(lim_d)) ? (uint32_t)lim_d : 0U;
            }
            if (limit == 0) return js_obj_val(arr);
            if (argc == 0 || argv[0].type == JS_UNDEFINED) {
                js_arr_push(vm, arr, js_obj_val((JsObj *)s));
                return js_obj_val(arr);
            }
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, js_obj_val((JsObj *)s));
            js_temp_push(vm, js_obj_val(arr));
            if (argv[0].type == JS_OBJECT && argv[0].u.obj && argv[0].u.obj->obj_type == OBJ_REGEX) {
                JsRegexObj *rx = (JsRegexObj *)argv[0].u.obj;
                if (!rx->compiled) {
                    js_arr_push(vm, arr, js_obj_val((JsObj *)s));
                    vm->temp_sp = saved_sp;
                    return js_obj_val(arr);
                }
                if (s->len == 0) {
                    TbRegexMatch em;
                    if (!tb_regex_exec(rx->compiled, "", 0, 0, &em)) {
                        js_arr_push(vm, arr, make_cstr_val(vm, ""));
                    }
                    vm->temp_sp = saved_sp;
                    return js_obj_val(arr);
                }
                size_t last_end = 0;
                size_t scan_pos = 0;
                TbRegexMatch m;
                while (scan_pos <= s->len &&
                       tb_regex_exec(rx->compiled, s->data, s->len, scan_pos, &m)) {
                    if (m.starts[0] == s->len && m.ends[0] == s->len) break;
                    if (m.ends[0] == last_end) {
                        scan_pos++;
                        continue;
                    }
                    js_arr_push(vm, arr, make_str_val(vm, s->data + last_end, m.starts[0] - last_end));
                    if (((JsArrObj *)arr)->len >= limit) {
                        vm->temp_sp = saved_sp;
                        return js_obj_val(arr);
                    }
                    for (uint32_t g = 1; g < m.group_count; g++) {
                        JsVal gv = (m.starts[g] != SIZE_MAX && m.ends[g] >= m.starts[g])
                                       ? make_str_val(vm, s->data + m.starts[g], m.ends[g] - m.starts[g])
                                       : js_undefined();
                        js_arr_push(vm, arr, gv);
                        if (((JsArrObj *)arr)->len >= limit) {
                            vm->temp_sp = saved_sp;
                            return js_obj_val(arr);
                        }
                    }
                    last_end = m.ends[0];
                    scan_pos = (m.ends[0] == m.starts[0]) ? m.ends[0] + 1 : m.ends[0];
                }
                if (((JsArrObj *)arr)->len < limit) {
                    js_arr_push(vm, arr, make_str_val(vm, s->data + last_end, s->len - last_end));
                }
                vm->temp_sp = saved_sp;
                return js_obj_val(arr);
            }
            JsStr *sep = js_to_str(vm, argv[0]);
            if (sep) js_temp_push(vm, js_obj_val((JsObj *)sep));
            if (!sep || sep->len == 0) {
                for (uint32_t i = 0; i < s->len && ((JsArrObj *)arr)->len < limit; i++) {
                    js_arr_push(vm, arr, make_str_val(vm, s->data + i, 1));
                }
                vm->temp_sp = saved_sp;
                return js_obj_val(arr);
            }
            const char *p = s->data;
            const char *hit;
            while ((hit = strstr(p, sep->data)) != NULL) {
                js_arr_push(vm, arr, make_str_val(vm, p, (size_t)(hit - p)));
                if (((JsArrObj *)arr)->len >= limit) {
                    vm->temp_sp = saved_sp;
                    return js_obj_val(arr);
                }
                p = hit + sep->len;
            }
            if (((JsArrObj *)arr)->len < limit) {
                js_arr_push(vm, arr, make_cstr_val(vm, p));
            }
            vm->temp_sp = saved_sp;
            return js_obj_val(arr);
        }
        case STR_REPLACE:
        case STR_REPLACE_ALL: {
            if (argc < 2) return js_obj_val((JsObj *)s);
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, js_obj_val((JsObj *)s));

            bool is_fn = (argv[1].type == JS_OBJECT && argv[1].u.obj &&
                          (argv[1].u.obj->obj_type == OBJ_FUNC ||
                           argv[1].u.obj->obj_type == OBJ_NATIVE_FN));
            JsStr *rep = NULL;
            if (!is_fn) {
                rep = js_to_str(vm, argv[1]);
                if (!rep) {
                    vm->temp_sp = saved_sp;
                    return js_obj_val((JsObj *)s);
                }
                js_temp_push(vm, js_obj_val((JsObj *)rep));
            }

            bool all = (magic == STR_REPLACE_ALL);
            TbBuf b;
            tb_buf_init(&b);

            if (argv[0].type == JS_OBJECT && argv[0].u.obj && argv[0].u.obj->obj_type == OBJ_REGEX) {
                JsRegexObj *rx = (JsRegexObj *)argv[0].u.obj;
                if (!rx->compiled) {
                    tb_buf_free(&b);
                    vm->temp_sp = saved_sp;
                    return js_obj_val((JsObj *)s);
                }
                uint32_t rf = tb_regex_flags(rx->compiled);
                if (rf & TB_RX_GLOBAL) {
                    all = true;
                    rx->last_index = 0;
                }
                size_t last_end = 0;
                size_t scan_pos = 0;
                TbRegexMatch m;
                while (scan_pos <= s->len &&
                       tb_regex_exec(rx->compiled, s->data, s->len, scan_pos, &m)) {
                    if (m.starts[0] > last_end) {
                        tb_buf_append(&b, s->data + last_end, m.starts[0] - last_end);
                    }
                    if (is_fn) {
                        if (!invoke_replace_cb(vm, argv[1], s, &m, &b)) {
                            tb_buf_free(&b);
                            vm->temp_sp = saved_sp;
                            return js_undefined();
                        }
                    } else {
                        append_regex_subst(&b, s->data, s->len, &m, rep->data, rep->len);
                    }
                    last_end = m.ends[0];
                    if (!all) break;
                    if (m.ends[0] == m.starts[0]) {
                        if (m.ends[0] < s->len) {
                            tb_buf_append_char(&b, s->data[m.ends[0]]);
                            last_end = m.ends[0] + 1;
                        }
                        scan_pos = m.ends[0] + 1;
                    } else {
                        scan_pos = m.ends[0];
                    }
                }
                if (last_end < s->len) tb_buf_append(&b, s->data + last_end, s->len - last_end);
            } else {
                JsStr *pat = js_to_str(vm, argv[0]);
                if (!pat) {
                    tb_buf_free(&b);
                    vm->temp_sp = saved_sp;
                    return js_obj_val((JsObj *)s);
                }
                js_temp_push(vm, js_obj_val((JsObj *)pat));
                if (pat->len == 0) {
                    for (size_t i = 0; i <= s->len; i++) {
                        TbRegexMatch m;
                        memset(&m, 0, sizeof(m));
                        m.group_count = 1;
                        m.starts[0]   = i;
                        m.ends[0]     = i;
                        if (is_fn) {
                            if (!invoke_replace_cb(vm, argv[1], s, &m, &b)) {
                                tb_buf_free(&b);
                                vm->temp_sp = saved_sp;
                                return js_undefined();
                            }
                        } else {
                            append_regex_subst(&b, s->data, s->len, &m, rep->data, rep->len);
                        }
                        if (!all) {
                            tb_buf_append(&b, s->data, s->len);
                            break;
                        }
                        if (i < s->len) tb_buf_append_char(&b, s->data[i]);
                    }
                } else {
                    size_t pos = 0;
                    const char *hit;
                    while ((hit = strstr(s->data + pos, pat->data)) != NULL) {
                        size_t ms = (size_t)(hit - s->data);
                        size_t me = ms + pat->len;
                        if (ms > pos) tb_buf_append(&b, s->data + pos, ms - pos);
                        TbRegexMatch m;
                        memset(&m, 0, sizeof(m));
                        m.group_count = 1;
                        m.starts[0]   = ms;
                        m.ends[0]     = me;
                        if (is_fn) {
                            if (!invoke_replace_cb(vm, argv[1], s, &m, &b)) {
                                tb_buf_free(&b);
                                vm->temp_sp = saved_sp;
                                return js_undefined();
                            }
                        } else {
                            append_regex_subst(&b, s->data, s->len, &m, rep->data, rep->len);
                        }
                        pos = me;
                        if (!all) break;
                    }
                    if (pos < s->len) tb_buf_append(&b, s->data + pos, s->len - pos);
                }
            }
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            vm->temp_sp = saved_sp;
            return r;
        }
        case STR_MATCH: {
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, js_obj_val((JsObj *)s));
            if (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj &&
                argv[0].u.obj->obj_type == OBJ_REGEX) {
                JsRegexObj *rx = (JsRegexObj *)argv[0].u.obj;
                if (!rx->compiled) {
                    vm->temp_sp = saved_sp;
                    return js_null();
                }
                uint32_t rf = tb_regex_flags(rx->compiled);
                if (!(rf & TB_RX_GLOBAL)) {
                    size_t start_pos = (rf & TB_RX_STICKY) ? rx->last_index : 0;
                    if (start_pos > s->len) {
                        if (rf & TB_RX_STICKY) rx->last_index = 0;
                        vm->temp_sp = saved_sp;
                        return js_null();
                    }
                    TbRegexMatch m;
                    bool hit = tb_regex_exec(rx->compiled, s->data, s->len, start_pos, &m);
                    if (!hit) {
                        if (rf & TB_RX_STICKY) rx->last_index = 0;
                        vm->temp_sp = saved_sp;
                        return js_null();
                    }
                    if (rf & TB_RX_STICKY) rx->last_index = m.ends[0];
                    JsVal res = build_match_array(vm, s, &m);
                    vm->temp_sp = saved_sp;
                    return res;
                }
                rx->last_index = 0;
                JsObj *arr = js_arr_new(vm, 4);
                if (arr) js_temp_push(vm, js_obj_val(arr));
                size_t pos = 0;
                bool any = false;
                TbRegexMatch m;
                while (pos <= s->len &&
                       tb_regex_exec(rx->compiled, s->data, s->len, pos, &m)) {
                    any = true;
                    js_arr_push(vm, arr, make_str_val(vm, s->data + m.starts[0],
                                                      m.ends[0] - m.starts[0]));
                    pos = (m.ends[0] > m.starts[0]) ? m.ends[0] : m.ends[0] + 1;
                }
                vm->temp_sp = saved_sp;
                return any ? js_obj_val(arr) : js_null();
            }
            const char *pat = "";
            if (argc > 0 && argv[0].type != JS_UNDEFINED) {
                JsStr *ps = js_to_str(vm, argv[0]);
                if (ps) {
                    js_temp_push(vm, js_obj_val((JsObj *)ps));
                    pat = ps->data;
                }
            }
            char err_buf[128] = "";
            TbRegex *tmp_rx = tb_regex_compile(pat, "", err_buf, sizeof(err_buf));
            if (!tmp_rx) {
                vm->temp_sp = saved_sp;
                if (err_buf[0]) js_throw_str(vm, err_buf);
                return js_undefined();
            }
            TbRegexMatch m;
            bool hit = tb_regex_exec(tmp_rx, s->data, s->len, 0, &m);
            tb_regex_free(tmp_rx);
            JsVal res = hit ? build_match_array(vm, s, &m) : js_null();
            vm->temp_sp = saved_sp;
            return res;
        }
        case STR_LAST_INDEX_OF: {
            JsStr *ndl = js_to_str(vm, argc > 0 ? argv[0] : js_undefined());
            if (!ndl || (int)ndl->len > slen) return js_num(-1);
            for (int i = slen - (int)ndl->len; i >= 0; i--) {
                if (memcmp(s->data + i, ndl->data, ndl->len) == 0) return js_num((double)i);
            }
            return js_num(-1);
        }
        case STR_SEARCH: {
            if (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj &&
                argv[0].u.obj->obj_type == OBJ_REGEX) {
                JsRegexObj *rx = (JsRegexObj *)argv[0].u.obj;
                if (!rx->compiled) return js_num(-1);
                TbRegexMatch m;
                bool hit = tb_regex_exec(rx->compiled, s->data, s->len, 0, &m);
                return js_num(hit ? (double)m.starts[0] : -1.0);
            }
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, js_obj_val((JsObj *)s));
            const char *pat = "";
            if (argc > 0 && argv[0].type != JS_UNDEFINED) {
                JsStr *ps = js_to_str(vm, argv[0]);
                if (ps) {
                    js_temp_push(vm, js_obj_val((JsObj *)ps));
                    pat = ps->data;
                }
            }
            char err_buf[128] = "";
            TbRegex *tmp_rx = tb_regex_compile(pat, "", err_buf, sizeof(err_buf));
            vm->temp_sp = saved_sp;
            if (!tmp_rx) {
                if (err_buf[0]) js_throw_str(vm, err_buf);
                return js_undefined();
            }
            TbRegexMatch m;
            bool hit = tb_regex_exec(tmp_rx, s->data, s->len, 0, &m);
            tb_regex_free(tmp_rx);
            return js_num(hit ? (double)m.starts[0] : -1.0);
        }
        default:
            return js_undefined();
    }
}

/* Array & Array.prototype */
typedef enum {
    ARR_CTOR = 0,
    ARR_IS_ARRAY,
    ARR_FROM
} JsArrayCtorMagic;

static JsVal fn_array_ctor(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    if (magic == ARR_IS_ARRAY) {
        return js_bool(argc > 0 && argv[0].type == JS_OBJECT &&
                       argv[0].u.obj && argv[0].u.obj->obj_type == OBJ_ARRAY);
    }
    if (magic == ARR_FROM) {
        JsObj *out = js_arr_new(vm, 8);
        if (!out || argc == 0) return js_obj_val(out);
        JsVal src = argv[0];
        JsVal lenv = js_get_prop(vm, src, "length");
        uint32_t len = (lenv.type == JS_NUMBER && lenv.u.num > 0 && lenv.u.num < 65536)
                           ? (uint32_t)lenv.u.num
                           : 0;
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(out));
        for (uint32_t i = 0; i < len; i++) {
            JsVal item = js_get_index(vm, src, i);
            if (argc > 1) {
                JsVal cargs[2] = { item, js_num((double)i) };
                item = js_call(vm, argv[1], js_undefined(), 2, cargs);
            }
            js_arr_push(vm, out, item);
        }
        vm->temp_sp = saved_sp;
        return js_obj_val(out);
    }
    if (argc == 1 && argv[0].type == JS_NUMBER && argv[0].u.num >= 0 && argv[0].u.num <= 65536) {
        uint32_t n = (uint32_t)argv[0].u.num;
        JsObj *a   = js_arr_new(vm, n);
        if (a) ((JsArrObj *)a)->len = n;
        return js_obj_val(a);
    }
    JsObj *a = js_arr_new(vm, (uint32_t)(argc > 0 ? argc : 4));
    for (int i = 0; i < argc; i++) js_arr_push(vm, a, argv[i]);
    return js_obj_val(a);
}

typedef enum {
    ARR_PUSH = 0,
    ARR_POP,
    ARR_SHIFT,
    ARR_UNSHIFT,
    ARR_SLICE,
    ARR_SPLICE,
    ARR_CONCAT,
    ARR_JOIN,
    ARR_INDEX_OF,
    ARR_INCLUDES,
    ARR_REVERSE,
    ARR_SORT,
    ARR_FOR_EACH,
    ARR_MAP,
    ARR_FILTER,
    ARR_FIND,
    ARR_FIND_INDEX,
    ARR_SOME,
    ARR_EVERY,
    ARR_REDUCE
} JsArrProtoMagic;

static JsVal fn_arr_proto(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (this_val.type != JS_OBJECT || !this_val.u.obj || this_val.u.obj->obj_type != OBJ_ARRAY)
        return js_undefined();
    JsArrObj *a = (JsArrObj *)this_val.u.obj;

    switch (magic) {
        case ARR_PUSH:
            for (int i = 0; i < argc; i++) js_arr_push(vm, (JsObj *)a, argv[i]);
            return js_num((double)a->len);
        case ARR_POP:
            if (a->len == 0) return js_undefined();
            return a->items[--a->len];
        case ARR_SHIFT: {
            if (a->len == 0) return js_undefined();
            JsVal first = a->items[0];
            for (uint32_t i = 0; i + 1 < a->len; i++) a->items[i] = a->items[i + 1];
            a->len--;
            return first;
        }
        case ARR_UNSHIFT: {
            if (argc <= 0) return js_num((double)a->len);
            for (int i = 0; i < argc; i++) js_arr_push(vm, (JsObj *)a, js_undefined());
            for (int i = (int)a->len - 1; i >= argc; i--) a->items[i] = a->items[i - argc];
            for (int i = 0; i < argc; i++) a->items[i] = argv[i];
            return js_num((double)a->len);
        }
        case ARR_SLICE: {
            int len = (int)a->len;
            int st  = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            int en  = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[1]) : len;
            if (st < 0) st = len + st;
            if (en < 0) en = len + en;
            if (st < 0) st = 0;
            if (en > len) en = len;
            JsObj *res = js_arr_new(vm, en > st ? (uint32_t)(en - st) : 0);
            for (int i = st; i < en; i++) js_arr_push(vm, res, a->items[i]);
            return js_obj_val(res);
        }
        case ARR_SPLICE: {
            int len = (int)a->len;
            int st  = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (st < 0) st = len + st;
            if (st < 0) st = 0;
            if (st > len) st = len;
            int del = (argc > 1) ? (int)js_to_num(vm, argv[1]) : (len - st);
            if (del < 0) del = 0;
            if (st + del > len) del = len - st;
            int ins = argc > 2 ? argc - 2 : 0;

            JsObj *removed = js_arr_new(vm, (uint32_t)del);
            for (int i = 0; i < del; i++) js_arr_push(vm, removed, a->items[st + i]);

            int tail_cnt = len - (st + del);
            if (ins > del) {
                int grow = ins - del;
                for (int i = 0; i < grow; i++) js_arr_push(vm, (JsObj *)a, js_undefined());
                for (int i = tail_cnt - 1; i >= 0; i--) {
                    a->items[st + ins + i] = a->items[st + del + i];
                }
            } else if (ins < del) {
                for (int i = 0; i < tail_cnt; i++) {
                    a->items[st + ins + i] = a->items[st + del + i];
                }
                a->len -= (uint32_t)(del - ins);
            }
            for (int i = 0; i < ins; i++) a->items[st + i] = argv[2 + i];
            return js_obj_val(removed);
        }
        case ARR_CONCAT: {
            JsObj *res = js_arr_new(vm, a->len + (uint32_t)argc * 2);
            for (uint32_t i = 0; i < a->len; i++) js_arr_push(vm, res, a->items[i]);
            for (int i = 0; i < argc; i++) {
                if (argv[i].type == JS_OBJECT && argv[i].u.obj && argv[i].u.obj->obj_type == OBJ_ARRAY) {
                    JsArrObj *sub = (JsArrObj *)argv[i].u.obj;
                    for (uint32_t j = 0; j < sub->len; j++) js_arr_push(vm, res, sub->items[j]);
                } else {
                    js_arr_push(vm, res, argv[i]);
                }
            }
            return js_obj_val(res);
        }
        case ARR_JOIN: {
            const char *sep = ",";
            JsStr *seps = NULL;
            if (argc > 0 && argv[0].type != JS_UNDEFINED) {
                seps = js_to_str(vm, argv[0]);
                if (seps) sep = seps->data;
            }
            TbBuf b;
            tb_buf_init(&b);
            for (uint32_t i = 0; i < a->len; i++) {
                if (i > 0) tb_buf_append_cstr(&b, sep);
                if (a->items[i].type != JS_UNDEFINED && a->items[i].type != JS_NULL) {
                    JsStr *is = js_to_str(vm, a->items[i]);
                    if (is) tb_buf_append(&b, is->data, is->len);
                }
            }
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case ARR_INDEX_OF:
        case ARR_INCLUDES: {
            JsVal needle = argc > 0 ? argv[0] : js_undefined();
            for (uint32_t i = 0; i < a->len; i++) {
                bool eq = js_strict_eq(a->items[i], needle) ||
                          (magic == ARR_INCLUDES && a->items[i].type == JS_NUMBER && needle.type == JS_NUMBER &&
                           tb_isnan(a->items[i].u.num) && tb_isnan(needle.u.num));
                if (eq) return magic == ARR_INDEX_OF ? js_num((double)i) : js_bool(true);
            }
            return magic == ARR_INDEX_OF ? js_num(-1) : js_bool(false);
        }
        case ARR_REVERSE: {
            for (uint32_t i = 0; i < a->len / 2; i++) {
                JsVal tmp = a->items[i];
                a->items[i] = a->items[a->len - 1 - i];
                a->items[a->len - 1 - i] = tmp;
            }
            return this_val;
        }
        case ARR_SORT: { /* insertion sort — stable, safe across JS callbacks & GC */
            bool has_cmp = (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj);
            for (uint32_t i = 1; i < a->len; i++) {
                uint32_t j = i;
                while (j > 0) {
                    double cmp = 0;
                    if (has_cmp) {
                        JsVal cargs[2] = { a->items[j - 1], a->items[j] };
                        JsVal cr = js_call(vm, argv[0], js_undefined(), 2, cargs);
                        if (vm->has_thrown) return this_val;
                        cmp = js_to_num(vm, cr);
                    } else {
                        JsStr *sa = js_to_str(vm, a->items[j - 1]);
                        JsStr *sb = js_to_str(vm, a->items[j]);
                        cmp = (sa && sb) ? (double)strcmp(sa->data, sb->data) : 0;
                    }
                    if (cmp > 0) {
                        JsVal t = a->items[j - 1];
                        a->items[j - 1] = a->items[j];
                        a->items[j] = t;
                        j--;
                    } else {
                        break;
                    }
                }
            }
            return this_val;
        }
        case ARR_FOR_EACH:
        case ARR_MAP:
        case ARR_FILTER:
        case ARR_FIND:
        case ARR_FIND_INDEX:
        case ARR_SOME:
        case ARR_EVERY: {
            if (argc == 0) return js_undefined();
            JsVal cb   = argv[0];
            JsVal targ = argc > 1 ? argv[1] : js_undefined();
            JsObj *res = (magic == ARR_MAP || magic == ARR_FILTER) ? js_arr_new(vm, a->len) : NULL;
            int saved_sp = vm->temp_sp;
            if (res) js_temp_push(vm, js_obj_val(res));

            uint32_t snap_len = a->len;
            for (uint32_t i = 0; i < snap_len && i < a->len; i++) {
                JsVal item = a->items[i];
                JsVal cargs[3] = { item, js_num((double)i), this_val };
                JsVal rv = js_call(vm, cb, targ, 3, cargs);
                if (vm->has_thrown) { vm->temp_sp = saved_sp; return js_undefined(); }
                if (magic == ARR_MAP) js_arr_push(vm, res, rv);
                else if (magic == ARR_FILTER && js_to_bool(rv)) js_arr_push(vm, res, item);
                else if (magic == ARR_FIND && js_to_bool(rv)) { vm->temp_sp = saved_sp; return item; }
                else if (magic == ARR_FIND_INDEX && js_to_bool(rv)) { vm->temp_sp = saved_sp; return js_num((double)i); }
                else if (magic == ARR_SOME && js_to_bool(rv)) { vm->temp_sp = saved_sp; return js_bool(true); }
                else if (magic == ARR_EVERY && !js_to_bool(rv)) { vm->temp_sp = saved_sp; return js_bool(false); }
            }
            vm->temp_sp = saved_sp;
            if (magic == ARR_MAP || magic == ARR_FILTER) return js_obj_val(res);
            if (magic == ARR_FIND) return js_undefined();
            if (magic == ARR_FIND_INDEX) return js_num(-1);
            if (magic == ARR_SOME) return js_bool(false);
            if (magic == ARR_EVERY) return js_bool(true);
            return js_undefined();
        }
        case ARR_REDUCE: {
            if (argc == 0) return js_undefined();
            JsVal cb  = argv[0];
            uint32_t i = 0;
            JsVal acc = js_undefined();
            if (argc > 1) {
                acc = argv[1];
            } else if (a->len > 0) {
                acc = a->items[i++];
            } else {
                js_throw_str(vm, "TypeError: Reduce of empty array with no initial value");
                return js_undefined();
            }
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, acc);
            for (; i < a->len; i++) {
                vm->temp_roots[saved_sp] = acc;
                JsVal cargs[4] = { acc, a->items[i], js_num((double)i), this_val };
                acc = js_call(vm, cb, js_undefined(), 4, cargs);
                if (vm->has_thrown) break;
            }
            vm->temp_sp = saved_sp;
            return acc;
        }
        default:
            return js_undefined();
    }
}

/* Math & Date */
typedef enum {
    MATH_ABS = 0,
    MATH_FLOOR,
    MATH_CEIL,
    MATH_ROUND,
    MATH_TRUNC,
    MATH_SQRT,
    MATH_SIN,
    MATH_COS,
    MATH_TAN,
    MATH_LOG,
    MATH_LOG10,
    MATH_EXP,
    MATH_POW,
    MATH_ATAN2,
    MATH_SIGN,
    MATH_RANDOM,
    MATH_MIN,
    MATH_MAX
} JsMathMagic;

static JsVal fn_math(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    if (magic == MATH_RANDOM) return js_num((double)rand() / ((double)RAND_MAX + 1.0));
    if (magic == MATH_MIN || magic == MATH_MAX) {
        double best = (magic == MATH_MIN) ? TB_INFINITY : -TB_INFINITY;
        for (int i = 0; i < argc; i++) {
            double v = js_to_num(vm, argv[i]);
            if (tb_isnan(v)) return js_num(TB_NAN);
            if ((magic == MATH_MIN && v < best) || (magic == MATH_MAX && v > best)) best = v;
        }
        return js_num(best);
    }
    double x = argc > 0 ? js_to_num(vm, argv[0]) : TB_NAN;
    double y = argc > 1 ? js_to_num(vm, argv[1]) : TB_NAN;
    switch (magic) {
        case MATH_ABS:   return js_num(tb_fabs(x));
        case MATH_FLOOR: return js_num(tb_floor(x));
        case MATH_CEIL:  return js_num(tb_ceil(x));
        case MATH_ROUND: return js_num(tb_round(x));
        case MATH_TRUNC: return js_num(tb_trunc(x));
        case MATH_SQRT:  return js_num(tb_sqrt(x));
        case MATH_SIN:   return js_num(tb_sin(x));
        case MATH_COS:   return js_num(tb_cos(x));
        case MATH_TAN:   return js_num(tb_tan(x));
        case MATH_LOG:   return js_num(tb_log(x));
        case MATH_LOG10: return js_num(tb_log10(x));
        case MATH_EXP:   return js_num(tb_exp(x));
        case MATH_POW:   return js_num(tb_pow(x, y));
        case MATH_ATAN2: return js_num(tb_atan2(x, y));
        case MATH_SIGN:  return js_num(tb_isnan(x) ? TB_NAN : (x > 0 ? 1.0 : (x < 0 ? -1.0 : 0.0)));
        default:         return js_num(TB_NAN);
    }
}

typedef enum {
    DATE_NOW = 0,
    DATE_CTOR,
    DATE_GET_TIME,
    DATE_TO_ISO_STRING
} JsDateMagic;

static JsVal fn_date(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    double epoch_ms = (double)ts.tv_sec * 1000.0 + (double)(ts.tv_nsec / 1000000LL);
    if (magic == DATE_NOW) return js_num(epoch_ms);
    if (magic == DATE_CTOR) {
        double init_ms = (argc > 0 && argv[0].type != JS_UNDEFINED)
                             ? js_to_num(vm, argv[0])
                             : epoch_ms;
        JsObj *d = js_map_new(vm, vm->object_proto);
        if (d) {
            js_set_prop(vm, js_obj_val(d), "_ms", js_num(init_ms));
            js_define_native(vm, d, "getTime", fn_date, DATE_GET_TIME);
            js_define_native(vm, d, "toISOString", fn_date, DATE_TO_ISO_STRING);
        }
        return js_obj_val(d);
    }
    double ms = js_to_num(vm, js_get_prop(vm, this_val, "_ms"));
    if (magic == DATE_GET_TIME) return js_num(ms);
    if (!tb_isfinite(ms)) {
        js_throw_str(vm, "RangeError: Invalid time value");
        return js_undefined();
    }
    char iso[64];
    tb_utc_to_iso8601(ms, iso, sizeof(iso));
    return make_cstr_val(vm, iso);
}

/* console.log / warn / error / clear */
static JsVal fn_console(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    if (magic == JS_LOG_CLEAR) {
        js_log(vm, JS_LOG_CLEAR, "%s", "");
        return js_undefined();
    }
    TbBuf b;
    tb_buf_init(&b);
    for (int i = 0; i < argc; i++) {
        if (i > 0) tb_buf_append_char(&b, ' ');
        js_val_format(vm, argv[i], &b, 0);
    }
    js_log(vm, (JsLogLevel)magic, "%s", b.data ? b.data : "");
    tb_buf_free(&b);
    return js_undefined();
}

void js_stdlib_init(JsVm *vm) {
    JsObj *g = vm->global_obj;
    js_set_prop(vm, js_obj_val(g), "globalThis", js_obj_val(g));
    js_set_prop(vm, js_obj_val(g), "NaN", js_num(TB_NAN));
    js_set_prop(vm, js_obj_val(g), "Infinity", js_num(TB_INFINITY));

    /* Global functions */
    js_define_native(vm, g, "parseInt", fn_global_misc, GM_PARSE_INT);
    js_define_native(vm, g, "parseFloat", fn_global_misc, GM_PARSE_FLOAT);
    js_define_native(vm, g, "isNaN", fn_global_misc, GM_IS_NAN);
    js_define_native(vm, g, "isFinite", fn_global_misc, GM_IS_FINITE);
    js_define_native(vm, g, "eval", fn_global_misc, GM_EVAL);
    js_define_native(vm, g, "encodeURIComponent", fn_global_misc, GM_ENCODE_URI_COMP);
    js_define_native(vm, g, "decodeURIComponent", fn_global_misc, GM_DECODE_URI_COMP);

    /* Object */
    js_define_native(vm, vm->object_proto, "hasOwnProperty", fn_object, OBJ_HAS_OWN_PROP);
    js_define_native(vm, vm->object_proto, "toString", fn_object, OBJ_TO_STRING);
    JsObj *obj_ctor = js_native_fn_new(vm, "Object", fn_object, OBJ_CTOR);
    js_define_native(vm, obj_ctor, "keys", fn_object, OBJ_KEYS);
    js_define_native(vm, obj_ctor, "values", fn_object, OBJ_VALUES);
    js_define_native(vm, obj_ctor, "entries", fn_object, OBJ_ENTRIES);
    js_define_native(vm, obj_ctor, "assign", fn_object, OBJ_ASSIGN);
    js_define_native(vm, obj_ctor, "create", fn_object, OBJ_CREATE);
    js_set_prop(vm, js_obj_val(g), "Object", js_obj_val(obj_ctor));

    /* Function.prototype */
    js_define_native(vm, vm->func_proto, "call", fn_func_proto, FN_CALL);
    js_define_native(vm, vm->func_proto, "apply", fn_func_proto, FN_APPLY);
    js_define_native(vm, vm->func_proto, "bind", fn_func_proto, FN_BIND);

    /* Number & Boolean & Error */
    js_define_native(vm, vm->number_proto, "toFixed", fn_num_proto, NUM_TO_FIXED);
    js_define_native(vm, vm->number_proto, "toString", fn_num_proto, NUM_TO_STRING);
    js_define_native(vm, vm->bool_proto, "toString", fn_object, OBJ_TO_STRING);

    JsObj *num_ctor = js_native_fn_new(vm, "Number", fn_global_misc, GM_NUMBER_CTOR);
    js_define_native(vm, num_ctor, "isNaN", fn_global_misc, GM_NUM_IS_NAN);
    js_define_native(vm, num_ctor, "isFinite", fn_global_misc, GM_IS_FINITE);
    js_define_native(vm, num_ctor, "isInteger", fn_global_misc, GM_NUM_IS_INTEGER);
    js_define_native(vm, num_ctor, "parseInt", fn_global_misc, GM_PARSE_INT);
    js_define_native(vm, num_ctor, "parseFloat", fn_global_misc, GM_PARSE_FLOAT);
    js_set_prop(vm, js_obj_val(g), "Number", js_obj_val(num_ctor));
    js_define_native(vm, g, "Boolean", fn_global_misc, GM_BOOLEAN_CTOR);
    js_define_native(vm, g, "Error", fn_global_misc, GM_ERROR_CTOR);
    js_define_native(vm, g, "TypeError", fn_global_misc, GM_ERROR_CTOR);
    js_define_native(vm, g, "RangeError", fn_global_misc, GM_ERROR_CTOR);
    js_define_native(vm, g, "ReferenceError", fn_global_misc, GM_ERROR_CTOR);
    js_define_native(vm, g, "SyntaxError", fn_global_misc, GM_ERROR_CTOR);

    /* String */
    JsObj *str_ctor = js_native_fn_new(vm, "String", fn_global_misc, GM_STRING_CTOR);
    js_define_native(vm, str_ctor, "fromCharCode", fn_str_from_char_code, 0);
    js_set_prop(vm, js_obj_val(g), "String", js_obj_val(str_ctor));
    js_define_native(vm, vm->string_proto, "fromCharCode", fn_str_from_char_code, 0);
    js_define_native(vm, vm->string_proto, "toString", fn_str_proto, STR_TO_STRING);
    js_define_native(vm, vm->string_proto, "valueOf", fn_str_proto, STR_TO_STRING);
    js_define_native(vm, vm->string_proto, "charAt", fn_str_proto, STR_CHAR_AT);
    js_define_native(vm, vm->string_proto, "charCodeAt", fn_str_proto, STR_CHAR_CODE_AT);
    js_define_native(vm, vm->string_proto, "slice", fn_str_proto, STR_SLICE);
    js_define_native(vm, vm->string_proto, "substring", fn_str_proto, STR_SUBSTRING);
    js_define_native(vm, vm->string_proto, "substr", fn_str_proto, STR_SUBSTR);
    js_define_native(vm, vm->string_proto, "indexOf", fn_str_proto, STR_INDEX_OF);
    js_define_native(vm, vm->string_proto, "includes", fn_str_proto, STR_INCLUDES);
    js_define_native(vm, vm->string_proto, "startsWith", fn_str_proto, STR_STARTS_WITH);
    js_define_native(vm, vm->string_proto, "endsWith", fn_str_proto, STR_ENDS_WITH);
    js_define_native(vm, vm->string_proto, "toLowerCase", fn_str_proto, STR_TO_LOWER_CASE);
    js_define_native(vm, vm->string_proto, "toUpperCase", fn_str_proto, STR_TO_UPPER_CASE);
    js_define_native(vm, vm->string_proto, "trim", fn_str_proto, STR_TRIM);
    js_define_native(vm, vm->string_proto, "repeat", fn_str_proto, STR_REPEAT);
    js_define_native(vm, vm->string_proto, "padStart", fn_str_proto, STR_PAD_START);
    js_define_native(vm, vm->string_proto, "padEnd", fn_str_proto, STR_PAD_END);
    js_define_native(vm, vm->string_proto, "split", fn_str_proto, STR_SPLIT);
    js_define_native(vm, vm->string_proto, "replace", fn_str_proto, STR_REPLACE);
    js_define_native(vm, vm->string_proto, "replaceAll", fn_str_proto, STR_REPLACE_ALL);
    js_define_native(vm, vm->string_proto, "match", fn_str_proto, STR_MATCH);
    js_define_native(vm, vm->string_proto, "lastIndexOf", fn_str_proto, STR_LAST_INDEX_OF);
    js_define_native(vm, vm->string_proto, "search", fn_str_proto, STR_SEARCH);

    /* RegExp */
    js_define_native(vm, g, "RegExp", fn_regexp, RX_CTOR);
    js_define_native(vm, vm->regex_proto, "test", fn_regexp, RX_TEST);
    js_define_native(vm, vm->regex_proto, "exec", fn_regexp, RX_EXEC);

    /* Array */
    JsObj *arr_ctor = js_native_fn_new(vm, "Array", fn_array_ctor, ARR_CTOR);
    js_define_native(vm, arr_ctor, "isArray", fn_array_ctor, ARR_IS_ARRAY);
    js_define_native(vm, arr_ctor, "from", fn_array_ctor, ARR_FROM);
    js_set_prop(vm, js_obj_val(g), "Array", js_obj_val(arr_ctor));
    js_define_native(vm, vm->array_proto, "push", fn_arr_proto, ARR_PUSH);
    js_define_native(vm, vm->array_proto, "pop", fn_arr_proto, ARR_POP);
    js_define_native(vm, vm->array_proto, "shift", fn_arr_proto, ARR_SHIFT);
    js_define_native(vm, vm->array_proto, "unshift", fn_arr_proto, ARR_UNSHIFT);
    js_define_native(vm, vm->array_proto, "slice", fn_arr_proto, ARR_SLICE);
    js_define_native(vm, vm->array_proto, "splice", fn_arr_proto, ARR_SPLICE);
    js_define_native(vm, vm->array_proto, "concat", fn_arr_proto, ARR_CONCAT);
    js_define_native(vm, vm->array_proto, "join", fn_arr_proto, ARR_JOIN);
    js_define_native(vm, vm->array_proto, "indexOf", fn_arr_proto, ARR_INDEX_OF);
    js_define_native(vm, vm->array_proto, "includes", fn_arr_proto, ARR_INCLUDES);
    js_define_native(vm, vm->array_proto, "reverse", fn_arr_proto, ARR_REVERSE);
    js_define_native(vm, vm->array_proto, "sort", fn_arr_proto, ARR_SORT);
    js_define_native(vm, vm->array_proto, "forEach", fn_arr_proto, ARR_FOR_EACH);
    js_define_native(vm, vm->array_proto, "map", fn_arr_proto, ARR_MAP);
    js_define_native(vm, vm->array_proto, "filter", fn_arr_proto, ARR_FILTER);
    js_define_native(vm, vm->array_proto, "find", fn_arr_proto, ARR_FIND);
    js_define_native(vm, vm->array_proto, "findIndex", fn_arr_proto, ARR_FIND_INDEX);
    js_define_native(vm, vm->array_proto, "some", fn_arr_proto, ARR_SOME);
    js_define_native(vm, vm->array_proto, "every", fn_arr_proto, ARR_EVERY);
    js_define_native(vm, vm->array_proto, "reduce", fn_arr_proto, ARR_REDUCE);

    /* Math */
    JsObj *math = js_map_new(vm, vm->object_proto);
    js_set_prop(vm, js_obj_val(math), "PI", js_num(3.14159265358979323846));
    js_set_prop(vm, js_obj_val(math), "E", js_num(2.71828182845904523536));
    js_define_native(vm, math, "abs", fn_math, MATH_ABS);
    js_define_native(vm, math, "floor", fn_math, MATH_FLOOR);
    js_define_native(vm, math, "ceil", fn_math, MATH_CEIL);
    js_define_native(vm, math, "round", fn_math, MATH_ROUND);
    js_define_native(vm, math, "trunc", fn_math, MATH_TRUNC);
    js_define_native(vm, math, "sqrt", fn_math, MATH_SQRT);
    js_define_native(vm, math, "sin", fn_math, MATH_SIN);
    js_define_native(vm, math, "cos", fn_math, MATH_COS);
    js_define_native(vm, math, "tan", fn_math, MATH_TAN);
    js_define_native(vm, math, "log", fn_math, MATH_LOG);
    js_define_native(vm, math, "log10", fn_math, MATH_LOG10);
    js_define_native(vm, math, "exp", fn_math, MATH_EXP);
    js_define_native(vm, math, "pow", fn_math, MATH_POW);
    js_define_native(vm, math, "atan2", fn_math, MATH_ATAN2);
    js_define_native(vm, math, "sign", fn_math, MATH_SIGN);
    js_define_native(vm, math, "random", fn_math, MATH_RANDOM);
    js_define_native(vm, math, "min", fn_math, MATH_MIN);
    js_define_native(vm, math, "max", fn_math, MATH_MAX);
    js_set_prop(vm, js_obj_val(g), "Math", js_obj_val(math));

    /* Date */
    JsObj *date_obj = js_native_fn_new(vm, "Date", fn_date, DATE_CTOR);
    js_define_native(vm, date_obj, "now", fn_date, DATE_NOW);
    js_set_prop(vm, js_obj_val(g), "Date", js_obj_val(date_obj));

    /* JSON */
    JsObj *json = js_map_new(vm, vm->object_proto);
    js_define_native(vm, json, "parse", js_fn_json, JSON_PARSE);
    js_define_native(vm, json, "stringify", js_fn_json, JSON_STRINGIFY);
    js_set_prop(vm, js_obj_val(g), "JSON", js_obj_val(json));

    /* console */
    JsObj *cons = js_map_new(vm, vm->object_proto);
    js_define_native(vm, cons, "log", fn_console, JS_LOG_INFO);
    js_define_native(vm, cons, "info", fn_console, JS_LOG_INFO);
    js_define_native(vm, cons, "warn", fn_console, JS_LOG_WARN);
    js_define_native(vm, cons, "error", fn_console, JS_LOG_ERROR);
    js_define_native(vm, cons, "clear", fn_console, JS_LOG_CLEAR);
    js_set_prop(vm, js_obj_val(g), "console", js_obj_val(cons));

    /* tb engine controls */
    JsObj *tb_obj = js_map_new(vm, vm->object_proto);
    js_define_native(vm, tb_obj, "gc", fn_global_misc, GM_TB_GC);
    js_set_prop(vm, js_obj_val(g), "tb", js_obj_val(tb_obj));
}
