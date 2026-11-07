#include "js.h"
#include "math_tb.h"
#include "regex_tb.h"
#include "net.h"

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
    GM_ENCODE_URI,
    GM_DECODE_URI,
    GM_ATOB,
    GM_BTOA,
    GM_QUEUE_MICROTASK,
    GM_TB_GC
} JsGlobalMagic;

static bool is_uri_reserved_or_mark(char c) {
    return tb_isalnum(c) || c == '-' || c == '_' || c == '.' || c == '!' ||
           c == '~' || c == '*' || c == '\'' || c == '(' || c == ')' ||
           c == ';' || c == ',' || c == '/' || c == '?' || c == ':' ||
           c == '@' || c == '&' || c == '=' || c == '+' || c == '$' || c == '#';
}

static bool is_uri_reserved_only(char c) {
    return c == ';' || c == ',' || c == '/' || c == '?' || c == ':' ||
           c == '@' || c == '&' || c == '=' || c == '+' || c == '$' || c == '#';
}

static int b64_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

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
        case GM_ENCODE_URI_COMP:
        case GM_ENCODE_URI: {
            JsStr *s = js_to_str(vm, a0);
            if (!s) return make_cstr_val(vm, "");
            TbBuf b;
            tb_buf_init(&b);
            for (uint32_t i = 0; i < s->len; i++) {
                uint8_t c = (uint8_t)s->data[i];
                bool keep = (magic == GM_ENCODE_URI)
                    ? is_uri_reserved_or_mark((char)c)
                    : (tb_isalnum((char)c) || c == '-' || c == '_' || c == '.' || c == '!' ||
                       c == '~' || c == '*' || c == '\'' || c == '(' || c == ')');
                if (keep) {
                    tb_buf_append_char(&b, (char)c);
                } else {
                    tb_buf_printf(&b, "%%%02X", c);
                }
            }
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case GM_DECODE_URI_COMP:
        case GM_DECODE_URI: {
            JsStr *s = js_to_str(vm, a0);
            if (!s) return make_cstr_val(vm, "");
            TbBuf b;
            tb_buf_init(&b);
            for (uint32_t i = 0; i < s->len; i++) {
                if (s->data[i] == '%' && i + 2 < s->len &&
                    tb_isxdigit(s->data[i + 1]) && tb_isxdigit(s->data[i + 2])) {
                    int hi = tb_hex_val(s->data[i + 1]);
                    int lo = tb_hex_val(s->data[i + 2]);
                    char dec = (char)((hi << 4) | lo);
                    if (magic == GM_DECODE_URI && is_uri_reserved_only(dec)) {
                        tb_buf_append(&b, s->data + i, 3);
                    } else {
                        tb_buf_append_char(&b, dec);
                    }
                    i += 2;
                } else {
                    tb_buf_append_char(&b, s->data[i]);
                }
            }
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case GM_BTOA: {
            JsStr *s = js_to_str(vm, a0);
            if (!s) return make_cstr_val(vm, "");
            static const char b64_tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            TbBuf b;
            tb_buf_init(&b);
            uint32_t i = 0;
            while (i < s->len) {
                uint32_t o0 = (uint8_t)s->data[i++];
                bool has1 = (i < s->len);
                uint32_t o1 = has1 ? (uint8_t)s->data[i++] : 0;
                bool has2 = (i < s->len);
                uint32_t o2 = has2 ? (uint8_t)s->data[i++] : 0;
                uint32_t triple = (o0 << 16) | (o1 << 8) | o2;
                tb_buf_append_char(&b, b64_tab[(triple >> 18) & 0x3F]);
                tb_buf_append_char(&b, b64_tab[(triple >> 12) & 0x3F]);
                tb_buf_append_char(&b, has1 ? b64_tab[(triple >> 6) & 0x3F] : '=');
                tb_buf_append_char(&b, has2 ? b64_tab[triple & 0x3F] : '=');
            }
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case GM_ATOB: {
            JsStr *s = js_to_str(vm, a0);
            if (!s) return make_cstr_val(vm, "");
            TbBuf b;
            tb_buf_init(&b);
            int vals[4];
            int vcnt = 0;
            int pad = 0;
            for (uint32_t i = 0; i < s->len; i++) {
                char c = s->data[i];
                if (tb_isspace(c)) continue;
                if (c == '=') {
                    vals[vcnt++] = 0;
                    pad++;
                } else {
                    int v = b64_char_val(c);
                    if (v < 0) {
                        tb_buf_free(&b);
                        js_throw_str(vm, "InvalidCharacterError: atob failed");
                        return js_undefined();
                    }
                    vals[vcnt++] = v;
                }
                if (vcnt == 4) {
                    uint32_t triple = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) |
                                      ((uint32_t)vals[2] << 6) | (uint32_t)vals[3];
                    tb_buf_append_char(&b, (char)((triple >> 16) & 0xFF));
                    if (pad < 2) tb_buf_append_char(&b, (char)((triple >> 8) & 0xFF));
                    if (pad < 1) tb_buf_append_char(&b, (char)(triple & 0xFF));
                    vcnt = 0;
                    pad = 0;
                }
            }
            if (vcnt >= 2) {
                for (int k = vcnt; k < 4; k++) vals[k] = 0;
                uint32_t triple = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) |
                                  ((uint32_t)vals[2] << 6) | (uint32_t)vals[3];
                tb_buf_append_char(&b, (char)((triple >> 16) & 0xFF));
                if (vcnt == 3) tb_buf_append_char(&b, (char)((triple >> 8) & 0xFF));
            }
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case GM_QUEUE_MICROTASK: {
            if (argc > 0) js_enqueue_microtask(vm, a0, js_undefined(), 0, NULL);
            return js_undefined();
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
    OBJ_HAS_OWN,
    OBJ_IS,
    OBJ_FROM_ENTRIES,
    OBJ_DEFINE_PROP,
    OBJ_DEFINE_PROPS,
    OBJ_GET_OWN_PROP_DESC,
    OBJ_GET_OWN_PROP_NAMES,
    OBJ_GET_PROTO_OF,
    OBJ_SET_PROTO_OF,
    OBJ_TO_STRING
} JsObjMagic;

static bool map_has_own_prop(JsMapObj *m, JsStr *k) {
    if (!m || !k || (k->len > 0 && k->data[0] == '\x01')) return false;
    for (uint32_t i = 0; i < m->count; i++) {
        if (m->props[i].key->len == k->len &&
            memcmp(m->props[i].key->data, k->data, k->len) == 0) return true;
        if ((m->hdr.pad & OBJ_FLAG_HAS_ACCESSORS) &&
            m->props[i].key->len == k->len + 3 &&
            m->props[i].key->data[0] == '\x01' &&
            (m->props[i].key->data[1] == 'g' || m->props[i].key->data[1] == 's') &&
            m->props[i].key->data[2] == ':' &&
            memcmp(m->props[i].key->data + 3, k->data, k->len) == 0) return true;
    }
    return false;
}

static void apply_prop_descriptor(JsVm *vm, JsVal target, JsStr *k, JsVal desc) {
    if (target.type != JS_OBJECT || !target.u.obj || !k || desc.type != JS_OBJECT || !desc.u.obj) return;
    JsObj *tobj = target.u.obj;
    if (tobj->obj_type == OBJ_FUNC) {
        JsFuncObj *fn = (JsFuncObj *)tobj;
        if (!fn->props_obj) fn->props_obj = js_map_new(vm, NULL);
        tobj = fn->props_obj;
    }
    if (!tobj || tobj->obj_type != OBJ_OBJECT) return;
    JsVal getter = js_get_prop(vm, desc, "get");
    JsVal setter = js_get_prop(vm, desc, "set");
    bool has_get = (getter.type == JS_OBJECT && getter.u.obj &&
                    (getter.u.obj->obj_type == OBJ_FUNC || getter.u.obj->obj_type == OBJ_NATIVE_FN));
    bool has_set = (setter.type == JS_OBJECT && setter.u.obj &&
                    (setter.u.obj->obj_type == OBJ_FUNC || setter.u.obj->obj_type == OBJ_NATIVE_FN));
    if (has_get || has_set) {
        js_define_accessor(vm, tobj, k, has_get ? getter.u.obj : NULL, has_set ? setter.u.obj : NULL);
    } else if (desc.u.obj->obj_type == OBJ_OBJECT) {
        JsStr *vk = js_str_cstr(vm, "value");
        if (vk && map_has_own_prop((JsMapObj *)desc.u.obj, vk)) {
            js_set_prop_str(vm, target, k, js_get_prop_str(vm, desc, vk));
        }
    }
}

static JsVal fn_object(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == OBJ_HAS_OWN_PROP || magic == OBJ_HAS_OWN) {
        JsVal targ = (magic == OBJ_HAS_OWN) ? (argc > 0 ? argv[0] : js_undefined()) : this_val;
        JsVal keyv = (magic == OBJ_HAS_OWN) ? (argc > 1 ? argv[1] : js_undefined()) : (argc > 0 ? argv[0] : js_undefined());
        if (targ.type != JS_OBJECT || !targ.u.obj) return js_bool(false);
        JsStr *k = js_to_str(vm, keyv);
        if (!k) return js_bool(false);
        JsObj *o = targ.u.obj;
        if (o->obj_type == OBJ_FUNC) o = ((JsFuncObj *)o)->props_obj;
        if (!o || o->obj_type != OBJ_OBJECT) return js_bool(false);
        return js_bool(map_has_own_prop((JsMapObj *)o, k));
    }
    if (magic == OBJ_IS) {
        JsVal a = argc > 0 ? argv[0] : js_undefined();
        JsVal b = argc > 1 ? argv[1] : js_undefined();
        if (a.type != b.type) return js_bool(false);
        if (a.type == JS_NUMBER) {
            if (tb_isnan(a.u.num) && tb_isnan(b.u.num)) return js_bool(true);
            if (a.u.num == 0.0 && b.u.num == 0.0) {
                return js_bool((1.0 / a.u.num) == (1.0 / b.u.num));
            }
            return js_bool(a.u.num == b.u.num);
        }
        return js_bool(js_strict_eq(a, b));
    }
    if (magic == OBJ_TO_STRING) {
        return js_obj_val((JsObj *)js_to_str(vm, this_val));
    }

    JsVal a0 = argc > 0 ? argv[0] : js_undefined();
    if (magic == OBJ_CTOR) {
        if (a0.type == JS_OBJECT && a0.u.obj) return a0;
        return js_obj_val(js_map_new(vm, vm->object_proto));
    }
    if (magic == OBJ_KEYS || magic == OBJ_VALUES || magic == OBJ_ENTRIES || magic == OBJ_GET_OWN_PROP_NAMES) {
        JsObj *arr = js_arr_new(vm, 8);
        if (!arr || a0.type != JS_OBJECT || !a0.u.obj) return js_obj_val(arr);
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(arr));
        JsObj *o = a0.u.obj;
        if (o->obj_type == OBJ_FUNC) o = ((JsFuncObj *)o)->props_obj;
        if (o && o->obj_type == OBJ_OBJECT) {
            JsMapObj *m = (JsMapObj *)o;
            for (uint32_t i = 0; i < m->count; i++) {
                JsStr *k = m->props[i].key;
                if (k->len > 0 && k->data[0] == '\x01') continue;
                /* Skip internal engine underscore-prefixed backing fields on built-in tags */
                if (o->native_tag != NATIVE_TAG_NONE && k->len > 0 && k->data[0] == '_') continue;
                if (magic == OBJ_KEYS || magic == OBJ_GET_OWN_PROP_NAMES) {
                    js_arr_push(vm, arr, js_obj_val((JsObj *)k));
                } else if (magic == OBJ_VALUES) {
                    js_arr_push(vm, arr, m->props[i].val);
                } else {
                    JsObj *pair = js_arr_new(vm, 2);
                    if (pair) {
                        js_arr_push(vm, pair, js_obj_val((JsObj *)k));
                        js_arr_push(vm, pair, m->props[i].val);
                        js_arr_push(vm, arr, js_obj_val(pair));
                    }
                }
            }
        }
        vm->temp_sp = saved_sp;
        return js_obj_val(arr);
    }
    if (magic == OBJ_FROM_ENTRIES) {
        JsObj *res = js_map_new(vm, vm->object_proto);
        if (!res || a0.type != JS_OBJECT || !a0.u.obj) return js_obj_val(res);
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(res));
        JsObj *items = js_arr_new(vm, 8);
        if (items) {
            js_temp_push(vm, js_obj_val(items));
            js_iterable_to_array(vm, a0, items);
            JsArrObj *ia = (JsArrObj *)items;
            for (uint32_t i = 0; i < ia->len; i++) {
                JsVal entry = ia->items[i];
                if (entry.type == JS_OBJECT && entry.u.obj) {
                    JsVal kv = js_get_index(vm, entry, 0);
                    JsVal vv = js_get_index(vm, entry, 1);
                    JsStr *ks = js_to_str(vm, kv);
                    if (ks) js_set_prop_str(vm, js_obj_val(res), ks, vv);
                }
            }
        }
        vm->temp_sp = saved_sp;
        return js_obj_val(res);
    }
    if (magic == OBJ_DEFINE_PROP) {
        if (argc < 3 || a0.type != JS_OBJECT || !a0.u.obj) return a0;
        JsStr *k = js_to_str(vm, argv[1]);
        if (k) apply_prop_descriptor(vm, a0, k, argv[2]);
        return a0;
    }
    if (magic == OBJ_DEFINE_PROPS) {
        if (argc < 2 || a0.type != JS_OBJECT || !a0.u.obj) return a0;
        if (argv[1].type == JS_OBJECT && argv[1].u.obj && argv[1].u.obj->obj_type == OBJ_OBJECT) {
            JsMapObj *pm = (JsMapObj *)argv[1].u.obj;
            for (uint32_t i = 0; i < pm->count; i++) {
                if (pm->props[i].key->len > 0 && pm->props[i].key->data[0] == '\x01') continue;
                apply_prop_descriptor(vm, a0, pm->props[i].key, pm->props[i].val);
            }
        }
        return a0;
    }
    if (magic == OBJ_GET_OWN_PROP_DESC) {
        if (argc < 2 || a0.type != JS_OBJECT || !a0.u.obj) return js_undefined();
        JsStr *k = js_to_str(vm, argv[1]);
        if (!k) return js_undefined();
        JsObj *o = a0.u.obj;
        if (o->obj_type == OBJ_FUNC) o = ((JsFuncObj *)o)->props_obj;
        if (!o || o->obj_type != OBJ_OBJECT) return js_undefined();
        JsMapObj *m = (JsMapObj *)o;
        if (m->hdr.pad & OBJ_FLAG_HAS_ACCESSORS) {
            JsVal gfn = js_undefined(), sfn = js_undefined();
            bool found_acc = false;
            for (uint32_t i = 0; i < m->count; i++) {
                JsStr *pk = m->props[i].key;
                if (pk->len == k->len + 3 && pk->data[0] == '\x01' && pk->data[2] == ':' &&
                    memcmp(pk->data + 3, k->data, k->len) == 0) {
                    if (pk->data[1] == 'g') { gfn = m->props[i].val; found_acc = true; }
                    else if (pk->data[1] == 's') { sfn = m->props[i].val; found_acc = true; }
                }
            }
            if (found_acc) {
                JsObj *d = js_map_new(vm, vm->object_proto);
                if (d) {
                    js_set_prop(vm, js_obj_val(d), "get", gfn);
                    js_set_prop(vm, js_obj_val(d), "set", sfn);
                    js_set_prop(vm, js_obj_val(d), "enumerable", js_bool(true));
                    js_set_prop(vm, js_obj_val(d), "configurable", js_bool(true));
                }
                return js_obj_val(d);
            }
        }
        for (uint32_t i = 0; i < m->count; i++) {
            if (m->props[i].key->len == k->len &&
                memcmp(m->props[i].key->data, k->data, k->len) == 0) {
                JsObj *d = js_map_new(vm, vm->object_proto);
                if (d) {
                    js_set_prop(vm, js_obj_val(d), "value", m->props[i].val);
                    js_set_prop(vm, js_obj_val(d), "writable", js_bool(true));
                    js_set_prop(vm, js_obj_val(d), "enumerable", js_bool(true));
                    js_set_prop(vm, js_obj_val(d), "configurable", js_bool(true));
                }
                return js_obj_val(d);
            }
        }
        return js_undefined();
    }
    if (magic == OBJ_GET_PROTO_OF) {
        if (a0.type != JS_OBJECT || !a0.u.obj) return js_null();
        JsObj *o = a0.u.obj;
        JsObj *p = NULL;
        if (o->obj_type == OBJ_OBJECT) p = ((JsMapObj *)o)->proto;
        else if (o->obj_type == OBJ_ARRAY) p = ((JsArrObj *)o)->proto;
        else if (o->obj_type == OBJ_FUNC) p = ((JsFuncObj *)o)->proto;
        else if (o->obj_type == OBJ_REGEX) p = ((JsRegexObj *)o)->proto;
        else if (o->obj_type == OBJ_STRING) p = vm->string_proto;
        return p ? js_obj_val(p) : js_null();
    }
    if (magic == OBJ_SET_PROTO_OF) {
        if (a0.type != JS_OBJECT || !a0.u.obj) return a0;
        JsObj *o = a0.u.obj;
        JsObj *np = (argc > 1 && argv[1].type == JS_OBJECT) ? argv[1].u.obj : NULL;
        if (o->obj_type == OBJ_OBJECT) ((JsMapObj *)o)->proto = np;
        else if (o->obj_type == OBJ_ARRAY) ((JsArrObj *)o)->proto = np;
        else if (o->obj_type == OBJ_FUNC) ((JsFuncObj *)o)->proto = np;
        else if (o->obj_type == OBJ_REGEX) ((JsRegexObj *)o)->proto = np;
        return a0;
    }
    if (magic == OBJ_ASSIGN) {
        if (a0.type != JS_OBJECT || !a0.u.obj) return a0;
        for (int s = 1; s < argc; s++) {
            if (argv[s].type == JS_OBJECT && argv[s].u.obj &&
                argv[s].u.obj->obj_type == OBJ_OBJECT) {
                JsMapObj *src = (JsMapObj *)argv[s].u.obj;
                for (uint32_t i = 0; i < src->count; i++) {
                    if (src->props[i].key->len > 0 && src->props[i].key->data[0] == '\x01') continue;
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
    STR_AT,
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
    STR_TRIM_START,
    STR_TRIM_END,
    STR_REPEAT,
    STR_PAD_START,
    STR_PAD_END,
    STR_SPLIT,
    STR_REPLACE,
    STR_REPLACE_ALL,
    STR_MATCH,
    STR_MATCH_ALL,
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
        case STR_AT: {
            int idx = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (idx < 0) idx += slen;
            if (idx < 0 || idx >= slen) return js_undefined();
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
        case STR_TRIM:
        case STR_TRIM_START:
        case STR_TRIM_END: {
            size_t st = 0, en = s->len;
            if (magic != STR_TRIM_END) {
                while (st < en && tb_isspace(s->data[st])) st++;
            }
            if (magic != STR_TRIM_START) {
                while (en > st && tb_isspace(s->data[en - 1])) en--;
            }
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
        case STR_MATCH_ALL: {
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, js_obj_val((JsObj *)s));
            JsObj *arr = js_arr_new(vm, 4);
            if (!arr) { vm->temp_sp = saved_sp; return js_undefined(); }
            js_temp_push(vm, js_obj_val(arr));
            TbRegex *compiled = NULL;
            bool own_rx = false;
            size_t pos = 0;
            if (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj &&
                argv[0].u.obj->obj_type == OBJ_REGEX) {
                JsRegexObj *rx = (JsRegexObj *)argv[0].u.obj;
                compiled = rx->compiled;
                pos = rx->last_index;
            } else {
                const char *pat = "";
                if (argc > 0 && argv[0].type != JS_UNDEFINED) {
                    JsStr *ps = js_to_str(vm, argv[0]);
                    if (ps) {
                        js_temp_push(vm, js_obj_val((JsObj *)ps));
                        pat = ps->data;
                    }
                }
                char err_buf[128] = "";
                compiled = tb_regex_compile(pat, "g", err_buf, sizeof(err_buf));
                own_rx = true;
            }
            if (compiled) {
                TbRegexMatch m;
                while (pos <= s->len &&
                       tb_regex_exec(compiled, s->data, s->len, pos, &m)) {
                    js_arr_push(vm, arr, build_match_array(vm, s, &m));
                    pos = (m.ends[0] > m.starts[0]) ? m.ends[0] : m.ends[0] + 1;
                }
                if (own_rx) tb_regex_free(compiled);
            }
            vm->temp_sp = saved_sp;
            return js_obj_val(arr);
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

/* Iterable helper for Array.from, spread [...x], for..of, Map/Set constructors */
bool js_iterable_to_array(JsVm *vm, JsVal src, JsObj *out_arr) {
    if (!out_arr || out_arr->obj_type != OBJ_ARRAY) return false;
    if (src.type != JS_OBJECT || !src.u.obj) return false;
    JsObj *o = src.u.obj;
    if (o->obj_type == OBJ_ARRAY) {
        JsArrObj *a = (JsArrObj *)o;
        for (uint32_t i = 0; i < a->len; i++) js_arr_push(vm, out_arr, a->items[i]);
        return true;
    }
    if (o->obj_type == OBJ_STRING) {
        JsStr *s = (JsStr *)o;
        for (uint32_t i = 0; i < s->len; i++) js_arr_push(vm, out_arr, make_str_val(vm, s->data + i, 1));
        return true;
    }
    if (o->native_tag == NATIVE_TAG_SET) {
        JsVal vals = js_get_prop(vm, src, "_vals");
        if (vals.type == JS_OBJECT && vals.u.obj && vals.u.obj->obj_type == OBJ_ARRAY) {
            JsArrObj *va = (JsArrObj *)vals.u.obj;
            for (uint32_t i = 0; i < va->len; i++) js_arr_push(vm, out_arr, va->items[i]);
        }
        return true;
    }
    if (o->native_tag == NATIVE_TAG_MAP || o->native_tag == NATIVE_TAG_URL_PARAMS) {
        JsVal keys = js_get_prop(vm, src, "_keys");
        JsVal vals = js_get_prop(vm, src, "_vals");
        if (keys.type == JS_OBJECT && keys.u.obj && keys.u.obj->obj_type == OBJ_ARRAY &&
            vals.type == JS_OBJECT && vals.u.obj && vals.u.obj->obj_type == OBJ_ARRAY) {
            JsArrObj *ka = (JsArrObj *)keys.u.obj;
            JsArrObj *va = (JsArrObj *)vals.u.obj;
            uint32_t n = ka->len < va->len ? ka->len : va->len;
            for (uint32_t i = 0; i < n; i++) {
                JsObj *pair = js_arr_new(vm, 2);
                if (pair) {
                    js_arr_push(vm, pair, ka->items[i]);
                    js_arr_push(vm, pair, va->items[i]);
                    js_arr_push(vm, out_arr, js_obj_val(pair));
                }
            }
        }
        return true;
    }
    JsVal lenv = js_get_prop(vm, src, "length");
    if (lenv.type == JS_NUMBER && lenv.u.num >= 0 && lenv.u.num < 65536) {
        uint32_t len = (uint32_t)lenv.u.num;
        for (uint32_t i = 0; i < len; i++) {
            js_arr_push(vm, out_arr, js_get_index(vm, src, i));
        }
        return true;
    }
    return false;
}

/* Array & Array.prototype */
typedef enum {
    ARR_CTOR = 0,
    ARR_IS_ARRAY,
    ARR_FROM,
    ARR_OF
} JsArrayCtorMagic;

static JsVal fn_array_ctor(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    if (magic == ARR_IS_ARRAY) {
        return js_bool(argc > 0 && argv[0].type == JS_OBJECT &&
                       argv[0].u.obj && argv[0].u.obj->obj_type == OBJ_ARRAY);
    }
    if (magic == ARR_OF) {
        JsObj *a = js_arr_new(vm, (uint32_t)(argc > 0 ? argc : 4));
        for (int i = 0; i < argc; i++) js_arr_push(vm, a, argv[i]);
        return js_obj_val(a);
    }
    if (magic == ARR_FROM) {
        JsObj *out = js_arr_new(vm, 8);
        if (!out || argc == 0) return js_obj_val(out);
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(out));
        js_iterable_to_array(vm, argv[0], out);
        if (argc > 1 && argv[1].type == JS_OBJECT && argv[1].u.obj) {
            JsVal targ = argc > 2 ? argv[2] : js_undefined();
            JsArrObj *oa = (JsArrObj *)out;
            for (uint32_t i = 0; i < oa->len; i++) {
                JsVal cargs[2] = { oa->items[i], js_num((double)i) };
                oa->items[i] = js_call(vm, argv[1], targ, 2, cargs);
                if (vm->has_thrown) break;
            }
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
    ARR_AT,
    ARR_FILL,
    ARR_FLAT,
    ARR_FLAT_MAP,
    ARR_SLICE,
    ARR_SPLICE,
    ARR_CONCAT,
    ARR_JOIN,
    ARR_INDEX_OF,
    ARR_LAST_INDEX_OF,
    ARR_INCLUDES,
    ARR_REVERSE,
    ARR_SORT,
    ARR_TO_REVERSED,
    ARR_TO_SORTED,
    ARR_TO_SPLICED,
    ARR_WITH,
    ARR_FOR_EACH,
    ARR_MAP,
    ARR_FILTER,
    ARR_FIND,
    ARR_FIND_INDEX,
    ARR_FIND_LAST,
    ARR_FIND_LAST_INDEX,
    ARR_SOME,
    ARR_EVERY,
    ARR_REDUCE,
    ARR_REDUCE_RIGHT
} JsArrProtoMagic;

static void arr_flat_rec(JsVm *vm, JsArrObj *src, JsObj *out, int depth) {
    for (uint32_t i = 0; i < src->len; i++) {
        JsVal it = src->items[i];
        if (depth > 0 && it.type == JS_OBJECT && it.u.obj && it.u.obj->obj_type == OBJ_ARRAY) {
            arr_flat_rec(vm, (JsArrObj *)it.u.obj, out, depth - 1);
        } else {
            js_arr_push(vm, out, it);
        }
    }
}

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
        case ARR_AT: {
            int len = (int)a->len;
            int idx = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (idx < 0) idx += len;
            if (idx < 0 || idx >= len) return js_undefined();
            return a->items[idx];
        }
        case ARR_FILL: {
            int len = (int)a->len;
            JsVal val = argc > 0 ? argv[0] : js_undefined();
            int st = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[1]) : 0;
            int en = (argc > 2 && argv[2].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[2]) : len;
            if (st < 0) st = len + st;
            if (en < 0) en = len + en;
            if (st < 0) st = 0;
            if (en > len) en = len;
            for (int i = st; i < en; i++) a->items[i] = val;
            return this_val;
        }
        case ARR_FLAT: {
            int depth = (argc > 0 && argv[0].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[0]) : 1;
            if (depth > 32) depth = 32;
            JsObj *res = js_arr_new(vm, a->len);
            if (!res) return js_undefined();
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, js_obj_val(res));
            arr_flat_rec(vm, a, res, depth);
            vm->temp_sp = saved_sp;
            return js_obj_val(res);
        }
        case ARR_FLAT_MAP: {
            if (argc == 0) return js_undefined();
            JsVal cb   = argv[0];
            JsVal targ = argc > 1 ? argv[1] : js_undefined();
            JsObj *res = js_arr_new(vm, a->len);
            if (!res) return js_undefined();
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, js_obj_val(res));
            uint32_t snap_len = a->len;
            for (uint32_t i = 0; i < snap_len && i < a->len; i++) {
                JsVal cargs[3] = { a->items[i], js_num((double)i), this_val };
                JsVal rv = js_call(vm, cb, targ, 3, cargs);
                if (vm->has_thrown) { vm->temp_sp = saved_sp; return js_undefined(); }
                if (rv.type == JS_OBJECT && rv.u.obj && rv.u.obj->obj_type == OBJ_ARRAY) {
                    JsArrObj *sub = (JsArrObj *)rv.u.obj;
                    for (uint32_t j = 0; j < sub->len; j++) js_arr_push(vm, res, sub->items[j]);
                } else {
                    js_arr_push(vm, res, rv);
                }
            }
            vm->temp_sp = saved_sp;
            return js_obj_val(res);
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
                bool eq = (magic == ARR_INCLUDES)
                    ? js_same_value_zero(a->items[i], needle)
                    : js_strict_eq(a->items[i], needle);
                if (eq) return magic == ARR_INDEX_OF ? js_num((double)i) : js_bool(true);
            }
            return magic == ARR_INDEX_OF ? js_num(-1) : js_bool(false);
        }
        case ARR_LAST_INDEX_OF: {
            JsVal needle = argc > 0 ? argv[0] : js_undefined();
            for (int i = (int)a->len - 1; i >= 0; i--) {
                if (js_strict_eq(a->items[i], needle)) return js_num((double)i);
            }
            return js_num(-1);
        }
        case ARR_REVERSE: {
            for (uint32_t i = 0; i < a->len / 2; i++) {
                JsVal tmp = a->items[i];
                a->items[i] = a->items[a->len - 1 - i];
                a->items[a->len - 1 - i] = tmp;
            }
            return this_val;
        }
        case ARR_TO_REVERSED: {
            JsObj *res = js_arr_new(vm, a->len);
            if (!res) return js_undefined();
            for (int i = (int)a->len - 1; i >= 0; i--) js_arr_push(vm, res, a->items[i]);
            return js_obj_val(res);
        }
        case ARR_TO_SORTED: {
            JsObj *res = js_arr_new(vm, a->len);
            if (!res) return js_undefined();
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, js_obj_val(res));
            for (uint32_t i = 0; i < a->len; i++) js_arr_push(vm, res, a->items[i]);
            JsVal r = fn_arr_proto(vm, js_obj_val(res), argc, argv, ARR_SORT);
            vm->temp_sp = saved_sp;
            return r;
        }
        case ARR_TO_SPLICED: {
            JsObj *res = js_arr_new(vm, a->len + (uint32_t)(argc > 2 ? argc - 2 : 0));
            if (!res) return js_undefined();
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, js_obj_val(res));
            for (uint32_t i = 0; i < a->len; i++) js_arr_push(vm, res, a->items[i]);
            (void)fn_arr_proto(vm, js_obj_val(res), argc, argv, ARR_SPLICE);
            vm->temp_sp = saved_sp;
            return js_obj_val(res);
        }
        case ARR_WITH: {
            int len = (int)a->len;
            int idx = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (idx < 0) idx += len;
            if (idx < 0 || idx >= len) {
                js_throw_str(vm, "RangeError: Invalid index in Array.prototype.with");
                return js_undefined();
            }
            JsObj *res = js_arr_new(vm, a->len);
            if (!res) return js_undefined();
            for (uint32_t i = 0; i < a->len; i++) js_arr_push(vm, res, a->items[i]);
            ((JsArrObj *)res)->items[idx] = argc > 1 ? argv[1] : js_undefined();
            return js_obj_val(res);
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
        case ARR_FIND_LAST:
        case ARR_FIND_LAST_INDEX: {
            if (argc == 0) return magic == ARR_FIND_LAST ? js_undefined() : js_num(-1);
            JsVal cb   = argv[0];
            JsVal targ = argc > 1 ? argv[1] : js_undefined();
            for (int i = (int)a->len - 1; i >= 0; i--) {
                if ((uint32_t)i >= a->len) continue;
                JsVal item = a->items[i];
                JsVal cargs[3] = { item, js_num((double)i), this_val };
                JsVal rv = js_call(vm, cb, targ, 3, cargs);
                if (vm->has_thrown) return js_undefined();
                if (js_to_bool(rv)) {
                    return magic == ARR_FIND_LAST ? item : js_num((double)i);
                }
            }
            return magic == ARR_FIND_LAST ? js_undefined() : js_num(-1);
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
        case ARR_REDUCE_RIGHT: {
            if (argc == 0) return js_undefined();
            JsVal cb  = argv[0];
            int i     = (int)a->len - 1;
            JsVal acc = js_undefined();
            if (argc > 1) {
                acc = argv[1];
            } else if (a->len > 0) {
                acc = a->items[i--];
            } else {
                js_throw_str(vm, "TypeError: Reduce of empty array with no initial value");
                return js_undefined();
            }
            int saved_sp = vm->temp_sp;
            js_temp_push(vm, acc);
            for (; i >= 0; i--) {
                if ((uint32_t)i >= a->len) continue;
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

/* Map & Set */
typedef enum {
    MAP_CTOR = 0,
    MAP_SET,
    MAP_GET,
    MAP_HAS,
    MAP_DELETE,
    MAP_CLEAR,
    MAP_FOR_EACH,
    MAP_KEYS,
    MAP_VALUES,
    MAP_ENTRIES,
    SET_CTOR,
    SET_ADD,
    SET_HAS,
    SET_DELETE,
    SET_CLEAR,
    SET_FOR_EACH,
    SET_VALUES,
    SET_ENTRIES
} JsCollectionMagic;

static JsVal fn_collection(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == MAP_CTOR) {
        JsObj *m = js_map_new(vm, vm->map_proto);
        if (!m) return js_undefined();
        m->native_tag = NATIVE_TAG_MAP;
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(m));
        JsObj *keys = js_arr_new(vm, 8);
        JsObj *vals = js_arr_new(vm, 8);
        js_set_prop(vm, js_obj_val(m), "_keys", js_obj_val(keys));
        js_set_prop(vm, js_obj_val(m), "_vals", js_obj_val(vals));
        if (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj) {
            JsObj *items = js_arr_new(vm, 8);
            if (items) {
                js_temp_push(vm, js_obj_val(items));
                js_iterable_to_array(vm, argv[0], items);
                JsArrObj *ia = (JsArrObj *)items;
                for (uint32_t i = 0; i < ia->len; i++) {
                    JsVal entry = ia->items[i];
                    if (entry.type == JS_OBJECT && entry.u.obj) {
                        JsVal cargs[2] = { js_get_index(vm, entry, 0), js_get_index(vm, entry, 1) };
                        (void)fn_collection(vm, js_obj_val(m), 2, cargs, MAP_SET);
                    }
                }
            }
        }
        vm->temp_sp = saved_sp;
        return js_obj_val(m);
    }
    if (magic == SET_CTOR) {
        JsObj *s = js_map_new(vm, vm->set_proto);
        if (!s) return js_undefined();
        s->native_tag = NATIVE_TAG_SET;
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(s));
        JsObj *vals = js_arr_new(vm, 8);
        js_set_prop(vm, js_obj_val(s), "_vals", js_obj_val(vals));
        if (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj) {
            JsObj *items = js_arr_new(vm, 8);
            if (items) {
                js_temp_push(vm, js_obj_val(items));
                js_iterable_to_array(vm, argv[0], items);
                JsArrObj *ia = (JsArrObj *)items;
                for (uint32_t i = 0; i < ia->len; i++) {
                    (void)fn_collection(vm, js_obj_val(s), 1, &ia->items[i], SET_ADD);
                }
            }
        }
        vm->temp_sp = saved_sp;
        return js_obj_val(s);
    }

    if (this_val.type != JS_OBJECT || !this_val.u.obj) return js_undefined();
    JsObj *self = this_val.u.obj;

    if (self->native_tag == NATIVE_TAG_MAP) {
        JsVal kv = js_get_prop(vm, this_val, "_keys");
        JsVal vv = js_get_prop(vm, this_val, "_vals");
        if (kv.type != JS_OBJECT || !kv.u.obj || kv.u.obj->obj_type != OBJ_ARRAY ||
            vv.type != JS_OBJECT || !vv.u.obj || vv.u.obj->obj_type != OBJ_ARRAY) {
            return js_undefined();
        }
        JsArrObj *ka = (JsArrObj *)kv.u.obj;
        JsArrObj *va = (JsArrObj *)vv.u.obj;
        JsVal k = argc > 0 ? argv[0] : js_undefined();
        JsVal v = argc > 1 ? argv[1] : js_undefined();

        switch (magic) {
            case MAP_SET: {
                for (uint32_t i = 0; i < ka->len; i++) {
                    if (js_same_value_zero(ka->items[i], k)) {
                        va->items[i] = v;
                        return this_val;
                    }
                }
                js_arr_push(vm, (JsObj *)ka, k);
                js_arr_push(vm, (JsObj *)va, v);
                return this_val;
            }
            case MAP_GET: {
                for (uint32_t i = 0; i < ka->len; i++) {
                    if (js_same_value_zero(ka->items[i], k)) return va->items[i];
                }
                return js_undefined();
            }
            case MAP_HAS: {
                for (uint32_t i = 0; i < ka->len; i++) {
                    if (js_same_value_zero(ka->items[i], k)) return js_bool(true);
                }
                return js_bool(false);
            }
            case MAP_DELETE: {
                for (uint32_t i = 0; i < ka->len; i++) {
                    if (js_same_value_zero(ka->items[i], k)) {
                        for (uint32_t j = i; j + 1 < ka->len; j++) {
                            ka->items[j] = ka->items[j + 1];
                            va->items[j] = va->items[j + 1];
                        }
                        ka->len--;
                        va->len--;
                        return js_bool(true);
                    }
                }
                return js_bool(false);
            }
            case MAP_CLEAR:
                ka->len = 0;
                va->len = 0;
                return js_undefined();
            case MAP_FOR_EACH: {
                if (argc == 0) return js_undefined();
                JsVal cb = argv[0];
                JsVal targ = argc > 1 ? argv[1] : js_undefined();
                uint32_t snap = ka->len;
                for (uint32_t i = 0; i < snap && i < ka->len; i++) {
                    JsVal cargs[3] = { va->items[i], ka->items[i], this_val };
                    (void)js_call(vm, cb, targ, 3, cargs);
                    if (vm->has_thrown) break;
                }
                return js_undefined();
            }
            case MAP_KEYS:
            case MAP_VALUES:
            case MAP_ENTRIES: {
                JsObj *res = js_arr_new(vm, ka->len);
                if (!res) return js_undefined();
                int saved_sp = vm->temp_sp;
                js_temp_push(vm, js_obj_val(res));
                for (uint32_t i = 0; i < ka->len; i++) {
                    if (magic == MAP_KEYS) js_arr_push(vm, res, ka->items[i]);
                    else if (magic == MAP_VALUES) js_arr_push(vm, res, va->items[i]);
                    else {
                        JsObj *pair = js_arr_new(vm, 2);
                        if (pair) {
                            js_arr_push(vm, pair, ka->items[i]);
                            js_arr_push(vm, pair, va->items[i]);
                            js_arr_push(vm, res, js_obj_val(pair));
                        }
                    }
                }
                vm->temp_sp = saved_sp;
                return js_obj_val(res);
            }
            default:
                return js_undefined();
        }
    }

    if (self->native_tag == NATIVE_TAG_SET) {
        JsVal vv = js_get_prop(vm, this_val, "_vals");
        if (vv.type != JS_OBJECT || !vv.u.obj || vv.u.obj->obj_type != OBJ_ARRAY)
            return js_undefined();
        JsArrObj *va = (JsArrObj *)vv.u.obj;
        JsVal v = argc > 0 ? argv[0] : js_undefined();

        switch (magic) {
            case SET_ADD: {
                for (uint32_t i = 0; i < va->len; i++) {
                    if (js_same_value_zero(va->items[i], v)) return this_val;
                }
                js_arr_push(vm, (JsObj *)va, v);
                return this_val;
            }
            case SET_HAS: {
                for (uint32_t i = 0; i < va->len; i++) {
                    if (js_same_value_zero(va->items[i], v)) return js_bool(true);
                }
                return js_bool(false);
            }
            case SET_DELETE: {
                for (uint32_t i = 0; i < va->len; i++) {
                    if (js_same_value_zero(va->items[i], v)) {
                        for (uint32_t j = i; j + 1 < va->len; j++) va->items[j] = va->items[j + 1];
                        va->len--;
                        return js_bool(true);
                    }
                }
                return js_bool(false);
            }
            case SET_CLEAR:
                va->len = 0;
                return js_undefined();
            case SET_FOR_EACH: {
                if (argc == 0) return js_undefined();
                JsVal cb = argv[0];
                JsVal targ = argc > 1 ? argv[1] : js_undefined();
                uint32_t snap = va->len;
                for (uint32_t i = 0; i < snap && i < va->len; i++) {
                    JsVal cargs[3] = { va->items[i], va->items[i], this_val };
                    (void)js_call(vm, cb, targ, 3, cargs);
                    if (vm->has_thrown) break;
                }
                return js_undefined();
            }
            case SET_VALUES:
            case SET_ENTRIES: {
                JsObj *res = js_arr_new(vm, va->len);
                if (!res) return js_undefined();
                int saved_sp = vm->temp_sp;
                js_temp_push(vm, js_obj_val(res));
                for (uint32_t i = 0; i < va->len; i++) {
                    if (magic == SET_VALUES) {
                        js_arr_push(vm, res, va->items[i]);
                    } else {
                        JsObj *pair = js_arr_new(vm, 2);
                        if (pair) {
                            js_arr_push(vm, pair, va->items[i]);
                            js_arr_push(vm, pair, va->items[i]);
                            js_arr_push(vm, res, js_obj_val(pair));
                        }
                    }
                }
                vm->temp_sp = saved_sp;
                return js_obj_val(res);
            }
            default:
                return js_undefined();
        }
    }
    return js_undefined();
}

/* Promise & Microtask Queue */
typedef enum {
    PROM_CTOR = 0,
    PROM_RESOLVE,
    PROM_REJECT,
    PROM_ALL,
    PROM_RACE,
    PROM_THEN,
    PROM_CATCH,
    PROM_FINALLY,
    PROM_RESOLVE_CB,
    PROM_REJECT_CB,
    PROM_ALL_STEP_CB
} JsPromiseMagic;

static JsVal fn_promise(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic);

void js_enqueue_microtask(JsVm *vm, JsVal fn, JsVal this_val, int argc, const JsVal *argv) {
    if (!vm || vm->microtask_count >= JS_MAX_MICROTASKS) return;
    int idx = (vm->microtask_head + vm->microtask_count) % JS_MAX_MICROTASKS;
    vm->microtasks[idx].fn       = fn;
    vm->microtasks[idx].this_val = this_val;
    vm->microtasks[idx].argc     = argc > 2 ? 2 : argc;
    for (int i = 0; i < vm->microtasks[idx].argc; i++) {
        vm->microtasks[idx].args[i] = argv[i];
    }
    vm->microtask_count++;
}

static void run_promise_reaction_job(JsVm *vm, JsVal react, int state, JsVal val) {
    if (react.type != JS_OBJECT || !react.u.obj) return;
    int saved_sp = vm->temp_sp;
    js_temp_push(vm, react);
    js_temp_push(vm, val);

    JsVal child_v = js_get_prop(vm, react, "_child");
    JsObj *child  = (child_v.type == JS_OBJECT) ? child_v.u.obj : NULL;

    JsVal on_finally = js_get_prop(vm, react, "_on_finally");
    if (on_finally.type == JS_OBJECT && on_finally.u.obj &&
        (on_finally.u.obj->obj_type == OBJ_FUNC || on_finally.u.obj->obj_type == OBJ_NATIVE_FN)) {
        (void)js_call(vm, on_finally, js_undefined(), 0, NULL);
        if (vm->has_thrown) {
            JsVal err = vm->thrown_val;
            vm->has_thrown = false;
            vm->thrown_val = js_undefined();
            if (child) js_promise_settle(vm, child, false, err);
            vm->temp_sp = saved_sp;
            return;
        }
        if (child) js_promise_settle(vm, child, state == 1, val);
        vm->temp_sp = saved_sp;
        return;
    }

    JsVal handler = js_get_prop(vm, react, (state == 1) ? "_on_fulfill" : "_on_reject");
    if (handler.type == JS_OBJECT && handler.u.obj &&
        (handler.u.obj->obj_type == OBJ_FUNC || handler.u.obj->obj_type == OBJ_NATIVE_FN)) {
        JsVal rv = js_call(vm, handler, js_undefined(), 1, &val);
        if (vm->has_thrown) {
            JsVal err = vm->thrown_val;
            vm->has_thrown = false;
            vm->thrown_val = js_undefined();
            if (child) js_promise_settle(vm, child, false, err);
        } else {
            if (child) js_promise_settle(vm, child, true, rv);
        }
    } else {
        if (child) js_promise_settle(vm, child, state == 1, val);
    }
    vm->temp_sp = saved_sp;
}

void js_drain_microtasks(JsVm *vm) {
    if (!vm || vm->draining_microtasks) return;
    vm->draining_microtasks = true;
    while (vm->microtask_count > 0 && !vm->has_thrown && vm->steps <= vm->step_limit) {
        JsMicrotask mt = vm->microtasks[vm->microtask_head];
        vm->microtasks[vm->microtask_head].fn       = js_undefined();
        vm->microtasks[vm->microtask_head].this_val = js_undefined();
        vm->microtask_head = (vm->microtask_head + 1) % JS_MAX_MICROTASKS;
        vm->microtask_count--;

        int saved_sp = vm->temp_sp;
        js_temp_push(vm, mt.fn);
        js_temp_push(vm, mt.this_val);
        for (int i = 0; i < mt.argc; i++) js_temp_push(vm, mt.args[i]);

        if (mt.fn.type == JS_UNDEFINED && mt.this_val.type == JS_OBJECT) {
            run_promise_reaction_job(vm, mt.this_val, (int)mt.args[0].u.num, mt.args[1]);
        } else {
            (void)js_call(vm, mt.fn, mt.this_val, mt.argc, mt.args);
        }
        vm->temp_sp = saved_sp;
    }
    vm->draining_microtasks = false;
}

JsObj *js_promise_new(JsVm *vm, int state, JsVal val) {
    JsObj *p = js_map_new(vm, vm->promise_proto);
    if (!p) return NULL;
    p->native_tag = NATIVE_TAG_PROMISE;
    int saved_sp = vm->temp_sp;
    js_temp_push(vm, js_obj_val(p));
    js_temp_push(vm, val);
    js_set_prop(vm, js_obj_val(p), "_state", js_num((double)state));
    js_set_prop(vm, js_obj_val(p), "_val", val);
    vm->temp_sp = saved_sp;
    return p;
}

static void promise_attach_reaction(JsVm *vm, JsObj *p, JsVal on_fulfill, JsVal on_reject, JsVal on_finally, JsObj *child) {
    if (!p || p->native_tag != NATIVE_TAG_PROMISE) return;
    int saved_sp = vm->temp_sp;
    js_temp_push(vm, js_obj_val(p));
    if (child) js_temp_push(vm, js_obj_val(child));
    js_temp_push(vm, on_fulfill);
    js_temp_push(vm, on_reject);
    js_temp_push(vm, on_finally);

    JsObj *react = js_map_new(vm, NULL);
    if (!react) { vm->temp_sp = saved_sp; return; }
    js_temp_push(vm, js_obj_val(react));
    js_set_prop(vm, js_obj_val(react), "_on_fulfill", on_fulfill);
    js_set_prop(vm, js_obj_val(react), "_on_reject", on_reject);
    js_set_prop(vm, js_obj_val(react), "_on_finally", on_finally);
    js_set_prop(vm, js_obj_val(react), "_child", child ? js_obj_val(child) : js_undefined());

    JsVal stv = js_get_prop(vm, js_obj_val(p), "_state");
    int state = (stv.type == JS_NUMBER) ? (int)stv.u.num : 0;
    if (state == 0) {
        JsVal reacts = js_get_prop(vm, js_obj_val(p), "_reactions");
        if (reacts.type != JS_OBJECT || !reacts.u.obj || reacts.u.obj->obj_type != OBJ_ARRAY) {
            JsObj *ra = js_arr_new(vm, 2);
            reacts = js_obj_val(ra);
            js_set_prop(vm, js_obj_val(p), "_reactions", reacts);
        }
        if (reacts.type == JS_OBJECT && reacts.u.obj) {
            js_arr_push(vm, reacts.u.obj, js_obj_val(react));
        }
    } else {
        JsVal margs[2] = { js_num((double)state), js_get_prop(vm, js_obj_val(p), "_val") };
        js_enqueue_microtask(vm, js_undefined(), js_obj_val(react), 2, margs);
    }
    vm->temp_sp = saved_sp;
}

void js_promise_settle(JsVm *vm, JsObj *p, bool fulfilled, JsVal val) {
    if (!p || p->native_tag != NATIVE_TAG_PROMISE) return;
    JsVal stv = js_get_prop(vm, js_obj_val(p), "_state");
    if (stv.type == JS_NUMBER && (int)stv.u.num != 0) return; /* Already settled */

    int saved_sp = vm->temp_sp;
    js_temp_push(vm, js_obj_val(p));
    js_temp_push(vm, val);

    if (fulfilled && val.type == JS_OBJECT && val.u.obj) {
        if (val.u.obj == p) {
            fulfilled = false;
            val = make_cstr_val(vm, "TypeError: Chaining cycle detected for promise");
        } else if (val.u.obj->native_tag == NATIVE_TAG_PROMISE) {
            promise_attach_reaction(vm, val.u.obj, js_undefined(), js_undefined(), js_undefined(), p);
            vm->temp_sp = saved_sp;
            return;
        } else {
            JsVal then_fn = js_get_prop(vm, val, "then");
            if (then_fn.type == JS_OBJECT && then_fn.u.obj &&
                (then_fn.u.obj->obj_type == OBJ_FUNC || then_fn.u.obj->obj_type == OBJ_NATIVE_FN)) {
                JsObj *res_fn = js_native_fn_new(vm, "resolve", fn_promise, PROM_RESOLVE_CB);
                JsObj *rej_fn = js_native_fn_new(vm, "reject", fn_promise, PROM_REJECT_CB);
                if (res_fn && rej_fn) {
                    js_temp_push(vm, js_obj_val(res_fn));
                    js_temp_push(vm, js_obj_val(rej_fn));
                    js_set_prop(vm, js_obj_val(res_fn), "_promise", js_obj_val(p));
                    js_set_prop(vm, js_obj_val(rej_fn), "_promise", js_obj_val(p));
                    JsVal cargs[2] = { js_obj_val(res_fn), js_obj_val(rej_fn) };
                    (void)js_call(vm, then_fn, val, 2, cargs);
                    if (vm->has_thrown) {
                        JsVal err = vm->thrown_val;
                        vm->has_thrown = false;
                        vm->thrown_val = js_undefined();
                        js_promise_settle(vm, p, false, err);
                    }
                }
                vm->temp_sp = saved_sp;
                return;
            }
        }
    }

    int state = fulfilled ? 1 : 2;
    js_set_prop(vm, js_obj_val(p), "_state", js_num((double)state));
    js_set_prop(vm, js_obj_val(p), "_val", val);

    JsVal reacts = js_get_prop(vm, js_obj_val(p), "_reactions");
    if (reacts.type == JS_OBJECT && reacts.u.obj && reacts.u.obj->obj_type == OBJ_ARRAY) {
        JsArrObj *ra = (JsArrObj *)reacts.u.obj;
        for (uint32_t i = 0; i < ra->len; i++) {
            JsVal margs[2] = { js_num((double)state), val };
            js_enqueue_microtask(vm, js_undefined(), ra->items[i], 2, margs);
        }
        ra->len = 0;
    }
    vm->temp_sp = saved_sp;
}

static JsVal fn_promise(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == PROM_RESOLVE_CB || magic == PROM_REJECT_CB) {
        JsVal pv = js_get_prop(vm, this_val, "_promise");
        if (pv.type == JS_OBJECT && pv.u.obj) {
            js_promise_settle(vm, pv.u.obj, magic == PROM_RESOLVE_CB, argc > 0 ? argv[0] : js_undefined());
        }
        return js_undefined();
    }
    if (magic == PROM_ALL_STEP_CB) {
        JsVal ctx_v = js_get_prop(vm, this_val, "_ctx");
        JsVal idx_v = js_get_prop(vm, this_val, "_idx");
        if (ctx_v.type == JS_OBJECT && ctx_v.u.obj && idx_v.type == JS_NUMBER) {
            JsVal done_v = js_get_prop(vm, this_val, "_done");
            if (js_to_bool(done_v)) return js_undefined();
            js_set_prop(vm, this_val, "_done", js_bool(true));
            JsVal res_arr = js_get_prop(vm, ctx_v, "_results");
            if (res_arr.type == JS_OBJECT && res_arr.u.obj && res_arr.u.obj->obj_type == OBJ_ARRAY) {
                uint32_t idx = (uint32_t)idx_v.u.num;
                JsArrObj *ra = (JsArrObj *)res_arr.u.obj;
                if (idx < ra->len) ra->items[idx] = argc > 0 ? argv[0] : js_undefined();
            }
            double rem = js_to_num(vm, js_get_prop(vm, ctx_v, "_remaining")) - 1.0;
            js_set_prop(vm, ctx_v, "_remaining", js_num(rem));
            if (rem <= 0.0) {
                JsVal out_p = js_get_prop(vm, ctx_v, "_promise");
                if (out_p.type == JS_OBJECT && out_p.u.obj) {
                    js_promise_settle(vm, out_p.u.obj, true, res_arr);
                }
            }
        }
        return js_undefined();
    }
    if (magic == PROM_CTOR) {
        JsObj *p = js_promise_new(vm, 0, js_undefined());
        if (!p) return js_undefined();
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(p));
        if (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj) {
            JsObj *res_fn = js_native_fn_new(vm, "resolve", fn_promise, PROM_RESOLVE_CB);
            JsObj *rej_fn = js_native_fn_new(vm, "reject", fn_promise, PROM_REJECT_CB);
            if (res_fn && rej_fn) {
                js_temp_push(vm, js_obj_val(res_fn));
                js_temp_push(vm, js_obj_val(rej_fn));
                js_set_prop(vm, js_obj_val(res_fn), "_promise", js_obj_val(p));
                js_set_prop(vm, js_obj_val(rej_fn), "_promise", js_obj_val(p));
                JsVal cargs[2] = { js_obj_val(res_fn), js_obj_val(rej_fn) };
                (void)js_call(vm, argv[0], js_undefined(), 2, cargs);
                if (vm->has_thrown) {
                    JsVal err = vm->thrown_val;
                    vm->has_thrown = false;
                    vm->thrown_val = js_undefined();
                    js_promise_settle(vm, p, false, err);
                }
            }
        }
        vm->temp_sp = saved_sp;
        return js_obj_val(p);
    }
    if (magic == PROM_RESOLVE) {
        JsVal v = argc > 0 ? argv[0] : js_undefined();
        if (v.type == JS_OBJECT && v.u.obj && v.u.obj->native_tag == NATIVE_TAG_PROMISE) {
            return v;
        }
        JsObj *p = js_promise_new(vm, 0, js_undefined());
        if (p) js_promise_settle(vm, p, true, v);
        return js_obj_val(p);
    }
    if (magic == PROM_REJECT) {
        JsVal v = argc > 0 ? argv[0] : js_undefined();
        JsObj *p = js_promise_new(vm, 2, v);
        return js_obj_val(p);
    }
    if (magic == PROM_ALL || magic == PROM_RACE) {
        JsObj *p = js_promise_new(vm, 0, js_undefined());
        if (!p) return js_undefined();
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(p));
        JsObj *items = js_arr_new(vm, 8);
        if (!items) { vm->temp_sp = saved_sp; return js_obj_val(p); }
        js_temp_push(vm, js_obj_val(items));
        if (argc > 0) js_iterable_to_array(vm, argv[0], items);
        JsArrObj *ia = (JsArrObj *)items;
        if (magic == PROM_RACE) {
            for (uint32_t i = 0; i < ia->len; i++) {
                JsVal item_p = fn_promise(vm, js_undefined(), 1, &ia->items[i], PROM_RESOLVE);
                if (item_p.type == JS_OBJECT && item_p.u.obj) {
                    promise_attach_reaction(vm, item_p.u.obj, js_undefined(), js_undefined(), js_undefined(), p);
                }
            }
            vm->temp_sp = saved_sp;
            return js_obj_val(p);
        }
        /* PROM_ALL */
        JsObj *results = js_arr_new(vm, ia->len);
        if (!results) { vm->temp_sp = saved_sp; return js_obj_val(p); }
        js_temp_push(vm, js_obj_val(results));
        if (ia->len == 0) {
            js_promise_settle(vm, p, true, js_obj_val(results));
            vm->temp_sp = saved_sp;
            return js_obj_val(p);
        }
        for (uint32_t i = 0; i < ia->len; i++) js_arr_push(vm, results, js_undefined());
        JsObj *ctx = js_map_new(vm, NULL);
        if (!ctx) { vm->temp_sp = saved_sp; return js_obj_val(p); }
        js_temp_push(vm, js_obj_val(ctx));
        js_set_prop(vm, js_obj_val(ctx), "_remaining", js_num((double)ia->len));
        js_set_prop(vm, js_obj_val(ctx), "_results", js_obj_val(results));
        js_set_prop(vm, js_obj_val(ctx), "_promise", js_obj_val(p));
        JsObj *rej_fn = js_native_fn_new(vm, "reject", fn_promise, PROM_REJECT_CB);
        if (rej_fn) {
            js_temp_push(vm, js_obj_val(rej_fn));
            js_set_prop(vm, js_obj_val(rej_fn), "_promise", js_obj_val(p));
        }
        for (uint32_t i = 0; i < ia->len; i++) {
            JsVal item_p = fn_promise(vm, js_undefined(), 1, &ia->items[i], PROM_RESOLVE);
            if (item_p.type == JS_OBJECT && item_p.u.obj) {
                js_temp_push(vm, item_p);
                JsObj *step_fn = js_native_fn_new(vm, "step", fn_promise, PROM_ALL_STEP_CB);
                if (step_fn) {
                    js_temp_push(vm, js_obj_val(step_fn));
                    js_set_prop(vm, js_obj_val(step_fn), "_ctx", js_obj_val(ctx));
                    js_set_prop(vm, js_obj_val(step_fn), "_idx", js_num((double)i));
                    promise_attach_reaction(vm, item_p.u.obj, js_obj_val(step_fn),
                                            rej_fn ? js_obj_val(rej_fn) : js_undefined(),
                                            js_undefined(), NULL);
                }
            }
        }
        vm->temp_sp = saved_sp;
        return js_obj_val(p);
    }

    if (this_val.type != JS_OBJECT || !this_val.u.obj || this_val.u.obj->native_tag != NATIVE_TAG_PROMISE)
        return js_undefined();
    JsObj *self = this_val.u.obj;
    JsObj *child = js_promise_new(vm, 0, js_undefined());
    if (!child) return js_undefined();

    if (magic == PROM_THEN) {
        JsVal on_f = argc > 0 ? argv[0] : js_undefined();
        JsVal on_r = argc > 1 ? argv[1] : js_undefined();
        promise_attach_reaction(vm, self, on_f, on_r, js_undefined(), child);
    } else if (magic == PROM_CATCH) {
        JsVal on_r = argc > 0 ? argv[0] : js_undefined();
        promise_attach_reaction(vm, self, js_undefined(), on_r, js_undefined(), child);
    } else if (magic == PROM_FINALLY) {
        JsVal on_fin = argc > 0 ? argv[0] : js_undefined();
        promise_attach_reaction(vm, self, js_undefined(), js_undefined(), on_fin, child);
    }
    return js_obj_val(child);
}

/* Storage (localStorage & sessionStorage) */
typedef enum {
    STORAGE_SET_ITEM,
    STORAGE_GET_ITEM,
    STORAGE_REMOVE_ITEM,
    STORAGE_CLEAR,
    STORAGE_KEY
} JsStorageMagic;

static JsVal fn_storage(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (this_val.type != JS_OBJECT || !this_val.u.obj) return js_undefined();
    JsVal sv = js_get_prop(vm, this_val, "_store");
    if (sv.type != JS_OBJECT || !sv.u.obj || sv.u.obj->obj_type != OBJ_OBJECT)
        return js_undefined();
    JsMapObj *sm = (JsMapObj *)sv.u.obj;

    switch (magic) {
        case STORAGE_SET_ITEM: {
            if (argc < 2) return js_undefined();
            JsStr *k = js_to_str(vm, argv[0]);
            JsStr *v = js_to_str(vm, argv[1]);
            if (!k || !v) return js_undefined();
            js_set_prop(vm, sv, k->data, js_obj_val((JsObj *)v));
            return js_undefined();
        }
        case STORAGE_GET_ITEM: {
            if (argc < 1) return js_null();
            JsStr *k = js_to_str(vm, argv[0]);
            if (!k) return js_null();
            for (uint32_t i = 0; i < sm->count; i++) {
                if (strcmp(sm->props[i].key->data, k->data) == 0) {
                    return sm->props[i].val;
                }
            }
            return js_null();
        }
        case STORAGE_REMOVE_ITEM: {
            if (argc < 1) return js_undefined();
            JsStr *k = js_to_str(vm, argv[0]);
            if (!k) return js_undefined();
            for (uint32_t i = 0; i < sm->count; i++) {
                if (strcmp(sm->props[i].key->data, k->data) == 0) {
                    for (uint32_t j = i; j + 1 < sm->count; j++) {
                        sm->props[j] = sm->props[j + 1];
                    }
                    sm->count--;
                    break;
                }
            }
            return js_undefined();
        }
        case STORAGE_CLEAR: {
            sm->count = 0;
            return js_undefined();
        }
        case STORAGE_KEY: {
            if (argc < 1) return js_null();
            int idx = (int)js_to_num(vm, argv[0]);
            if (idx >= 0 && (uint32_t)idx < sm->count) {
                return js_obj_val((JsObj *)sm->props[idx].key);
            }
            return js_null();
        }
        default:
            return js_undefined();
    }
}

/* URLSearchParams */
typedef enum {
    URL_PARAMS_CTOR,
    URL_PARAMS_APPEND,
    URL_PARAMS_GET,
    URL_PARAMS_GET_ALL,
    URL_PARAMS_SET,
    URL_PARAMS_HAS,
    URL_PARAMS_DELETE,
    URL_PARAMS_TO_STRING,
    URL_PARAMS_FOR_EACH
} JsUrlParamsMagic;

static void url_params_parse_query(JsVm *vm, JsObj *params_obj, const char *qs) {
    if (!qs) return;
    if (*qs == '?') qs++;
    const char *p = qs;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t len = amp ? (size_t)(amp - p) : strlen(p);
        if (len > 0) {
            const char *eq = memchr(p, '=', len);
            size_t klen = eq ? (size_t)(eq - p) : len;
            size_t vlen = eq ? len - klen - 1 : 0;
            const char *vstart = eq ? eq + 1 : "";

            char kbuf[512], vbuf[1024];
            size_t kc = klen < sizeof(kbuf) - 1 ? klen : sizeof(kbuf) - 1;
            memcpy(kbuf, p, kc); kbuf[kc] = '\0';
            size_t vc = vlen < sizeof(vbuf) - 1 ? vlen : sizeof(vbuf) - 1;
            memcpy(vbuf, vstart, vc); vbuf[vc] = '\0';

            for (size_t i = 0; i < kc; i++) if (kbuf[i] == '+') kbuf[i] = ' ';
            for (size_t i = 0; i < vc; i++) if (vbuf[i] == '+') vbuf[i] = ' ';

            JsVal kv = make_cstr_val(vm, kbuf);
            JsVal vv = make_cstr_val(vm, vbuf);
            JsVal k_arr = js_get_prop(vm, js_obj_val(params_obj), "_keys");
            JsVal v_arr = js_get_prop(vm, js_obj_val(params_obj), "_vals");
            if (k_arr.type == JS_OBJECT && k_arr.u.obj && v_arr.type == JS_OBJECT && v_arr.u.obj) {
                js_arr_push(vm, k_arr.u.obj, kv);
                js_arr_push(vm, v_arr.u.obj, vv);
            }
        }
        if (!amp) break;
        p = amp + 1;
    }
}

static JsVal fn_url_params(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == URL_PARAMS_CTOR) {
        JsObj *usp = js_map_new(vm, vm->url_params_proto);
        if (!usp) return js_undefined();
        usp->native_tag = NATIVE_TAG_URL_PARAMS;
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(usp));
        JsObj *keys = js_arr_new(vm, 8);
        JsObj *vals = js_arr_new(vm, 8);
        js_set_prop(vm, js_obj_val(usp), "_keys", js_obj_val(keys));
        js_set_prop(vm, js_obj_val(usp), "_vals", js_obj_val(vals));

        if (argc > 0) {
            if (argv[0].type == JS_OBJECT && argv[0].u.obj) {
                JsObj *o = argv[0].u.obj;
                if (o->obj_type == OBJ_STRING) {
                    url_params_parse_query(vm, usp, ((JsStr *)o)->data);
                } else if (o->native_tag == NATIVE_TAG_URL_PARAMS) {
                    JsVal ok = js_get_prop(vm, argv[0], "_keys");
                    JsVal ov = js_get_prop(vm, argv[0], "_vals");
                    if (ok.type == JS_OBJECT && ok.u.obj && ok.u.obj->obj_type == OBJ_ARRAY &&
                        ov.type == JS_OBJECT && ov.u.obj && ov.u.obj->obj_type == OBJ_ARRAY) {
                        JsArrObj *oka = (JsArrObj *)ok.u.obj;
                        JsArrObj *ova = (JsArrObj *)ov.u.obj;
                        uint32_t n = oka->len < ova->len ? oka->len : ova->len;
                        for (uint32_t i = 0; i < n; i++) {
                            js_arr_push(vm, keys, oka->items[i]);
                            js_arr_push(vm, vals, ova->items[i]);
                        }
                    }
                } else if (o->obj_type == OBJ_OBJECT) {
                    JsMapObj *mo = (JsMapObj *)o;
                    for (uint32_t i = 0; i < mo->count; i++) {
                        if (mo->props[i].key->data[0] == '\x01' || mo->props[i].key->data[0] == '_') continue;
                        JsStr *vs = js_to_str(vm, mo->props[i].val);
                        js_arr_push(vm, keys, js_obj_val((JsObj *)mo->props[i].key));
                        js_arr_push(vm, vals, vs ? js_obj_val((JsObj *)vs) : make_cstr_val(vm, ""));
                    }
                }
            } else if (argv[0].type != JS_UNDEFINED && argv[0].type != JS_NULL) {
                JsStr *qs = js_to_str(vm, argv[0]);
                if (qs) url_params_parse_query(vm, usp, qs->data);
            }
        }
        vm->temp_sp = saved_sp;
        return js_obj_val(usp);
    }

    if (this_val.type != JS_OBJECT || !this_val.u.obj) return js_undefined();
    JsVal kv = js_get_prop(vm, this_val, "_keys");
    JsVal vv = js_get_prop(vm, this_val, "_vals");
    if (kv.type != JS_OBJECT || !kv.u.obj || kv.u.obj->obj_type != OBJ_ARRAY ||
        vv.type != JS_OBJECT || !vv.u.obj || vv.u.obj->obj_type != OBJ_ARRAY) {
        return js_undefined();
    }
    JsArrObj *ka = (JsArrObj *)kv.u.obj;
    JsArrObj *va = (JsArrObj *)vv.u.obj;

    switch (magic) {
        case URL_PARAMS_APPEND: {
            if (argc < 2) return js_undefined();
            JsStr *k = js_to_str(vm, argv[0]);
            JsStr *v = js_to_str(vm, argv[1]);
            js_arr_push(vm, (JsObj *)ka, k ? js_obj_val((JsObj *)k) : make_cstr_val(vm, ""));
            js_arr_push(vm, (JsObj *)va, v ? js_obj_val((JsObj *)v) : make_cstr_val(vm, ""));
            return js_undefined();
        }
        case URL_PARAMS_GET: {
            if (argc < 1) return js_null();
            JsStr *k = js_to_str(vm, argv[0]);
            if (!k) return js_null();
            for (uint32_t i = 0; i < ka->len; i++) {
                JsStr *ki = js_to_str(vm, ka->items[i]);
                if (ki && strcmp(ki->data, k->data) == 0) {
                    return va->items[i];
                }
            }
            return js_null();
        }
        case URL_PARAMS_GET_ALL: {
            JsObj *res = js_arr_new(vm, 4);
            if (!res) return js_undefined();
            if (argc > 0) {
                JsStr *k = js_to_str(vm, argv[0]);
                if (k) {
                    for (uint32_t i = 0; i < ka->len; i++) {
                        JsStr *ki = js_to_str(vm, ka->items[i]);
                        if (ki && strcmp(ki->data, k->data) == 0) {
                            js_arr_push(vm, res, va->items[i]);
                        }
                    }
                }
            }
            return js_obj_val(res);
        }
        case URL_PARAMS_SET: {
            if (argc < 2) return js_undefined();
            JsStr *k = js_to_str(vm, argv[0]);
            JsStr *v = js_to_str(vm, argv[1]);
            if (!k) return js_undefined();
            JsVal k_val = js_obj_val((JsObj *)k);
            JsVal v_val = v ? js_obj_val((JsObj *)v) : make_cstr_val(vm, "");
            bool replaced = false;
            for (uint32_t i = 0; i < ka->len; i++) {
                JsStr *ki = js_to_str(vm, ka->items[i]);
                if (ki && strcmp(ki->data, k->data) == 0) {
                    if (!replaced) {
                        va->items[i] = v_val;
                        replaced = true;
                    } else {
                        for (uint32_t j = i; j + 1 < ka->len; j++) {
                            ka->items[j] = ka->items[j + 1];
                            va->items[j] = va->items[j + 1];
                        }
                        ka->len--;
                        va->len--;
                        i--;
                    }
                }
            }
            if (!replaced) {
                js_arr_push(vm, (JsObj *)ka, k_val);
                js_arr_push(vm, (JsObj *)va, v_val);
            }
            return js_undefined();
        }
        case URL_PARAMS_HAS: {
            if (argc < 1) return js_bool(false);
            JsStr *k = js_to_str(vm, argv[0]);
            if (!k) return js_bool(false);
            for (uint32_t i = 0; i < ka->len; i++) {
                JsStr *ki = js_to_str(vm, ka->items[i]);
                if (ki && strcmp(ki->data, k->data) == 0) return js_bool(true);
            }
            return js_bool(false);
        }
        case URL_PARAMS_DELETE: {
            if (argc < 1) return js_undefined();
            JsStr *k = js_to_str(vm, argv[0]);
            if (!k) return js_undefined();
            for (uint32_t i = 0; i < ka->len; i++) {
                JsStr *ki = js_to_str(vm, ka->items[i]);
                if (ki && strcmp(ki->data, k->data) == 0) {
                    for (uint32_t j = i; j + 1 < ka->len; j++) {
                        ka->items[j] = ka->items[j + 1];
                        va->items[j] = va->items[j + 1];
                    }
                    ka->len--;
                    va->len--;
                    i--;
                }
            }
            return js_undefined();
        }
        case URL_PARAMS_TO_STRING: {
            TbBuf b;
            tb_buf_init(&b);
            uint32_t n = ka->len < va->len ? ka->len : va->len;
            for (uint32_t i = 0; i < n; i++) {
                if (i > 0) tb_buf_append_char(&b, '&');
                JsStr *ki = js_to_str(vm, ka->items[i]);
                JsStr *vi = js_to_str(vm, va->items[i]);
                if (ki) tb_buf_append_cstr(&b, ki->data);
                tb_buf_append_char(&b, '=');
                if (vi) tb_buf_append_cstr(&b, vi->data);
            }
            JsVal res = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return res;
        }
        case URL_PARAMS_FOR_EACH: {
            if (argc < 1) return js_undefined();
            JsVal cb = argv[0];
            JsVal this_arg = argc > 1 ? argv[1] : js_undefined();
            uint32_t snap = ka->len < va->len ? ka->len : va->len;
            for (uint32_t i = 0; i < snap && i < ka->len && i < va->len; i++) {
                JsVal cargs[3] = { va->items[i], ka->items[i], this_val };
                (void)js_call(vm, cb, this_arg, 3, cargs);
                if (vm->has_thrown) break;
            }
            return js_undefined();
        }
        default:
            return js_undefined();
    }
}

/* URL */
typedef enum {
    URL_CTOR,
    URL_TO_STRING
} JsUrlMagic;

static JsVal fn_url(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == URL_TO_STRING) {
        if (this_val.type != JS_OBJECT || !this_val.u.obj) return js_undefined();
        return js_get_prop(vm, this_val, "href");
    }

    if (magic == URL_CTOR) {
        if (argc < 1) {
            js_throw_str(vm, "TypeError: Failed to construct 'URL': 1 argument required");
            return js_undefined();
        }
        JsStr *u_s = js_to_str(vm, argv[0]);
        if (!u_s) {
            js_throw_str(vm, "TypeError: Invalid URL string");
            return js_undefined();
        }

        char resolved[1536];
        TbUrl parsed;
        if (argc > 1 && argv[1].type != JS_UNDEFINED && argv[1].type != JS_NULL) {
            JsStr *base_s = js_to_str(vm, argv[1]);
            if (!base_s) {
                js_throw_str(vm, "TypeError: Invalid base URL");
                return js_undefined();
            }
            TbUrl base_u;
            if (!tb_url_parse(base_s->data, &base_u)) {
                js_throw_str(vm, "TypeError: Invalid base URL");
                return js_undefined();
            }
            tb_url_resolve(&base_u, u_s->data, resolved, sizeof(resolved));
            if (!tb_url_parse(resolved, &parsed)) {
                js_throw_str(vm, "TypeError: Invalid URL");
                return js_undefined();
            }
        } else {
            if (!tb_url_parse(u_s->data, &parsed)) {
                js_throw_str(vm, "TypeError: Invalid URL");
                return js_undefined();
            }
            tb_url_format(&parsed, resolved, sizeof(resolved), true);
        }

        JsObj *uo = js_map_new(vm, vm->url_proto);
        if (!uo) return js_undefined();
        uo->native_tag = NATIVE_TAG_URL;
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(uo));

        /* Origin */
        char origin_buf[512] = "";
        bool is_std_port = (strcmp(parsed.scheme, "http") == 0 && (parsed.port == 80 || parsed.port == 0)) ||
                           (strcmp(parsed.scheme, "https") == 0 && (parsed.port == 443 || parsed.port == 0));
        if (strcmp(parsed.scheme, "http") == 0 || strcmp(parsed.scheme, "https") == 0) {
            if (parsed.port > 0 && !is_std_port) {
                snprintf(origin_buf, sizeof(origin_buf), "%s://%s:%d", parsed.scheme, parsed.host, parsed.port);
            } else {
                snprintf(origin_buf, sizeof(origin_buf), "%s://%s", parsed.scheme, parsed.host);
            }
        } else {
            snprintf(origin_buf, sizeof(origin_buf), "%s://%s", parsed.scheme, parsed.host);
        }

        /* Pathname */
        char pathname_buf[1024];
        const char *qpos = strchr(parsed.path, '?');
        if (qpos) {
            size_t plen = (size_t)(qpos - parsed.path);
            if (plen >= sizeof(pathname_buf)) plen = sizeof(pathname_buf) - 1;
            memcpy(pathname_buf, parsed.path, plen);
            pathname_buf[plen] = '\0';
        } else {
            snprintf(pathname_buf, sizeof(pathname_buf), "%s", parsed.path[0] ? parsed.path : "/");
        }

        /* Search */
        char search_buf[1024] = "";
        char query_only[1024] = "";
        if (qpos) {
            snprintf(search_buf, sizeof(search_buf), "%s", qpos);
            snprintf(query_only, sizeof(query_only), "%s", qpos + 1);
        }

        /* Hash */
        char hash_buf[256] = "";
        if (parsed.fragment[0]) {
            snprintf(hash_buf, sizeof(hash_buf), "#%s", parsed.fragment);
        }

        /* Host & Hostname & Port */
        char host_buf[512];
        char port_buf[16] = "";
        if (parsed.port > 0 && !is_std_port) {
            snprintf(host_buf, sizeof(host_buf), "%s:%d", parsed.host, parsed.port);
            snprintf(port_buf, sizeof(port_buf), "%d", parsed.port);
        } else {
            snprintf(host_buf, sizeof(host_buf), "%s", parsed.host);
        }

        /* Protocol */
        char proto_buf[32];
        snprintf(proto_buf, sizeof(proto_buf), "%s:", parsed.scheme);

        /* searchParams */
        JsVal q_val = make_cstr_val(vm, query_only);
        JsVal sp_val = fn_url_params(vm, js_undefined(), 1, &q_val, URL_PARAMS_CTOR);

        js_set_prop(vm, js_obj_val(uo), "href", make_cstr_val(vm, resolved));
        js_set_prop(vm, js_obj_val(uo), "origin", make_cstr_val(vm, origin_buf));
        js_set_prop(vm, js_obj_val(uo), "protocol", make_cstr_val(vm, proto_buf));
        js_set_prop(vm, js_obj_val(uo), "host", make_cstr_val(vm, host_buf));
        js_set_prop(vm, js_obj_val(uo), "hostname", make_cstr_val(vm, parsed.host));
        js_set_prop(vm, js_obj_val(uo), "port", make_cstr_val(vm, port_buf));
        js_set_prop(vm, js_obj_val(uo), "pathname", make_cstr_val(vm, pathname_buf));
        js_set_prop(vm, js_obj_val(uo), "search", make_cstr_val(vm, search_buf));
        js_set_prop(vm, js_obj_val(uo), "hash", make_cstr_val(vm, hash_buf));
        js_set_prop(vm, js_obj_val(uo), "searchParams", sp_val);

        vm->temp_sp = saved_sp;
        return js_obj_val(uo);
    }

    return js_undefined();
}

/* Headers */
typedef enum {
    HEADERS_CTOR,
    HEADERS_APPEND,
    HEADERS_GET,
    HEADERS_SET,
    HEADERS_HAS,
    HEADERS_DELETE,
    HEADERS_FOR_EACH
} JsHeadersMagic;

static JsVal fn_headers(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == HEADERS_CTOR) {
        JsObj *ho = js_map_new(vm, vm->headers_proto);
        if (!ho) return js_undefined();
        ho->native_tag = NATIVE_TAG_HEADERS;
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(ho));
        JsObj *map = js_map_new(vm, NULL);
        js_set_prop(vm, js_obj_val(ho), "_map", js_obj_val(map));

        if (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj) {
            JsObj *init = argv[0].u.obj;
            if (init->native_tag == NATIVE_TAG_HEADERS) {
                JsVal src_map = js_get_prop(vm, argv[0], "_map");
                if (src_map.type == JS_OBJECT && src_map.u.obj && src_map.u.obj->obj_type == OBJ_OBJECT) {
                    JsMapObj *sm = (JsMapObj *)src_map.u.obj;
                    for (uint32_t i = 0; i < sm->count; i++) {
                        JsVal cargs[2] = { js_obj_val((JsObj *)sm->props[i].key), sm->props[i].val };
                        (void)fn_headers(vm, js_obj_val(ho), 2, cargs, HEADERS_APPEND);
                    }
                }
            } else if (init->obj_type == OBJ_OBJECT) {
                JsMapObj *mo = (JsMapObj *)init;
                for (uint32_t i = 0; i < mo->count; i++) {
                    if (mo->props[i].key->data[0] == '\x01' || mo->props[i].key->data[0] == '_') continue;
                    JsStr *vs = js_to_str(vm, mo->props[i].val);
                    JsVal cargs[2] = { js_obj_val((JsObj *)mo->props[i].key),
                                       vs ? js_obj_val((JsObj *)vs) : make_cstr_val(vm, "") };
                    (void)fn_headers(vm, js_obj_val(ho), 2, cargs, HEADERS_APPEND);
                }
            } else if (init->obj_type == OBJ_ARRAY) {
                JsArrObj *ao = (JsArrObj *)init;
                for (uint32_t i = 0; i < ao->len; i++) {
                    JsVal item = ao->items[i];
                    if (item.type == JS_OBJECT && item.u.obj) {
                        JsVal cargs[2] = { js_get_index(vm, item, 0), js_get_index(vm, item, 1) };
                        (void)fn_headers(vm, js_obj_val(ho), 2, cargs, HEADERS_APPEND);
                    }
                }
            }
        }
        vm->temp_sp = saved_sp;
        return js_obj_val(ho);
    }

    if (this_val.type != JS_OBJECT || !this_val.u.obj) return js_undefined();
    JsVal mv = js_get_prop(vm, this_val, "_map");
    if (mv.type != JS_OBJECT || !mv.u.obj || mv.u.obj->obj_type != OBJ_OBJECT) return js_undefined();
    JsMapObj *m = (JsMapObj *)mv.u.obj;

    switch (magic) {
        case HEADERS_APPEND: {
            if (argc < 2) return js_undefined();
            JsStr *k = js_to_str(vm, argv[0]);
            JsStr *v = js_to_str(vm, argv[1]);
            if (!k || !v) return js_undefined();
            for (uint32_t i = 0; i < m->count; i++) {
                if (tb_strcasecmp(m->props[i].key->data, k->data) == 0) {
                    JsStr *old_s = js_to_str(vm, m->props[i].val);
                    const char *old_c = old_s ? old_s->data : "";
                    size_t nlen = strlen(old_c) + 2 + v->len + 1;
                    char *combined = (char *)tb_malloc(nlen);
                    if (combined) {
                        snprintf(combined, nlen, "%s, %s", old_c, v->data);
                        m->props[i].val = make_cstr_val(vm, combined);
                        tb_free(combined);
                    }
                    return js_undefined();
                }
            }
            js_set_prop(vm, mv, k->data, js_obj_val((JsObj *)v));
            return js_undefined();
        }
        case HEADERS_GET: {
            if (argc < 1) return js_null();
            JsStr *k = js_to_str(vm, argv[0]);
            if (!k) return js_null();
            for (uint32_t i = 0; i < m->count; i++) {
                if (tb_strcasecmp(m->props[i].key->data, k->data) == 0) {
                    return m->props[i].val;
                }
            }
            return js_null();
        }
        case HEADERS_SET: {
            if (argc < 2) return js_undefined();
            JsStr *k = js_to_str(vm, argv[0]);
            JsStr *v = js_to_str(vm, argv[1]);
            if (!k) return js_undefined();
            for (uint32_t i = 0; i < m->count; i++) {
                if (tb_strcasecmp(m->props[i].key->data, k->data) == 0) {
                    m->props[i].val = v ? js_obj_val((JsObj *)v) : make_cstr_val(vm, "");
                    return js_undefined();
                }
            }
            js_set_prop(vm, mv, k->data, v ? js_obj_val((JsObj *)v) : make_cstr_val(vm, ""));
            return js_undefined();
        }
        case HEADERS_HAS: {
            if (argc < 1) return js_bool(false);
            JsStr *k = js_to_str(vm, argv[0]);
            if (!k) return js_bool(false);
            for (uint32_t i = 0; i < m->count; i++) {
                if (tb_strcasecmp(m->props[i].key->data, k->data) == 0) return js_bool(true);
            }
            return js_bool(false);
        }
        case HEADERS_DELETE: {
            if (argc < 1) return js_undefined();
            JsStr *k = js_to_str(vm, argv[0]);
            if (!k) return js_undefined();
            for (uint32_t i = 0; i < m->count; i++) {
                if (tb_strcasecmp(m->props[i].key->data, k->data) == 0) {
                    for (uint32_t j = i; j + 1 < m->count; j++) {
                        m->props[j] = m->props[j + 1];
                    }
                    m->count--;
                    break;
                }
            }
            return js_undefined();
        }
        case HEADERS_FOR_EACH: {
            if (argc < 1) return js_undefined();
            JsVal cb = argv[0];
            JsVal this_arg = argc > 1 ? argv[1] : js_undefined();
            uint32_t snap = m->count;
            for (uint32_t i = 0; i < snap && i < m->count; i++) {
                JsVal cargs[3] = { m->props[i].val, js_obj_val((JsObj *)m->props[i].key), this_val };
                (void)js_call(vm, cb, this_arg, 3, cargs);
                if (vm->has_thrown) break;
            }
            return js_undefined();
        }
        default:
            return js_undefined();
    }
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
    js_define_native(vm, g, "encodeURI", fn_global_misc, GM_ENCODE_URI);
    js_define_native(vm, g, "decodeURI", fn_global_misc, GM_DECODE_URI);
    js_define_native(vm, g, "atob", fn_global_misc, GM_ATOB);
    js_define_native(vm, g, "btoa", fn_global_misc, GM_BTOA);
    js_define_native(vm, g, "queueMicrotask", fn_global_misc, GM_QUEUE_MICROTASK);

    /* Object */
    js_define_native(vm, vm->object_proto, "hasOwnProperty", fn_object, OBJ_HAS_OWN_PROP);
    js_define_native(vm, vm->object_proto, "toString", fn_object, OBJ_TO_STRING);
    JsObj *obj_ctor = js_native_fn_new(vm, "Object", fn_object, OBJ_CTOR);
    js_define_native(vm, obj_ctor, "keys", fn_object, OBJ_KEYS);
    js_define_native(vm, obj_ctor, "values", fn_object, OBJ_VALUES);
    js_define_native(vm, obj_ctor, "entries", fn_object, OBJ_ENTRIES);
    js_define_native(vm, obj_ctor, "fromEntries", fn_object, OBJ_FROM_ENTRIES);
    js_define_native(vm, obj_ctor, "assign", fn_object, OBJ_ASSIGN);
    js_define_native(vm, obj_ctor, "create", fn_object, OBJ_CREATE);
    js_define_native(vm, obj_ctor, "is", fn_object, OBJ_IS);
    js_define_native(vm, obj_ctor, "hasOwn", fn_object, OBJ_HAS_OWN);
    js_define_native(vm, obj_ctor, "defineProperty", fn_object, OBJ_DEFINE_PROP);
    js_define_native(vm, obj_ctor, "defineProperties", fn_object, OBJ_DEFINE_PROPS);
    js_define_native(vm, obj_ctor, "getOwnPropertyDescriptor", fn_object, OBJ_GET_OWN_PROP_DESC);
    js_define_native(vm, obj_ctor, "getOwnPropertyNames", fn_object, OBJ_GET_OWN_PROP_NAMES);
    js_define_native(vm, obj_ctor, "getPrototypeOf", fn_object, OBJ_GET_PROTO_OF);
    js_define_native(vm, obj_ctor, "setPrototypeOf", fn_object, OBJ_SET_PROTO_OF);
    js_set_prop(vm, js_obj_val(obj_ctor), "prototype", js_obj_val(vm->object_proto));
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
    js_set_prop(vm, js_obj_val(str_ctor), "prototype", js_obj_val(vm->string_proto));
    js_set_prop(vm, js_obj_val(g), "String", js_obj_val(str_ctor));
    js_define_native(vm, vm->string_proto, "fromCharCode", fn_str_from_char_code, 0);
    js_define_native(vm, vm->string_proto, "toString", fn_str_proto, STR_TO_STRING);
    js_define_native(vm, vm->string_proto, "valueOf", fn_str_proto, STR_TO_STRING);
    js_define_native(vm, vm->string_proto, "charAt", fn_str_proto, STR_CHAR_AT);
    js_define_native(vm, vm->string_proto, "at", fn_str_proto, STR_AT);
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
    js_define_native(vm, vm->string_proto, "trimStart", fn_str_proto, STR_TRIM_START);
    js_define_native(vm, vm->string_proto, "trimLeft", fn_str_proto, STR_TRIM_START);
    js_define_native(vm, vm->string_proto, "trimEnd", fn_str_proto, STR_TRIM_END);
    js_define_native(vm, vm->string_proto, "trimRight", fn_str_proto, STR_TRIM_END);
    js_define_native(vm, vm->string_proto, "repeat", fn_str_proto, STR_REPEAT);
    js_define_native(vm, vm->string_proto, "padStart", fn_str_proto, STR_PAD_START);
    js_define_native(vm, vm->string_proto, "padEnd", fn_str_proto, STR_PAD_END);
    js_define_native(vm, vm->string_proto, "split", fn_str_proto, STR_SPLIT);
    js_define_native(vm, vm->string_proto, "replace", fn_str_proto, STR_REPLACE);
    js_define_native(vm, vm->string_proto, "replaceAll", fn_str_proto, STR_REPLACE_ALL);
    js_define_native(vm, vm->string_proto, "match", fn_str_proto, STR_MATCH);
    js_define_native(vm, vm->string_proto, "matchAll", fn_str_proto, STR_MATCH_ALL);
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
    js_define_native(vm, arr_ctor, "of", fn_array_ctor, ARR_OF);
    js_set_prop(vm, js_obj_val(arr_ctor), "prototype", js_obj_val(vm->array_proto));
    js_set_prop(vm, js_obj_val(g), "Array", js_obj_val(arr_ctor));
    js_define_native(vm, vm->array_proto, "push", fn_arr_proto, ARR_PUSH);
    js_define_native(vm, vm->array_proto, "pop", fn_arr_proto, ARR_POP);
    js_define_native(vm, vm->array_proto, "shift", fn_arr_proto, ARR_SHIFT);
    js_define_native(vm, vm->array_proto, "unshift", fn_arr_proto, ARR_UNSHIFT);
    js_define_native(vm, vm->array_proto, "at", fn_arr_proto, ARR_AT);
    js_define_native(vm, vm->array_proto, "fill", fn_arr_proto, ARR_FILL);
    js_define_native(vm, vm->array_proto, "flat", fn_arr_proto, ARR_FLAT);
    js_define_native(vm, vm->array_proto, "flatMap", fn_arr_proto, ARR_FLAT_MAP);
    js_define_native(vm, vm->array_proto, "slice", fn_arr_proto, ARR_SLICE);
    js_define_native(vm, vm->array_proto, "splice", fn_arr_proto, ARR_SPLICE);
    js_define_native(vm, vm->array_proto, "concat", fn_arr_proto, ARR_CONCAT);
    js_define_native(vm, vm->array_proto, "join", fn_arr_proto, ARR_JOIN);
    js_define_native(vm, vm->array_proto, "indexOf", fn_arr_proto, ARR_INDEX_OF);
    js_define_native(vm, vm->array_proto, "lastIndexOf", fn_arr_proto, ARR_LAST_INDEX_OF);
    js_define_native(vm, vm->array_proto, "includes", fn_arr_proto, ARR_INCLUDES);
    js_define_native(vm, vm->array_proto, "reverse", fn_arr_proto, ARR_REVERSE);
    js_define_native(vm, vm->array_proto, "sort", fn_arr_proto, ARR_SORT);
    js_define_native(vm, vm->array_proto, "toReversed", fn_arr_proto, ARR_TO_REVERSED);
    js_define_native(vm, vm->array_proto, "toSorted", fn_arr_proto, ARR_TO_SORTED);
    js_define_native(vm, vm->array_proto, "toSpliced", fn_arr_proto, ARR_TO_SPLICED);
    js_define_native(vm, vm->array_proto, "with", fn_arr_proto, ARR_WITH);
    js_define_native(vm, vm->array_proto, "forEach", fn_arr_proto, ARR_FOR_EACH);
    js_define_native(vm, vm->array_proto, "map", fn_arr_proto, ARR_MAP);
    js_define_native(vm, vm->array_proto, "filter", fn_arr_proto, ARR_FILTER);
    js_define_native(vm, vm->array_proto, "find", fn_arr_proto, ARR_FIND);
    js_define_native(vm, vm->array_proto, "findIndex", fn_arr_proto, ARR_FIND_INDEX);
    js_define_native(vm, vm->array_proto, "findLast", fn_arr_proto, ARR_FIND_LAST);
    js_define_native(vm, vm->array_proto, "findLastIndex", fn_arr_proto, ARR_FIND_LAST_INDEX);
    js_define_native(vm, vm->array_proto, "some", fn_arr_proto, ARR_SOME);
    js_define_native(vm, vm->array_proto, "every", fn_arr_proto, ARR_EVERY);
    js_define_native(vm, vm->array_proto, "reduce", fn_arr_proto, ARR_REDUCE);
    js_define_native(vm, vm->array_proto, "reduceRight", fn_arr_proto, ARR_REDUCE_RIGHT);

    /* Map & Set & WeakMap & WeakSet */
    js_define_native(vm, vm->map_proto, "set", fn_collection, MAP_SET);
    js_define_native(vm, vm->map_proto, "get", fn_collection, MAP_GET);
    js_define_native(vm, vm->map_proto, "has", fn_collection, MAP_HAS);
    js_define_native(vm, vm->map_proto, "delete", fn_collection, MAP_DELETE);
    js_define_native(vm, vm->map_proto, "clear", fn_collection, MAP_CLEAR);
    js_define_native(vm, vm->map_proto, "forEach", fn_collection, MAP_FOR_EACH);
    js_define_native(vm, vm->map_proto, "keys", fn_collection, MAP_KEYS);
    js_define_native(vm, vm->map_proto, "values", fn_collection, MAP_VALUES);
    js_define_native(vm, vm->map_proto, "entries", fn_collection, MAP_ENTRIES);
    JsObj *map_ctor = js_native_fn_new(vm, "Map", fn_collection, MAP_CTOR);
    js_set_prop(vm, js_obj_val(map_ctor), "prototype", js_obj_val(vm->map_proto));
    js_set_prop(vm, js_obj_val(g), "Map", js_obj_val(map_ctor));
    js_set_prop(vm, js_obj_val(g), "WeakMap", js_obj_val(map_ctor));

    js_define_native(vm, vm->set_proto, "add", fn_collection, SET_ADD);
    js_define_native(vm, vm->set_proto, "has", fn_collection, SET_HAS);
    js_define_native(vm, vm->set_proto, "delete", fn_collection, SET_DELETE);
    js_define_native(vm, vm->set_proto, "clear", fn_collection, SET_CLEAR);
    js_define_native(vm, vm->set_proto, "forEach", fn_collection, SET_FOR_EACH);
    js_define_native(vm, vm->set_proto, "keys", fn_collection, SET_VALUES);
    js_define_native(vm, vm->set_proto, "values", fn_collection, SET_VALUES);
    js_define_native(vm, vm->set_proto, "entries", fn_collection, SET_ENTRIES);
    JsObj *set_ctor = js_native_fn_new(vm, "Set", fn_collection, SET_CTOR);
    js_set_prop(vm, js_obj_val(set_ctor), "prototype", js_obj_val(vm->set_proto));
    js_set_prop(vm, js_obj_val(g), "Set", js_obj_val(set_ctor));
    js_set_prop(vm, js_obj_val(g), "WeakSet", js_obj_val(set_ctor));

    /* Promise */
    js_define_native(vm, vm->promise_proto, "then", fn_promise, PROM_THEN);
    js_define_native(vm, vm->promise_proto, "catch", fn_promise, PROM_CATCH);
    js_define_native(vm, vm->promise_proto, "finally", fn_promise, PROM_FINALLY);
    JsObj *prom_ctor = js_native_fn_new(vm, "Promise", fn_promise, PROM_CTOR);
    js_define_native(vm, prom_ctor, "resolve", fn_promise, PROM_RESOLVE);
    js_define_native(vm, prom_ctor, "reject", fn_promise, PROM_REJECT);
    js_define_native(vm, prom_ctor, "all", fn_promise, PROM_ALL);
    js_define_native(vm, prom_ctor, "race", fn_promise, PROM_RACE);
    js_set_prop(vm, js_obj_val(prom_ctor), "prototype", js_obj_val(vm->promise_proto));
    js_set_prop(vm, js_obj_val(g), "Promise", js_obj_val(prom_ctor));

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

    /* URL & URLSearchParams */
    JsObj *url_ctor = js_native_fn_new(vm, "URL", fn_url, URL_CTOR);
    js_set_prop(vm, js_obj_val(url_ctor), "prototype", js_obj_val(vm->url_proto));
    js_set_prop(vm, js_obj_val(g), "URL", js_obj_val(url_ctor));
    js_define_native(vm, vm->url_proto, "toString", fn_url, URL_TO_STRING);
    js_define_native(vm, vm->url_proto, "toJSON", fn_url, URL_TO_STRING);

    JsObj *usp_ctor = js_native_fn_new(vm, "URLSearchParams", fn_url_params, URL_PARAMS_CTOR);
    js_set_prop(vm, js_obj_val(usp_ctor), "prototype", js_obj_val(vm->url_params_proto));
    js_set_prop(vm, js_obj_val(g), "URLSearchParams", js_obj_val(usp_ctor));
    js_define_native(vm, vm->url_params_proto, "append", fn_url_params, URL_PARAMS_APPEND);
    js_define_native(vm, vm->url_params_proto, "get", fn_url_params, URL_PARAMS_GET);
    js_define_native(vm, vm->url_params_proto, "getAll", fn_url_params, URL_PARAMS_GET_ALL);
    js_define_native(vm, vm->url_params_proto, "set", fn_url_params, URL_PARAMS_SET);
    js_define_native(vm, vm->url_params_proto, "has", fn_url_params, URL_PARAMS_HAS);
    js_define_native(vm, vm->url_params_proto, "delete", fn_url_params, URL_PARAMS_DELETE);
    js_define_native(vm, vm->url_params_proto, "toString", fn_url_params, URL_PARAMS_TO_STRING);
    js_define_native(vm, vm->url_params_proto, "forEach", fn_url_params, URL_PARAMS_FOR_EACH);

    /* Headers */
    JsObj *hdrs_ctor = js_native_fn_new(vm, "Headers", fn_headers, HEADERS_CTOR);
    js_set_prop(vm, js_obj_val(hdrs_ctor), "prototype", js_obj_val(vm->headers_proto));
    js_set_prop(vm, js_obj_val(g), "Headers", js_obj_val(hdrs_ctor));
    js_define_native(vm, vm->headers_proto, "append", fn_headers, HEADERS_APPEND);
    js_define_native(vm, vm->headers_proto, "get", fn_headers, HEADERS_GET);
    js_define_native(vm, vm->headers_proto, "set", fn_headers, HEADERS_SET);
    js_define_native(vm, vm->headers_proto, "has", fn_headers, HEADERS_HAS);
    js_define_native(vm, vm->headers_proto, "delete", fn_headers, HEADERS_DELETE);
    js_define_native(vm, vm->headers_proto, "forEach", fn_headers, HEADERS_FOR_EACH);

    /* localStorage & sessionStorage */
    JsObj *ls = js_map_new(vm, vm->object_proto);
    ls->native_tag = NATIVE_TAG_STORAGE;
    JsObj *ls_store = js_map_new(vm, NULL);
    js_set_prop(vm, js_obj_val(ls), "_store", js_obj_val(ls_store));
    js_define_native(vm, ls, "setItem", fn_storage, STORAGE_SET_ITEM);
    js_define_native(vm, ls, "getItem", fn_storage, STORAGE_GET_ITEM);
    js_define_native(vm, ls, "removeItem", fn_storage, STORAGE_REMOVE_ITEM);
    js_define_native(vm, ls, "clear", fn_storage, STORAGE_CLEAR);
    js_define_native(vm, ls, "key", fn_storage, STORAGE_KEY);
    vm->local_storage_obj = ls;
    js_set_prop(vm, js_obj_val(g), "localStorage", js_obj_val(ls));

    JsObj *ss = js_map_new(vm, vm->object_proto);
    ss->native_tag = NATIVE_TAG_STORAGE;
    JsObj *ss_store = js_map_new(vm, NULL);
    js_set_prop(vm, js_obj_val(ss), "_store", js_obj_val(ss_store));
    js_define_native(vm, ss, "setItem", fn_storage, STORAGE_SET_ITEM);
    js_define_native(vm, ss, "getItem", fn_storage, STORAGE_GET_ITEM);
    js_define_native(vm, ss, "removeItem", fn_storage, STORAGE_REMOVE_ITEM);
    js_define_native(vm, ss, "clear", fn_storage, STORAGE_CLEAR);
    js_define_native(vm, ss, "key", fn_storage, STORAGE_KEY);
    vm->session_storage_obj = ss;
    js_set_prop(vm, js_obj_val(g), "sessionStorage", js_obj_val(ss));
}
