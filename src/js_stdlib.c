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
static JsVal fn_global_misc(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    JsVal a0 = argc > 0 ? argv[0] : js_undefined();
    switch (magic) {
        case 0: { /* parseInt */
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
        case 1: { /* parseFloat */
            JsStr *s = js_to_str(vm, a0);
            if (!s) return js_num(TB_NAN);
            const char *p = s->data;
            while (*p && tb_isspace(*p)) p++;
            char *endp = NULL;
            double v   = strtod(p, &endp);
            return (endp == p) ? js_num(TB_NAN) : js_num(v);
        }
        case 2: /* isNaN */
            return js_bool(tb_isnan(js_to_num(vm, a0)));
        case 3: { /* isFinite */
            double d = js_to_num(vm, a0);
            return js_bool(!tb_isnan(d) && !tb_isinf(d));
        }
        case 4: /* Number.isNaN */
            return js_bool(a0.type == JS_NUMBER && tb_isnan(a0.u.num));
        case 5: /* Number.isInteger */
            return js_bool(a0.type == JS_NUMBER && tb_isfinite(a0.u.num) && tb_floor(a0.u.num) == a0.u.num);
        case 6: /* Number() */
            return js_num(argc > 0 ? js_to_num(vm, a0) : 0.0);
        case 7: /* String() */
            return argc > 0 ? js_obj_val((JsObj *)js_to_str(vm, a0)) : make_cstr_val(vm, "");
        case 8: /* Boolean() */
            return js_bool(js_to_bool(a0));
        case 9: { /* Error / TypeError / RangeError */
            JsObj *err = js_map_new(vm, vm->object_proto);
            JsStr *ms  = (argc > 0 && a0.type != JS_UNDEFINED) ? js_to_str(vm, a0) : js_str_cstr(vm, "");
            if (err && ms) {
                js_set_prop(vm, js_obj_val(err), "message", js_obj_val((JsObj *)ms));
                js_set_prop(vm, js_obj_val(err), "name", make_cstr_val(vm, "Error"));
            }
            return js_obj_val(err);
        }
        case 10: { /* eval */
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
        case 11: { /* encodeURIComponent */
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
        case 12: { /* decodeURIComponent */
            JsStr *s = js_to_str(vm, a0);
            if (!s) return make_cstr_val(vm, "");
            TbBuf b;
            tb_buf_init(&b);
            for (uint32_t i = 0; i < s->len; i++) {
                if (s->data[i] == '%' && i + 2 < s->len &&
                    tb_isxdigit(s->data[i + 1]) && tb_isxdigit(s->data[i + 2])) {
                    char hx[3] = { s->data[i + 1], s->data[i + 2], '\0' };
                    tb_buf_append_char(&b, (char)strtol(hx, NULL, 16));
                    i += 2;
                } else {
                    tb_buf_append_char(&b, s->data[i]);
                }
            }
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case 13: { /* tb.gc() */
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

static JsVal fn_num_proto(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    double n = js_to_num(vm, this_val);
    if (magic == 0) { /* toFixed */
        int digits = (argc > 0 && argv[0].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[0]) : 0;
        if (digits < 0) digits = 0;
        if (digits > 20) digits = 20;
        if (tb_isnan(n) || tb_isinf(n)) return js_obj_val((JsObj *)js_to_str(vm, js_num(n)));
        char buf[128];
        snprintf(buf, sizeof(buf), "%.*f", digits, n);
        return make_cstr_val(vm, buf);
    }
    /* toString(radix) */
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
static JsVal fn_func_proto(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    JsVal bound_this = argc > 0 ? argv[0] : js_undefined();
    if (magic == 0) { /* call */
        return js_call(vm, this_val, bound_this, argc > 1 ? argc - 1 : 0, argc > 1 ? argv + 1 : NULL);
    }
    if (magic == 1) { /* apply */
        if (argc > 1 && argv[1].type == JS_OBJECT && argv[1].u.obj &&
            argv[1].u.obj->obj_type == OBJ_ARRAY) {
            JsArrObj *a = (JsArrObj *)argv[1].u.obj;
            return js_call(vm, this_val, bound_this, (int)a->len, a->items);
        }
        return js_call(vm, this_val, bound_this, 0, NULL);
    }
    /* bind */
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
static JsVal fn_object(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == 10) { /* Object.prototype.hasOwnProperty */
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
    if (magic == 11) { /* Object.prototype.toString */
        return js_obj_val((JsObj *)js_to_str(vm, this_val));
    }

    JsVal a0 = argc > 0 ? argv[0] : js_undefined();
    if (magic == 0) { /* Object() constructor */
        if (a0.type == JS_OBJECT && a0.u.obj) return a0;
        return js_obj_val(js_map_new(vm, vm->object_proto));
    }
    if (magic >= 1 && magic <= 3) { /* keys(1), values(2), entries(3) */
        JsObj *arr = js_arr_new(vm, 8);
        if (!arr || a0.type != JS_OBJECT || !a0.u.obj) return js_obj_val(arr);
        if (a0.u.obj->obj_type == OBJ_OBJECT) {
            JsMapObj *m = (JsMapObj *)a0.u.obj;
            for (uint32_t i = 0; i < m->count; i++) {
                if (magic == 1) {
                    js_arr_push(vm, arr, js_obj_val((JsObj *)m->props[i].key));
                } else if (magic == 2) {
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
    if (magic == 4) { /* Object.assign */
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
    if (magic == 5) { /* Object.create */
        JsObj *proto = (a0.type == JS_OBJECT) ? a0.u.obj : NULL;
        return js_obj_val(js_map_new(vm, proto));
    }
    return js_undefined();
}

/* RegExp methods */
static JsVal fn_regexp(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == 0) { /* RegExp(pat, flags) */
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
        return magic == 1 ? js_bool(false) : js_null();
    JsRegexObj *rx = (JsRegexObj *)this_val.u.obj;
    JsStr *subj    = js_to_str(vm, argc > 0 ? argv[0] : js_undefined());
    if (!subj || !rx->compiled) return magic == 1 ? js_bool(false) : js_null();

    uint32_t rf      = tb_regex_flags(rx->compiled);
    bool use_last    = (rf & (TB_RX_GLOBAL | TB_RX_STICKY)) != 0;
    size_t start_pos = use_last ? rx->last_index : 0;
    if (start_pos > subj->len) {
        if (use_last) rx->last_index = 0;
        return magic == 1 ? js_bool(false) : js_null();
    }
    TbRegexMatch m;
    bool hit = tb_regex_exec(rx->compiled, subj->data, subj->len, start_pos, &m);
    if (!hit) {
        if (use_last) rx->last_index = 0;
        return magic == 1 ? js_bool(false) : js_null();
    }
    if (use_last) rx->last_index = m.ends[0];
    if (magic == 1) return js_bool(true); /* test */
    return build_match_array(vm, subj, &m); /* exec */
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

static JsVal fn_str_proto(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    JsStr *s = js_to_str(vm, this_val);
    if (!s) return make_cstr_val(vm, "");
    int slen = (int)s->len;

    switch (magic) {
        case 0: return js_obj_val((JsObj *)s); /* toString / valueOf */
        case 1: { /* charAt */
            int idx = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (idx < 0 || idx >= slen) return make_cstr_val(vm, "");
            return make_str_val(vm, s->data + idx, 1);
        }
        case 2: { /* charCodeAt */
            int idx = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (idx < 0 || idx >= slen) return js_num(TB_NAN);
            return js_num((double)(uint8_t)s->data[idx]);
        }
        case 3: { /* slice */
            int st = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            int en = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[1]) : slen;
            if (st < 0) st = slen + st;
            if (en < 0) en = slen + en;
            if (st < 0) st = 0;
            if (en > slen) en = slen;
            if (en <= st) return make_cstr_val(vm, "");
            return make_str_val(vm, s->data + st, (size_t)(en - st));
        }
        case 4: { /* substring */
            int st = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            int en = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[1]) : slen;
            if (st < 0) st = 0;
            if (en < 0) en = 0;
            if (st > slen) st = slen;
            if (en > slen) en = slen;
            if (st > en) { int t = st; st = en; en = t; }
            return make_str_val(vm, s->data + st, (size_t)(en - st));
        }
        case 5: { /* substr */
            int st  = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            int cnt = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (int)js_to_num(vm, argv[1]) : slen;
            if (st < 0) st = slen + st;
            if (st < 0) st = 0;
            if (cnt <= 0 || st >= slen) return make_cstr_val(vm, "");
            if (st + cnt > slen) cnt = slen - st;
            return make_str_val(vm, s->data + st, (size_t)cnt);
        }
        case 6:   /* indexOf */
        case 7:   /* includes */
        case 8:   /* startsWith */
        case 9: { /* endsWith */
            JsStr *ndl = js_to_str(vm, argc > 0 ? argv[0] : js_undefined());
            if (!ndl) return magic == 6 ? js_num(-1) : js_bool(false);
            int nlen = (int)ndl->len;
            if (magic == 8) {
                int pos = argc > 1 ? (int)js_to_num(vm, argv[1]) : 0;
                if (pos < 0) pos = 0;
                return js_bool(pos + nlen <= slen && memcmp(s->data + pos, ndl->data, (size_t)nlen) == 0);
            }
            if (magic == 9) {
                return js_bool(nlen <= slen && memcmp(s->data + slen - nlen, ndl->data, (size_t)nlen) == 0);
            }
            int from = argc > 1 ? (int)js_to_num(vm, argv[1]) : 0;
            if (from < 0) from = 0;
            if (from > slen) return magic == 6 ? js_num(-1) : js_bool(false);
            const char *hit = strstr(s->data + from, ndl->data);
            if (!hit) return magic == 6 ? js_num(-1) : js_bool(false);
            return magic == 6 ? js_num((double)(hit - s->data)) : js_bool(true);
        }
        case 10:   /* toLowerCase */
        case 11: { /* toUpperCase */
            char *tmp = tb_strndup(s->data, s->len);
            if (!tmp) return js_obj_val((JsObj *)s);
            for (uint32_t i = 0; i < s->len; i++) {
                tmp[i] = (magic == 10) ? tb_tolower(tmp[i]) : tb_toupper(tmp[i]);
            }
            JsVal r = make_str_val(vm, tmp, s->len);
            tb_free(tmp);
            return r;
        }
        case 12: { /* trim */
            size_t st = 0, en = s->len;
            while (st < en && tb_isspace(s->data[st])) st++;
            while (en > st && tb_isspace(s->data[en - 1])) en--;
            return make_str_val(vm, s->data + st, en - st);
        }
        case 13: { /* repeat */
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
        case 14:   /* padStart */
        case 15: { /* padEnd */
            int target_len = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            if (target_len <= slen || target_len > 65536) return js_obj_val((JsObj *)s);
            JsStr *pad = (argc > 1 && argv[1].type != JS_UNDEFINED)
                             ? js_to_str(vm, argv[1])
                             : js_str_cstr(vm, " ");
            if (!pad || pad->len == 0) return js_obj_val((JsObj *)s);
            int need = target_len - slen;
            TbBuf b;
            tb_buf_init(&b);
            if (magic == 15) tb_buf_append(&b, s->data, s->len);
            while (need > 0) {
                size_t take = (size_t)need < pad->len ? (size_t)need : pad->len;
                tb_buf_append(&b, pad->data, take);
                need -= (int)take;
            }
            if (magic == 14) tb_buf_append(&b, s->data, s->len);
            JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            return r;
        }
        case 16: { /* split */
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
        case 17:   /* replace */
        case 18: { /* replaceAll */
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

            bool all = (magic == 18);
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
        case 19: { /* match */
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
        case 20: { /* lastIndexOf */
            JsStr *ndl = js_to_str(vm, argc > 0 ? argv[0] : js_undefined());
            if (!ndl || (int)ndl->len > slen) return js_num(-1);
            for (int i = slen - (int)ndl->len; i >= 0; i--) {
                if (memcmp(s->data + i, ndl->data, ndl->len) == 0) return js_num((double)i);
            }
            return js_num(-1);
        }
        case 21: { /* search */
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
static JsVal fn_array_ctor(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    if (magic == 1) { /* Array.isArray */
        return js_bool(argc > 0 && argv[0].type == JS_OBJECT &&
                       argv[0].u.obj && argv[0].u.obj->obj_type == OBJ_ARRAY);
    }
    if (magic == 2) { /* Array.from */
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

static JsVal fn_arr_proto(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (this_val.type != JS_OBJECT || !this_val.u.obj || this_val.u.obj->obj_type != OBJ_ARRAY)
        return js_undefined();
    JsArrObj *a = (JsArrObj *)this_val.u.obj;

    switch (magic) {
        case 0: /* push */
            for (int i = 0; i < argc; i++) js_arr_push(vm, (JsObj *)a, argv[i]);
            return js_num((double)a->len);
        case 1: /* pop */
            if (a->len == 0) return js_undefined();
            return a->items[--a->len];
        case 2: { /* shift */
            if (a->len == 0) return js_undefined();
            JsVal first = a->items[0];
            for (uint32_t i = 0; i + 1 < a->len; i++) a->items[i] = a->items[i + 1];
            a->len--;
            return first;
        }
        case 3: { /* unshift */
            if (argc <= 0) return js_num((double)a->len);
            for (int i = 0; i < argc; i++) js_arr_push(vm, (JsObj *)a, js_undefined());
            for (int i = (int)a->len - 1; i >= argc; i--) a->items[i] = a->items[i - argc];
            for (int i = 0; i < argc; i++) a->items[i] = argv[i];
            return js_num((double)a->len);
        }
        case 4: { /* slice */
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
        case 5: { /* splice */
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
        case 6: { /* concat */
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
        case 7: { /* join */
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
        case 8:   /* indexOf */
        case 9: { /* includes */
            JsVal needle = argc > 0 ? argv[0] : js_undefined();
            for (uint32_t i = 0; i < a->len; i++) {
                bool eq = js_strict_eq(a->items[i], needle) ||
                          (magic == 9 && a->items[i].type == JS_NUMBER && needle.type == JS_NUMBER &&
                           tb_isnan(a->items[i].u.num) && tb_isnan(needle.u.num));
                if (eq) return magic == 8 ? js_num((double)i) : js_bool(true);
            }
            return magic == 8 ? js_num(-1) : js_bool(false);
        }
        case 10: { /* reverse */
            for (uint32_t i = 0; i < a->len / 2; i++) {
                JsVal tmp = a->items[i];
                a->items[i] = a->items[a->len - 1 - i];
                a->items[a->len - 1 - i] = tmp;
            }
            return this_val;
        }
        case 11: { /* sort (insertion sort — stable, safe across JS callbacks & GC!) */
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
        case 12:   /* forEach */
        case 13:   /* map */
        case 14:   /* filter */
        case 15:   /* find */
        case 16:   /* findIndex */
        case 17:   /* some */
        case 18: { /* every */
            if (argc == 0) return js_undefined();
            JsVal cb   = argv[0];
            JsVal targ = argc > 1 ? argv[1] : js_undefined();
            JsObj *res = (magic == 13 || magic == 14) ? js_arr_new(vm, a->len) : NULL;
            int saved_sp = vm->temp_sp;
            if (res) js_temp_push(vm, js_obj_val(res));

            uint32_t snap_len = a->len;
            for (uint32_t i = 0; i < snap_len && i < a->len; i++) {
                JsVal item = a->items[i];
                JsVal cargs[3] = { item, js_num((double)i), this_val };
                JsVal rv = js_call(vm, cb, targ, 3, cargs);
                if (vm->has_thrown) { vm->temp_sp = saved_sp; return js_undefined(); }
                if (magic == 13) js_arr_push(vm, res, rv);
                else if (magic == 14 && js_to_bool(rv)) js_arr_push(vm, res, item);
                else if (magic == 15 && js_to_bool(rv)) { vm->temp_sp = saved_sp; return item; }
                else if (magic == 16 && js_to_bool(rv)) { vm->temp_sp = saved_sp; return js_num((double)i); }
                else if (magic == 17 && js_to_bool(rv)) { vm->temp_sp = saved_sp; return js_bool(true); }
                else if (magic == 18 && !js_to_bool(rv)) { vm->temp_sp = saved_sp; return js_bool(false); }
            }
            vm->temp_sp = saved_sp;
            if (magic == 13 || magic == 14) return js_obj_val(res);
            if (magic == 15) return js_undefined();
            if (magic == 16) return js_num(-1);
            if (magic == 17) return js_bool(false);
            if (magic == 18) return js_bool(true);
            return js_undefined();
        }
        case 19: { /* reduce */
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
static JsVal fn_math(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    if (magic == 20) return js_num((double)rand() / ((double)RAND_MAX + 1.0));
    if (magic == 21 || magic == 22) { /* min(21), max(22) */
        double best = (magic == 21) ? TB_INFINITY : -TB_INFINITY;
        for (int i = 0; i < argc; i++) {
            double v = js_to_num(vm, argv[i]);
            if (tb_isnan(v)) return js_num(TB_NAN);
            if ((magic == 21 && v < best) || (magic == 22 && v > best)) best = v;
        }
        return js_num(best);
    }
    double x = argc > 0 ? js_to_num(vm, argv[0]) : TB_NAN;
    double y = argc > 1 ? js_to_num(vm, argv[1]) : TB_NAN;
    switch (magic) {
        case 0:  return js_num(tb_fabs(x));
        case 1:  return js_num(tb_floor(x));
        case 2:  return js_num(tb_ceil(x));
        case 3:  return js_num(tb_round(x));
        case 4:  return js_num(tb_trunc(x));
        case 5:  return js_num(tb_sqrt(x));
        case 6:  return js_num(tb_sin(x));
        case 7:  return js_num(tb_cos(x));
        case 8:  return js_num(tb_tan(x));
        case 9:  return js_num(tb_log(x));
        case 10: return js_num(tb_log10(x));
        case 11: return js_num(tb_exp(x));
        case 12: return js_num(tb_pow(x, y));
        case 13: return js_num(tb_atan2(x, y));
        case 14: return js_num(tb_isnan(x) ? TB_NAN : (x > 0 ? 1.0 : (x < 0 ? -1.0 : 0.0)));
        default: return js_num(TB_NAN);
    }
}

static JsVal fn_date(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    double epoch_ms = (double)ts.tv_sec * 1000.0 + (double)(ts.tv_nsec / 1000000LL);
    if (magic == 0) return js_num(epoch_ms); /* Date.now() */
    if (magic == 1) { /* Date constructor */
        double init_ms = (argc > 0 && argv[0].type != JS_UNDEFINED)
                             ? js_to_num(vm, argv[0])
                             : epoch_ms;
        JsObj *d = js_map_new(vm, vm->object_proto);
        if (d) {
            js_set_prop(vm, js_obj_val(d), "_ms", js_num(init_ms));
            js_define_native(vm, d, "getTime", fn_date, 2);
            js_define_native(vm, d, "toISOString", fn_date, 3);
        }
        return js_obj_val(d);
    }
    double ms = js_to_num(vm, js_get_prop(vm, this_val, "_ms"));
    if (magic == 2) return js_num(ms);
    if (!tb_isfinite(ms)) {
        js_throw_str(vm, "RangeError: Invalid time value");
        return js_undefined();
    }
    char iso[64];
    tb_utc_to_iso8601(ms, iso, sizeof(iso));
    return make_cstr_val(vm, iso);
}

/* JSON.parse & JSON.stringify */
typedef struct {
    JsVm       *vm;
    const char *s;
    size_t      pos;
    size_t      len;
    bool        err;
} JsonParser;

static void jp_skip_ws(JsonParser *jp) {
    while (jp->pos < jp->len && tb_isspace(jp->s[jp->pos])) jp->pos++;
}

static JsVal jp_val(JsonParser *jp);

static JsStr *jp_str(JsonParser *jp) {
    if (jp->pos >= jp->len || jp->s[jp->pos] != '"') { jp->err = true; return NULL; }
    jp->pos++;
    TbBuf b;
    tb_buf_init(&b);
    while (jp->pos < jp->len && jp->s[jp->pos] != '"') {
        char c = jp->s[jp->pos++];
        if (c == '\\' && jp->pos < jp->len) {
            char e = jp->s[jp->pos++];
            switch (e) {
                case '"': case '\\': case '/': tb_buf_append_char(&b, e); break;
                case 'b': tb_buf_append_char(&b, '\b'); break;
                case 'f': tb_buf_append_char(&b, '\f'); break;
                case 'n': tb_buf_append_char(&b, '\n'); break;
                case 'r': tb_buf_append_char(&b, '\r'); break;
                case 't': tb_buf_append_char(&b, '\t'); break;
                case 'u': {
                    if (jp->pos + 4 <= jp->len) {
                        char hx[5] = { jp->s[jp->pos], jp->s[jp->pos+1],
                                       jp->s[jp->pos+2], jp->s[jp->pos+3], '\0' };
                        uint32_t cp = (uint32_t)strtoul(hx, NULL, 16);
                        char u8[4];
                        tb_buf_append(&b, u8, tb_utf8_encode(cp, u8));
                        jp->pos += 4;
                    }
                    break;
                }
                default: tb_buf_append_char(&b, e); break;
            }
        } else {
            tb_buf_append_char(&b, c);
        }
    }
    if (jp->pos >= jp->len || jp->s[jp->pos] != '"') {
        jp->err = true;
        tb_buf_free(&b);
        return NULL;
    }
    jp->pos++;
    JsStr *res = js_str_new(jp->vm, b.data ? b.data : "", b.len);
    tb_buf_free(&b);
    return res;
}

static JsVal jp_val(JsonParser *jp) {
    jp_skip_ws(jp);
    if (jp->pos >= jp->len) { jp->err = true; return js_undefined(); }
    char c = jp->s[jp->pos];
    if (c == '"') {
        JsStr *s = jp_str(jp);
        return s ? js_obj_val((JsObj *)s) : js_undefined();
    }
    if (c == '{') {
        jp->pos++;
        JsObj *obj = js_map_new(jp->vm, jp->vm->object_proto);
        jp_skip_ws(jp);
        if (jp->pos < jp->len && jp->s[jp->pos] == '}') { jp->pos++; return js_obj_val(obj); }
        while (!jp->err && jp->pos < jp->len) {
            jp_skip_ws(jp);
            JsStr *k = jp_str(jp);
            jp_skip_ws(jp);
            if (!k || jp->pos >= jp->len || jp->s[jp->pos] != ':') { jp->err = true; break; }
            jp->pos++;
            JsVal v = jp_val(jp);
            if (obj) js_set_prop_str(jp->vm, js_obj_val(obj), k, v);
            jp_skip_ws(jp);
            if (jp->pos < jp->len && jp->s[jp->pos] == ',') { jp->pos++; continue; }
            if (jp->pos < jp->len && jp->s[jp->pos] == '}') { jp->pos++; return js_obj_val(obj); }
            jp->err = true;
        }
        return js_undefined();
    }
    if (c == '[') {
        jp->pos++;
        JsObj *arr = js_arr_new(jp->vm, 4);
        jp_skip_ws(jp);
        if (jp->pos < jp->len && jp->s[jp->pos] == ']') { jp->pos++; return js_obj_val(arr); }
        while (!jp->err && jp->pos < jp->len) {
            JsVal v = jp_val(jp);
            if (arr) js_arr_push(jp->vm, arr, v);
            jp_skip_ws(jp);
            if (jp->pos < jp->len && jp->s[jp->pos] == ',') { jp->pos++; continue; }
            if (jp->pos < jp->len && jp->s[jp->pos] == ']') { jp->pos++; return js_obj_val(arr); }
            jp->err = true;
        }
        return js_undefined();
    }
    if (jp->pos + 4 <= jp->len && strncmp(jp->s + jp->pos, "true", 4) == 0) {
        jp->pos += 4;
        return js_bool(true);
    }
    if (jp->pos + 5 <= jp->len && strncmp(jp->s + jp->pos, "false", 5) == 0) {
        jp->pos += 5;
        return js_bool(false);
    }
    if (jp->pos + 4 <= jp->len && strncmp(jp->s + jp->pos, "null", 4) == 0) {
        jp->pos += 4;
        return js_null();
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        char *endp = NULL;
        double d   = strtod(jp->s + jp->pos, &endp);
        if (endp == jp->s + jp->pos) { jp->err = true; return js_undefined(); }
        jp->pos = (size_t)(endp - jp->s);
        return js_num(d);
    }
    jp->err = true;
    return js_undefined();
}

static void json_quote_str(const char *s, size_t len, TbBuf *out) {
    tb_buf_append_char(out, '"');
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)s[i];
        switch (c) {
            case '"':  tb_buf_append_cstr(out, "\\\""); break;
            case '\\': tb_buf_append_cstr(out, "\\\\"); break;
            case '\b': tb_buf_append_cstr(out, "\\b"); break;
            case '\f': tb_buf_append_cstr(out, "\\f"); break;
            case '\n': tb_buf_append_cstr(out, "\\n"); break;
            case '\r': tb_buf_append_cstr(out, "\\r"); break;
            case '\t': tb_buf_append_cstr(out, "\\t"); break;
            default:
                if (c < 0x20) tb_buf_printf(out, "\\u%04x", c);
                else tb_buf_append_char(out, (char)c);
                break;
        }
    }
    tb_buf_append_char(out, '"');
}

static bool json_stringify_rec(JsVm *vm, JsVal v, TbBuf *out, int depth) {
    if (depth > 16) return false;
    switch (v.type) {
        case JS_UNDEFINED: return false;
        case JS_NULL:      tb_buf_append_cstr(out, "null"); return true;
        case JS_BOOL:      tb_buf_append_cstr(out, v.u.boolean ? "true" : "false"); return true;
        case JS_NUMBER:
            if (!tb_isfinite(v.u.num)) tb_buf_append_cstr(out, "null");
            else tb_buf_printf(out, "%.15g", v.u.num);
            return true;
        case JS_OBJECT: {
            if (!v.u.obj) { tb_buf_append_cstr(out, "null"); return true; }
            if (v.u.obj->obj_type == OBJ_STRING) {
                JsStr *s = (JsStr *)v.u.obj;
                json_quote_str(s->data, s->len, out);
                return true;
            }
            if (v.u.obj->obj_type == OBJ_ARRAY) {
                JsArrObj *a = (JsArrObj *)v.u.obj;
                tb_buf_append_char(out, '[');
                for (uint32_t i = 0; i < a->len; i++) {
                    if (i > 0) tb_buf_append_char(out, ',');
                    if (!json_stringify_rec(vm, a->items[i], out, depth + 1)) {
                        tb_buf_append_cstr(out, "null");
                    }
                }
                tb_buf_append_char(out, ']');
                return true;
            }
            if (v.u.obj->obj_type == OBJ_OBJECT) {
                JsMapObj *m = (JsMapObj *)v.u.obj;
                tb_buf_append_char(out, '{');
                bool first = true;
                for (uint32_t i = 0; i < m->count; i++) {
                    JsVal pv = m->props[i].val;
                    if (pv.type == JS_UNDEFINED ||
                        (pv.type == JS_OBJECT && pv.u.obj &&
                         (pv.u.obj->obj_type == OBJ_FUNC || pv.u.obj->obj_type == OBJ_NATIVE_FN))) {
                        continue;
                    }
                    if (!first) tb_buf_append_char(out, ',');
                    first = false;
                    json_quote_str(m->props[i].key->data, m->props[i].key->len, out);
                    tb_buf_append_char(out, ':');
                    if (!json_stringify_rec(vm, pv, out, depth + 1)) {
                        tb_buf_append_cstr(out, "null");
                    }
                }
                tb_buf_append_char(out, '}');
                return true;
            }
            return false;
        }
    }
    return false;
}

static JsVal fn_json(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    if (magic == 0) { /* JSON.parse */
        JsStr *s = js_to_str(vm, argc > 0 ? argv[0] : js_undefined());
        if (!s) { js_throw_str(vm, "SyntaxError: Unexpected end of JSON input"); return js_undefined(); }
        vm->gc_pause++;
        JsonParser jp = { vm, s->data, 0, s->len, false };
        JsVal res = jp_val(&jp);
        jp_skip_ws(&jp);
        vm->gc_pause--;
        if (jp.err || jp.pos != jp.len) {
            js_throw_str(vm, "SyntaxError: Invalid JSON");
            return js_undefined();
        }
        return res;
    }
    /* JSON.stringify */
    if (argc == 0) return js_undefined();
    TbBuf b;
    tb_buf_init(&b);
    if (!json_stringify_rec(vm, argv[0], &b, 0)) {
        tb_buf_free(&b);
        return js_undefined();
    }
    JsVal r = make_str_val(vm, b.data ? b.data : "", b.len);
    tb_buf_free(&b);
    return r;
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
    js_define_native(vm, g, "parseInt", fn_global_misc, 0);
    js_define_native(vm, g, "parseFloat", fn_global_misc, 1);
    js_define_native(vm, g, "isNaN", fn_global_misc, 2);
    js_define_native(vm, g, "isFinite", fn_global_misc, 3);
    js_define_native(vm, g, "eval", fn_global_misc, 10);
    js_define_native(vm, g, "encodeURIComponent", fn_global_misc, 11);
    js_define_native(vm, g, "decodeURIComponent", fn_global_misc, 12);

    /* Object */
    js_define_native(vm, vm->object_proto, "hasOwnProperty", fn_object, 10);
    js_define_native(vm, vm->object_proto, "toString", fn_object, 11);
    JsObj *obj_ctor = js_native_fn_new(vm, "Object", fn_object, 0);
    js_define_native(vm, obj_ctor, "keys", fn_object, 1);
    js_define_native(vm, obj_ctor, "values", fn_object, 2);
    js_define_native(vm, obj_ctor, "entries", fn_object, 3);
    js_define_native(vm, obj_ctor, "assign", fn_object, 4);
    js_define_native(vm, obj_ctor, "create", fn_object, 5);
    js_set_prop(vm, js_obj_val(g), "Object", js_obj_val(obj_ctor));

    /* Function.prototype */
    js_define_native(vm, vm->func_proto, "call", fn_func_proto, 0);
    js_define_native(vm, vm->func_proto, "apply", fn_func_proto, 1);
    js_define_native(vm, vm->func_proto, "bind", fn_func_proto, 2);

    /* Number & Boolean & Error */
    js_define_native(vm, vm->number_proto, "toFixed", fn_num_proto, 0);
    js_define_native(vm, vm->number_proto, "toString", fn_num_proto, 1);
    js_define_native(vm, vm->bool_proto, "toString", fn_object, 11);

    JsObj *num_ctor = js_native_fn_new(vm, "Number", fn_global_misc, 6);
    js_define_native(vm, num_ctor, "isNaN", fn_global_misc, 4);
    js_define_native(vm, num_ctor, "isFinite", fn_global_misc, 3);
    js_define_native(vm, num_ctor, "isInteger", fn_global_misc, 5);
    js_define_native(vm, num_ctor, "parseInt", fn_global_misc, 0);
    js_define_native(vm, num_ctor, "parseFloat", fn_global_misc, 1);
    js_set_prop(vm, js_obj_val(g), "Number", js_obj_val(num_ctor));
    js_define_native(vm, g, "Boolean", fn_global_misc, 8);
    js_define_native(vm, g, "Error", fn_global_misc, 9);
    js_define_native(vm, g, "TypeError", fn_global_misc, 9);
    js_define_native(vm, g, "RangeError", fn_global_misc, 9);
    js_define_native(vm, g, "ReferenceError", fn_global_misc, 9);
    js_define_native(vm, g, "SyntaxError", fn_global_misc, 9);

    /* String */
    JsObj *str_ctor = js_native_fn_new(vm, "String", fn_global_misc, 7);
    js_define_native(vm, str_ctor, "fromCharCode", fn_str_from_char_code, 0);
    js_set_prop(vm, js_obj_val(g), "String", js_obj_val(str_ctor));
    js_define_native(vm, vm->string_proto, "fromCharCode", fn_str_from_char_code, 0);
    js_define_native(vm, vm->string_proto, "toString", fn_str_proto, 0);
    js_define_native(vm, vm->string_proto, "valueOf", fn_str_proto, 0);
    js_define_native(vm, vm->string_proto, "charAt", fn_str_proto, 1);
    js_define_native(vm, vm->string_proto, "charCodeAt", fn_str_proto, 2);
    js_define_native(vm, vm->string_proto, "slice", fn_str_proto, 3);
    js_define_native(vm, vm->string_proto, "substring", fn_str_proto, 4);
    js_define_native(vm, vm->string_proto, "substr", fn_str_proto, 5);
    js_define_native(vm, vm->string_proto, "indexOf", fn_str_proto, 6);
    js_define_native(vm, vm->string_proto, "includes", fn_str_proto, 7);
    js_define_native(vm, vm->string_proto, "startsWith", fn_str_proto, 8);
    js_define_native(vm, vm->string_proto, "endsWith", fn_str_proto, 9);
    js_define_native(vm, vm->string_proto, "toLowerCase", fn_str_proto, 10);
    js_define_native(vm, vm->string_proto, "toUpperCase", fn_str_proto, 11);
    js_define_native(vm, vm->string_proto, "trim", fn_str_proto, 12);
    js_define_native(vm, vm->string_proto, "repeat", fn_str_proto, 13);
    js_define_native(vm, vm->string_proto, "padStart", fn_str_proto, 14);
    js_define_native(vm, vm->string_proto, "padEnd", fn_str_proto, 15);
    js_define_native(vm, vm->string_proto, "split", fn_str_proto, 16);
    js_define_native(vm, vm->string_proto, "replace", fn_str_proto, 17);
    js_define_native(vm, vm->string_proto, "replaceAll", fn_str_proto, 18);
    js_define_native(vm, vm->string_proto, "match", fn_str_proto, 19);
    js_define_native(vm, vm->string_proto, "lastIndexOf", fn_str_proto, 20);
    js_define_native(vm, vm->string_proto, "search", fn_str_proto, 21);

    /* RegExp */
    js_define_native(vm, g, "RegExp", fn_regexp, 0);
    js_define_native(vm, vm->regex_proto, "test", fn_regexp, 1);
    js_define_native(vm, vm->regex_proto, "exec", fn_regexp, 2);

    /* Array */
    JsObj *arr_ctor = js_native_fn_new(vm, "Array", fn_array_ctor, 0);
    js_define_native(vm, arr_ctor, "isArray", fn_array_ctor, 1);
    js_define_native(vm, arr_ctor, "from", fn_array_ctor, 2);
    js_set_prop(vm, js_obj_val(g), "Array", js_obj_val(arr_ctor));
    js_define_native(vm, vm->array_proto, "push", fn_arr_proto, 0);
    js_define_native(vm, vm->array_proto, "pop", fn_arr_proto, 1);
    js_define_native(vm, vm->array_proto, "shift", fn_arr_proto, 2);
    js_define_native(vm, vm->array_proto, "unshift", fn_arr_proto, 3);
    js_define_native(vm, vm->array_proto, "slice", fn_arr_proto, 4);
    js_define_native(vm, vm->array_proto, "splice", fn_arr_proto, 5);
    js_define_native(vm, vm->array_proto, "concat", fn_arr_proto, 6);
    js_define_native(vm, vm->array_proto, "join", fn_arr_proto, 7);
    js_define_native(vm, vm->array_proto, "indexOf", fn_arr_proto, 8);
    js_define_native(vm, vm->array_proto, "includes", fn_arr_proto, 9);
    js_define_native(vm, vm->array_proto, "reverse", fn_arr_proto, 10);
    js_define_native(vm, vm->array_proto, "sort", fn_arr_proto, 11);
    js_define_native(vm, vm->array_proto, "forEach", fn_arr_proto, 12);
    js_define_native(vm, vm->array_proto, "map", fn_arr_proto, 13);
    js_define_native(vm, vm->array_proto, "filter", fn_arr_proto, 14);
    js_define_native(vm, vm->array_proto, "find", fn_arr_proto, 15);
    js_define_native(vm, vm->array_proto, "findIndex", fn_arr_proto, 16);
    js_define_native(vm, vm->array_proto, "some", fn_arr_proto, 17);
    js_define_native(vm, vm->array_proto, "every", fn_arr_proto, 18);
    js_define_native(vm, vm->array_proto, "reduce", fn_arr_proto, 19);

    /* Math */
    JsObj *math = js_map_new(vm, vm->object_proto);
    js_set_prop(vm, js_obj_val(math), "PI", js_num(3.14159265358979323846));
    js_set_prop(vm, js_obj_val(math), "E", js_num(2.71828182845904523536));
    js_define_native(vm, math, "abs", fn_math, 0);
    js_define_native(vm, math, "floor", fn_math, 1);
    js_define_native(vm, math, "ceil", fn_math, 2);
    js_define_native(vm, math, "round", fn_math, 3);
    js_define_native(vm, math, "trunc", fn_math, 4);
    js_define_native(vm, math, "sqrt", fn_math, 5);
    js_define_native(vm, math, "sin", fn_math, 6);
    js_define_native(vm, math, "cos", fn_math, 7);
    js_define_native(vm, math, "tan", fn_math, 8);
    js_define_native(vm, math, "log", fn_math, 9);
    js_define_native(vm, math, "log10", fn_math, 10);
    js_define_native(vm, math, "exp", fn_math, 11);
    js_define_native(vm, math, "pow", fn_math, 12);
    js_define_native(vm, math, "atan2", fn_math, 13);
    js_define_native(vm, math, "sign", fn_math, 14);
    js_define_native(vm, math, "random", fn_math, 20);
    js_define_native(vm, math, "min", fn_math, 21);
    js_define_native(vm, math, "max", fn_math, 22);
    js_set_prop(vm, js_obj_val(g), "Math", js_obj_val(math));

    /* Date */
    JsObj *date_obj = js_native_fn_new(vm, "Date", fn_date, 1);
    js_define_native(vm, date_obj, "now", fn_date, 0);
    js_set_prop(vm, js_obj_val(g), "Date", js_obj_val(date_obj));

    /* JSON */
    JsObj *json = js_map_new(vm, vm->object_proto);
    js_define_native(vm, json, "parse", fn_json, 0);
    js_define_native(vm, json, "stringify", fn_json, 1);
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
    js_define_native(vm, tb_obj, "gc", fn_global_misc, 13);
    js_set_prop(vm, js_obj_val(g), "tb", js_obj_val(tb_obj));
}
