#include "js.h"
#include "math_tb.h"

/* ============================================================================
 * JSON.parse & JSON.stringify (RFC 8259)
 * ============================================================================ */

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

JsVal js_fn_json(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    if (magic == JSON_PARSE) {
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
    /* JSON_STRINGIFY */
    if (argc == 0) return js_undefined();
    TbBuf b;
    tb_buf_init(&b);
    if (!json_stringify_rec(vm, argv[0], &b, 0)) {
        tb_buf_free(&b);
        return js_undefined();
    }
    JsStr *str = js_str_new(vm, b.data ? b.data : "", b.len);
    tb_buf_free(&b);
    return str ? js_obj_val((JsObj *)str) : js_undefined();
}
