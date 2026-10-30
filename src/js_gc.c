#define _GNU_SOURCE
#include "js.h"

#include <math.h>
#include <stdlib.h>
#include <time.h>

int64_t js_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000LL + (int64_t)(ts.tv_nsec / 1000000LL);
}

static void emergency_gc_cb(void *userdata) {
    JsVm *vm = (JsVm *)userdata;
    if (vm && vm->gc_pause == 0) {
        js_gc_collect(vm);
    }
}

void js_log(JsVm *vm, JsLogLevel level, const char *fmt, ...) {
    if (!vm || !vm->on_console) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    vm->on_console(vm->host_userdata, level, buf);
}

void js_throw_str(JsVm *vm, const char *msg) {
    if (!vm) return;
    snprintf(vm->last_error, sizeof(vm->last_error), "%s", msg ? msg : "Error");
    vm->gc_pause++;
    JsObj *err = js_map_new(vm, vm->object_proto);
    JsStr *ms  = js_str_cstr(vm, vm->last_error);
    if (err && ms) {
        js_set_prop(vm, js_obj_val(err), "message", js_obj_val((JsObj *)ms));
        js_set_prop(vm, js_obj_val(err), "name", js_obj_val((JsObj *)js_str_cstr(vm, "Error")));
        vm->thrown_val = js_obj_val(err);
    } else if (ms) {
        vm->thrown_val = js_obj_val((JsObj *)ms);
    } else {
        vm->thrown_val = js_undefined();
    }
    vm->gc_pause--;
    vm->has_thrown = true;
}

JsObj *js_gc_alloc(JsVm *vm, size_t size, JsObjType type) {
    if (!vm || vm->gc_bytes + size > vm->gc_max_bytes) {
        if (vm && vm->gc_pause == 0) {
            js_gc_collect(vm);
        }
        if (!vm || vm->gc_bytes + size > vm->gc_max_bytes) {
            return NULL;
        }
    }
    JsObj *o = (JsObj *)tb_calloc(1, size);
    if (!o) return NULL;
    o->obj_type   = (uint8_t)type;
    o->alloc_size = (uint32_t)size;
    o->gc_next    = vm->gc_objects;
    vm->gc_objects = o;
    vm->gc_bytes  += size;
    vm->gc_obj_count++;
    return o;
}

JsStr *js_str_new(JsVm *vm, const char *s, size_t len) {
    if (!s) { s = ""; len = 0; }
    JsStr *st = (JsStr *)js_gc_alloc(vm, sizeof(JsStr) + len + 1, OBJ_STRING);
    if (!st) return NULL;
    st->len = (uint32_t)len;
    if (len > 0) memcpy(st->data, s, len);
    st->data[len] = '\0';
    st->hash = tb_fnv1a(st->data, len);
    return st;
}

JsStr *js_str_cstr(JsVm *vm, const char *s) {
    return js_str_new(vm, s ? s : "", s ? strlen(s) : 0);
}

JsObj *js_map_new(JsVm *vm, JsObj *proto) {
    JsMapObj *m = (JsMapObj *)js_gc_alloc(vm, sizeof(JsMapObj), OBJ_OBJECT);
    if (!m) return NULL;
    m->proto = proto;
    return (JsObj *)m;
}

JsObj *js_arr_new(JsVm *vm, uint32_t cap) {
    JsArrObj *a = (JsArrObj *)js_gc_alloc(vm, sizeof(JsArrObj), OBJ_ARRAY);
    if (!a) return NULL;
    a->proto = vm->array_proto;
    if (cap > 0) {
        JsVal *it = (JsVal *)tb_calloc(cap, sizeof(JsVal));
        if (it) {
            a->items = it;
            a->cap   = cap;
            vm->gc_bytes += cap * sizeof(JsVal);
        }
    }
    return (JsObj *)a;
}

JsObj *js_func_new(JsVm *vm, JsChunk *chunk, uint32_t ast_idx, JsEnv *closure, bool is_arrow) {
    JsFuncObj *f = (JsFuncObj *)js_gc_alloc(vm, sizeof(JsFuncObj), OBJ_FUNC);
    if (!f) return NULL;
    f->proto    = vm->func_proto;
    f->chunk    = chunk;
    f->ast_idx  = ast_idx;
    f->closure  = closure;
    f->is_arrow = is_arrow;
    return (JsObj *)f;
}

JsObj *js_native_fn_new(JsVm *vm, const char *name, JsNativeFn fn, int magic) {
    JsNativeFnObj *nf = (JsNativeFnObj *)js_gc_alloc(vm, sizeof(JsNativeFnObj), OBJ_NATIVE_FN);
    if (!nf) return NULL;
    nf->proto = vm->func_proto;
    nf->fn    = fn;
    nf->magic = magic;
    if (name) snprintf(nf->name, sizeof(nf->name), "%s", name);
    return (JsObj *)nf;
}

JsObj *js_regex_new(JsVm *vm, const char *pattern, const char *flags) {
    JsRegexObj *rx = (JsRegexObj *)js_gc_alloc(vm, sizeof(JsRegexObj), OBJ_REGEX);
    if (!rx) return NULL;
    rx->proto   = vm->regex_proto;
    rx->pattern = tb_strdup(pattern ? pattern : "");
    rx->flags   = tb_strdup(flags ? flags : "");
    vm->gc_bytes += (rx->pattern ? strlen(rx->pattern) + 1 : 0) +
                    (rx->flags ? strlen(rx->flags) + 1 : 0);
    return (JsObj *)rx;
}

JsEnv *js_env_new(JsVm *vm, JsEnv *parent, bool is_func_scope, bool has_this, JsVal this_val) {
    JsEnv *e = (JsEnv *)js_gc_alloc(vm, sizeof(JsEnv), OBJ_ENV);
    if (!e) return NULL;
    e->parent        = parent;
    e->is_func_scope = is_func_scope;
    e->has_this      = has_this;
    e->this_val      = this_val;
    return e;
}

static bool str_eq(const JsStr *a, const JsStr *b) {
    if (a == b) return true;
    if (!a || !b || a->hash != b->hash || a->len != b->len) return false;
    return memcmp(a->data, b->data, a->len) == 0;
}

static bool parse_array_index(const char *s, uint32_t len, uint32_t *out_idx) {
    if (len == 0 || len > 10) return false;
    if (len > 1 && s[0] == '0') return false;
    uint64_t v = 0;
    for (uint32_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    if (v >= 0xFFFFFFFEULL) return false;
    *out_idx = (uint32_t)v;
    return true;
}

static bool map_find_own(const JsMapObj *m, const JsStr *key, uint32_t *out_pos) {
    for (uint32_t i = 0; i < m->count; i++) {
        if (str_eq(m->props[i].key, key)) {
            if (out_pos) *out_pos = i;
            return true;
        }
    }
    return false;
}

static bool map_set_own(JsVm *vm, JsMapObj *m, JsStr *key, JsVal val) {
    uint32_t pos = 0;
    if (map_find_own(m, key, &pos)) {
        m->props[pos].val = val;
        return true;
    }
    if (m->count >= m->cap) {
        uint32_t old_cap = m->cap;
        uint32_t ncap    = old_cap ? old_cap * 2 : 4;
        JsProp *np       = (JsProp *)tb_realloc(m->props, ncap * sizeof(JsProp));
        if (!np) return false;
        m->props = np;
        m->cap   = ncap;
        vm->gc_bytes += (ncap - old_cap) * sizeof(JsProp);
    }
    m->props[m->count].key = key;
    m->props[m->count].val = val;
    m->count++;
    return true;
}

void js_define_native(JsVm *vm, JsObj *target, const char *name, JsNativeFn fn, int magic) {
    if (!vm || !target) return;
    vm->gc_pause++;
    if (target->obj_type == OBJ_NATIVE_FN) {
        JsNativeFnObj *nf = (JsNativeFnObj *)target;
        if (!nf->props_obj) nf->props_obj = js_map_new(vm, NULL);
        target = nf->props_obj;
    }
    if (target && target->obj_type == OBJ_OBJECT) {
        JsStr *k   = js_str_cstr(vm, name);
        JsObj *nfn = js_native_fn_new(vm, name, fn, magic);
        if (k && nfn) {
            map_set_own(vm, (JsMapObj *)target, k, js_obj_val(nfn));
        }
    }
    vm->gc_pause--;
}

void js_arr_push(JsVm *vm, JsObj *arr_obj, JsVal val) {
    if (!arr_obj || arr_obj->obj_type != OBJ_ARRAY) return;
    JsArrObj *a = (JsArrObj *)arr_obj;
    if (a->len >= a->cap) {
        uint32_t old_cap = a->cap;
        uint32_t ncap    = old_cap ? old_cap * 2 : 8;
        JsVal *ni        = (JsVal *)tb_realloc(a->items, ncap * sizeof(JsVal));
        if (!ni) return;
        a->items = ni;
        a->cap   = ncap;
        vm->gc_bytes += (ncap - old_cap) * sizeof(JsVal);
    }
    a->items[a->len++] = val;
}

JsVal js_get_index(JsVm *vm, JsVal target, uint32_t idx) {
    if (target.type == JS_OBJECT && target.u.obj) {
        JsObj *o = target.u.obj;
        if (o->obj_type == OBJ_ARRAY) {
            JsArrObj *a = (JsArrObj *)o;
            return (idx < a->len) ? a->items[idx] : js_undefined();
        }
        if (o->obj_type == OBJ_STRING) {
            JsStr *s = (JsStr *)o;
            if (idx < s->len) {
                JsStr *ch = js_str_new(vm, s->data + idx, 1);
                return ch ? js_obj_val((JsObj *)ch) : js_undefined();
            }
            return js_undefined();
        }
    }
    char kbuf[16];
    snprintf(kbuf, sizeof(kbuf), "%u", idx);
    return js_get_prop(vm, target, kbuf);
}

bool js_set_index(JsVm *vm, JsVal target, uint32_t idx, JsVal val) {
    if (target.type == JS_OBJECT && target.u.obj && target.u.obj->obj_type == OBJ_ARRAY) {
        JsArrObj *a = (JsArrObj *)target.u.obj;
        if (idx > 65536) return false; /* Guard against sparse array memory bombs */
        if (idx >= a->cap) {
            uint32_t old_cap = a->cap;
            uint32_t ncap    = old_cap ? old_cap * 2 : 8;
            while (ncap <= idx) ncap *= 2;
            JsVal *ni = (JsVal *)tb_realloc(a->items, ncap * sizeof(JsVal));
            if (!ni) return false;
            for (uint32_t i = old_cap; i < ncap; i++) ni[i] = js_undefined();
            a->items = ni;
            a->cap   = ncap;
            vm->gc_bytes += (ncap - old_cap) * sizeof(JsVal);
        }
        for (uint32_t i = a->len; i < idx; i++) a->items[i] = js_undefined();
        a->items[idx] = val;
        if (idx >= a->len) a->len = idx + 1;
        return true;
    }
    char kbuf[16];
    snprintf(kbuf, sizeof(kbuf), "%u", idx);
    return js_set_prop(vm, target, kbuf, val);
}

JsVal js_get_prop_str(JsVm *vm, JsVal target, JsStr *key) {
    if (!key) return js_undefined();
    if (target.type == JS_UNDEFINED || target.type == JS_NULL) {
        char msg[128];
        snprintf(msg, sizeof(msg), "TypeError: Cannot read properties of %s (reading '%s')",
                 target.type == JS_NULL ? "null" : "undefined", key->data);
        js_throw_str(vm, msg);
        return js_undefined();
    }

    JsObj *proto_walk = NULL;
    if (target.type == JS_NUMBER) {
        proto_walk = vm->number_proto;
    } else if (target.type == JS_BOOL) {
        proto_walk = vm->bool_proto;
    } else if (target.type == JS_OBJECT && target.u.obj) {
        JsObj *o = target.u.obj;
        if (o->obj_type == OBJ_STRING) {
            JsStr *s = (JsStr *)o;
            if (strcmp(key->data, "length") == 0) return js_num((double)s->len);
            uint32_t idx = 0;
            if (parse_array_index(key->data, key->len, &idx)) {
                return (idx < s->len) ? js_obj_val((JsObj *)js_str_new(vm, s->data + idx, 1))
                                      : js_undefined();
            }
            proto_walk = vm->string_proto;
        } else if (o->obj_type == OBJ_ARRAY) {
            JsArrObj *a = (JsArrObj *)o;
            if (strcmp(key->data, "length") == 0) return js_num((double)a->len);
            uint32_t idx = 0;
            if (parse_array_index(key->data, key->len, &idx)) {
                return (idx < a->len) ? a->items[idx] : js_undefined();
            }
            proto_walk = a->proto;
        } else if (o->obj_type == OBJ_FUNC) {
            JsFuncObj *f = (JsFuncObj *)o;
            if (strcmp(key->data, "prototype") == 0) {
                if (!f->func_prototype) {
                    vm->gc_pause++;
                    f->func_prototype = js_map_new(vm, vm->object_proto);
                    if (f->func_prototype) {
                        js_set_prop(vm, js_obj_val(f->func_prototype), "constructor", target);
                    }
                    vm->gc_pause--;
                }
                return js_obj_val(f->func_prototype);
            }
            proto_walk = f->proto;
        } else if (o->obj_type == OBJ_NATIVE_FN) {
            JsNativeFnObj *nf = (JsNativeFnObj *)o;
            if (nf->props_obj && nf->props_obj->obj_type == OBJ_OBJECT) {
                uint32_t pos = 0;
                JsMapObj *pm = (JsMapObj *)nf->props_obj;
                if (map_find_own(pm, key, &pos)) return pm->props[pos].val;
            }
            if (strcmp(key->data, "name") == 0) {
                return js_obj_val((JsObj *)js_str_cstr(vm, nf->name));
            }
            proto_walk = nf->proto;
        } else if (o->obj_type == OBJ_REGEX) {
            JsRegexObj *rx = (JsRegexObj *)o;
            if (strcmp(key->data, "source") == 0)
                return js_obj_val((JsObj *)js_str_cstr(vm, rx->pattern));
            if (strcmp(key->data, "flags") == 0)
                return js_obj_val((JsObj *)js_str_cstr(vm, rx->flags));
            proto_walk = rx->proto;
        } else if (o->obj_type == OBJ_OBJECT) {
            JsMapObj *m = (JsMapObj *)o;
            if (m->hdr.native_tag != NATIVE_TAG_NONE) {
                JsVal vout = js_undefined();
                if (js_dom_get_virtual(vm, m, key->data, &vout)) return vout;
            }
            if (strcmp(key->data, "__proto__") == 0) return js_obj_val(m->proto);
            uint32_t pos = 0;
            if (map_find_own(m, key, &pos)) return m->props[pos].val;
            proto_walk = m->proto;
        }
    }

    int guard = 0;
    while (proto_walk && proto_walk->obj_type == OBJ_OBJECT && guard++ < 16) {
        JsMapObj *pm = (JsMapObj *)proto_walk;
        uint32_t pos = 0;
        if (map_find_own(pm, key, &pos)) return pm->props[pos].val;
        proto_walk = pm->proto;
    }
    return js_undefined();
}

JsVal js_get_prop(JsVm *vm, JsVal target, const char *key) {
    vm->gc_pause++;
    JsStr *ks = js_str_cstr(vm, key);
    vm->gc_pause--;
    if (!ks) return js_undefined();
    int saved_sp = vm->temp_sp;
    js_temp_push(vm, js_obj_val((JsObj *)ks));
    JsVal res = js_get_prop_str(vm, target, ks);
    vm->temp_sp = saved_sp;
    return res;
}

bool js_set_prop_str(JsVm *vm, JsVal target, JsStr *key, JsVal val) {
    if (!key || target.type != JS_OBJECT || !target.u.obj) return false;
    JsObj *o = target.u.obj;
    if (o->obj_type == OBJ_ARRAY) {
        JsArrObj *a = (JsArrObj *)o;
        if (strcmp(key->data, "length") == 0) {
            double nl = js_to_num(vm, val);
            uint32_t ulen = (nl >= 0 && nl <= (double)a->len) ? (uint32_t)nl : 0;
            if (nl >= 0 && ulen <= a->len) a->len = ulen;
            return true;
        }
        uint32_t idx = 0;
        if (parse_array_index(key->data, key->len, &idx)) {
            return js_set_index(vm, target, idx, val);
        }
        return false;
    }
    if (o->obj_type == OBJ_FUNC) {
        JsFuncObj *f = (JsFuncObj *)o;
        if (strcmp(key->data, "prototype") == 0 && val.type == JS_OBJECT) {
            f->func_prototype = val.u.obj;
            return true;
        }
        return false;
    }
    if (o->obj_type != OBJ_OBJECT) return false;

    JsMapObj *m = (JsMapObj *)o;
    if (m->hdr.native_tag != NATIVE_TAG_NONE) {
        if (js_dom_set_virtual(vm, m, key->data, val)) return true;
    }
    if (strcmp(key->data, "__proto__") == 0) {
        if (val.type == JS_OBJECT) m->proto = val.u.obj;
        else if (val.type == JS_NULL) m->proto = NULL;
        return true;
    }
    return map_set_own(vm, m, key, val);
}

bool js_set_prop(JsVm *vm, JsVal target, const char *key, JsVal val) {
    vm->gc_pause++;
    JsStr *ks = js_str_cstr(vm, key);
    bool ok   = ks ? js_set_prop_str(vm, target, ks, val) : false;
    vm->gc_pause--;
    return ok;
}

bool js_del_prop_str(JsVm *vm, JsVal target, JsStr *key) {
    (void)vm;
    if (!key || target.type != JS_OBJECT || !target.u.obj) return true;
    if (target.u.obj->obj_type == OBJ_ARRAY) {
        uint32_t idx = 0;
        JsArrObj *a = (JsArrObj *)target.u.obj;
        if (parse_array_index(key->data, key->len, &idx) && idx < a->len) {
            a->items[idx] = js_undefined();
        }
        return true;
    }
    if (target.u.obj->obj_type != OBJ_OBJECT) return true;
    JsMapObj *m = (JsMapObj *)target.u.obj;
    uint32_t pos = 0;
    if (map_find_own(m, key, &pos)) {
        for (uint32_t i = pos; i + 1 < m->count; i++) m->props[i] = m->props[i + 1];
        m->count--;
    }
    return true;
}

bool js_has_prop_str(JsVm *vm, JsVal target, JsStr *key) {
    if (!key || target.type != JS_OBJECT || !target.u.obj) return false;
    JsObj *o = target.u.obj;
    if (o->obj_type == OBJ_ARRAY) {
        JsArrObj *a = (JsArrObj *)o;
        if (strcmp(key->data, "length") == 0) return true;
        uint32_t idx = 0;
        if (parse_array_index(key->data, key->len, &idx)) return idx < a->len;
        o = a->proto;
    }
    int guard = 0;
    while (o && o->obj_type == OBJ_OBJECT && guard++ < 16) {
        JsMapObj *m = (JsMapObj *)o;
        if (m->hdr.native_tag != NATIVE_TAG_NONE) {
            JsVal dummy;
            if (js_dom_get_virtual(vm, m, key->data, &dummy)) return true;
        }
        if (map_find_own(m, key, NULL)) return true;
        o = m->proto;
    }
    return false;
}

/* Lexical Environments */
bool js_env_define(JsVm *vm, JsEnv *env, JsStr *name, JsVal val, uint16_t decl_kind) {
    if (!env || !name) return false;
    JsEnv *target = env;
    if (decl_kind == DECL_VAR) {
        while (target->parent && !target->is_func_scope) target = target->parent;
    }
    for (uint16_t i = 0; i < target->count; i++) {
        if (str_eq(target->vars[i].name, name)) {
            target->vars[i].val = val;
            if (target == vm->global_env && decl_kind == DECL_VAR) {
                map_set_own(vm, (JsMapObj *)vm->global_obj, name, val);
            }
            return true;
        }
    }
    if (target->count >= target->cap) {
        uint16_t old_cap = target->cap;
        uint16_t ncap    = old_cap ? (uint16_t)(old_cap * 2) : 4;
        JsEnvVar *nv     = (JsEnvVar *)tb_realloc(target->vars, ncap * sizeof(JsEnvVar));
        if (!nv) return false;
        target->vars = nv;
        target->cap  = ncap;
        vm->gc_bytes += (ncap - old_cap) * sizeof(JsEnvVar);
    }
    target->vars[target->count].name     = name;
    target->vars[target->count].val      = val;
    target->vars[target->count].is_const = (decl_kind == DECL_CONST);
    target->count++;

    if (target == vm->global_env && decl_kind == DECL_VAR) {
        map_set_own(vm, (JsMapObj *)vm->global_obj, name, val);
    }
    return true;
}

bool js_env_lookup(JsVm *vm, JsEnv *env, JsStr *name, JsVal *out) {
    for (JsEnv *e = env; e; e = e->parent) {
        for (uint16_t i = 0; i < e->count; i++) {
            if (str_eq(e->vars[i].name, name)) {
                *out = e->vars[i].val;
                return true;
            }
        }
    }
    if (js_has_prop_str(vm, js_obj_val(vm->global_obj), name)) {
        *out = js_get_prop_str(vm, js_obj_val(vm->global_obj), name);
        return true;
    }
    return false;
}

bool js_env_assign(JsVm *vm, JsEnv *env, JsStr *name, JsVal val) {
    for (JsEnv *e = env; e; e = e->parent) {
        for (uint16_t i = 0; i < e->count; i++) {
            if (str_eq(e->vars[i].name, name)) {
                if (e->vars[i].is_const) {
                    js_throw_str(vm, "TypeError: Assignment to constant variable");
                    return false;
                }
                e->vars[i].val = val;
                if (e == vm->global_env) {
                    map_set_own(vm, (JsMapObj *)vm->global_obj, name, val);
                }
                return true;
            }
        }
    }
    return map_set_own(vm, (JsMapObj *)vm->global_obj, name, val);
}

JsVal js_env_resolve_this(JsVm *vm, JsEnv *env) {
    for (JsEnv *e = env; e; e = e->parent) {
        if (e->has_this) return e->this_val;
    }
    return js_obj_val(vm->global_obj);
}

/* Coercions & Equality */
bool js_to_bool(JsVal v) {
    switch (v.type) {
        case JS_UNDEFINED:
        case JS_NULL:   return false;
        case JS_BOOL:   return v.u.boolean;
        case JS_NUMBER: return v.u.num != 0.0 && !isnan(v.u.num);
        case JS_OBJECT:
            if (!v.u.obj) return false;
            if (v.u.obj->obj_type == OBJ_STRING) return ((JsStr *)v.u.obj)->len > 0;
            return true;
    }
    return false;
}

double js_to_num(JsVm *vm, JsVal v) {
    (void)vm;
    switch (v.type) {
        case JS_UNDEFINED: return NAN;
        case JS_NULL:      return 0.0;
        case JS_BOOL:      return v.u.boolean ? 1.0 : 0.0;
        case JS_NUMBER:    return v.u.num;
        case JS_OBJECT: {
            if (!v.u.obj) return 0.0;
            if (v.u.obj->obj_type == OBJ_STRING) {
                const char *s = ((JsStr *)v.u.obj)->data;
                while (*s && tb_isspace(*s)) s++;
                if (!*s) return 0.0;
                char *endp = NULL;
                double d   = strtod(s, &endp);
                while (endp && *endp && tb_isspace(*endp)) endp++;
                return (endp && *endp == '\0') ? d : NAN;
            }
            if (v.u.obj->obj_type == OBJ_ARRAY) {
                JsArrObj *a = (JsArrObj *)v.u.obj;
                if (a->len == 0) return 0.0;
                if (a->len == 1) return js_to_num(vm, a->items[0]);
            }
            return NAN;
        }
    }
    return NAN;
}

JsStr *js_to_str(JsVm *vm, JsVal v) {
    switch (v.type) {
        case JS_UNDEFINED: return js_str_cstr(vm, "undefined");
        case JS_NULL:      return js_str_cstr(vm, "null");
        case JS_BOOL:      return js_str_cstr(vm, v.u.boolean ? "true" : "false");
        case JS_NUMBER: {
            if (isnan(v.u.num)) return js_str_cstr(vm, "NaN");
            if (isinf(v.u.num)) return js_str_cstr(vm, v.u.num < 0 ? "-Infinity" : "Infinity");
            if (v.u.num == 0.0) return js_str_cstr(vm, "0");
            char buf[64];
            snprintf(buf, sizeof(buf), "%.15g", v.u.num);
            return js_str_cstr(vm, buf);
        }
        case JS_OBJECT: {
            if (!v.u.obj) return js_str_cstr(vm, "null");
            if (v.u.obj->obj_type == OBJ_STRING) return (JsStr *)v.u.obj;
            if (v.u.obj->obj_type == OBJ_ARRAY) {
                JsArrObj *a = (JsArrObj *)v.u.obj;
                TbBuf b;
                tb_buf_init(&b);
                for (uint32_t i = 0; i < a->len; i++) {
                    if (i > 0) tb_buf_append_char(&b, ',');
                    if (a->items[i].type != JS_UNDEFINED && a->items[i].type != JS_NULL) {
                        JsStr *is = js_to_str(vm, a->items[i]);
                        if (is) tb_buf_append(&b, is->data, is->len);
                    }
                }
                JsStr *res = js_str_new(vm, b.data ? b.data : "", b.len);
                tb_buf_free(&b);
                return res;
            }
            if (v.u.obj->obj_type == OBJ_OBJECT) {
                /* Check for Error object with .message */
                JsMapObj *m = (JsMapObj *)v.u.obj;
                JsStr *msg_k = js_str_cstr(vm, "message");
                uint32_t pos = 0;
                if (msg_k && map_find_own(m, msg_k, &pos) &&
                    m->props[pos].val.type == JS_OBJECT &&
                    m->props[pos].val.u.obj->obj_type == OBJ_STRING) {
                    return (JsStr *)m->props[pos].val.u.obj;
                }
                return js_str_cstr(vm, "[object Object]");
            }
            if (v.u.obj->obj_type == OBJ_REGEX) {
                JsRegexObj *rx = (JsRegexObj *)v.u.obj;
                TbBuf b;
                tb_buf_init(&b);
                tb_buf_printf(&b, "/%s/%s", rx->pattern, rx->flags);
                JsStr *res = js_str_new(vm, b.data, b.len);
                tb_buf_free(&b);
                return res;
            }
            return js_str_cstr(vm, "[Function]");
        }
    }
    return js_str_cstr(vm, "");
}

bool js_strict_eq(JsVal a, JsVal b) {
    if (a.type != b.type) return false;
    switch (a.type) {
        case JS_UNDEFINED:
        case JS_NULL:   return true;
        case JS_BOOL:   return a.u.boolean == b.u.boolean;
        case JS_NUMBER: return a.u.num == b.u.num; /* NaN == NaN is false */
        case JS_OBJECT:
            if (a.u.obj == b.u.obj) return true;
            if (a.u.obj && b.u.obj &&
                a.u.obj->obj_type == OBJ_STRING && b.u.obj->obj_type == OBJ_STRING) {
                return str_eq((const JsStr *)a.u.obj, (const JsStr *)b.u.obj);
            }
            return false;
    }
    return false;
}

bool js_loose_eq(JsVm *vm, JsVal a, JsVal b) {
    if (a.type == b.type) return js_strict_eq(a, b);
    if ((a.type == JS_NULL && b.type == JS_UNDEFINED) ||
        (a.type == JS_UNDEFINED && b.type == JS_NULL)) {
        return true;
    }
    if (a.type == JS_NUMBER || b.type == JS_NUMBER || a.type == JS_BOOL || b.type == JS_BOOL) {
        return js_to_num(vm, a) == js_to_num(vm, b);
    }
    return false;
}

void js_val_format(JsVm *vm, JsVal v, TbBuf *out, int depth) {
    if (depth > 3) {
        tb_buf_append_cstr(out, "[...]");
        return;
    }
    if (v.type == JS_OBJECT && v.u.obj) {
        if (v.u.obj->obj_type == OBJ_STRING) {
            JsStr *s = (JsStr *)v.u.obj;
            if (depth == 0) tb_buf_append(out, s->data, s->len);
            else tb_buf_printf(out, "'%s'", s->data);
            return;
        }
        if (v.u.obj->obj_type == OBJ_ARRAY) {
            JsArrObj *a = (JsArrObj *)v.u.obj;
            tb_buf_append_char(out, '[');
            for (uint32_t i = 0; i < a->len && i < 20; i++) {
                if (i > 0) tb_buf_append_cstr(out, ", ");
                js_val_format(vm, a->items[i], out, depth + 1);
            }
            if (a->len > 20) tb_buf_printf(out, ", ... +%u more", a->len - 20);
            tb_buf_append_char(out, ']');
            return;
        }
        if (v.u.obj->obj_type == OBJ_OBJECT) {
            JsMapObj *m = (JsMapObj *)v.u.obj;
            if (m->hdr.native_tag == NATIVE_TAG_DOM_NODE && m->native_ptr) {
                DomNode *dn = (DomNode *)m->native_ptr;
                const char *id = dom_get_attr(dn, "id");
                if (id) tb_buf_printf(out, "<%s#%s>", dom_node_tag_name(dn), id);
                else tb_buf_printf(out, "<%s>", dom_node_tag_name(dn));
                return;
            }
            tb_buf_append_cstr(out, "{ ");
            for (uint32_t i = 0; i < m->count && i < 12; i++) {
                if (i > 0) tb_buf_append_cstr(out, ", ");
                tb_buf_printf(out, "%s: ", m->props[i].key->data);
                js_val_format(vm, m->props[i].val, out, depth + 1);
            }
            if (m->count > 12) tb_buf_append_cstr(out, ", ...");
            tb_buf_append_cstr(out, " }");
            return;
        }
    }
    JsStr *s = js_to_str(vm, v);
    if (s) tb_buf_append(out, s->data, s->len);
}

/* Mark-and-Sweep Garbage Collector */
static void gc_mark_obj(JsVm *vm, JsObj *o);

static void gc_mark_val(JsVm *vm, JsVal v) {
    if (v.type == JS_OBJECT && v.u.obj) {
        gc_mark_obj(vm, v.u.obj);
    }
}

static void gc_mark_obj(JsVm *vm, JsObj *o) {
    if (!o || o->gc_mark) return;
    o->gc_mark = 1;

    switch (o->obj_type) {
        case OBJ_STRING:
            break;
        case OBJ_OBJECT: {
            JsMapObj *m = (JsMapObj *)o;
            gc_mark_obj(vm, m->proto);
            for (uint32_t i = 0; i < m->count; i++) {
                gc_mark_obj(vm, (JsObj *)m->props[i].key);
                gc_mark_val(vm, m->props[i].val);
            }
            /* If this is a detached DOM node wrapper, mark connected detached subtree wrappers */
            if (m->hdr.native_tag == NATIVE_TAG_DOM_NODE && m->native_ptr) {
                DomNode *n = (DomNode *)m->native_ptr;
                while (n->parent) n = n->parent;
                if (!vm->doc || n != vm->doc->root) {
                    /* Walk detached tree via simple parent/child/sibling traversal */
                    DomNode *cur = n;
                    while (cur) {
                        if (cur->js_wrapper) gc_mark_obj(vm, (JsObj *)cur->js_wrapper);
                        for (DomListener *ls = cur->listeners; ls; ls = ls->next) {
                            gc_mark_obj(vm, (JsObj *)ls->js_fn);
                        }
                        if (cur->first_child) {
                            cur = cur->first_child;
                        } else {
                            while (cur && !cur->next_sibling && cur != n) cur = cur->parent;
                            cur = (cur && cur != n) ? cur->next_sibling : NULL;
                        }
                    }
                }
            }
            break;
        }
        case OBJ_ARRAY: {
            JsArrObj *a = (JsArrObj *)o;
            gc_mark_obj(vm, a->proto);
            for (uint32_t i = 0; i < a->len; i++) gc_mark_val(vm, a->items[i]);
            break;
        }
        case OBJ_FUNC: {
            JsFuncObj *f = (JsFuncObj *)o;
            gc_mark_obj(vm, f->proto);
            gc_mark_obj(vm, f->func_prototype);
            gc_mark_obj(vm, (JsObj *)f->closure);
            if (f->has_bound_this) gc_mark_val(vm, f->bound_this);
            if (f->chunk) f->chunk->gc_mark = 1;
            break;
        }
        case OBJ_NATIVE_FN: {
            JsNativeFnObj *nf = (JsNativeFnObj *)o;
            gc_mark_obj(vm, nf->proto);
            gc_mark_obj(vm, nf->props_obj);
            break;
        }
        case OBJ_REGEX: {
            JsRegexObj *rx = (JsRegexObj *)o;
            gc_mark_obj(vm, rx->proto);
            break;
        }
        case OBJ_ENV: {
            JsEnv *e = (JsEnv *)o;
            gc_mark_obj(vm, (JsObj *)e->parent);
            if (e->has_this) gc_mark_val(vm, e->this_val);
            for (uint16_t i = 0; i < e->count; i++) {
                gc_mark_obj(vm, (JsObj *)e->vars[i].name);
                gc_mark_val(vm, e->vars[i].val);
            }
            break;
        }
    }
}

static void gc_free_obj(JsVm *vm, JsObj *o, bool vm_teardown) {
    size_t extra = 0;
    switch (o->obj_type) {
        case OBJ_OBJECT: {
            JsMapObj *m = (JsMapObj *)o;
            if (!vm_teardown && m->hdr.native_tag == NATIVE_TAG_DOM_NODE) {
                js_dom_on_wrapper_swept(m);
            }
            extra += m->cap * sizeof(JsProp);
            tb_free(m->props);
            break;
        }
        case OBJ_ARRAY: {
            JsArrObj *a = (JsArrObj *)o;
            extra += a->cap * sizeof(JsVal);
            tb_free(a->items);
            break;
        }
        case OBJ_REGEX: {
            JsRegexObj *rx = (JsRegexObj *)o;
            extra += (rx->pattern ? strlen(rx->pattern) + 1 : 0) +
                     (rx->flags ? strlen(rx->flags) + 1 : 0);
            tb_free(rx->pattern);
            tb_free(rx->flags);
            break;
        }
        case OBJ_ENV: {
            JsEnv *e = (JsEnv *)o;
            extra += e->cap * sizeof(JsEnvVar);
            tb_free(e->vars);
            break;
        }
        default:
            break;
    }
    size_t total = o->alloc_size + extra;
    if (vm->gc_bytes >= total) vm->gc_bytes -= total;
    else vm->gc_bytes = 0;
    if (vm->gc_obj_count > 0) vm->gc_obj_count--;
    tb_free(o);
}

size_t js_gc_collect(JsVm *vm) {
    if (!vm || vm->gc_pause > 0) return 0;
    vm->gc_pause++;

    /* 1. Clear marks on chunks */
    for (JsChunk *c = vm->chunks; c; c = c->gc_next) {
        c->gc_mark = c->pinned;
    }

    /* 2. Mark VM roots */
    gc_mark_obj(vm, vm->global_obj);
    gc_mark_obj(vm, (JsObj *)vm->global_env);
    gc_mark_obj(vm, vm->object_proto);
    gc_mark_obj(vm, vm->array_proto);
    gc_mark_obj(vm, vm->string_proto);
    gc_mark_obj(vm, vm->number_proto);
    gc_mark_obj(vm, vm->bool_proto);
    gc_mark_obj(vm, vm->func_proto);
    gc_mark_obj(vm, vm->regex_proto);
    gc_mark_obj(vm, vm->elem_proto);
    gc_mark_obj(vm, vm->doc_obj);

    for (int i = 0; i < vm->env_sp; i++) gc_mark_obj(vm, (JsObj *)vm->env_stack[i]);
    for (int i = 0; i < vm->temp_sp; i++) gc_mark_val(vm, vm->temp_roots[i]);
    if (vm->has_thrown) gc_mark_val(vm, vm->thrown_val);

    for (int i = 0; i < JS_MAX_TIMERS; i++) {
        if (vm->timers[i].active && vm->timers[i].fn_obj) {
            gc_mark_obj(vm, vm->timers[i].fn_obj);
        }
    }
    js_gc_mark_dom(vm, gc_mark_obj);

    /* 3. Sweep unmarked objects */
    size_t swept = 0;
    JsObj **prev = &vm->gc_objects;
    JsObj *cur   = vm->gc_objects;
    while (cur) {
        if (cur->gc_mark) {
            cur->gc_mark = 0;
            prev = &cur->gc_next;
            cur  = cur->gc_next;
        } else {
            JsObj *dead = cur;
            cur   = cur->gc_next;
            *prev = cur;
            gc_free_obj(vm, dead, false);
            swept++;
        }
    }

    /* 4. Sweep unreferenced & unpinned AST chunks */
    JsChunk **cprev = &vm->chunks;
    JsChunk *ccur   = vm->chunks;
    while (ccur) {
        if (ccur->gc_mark || ccur->pinned) {
            ccur->gc_mark = 0;
            cprev = &ccur->gc_next;
            ccur  = ccur->gc_next;
        } else {
            JsChunk *deadc = ccur;
            ccur   = ccur->gc_next;
            *cprev = ccur;
            js_chunk_free(vm, deadc);
        }
    }

    size_t next_thresh = vm->gc_bytes * 2;
    if (next_thresh < JS_INITIAL_GC_THRESHOLD) next_thresh = JS_INITIAL_GC_THRESHOLD;
    if (next_thresh > JS_MAX_HEAP_BYTES) next_thresh = JS_MAX_HEAP_BYTES;
    vm->gc_threshold = next_thresh;

    vm->gc_pause--;
    return swept;
}

JsVm *js_vm_new(void) {
    JsVm *vm = (JsVm *)tb_calloc(1, sizeof(JsVm));
    if (!vm) return NULL;
    vm->gc_threshold  = JS_INITIAL_GC_THRESHOLD;
    vm->gc_max_bytes  = JS_MAX_HEAP_BYTES;
    vm->step_limit    = JS_DEFAULT_STEP_LIMIT;
    vm->boot_ms       = js_now_ms();
    vm->next_timer_id = 1;

    vm->gc_pause = 1;
    vm->object_proto = js_map_new(vm, NULL);
    vm->func_proto   = js_map_new(vm, vm->object_proto);
    vm->array_proto  = js_map_new(vm, vm->object_proto);
    vm->string_proto = js_map_new(vm, vm->object_proto);
    vm->number_proto = js_map_new(vm, vm->object_proto);
    vm->bool_proto   = js_map_new(vm, vm->object_proto);
    vm->regex_proto  = js_map_new(vm, vm->object_proto);
    vm->elem_proto   = js_map_new(vm, vm->object_proto);
    vm->global_obj   = js_map_new(vm, vm->object_proto);
    vm->global_env   = js_env_new(vm, NULL, true, true, js_obj_val(vm->global_obj));

    js_stdlib_init(vm);
    vm->gc_pause = 0;

    tb_mem_set_gc_hook(emergency_gc_cb, vm);
    return vm;
}

void js_vm_free(JsVm *vm) {
    if (!vm) return;
    tb_mem_set_gc_hook(NULL, NULL);
    if (vm->doc && vm->doc->userdata == vm) {
        vm->doc->on_node_destroy = NULL;
        vm->doc->userdata        = NULL;
    }

    JsObj *o = vm->gc_objects;
    while (o) {
        JsObj *next = o->gc_next;
        gc_free_obj(vm, o, true);
        o = next;
    }
    JsChunk *c = vm->chunks;
    while (c) {
        JsChunk *next = c->gc_next;
        js_chunk_free(vm, c);
        c = next;
    }
    tb_free(vm);
}
