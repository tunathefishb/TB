#include "js.h"
#include "net.h"

static void on_dom_node_destroy(void *userdata, DomNode *node) {
    JsVm *vm = (JsVm *)userdata;
    if (node && node->js_wrapper) {
        JsMapObj *m   = (JsMapObj *)node->js_wrapper;
        m->native_ptr = NULL;
        node->js_wrapper = NULL;
    }
    if (vm && vm->on_node_destroy) {
        vm->on_node_destroy(vm->host_userdata, node);
    }
}

void js_dom_on_wrapper_swept(JsMapObj *m) {
    if (!m || !m->native_ptr) return;
    DomNode *n = (DomNode *)m->native_ptr;
    m->native_ptr = NULL;
    if (n->js_wrapper == (void *)m) {
        n->js_wrapper = NULL;
    }
    DomNode *top = n;
    while (top->parent) top = top->parent;
    if (top->type == DOM_NODE_DOCUMENT) {
        return; /* Attached to live document: keep DomNode alive */
    }
    /* Orphan detached subtree: free once its last JS wrapper is swept */
    if (!dom_subtree_has_wrapper(top)) {
        dom_node_free(top);
    }
}

static void mark_attached_dom_rec(JsVm *vm, const DomNode *n, void (*mark_obj)(JsVm *, JsObj *)) {
    if (!n) return;
    for (DomListener *ls = n->listeners; ls; ls = ls->next) {
        if (ls->js_fn) mark_obj(vm, (JsObj *)ls->js_fn);
    }
    if (n->js_wrapper) {
        JsMapObj *m = (JsMapObj *)n->js_wrapper;
        if (n->listeners != NULL || m->count > 0) {
            mark_obj(vm, (JsObj *)m);
        }
    }
    for (const DomNode *ch = n->first_child; ch; ch = ch->next_sibling) {
        mark_attached_dom_rec(vm, ch, mark_obj);
    }
}

void js_gc_mark_dom(JsVm *vm, void (*mark_obj)(JsVm *, JsObj *)) {
    if (!vm || !vm->doc || !vm->doc->root) return;
    mark_attached_dom_rec(vm, vm->doc->root, mark_obj);
}

static DomNode *unwrap_node(JsVal v) {
    if (v.type != JS_OBJECT || !v.u.obj || v.u.obj->obj_type != OBJ_OBJECT) return NULL;
    JsMapObj *m = (JsMapObj *)v.u.obj;
    if (m->hdr.native_tag == NATIVE_TAG_DOM_NODE ||
        m->hdr.native_tag == NATIVE_TAG_DOCUMENT ||
        m->hdr.native_tag == NATIVE_TAG_STYLE ||
        m->hdr.native_tag == NATIVE_TAG_CLASSLIST ||
        m->hdr.native_tag == NATIVE_TAG_DATASET) {
        return (DomNode *)m->native_ptr;
    }
    return NULL;
}

JsVal js_wrap_dom_node(JsVm *vm, DomNode *node) {
    if (!vm || !node) return js_null();
    if (vm->doc && node == vm->doc->root && vm->doc_obj) {
        return js_obj_val(vm->doc_obj);
    }
    if (node->js_wrapper) {
        return js_obj_val((JsObj *)node->js_wrapper);
    }
    vm->gc_pause++;
    JsMapObj *m = (JsMapObj *)js_map_new(vm, vm->elem_proto);
    if (m) {
        m->hdr.native_tag = NATIVE_TAG_DOM_NODE;
        m->native_ptr     = node;
        node->js_wrapper  = m;
    }
    vm->gc_pause--;
    return js_obj_val((JsObj *)m);
}

static void camel_to_kebab(const char *in, char *out, size_t cap) {
    if (strcmp(in, "cssFloat") == 0) {
        snprintf(out, cap, "float");
        return;
    }
    size_t w = 0;
    for (size_t r = 0; in[r] && w + 2 < cap; r++) {
        if (in[r] >= 'A' && in[r] <= 'Z') {
            out[w++] = '-';
            out[w++] = tb_tolower(in[r]);
        } else {
            out[w++] = in[r];
        }
    }
    out[w] = '\0';
}

/* classList methods */
typedef enum {
    CL_ADD = 0,
    CL_REMOVE,
    CL_TOGGLE,
    CL_CONTAINS
} JsClassListMagic;

static JsVal fn_classlist(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    DomNode *n = unwrap_node(this_val);
    if (!n) return magic >= CL_TOGGLE ? js_bool(false) : js_undefined();
    if (magic == CL_ADD) {
        for (int i = 0; i < argc; i++) {
            JsStr *s = js_to_str(vm, argv[i]);
            if (s) dom_class_add(n, s->data);
        }
        return js_undefined();
    }
    if (magic == CL_REMOVE) {
        for (int i = 0; i < argc; i++) {
            JsStr *s = js_to_str(vm, argv[i]);
            if (s) dom_class_remove(n, s->data);
        }
        return js_undefined();
    }
    if (magic == CL_TOGGLE) {
        if (argc == 0) return js_bool(false);
        JsStr *s  = js_to_str(vm, argv[0]);
        int force = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (js_to_bool(argv[1]) ? 1 : 0) : -1;
        return js_bool(s ? dom_class_toggle(n, s->data, force) : false);
    }
    /* CL_CONTAINS */
    if (argc == 0) return js_bool(false);
    JsStr *s = js_to_str(vm, argv[0]);
    return js_bool(s && dom_class_contains(n, s->data));
}

/* CSSStyleDeclaration methods: getPropertyValue(prop), setProperty(prop, val), removeProperty(prop) */
typedef enum {
    STYLE_GET_PROP_VAL = 0,
    STYLE_SET_PROP,
    STYLE_REMOVE_PROP
} JsStyleMagic;

static void color_to_css_str(CssColor c, bool is_bg, char *buf, size_t cap) {
    if (c.mode == CSS_COLOR_RGB) {
        snprintf(buf, cap, "rgb(%u, %u, %u)", (unsigned)c.r, (unsigned)c.g, (unsigned)c.b);
    } else {
        snprintf(buf, cap, "%s", is_bg ? "rgba(0, 0, 0, 0)" : "rgb(208, 208, 208)");
    }
}

static bool get_computed_style_prop(JsVm *vm, DomNode *n, const char *prop_in, JsVal *out) {
    if (!n) { *out = js_obj_val((JsObj *)js_str_cstr(vm, "")); return true; }
    char kebab[64];
    if (prop_in[0] == '-' && prop_in[1] == '-') {
        snprintf(kebab, sizeof(kebab), "%s", prop_in);
    } else {
        camel_to_kebab(prop_in, kebab, sizeof(kebab));
    }

    /* Custom property lookup across inline + ancestors, or stylesheet rules */
    if (kebab[0] == '-' && kebab[1] == '-') {
        for (DomNode *cur = n; cur; cur = cur->parent) {
            const char *inl = dom_get_attr(cur, "style");
            if (inl) {
                size_t klen = strlen(kebab);
                const char *p = inl;
                while (*p) {
                    while (*p && (tb_isspace(*p) || *p == ';')) p++;
                    if (strncmp(p, kebab, klen) == 0 && (p[klen] == ':' || tb_isspace(p[klen]))) {
                        const char *col = strchr(p + klen, ':');
                        if (col) {
                            col++;
                            while (*col && tb_isspace(*col)) col++;
                            const char *semi = strchr(col, ';');
                            size_t vlen = semi ? (size_t)(semi - col) : strlen(col);
                            while (vlen > 0 && tb_isspace(col[vlen - 1])) vlen--;
                            *out = js_obj_val((JsObj *)js_str_new(vm, col, vlen));
                            return true;
                        }
                    }
                    const char *semi = strchr(p, ';');
                    if (!semi) break;
                    p = semi + 1;
                }
            }
        }
    }

    /* Recompute document styles if needed so getComputedStyle reflects latest DOM/class/inline mutations */
    if (vm->doc) {
        css_compute_document_ex(vm->doc, NULL, vm->viewport_w > 0 ? vm->viewport_w : 80);
    }

    if (kebab[0] == '-' && kebab[1] == '-') {
        const char *cv = dom_get_css_var(n, kebab);
        *out = js_obj_val((JsObj *)js_str_cstr(vm, cv ? cv : ""));
        return true;
    }

    const char *inl = dom_get_attr(n, "style");
    const CssStyle *st = &n->style;
    char buf[64];
    if (strcmp(kebab, "display") == 0) {
        const char *d = "block";
        if (st->display == CSS_DISP_NONE) d = "none";
        else if (st->display == CSS_DISP_INLINE) d = "inline";
        else if (st->display == CSS_DISP_LIST_ITEM) d = "list-item";
        else if (st->display == CSS_DISP_TABLE) d = "table";
        else if (st->display == CSS_DISP_TABLE_ROW) d = "table-row";
        else if (st->display == CSS_DISP_TABLE_CELL) d = "table-cell";
        else if (st->display == CSS_DISP_FLEX) d = "flex";
        *out = js_obj_val((JsObj *)js_str_cstr(vm, d));
        return true;
    }
    if (strcmp(kebab, "visibility") == 0) {
        *out = js_obj_val((JsObj *)js_str_cstr(vm, st->display == CSS_DISP_NONE ? "hidden" : "visible"));
        return true;
    }
    if (strcmp(kebab, "color") == 0) {
        color_to_css_str(st->fg, false, buf, sizeof(buf));
        *out = js_obj_val((JsObj *)js_str_cstr(vm, buf));
        return true;
    }
    if (strcmp(kebab, "background-color") == 0 || strcmp(kebab, "background") == 0) {
        color_to_css_str(st->bg, true, buf, sizeof(buf));
        *out = js_obj_val((JsObj *)js_str_cstr(vm, buf));
        return true;
    }
    if (strcmp(kebab, "font-weight") == 0) {
        *out = js_obj_val((JsObj *)js_str_cstr(vm, st->bold ? "700" : "400"));
        return true;
    }
    if (strcmp(kebab, "font-style") == 0) {
        *out = js_obj_val((JsObj *)js_str_cstr(vm, st->italic ? "italic" : "normal"));
        return true;
    }
    if (strcmp(kebab, "text-align") == 0) {
        const char *ta = "left";
        if (st->text_align == CSS_ALIGN_CENTER) ta = "center";
        else if (st->text_align == CSS_ALIGN_RIGHT) ta = "right";
        *out = js_obj_val((JsObj *)js_str_cstr(vm, ta));
        return true;
    }
    if (strcmp(kebab, "justify-content") == 0) {
        const char *jc = "flex-start";
        if (st->justify_content == CSS_JUSTIFY_CENTER) jc = "center";
        else if (st->justify_content == CSS_JUSTIFY_END) jc = "flex-end";
        else if (st->justify_content == CSS_JUSTIFY_SPACE_BETWEEN) jc = "space-between";
        else if (st->justify_content == CSS_JUSTIFY_SPACE_AROUND) jc = "space-around";
        *out = js_obj_val((JsObj *)js_str_cstr(vm, jc));
        return true;
    }
    if (strcmp(kebab, "gap") == 0 || strcmp(kebab, "column-gap") == 0) {
        snprintf(buf, sizeof(buf), "%dpx", (int)st->gap * 8);
        *out = js_obj_val((JsObj *)js_str_cstr(vm, buf));
        return true;
    }
    if (strcmp(kebab, "width") == 0) {
        int w = st->width_cols > 0 ? st->width_cols : n->box_w;
        snprintf(buf, sizeof(buf), "%dpx", w);
        *out = js_obj_val((JsObj *)js_str_cstr(vm, buf));
        return true;
    }
    if (strcmp(kebab, "height") == 0) {
        snprintf(buf, sizeof(buf), "%dpx", n->box_h);
        *out = js_obj_val((JsObj *)js_str_cstr(vm, buf));
        return true;
    }
    /* Fallback to inline style value if present */
    if (inl) {
        size_t klen = strlen(kebab);
        const char *p = inl;
        while (*p) {
            while (*p && (tb_isspace(*p) || *p == ';')) p++;
            if (tb_strncasecmp(p, kebab, klen) == 0 && (p[klen] == ':' || tb_isspace(p[klen]))) {
                const char *col = strchr(p + klen, ':');
                if (col) {
                    col++;
                    while (*col && tb_isspace(*col)) col++;
                    const char *semi = strchr(col, ';');
                    size_t vlen = semi ? (size_t)(semi - col) : strlen(col);
                    while (vlen > 0 && tb_isspace(col[vlen - 1])) vlen--;
                    *out = js_obj_val((JsObj *)js_str_new(vm, col, vlen));
                    return true;
                }
            }
            const char *semi = strchr(p, ';');
            if (!semi) break;
            p = semi + 1;
        }
    }
    *out = js_obj_val((JsObj *)js_str_cstr(vm, ""));
    return true;
}

static JsVal fn_style_method(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (this_val.type != JS_OBJECT || !this_val.u.obj || this_val.u.obj->obj_type != OBJ_OBJECT)
        return js_undefined();
    JsMapObj *m = (JsMapObj *)this_val.u.obj;
    DomNode *n = (DomNode *)m->native_ptr;
    if (!n || argc == 0) return magic == STYLE_SET_PROP ? js_undefined() : js_obj_val((JsObj *)js_str_cstr(vm, ""));
    JsStr *prop = js_to_str(vm, argv[0]);
    if (!prop) return js_undefined();

    if (magic == STYLE_GET_PROP_VAL) {
        JsVal out = js_undefined();
        if (m->hdr.native_tag == NATIVE_TAG_COMPUTED_STYLE) {
            get_computed_style_prop(vm, n, prop->data, &out);
            return out;
        }
        if (js_dom_get_virtual(vm, m, prop->data, &out)) return out;
        return js_obj_val((JsObj *)js_str_cstr(vm, ""));
    }
    if (magic == STYLE_SET_PROP) {
        if (m->hdr.native_tag == NATIVE_TAG_COMPUTED_STYLE) return js_undefined();
        JsVal v = argc > 1 ? argv[1] : js_obj_val((JsObj *)js_str_cstr(vm, ""));
        if (argc > 2 && argv[2].type != JS_UNDEFINED && argv[2].type != JS_NULL) {
            JsStr *prio = js_to_str(vm, argv[2]);
            JsStr *vs   = js_to_str(vm, v);
            if (prio && vs && vs->len > 0 && tb_strcasecmp(prio->data, "important") == 0) {
                char buf[256];
                snprintf(buf, sizeof(buf), "%s !important", vs->data);
                v = js_obj_val((JsObj *)js_str_cstr(vm, buf));
            }
        }
        js_dom_set_virtual(vm, m, prop->data, v);
        return js_undefined();
    }
    /* STYLE_REMOVE_PROP */
    if (m->hdr.native_tag == NATIVE_TAG_COMPUTED_STYLE) return js_obj_val((JsObj *)js_str_cstr(vm, ""));
    JsVal old_v = js_undefined();
    js_dom_get_virtual(vm, m, prop->data, &old_v);
    js_dom_set_virtual(vm, m, prop->data, js_obj_val((JsObj *)js_str_cstr(vm, "")));
    return old_v;
}

static JsObj *make_proxy_obj(JsVm *vm, DomNode *node, JsNativeTag tag) {
    vm->gc_pause++;
    JsMapObj *m = (JsMapObj *)js_map_new(vm, vm->object_proto);
    if (m) {
        m->hdr.native_tag = (uint8_t)tag;
        m->native_ptr     = node;
        if (tag == NATIVE_TAG_CLASSLIST) {
            js_define_native(vm, (JsObj *)m, "add", fn_classlist, CL_ADD);
            js_define_native(vm, (JsObj *)m, "remove", fn_classlist, CL_REMOVE);
            js_define_native(vm, (JsObj *)m, "toggle", fn_classlist, CL_TOGGLE);
            js_define_native(vm, (JsObj *)m, "contains", fn_classlist, CL_CONTAINS);
        } else if (tag == NATIVE_TAG_STYLE || tag == NATIVE_TAG_COMPUTED_STYLE) {
            js_define_native(vm, (JsObj *)m, "getPropertyValue", fn_style_method, STYLE_GET_PROP_VAL);
            js_define_native(vm, (JsObj *)m, "setProperty", fn_style_method, STYLE_SET_PROP);
            js_define_native(vm, (JsObj *)m, "removeProperty", fn_style_method, STYLE_REMOVE_PROP);
        }
    }
    vm->gc_pause--;
    return (JsObj *)m;
}

static void add_node_listener(DomNode *n, const char *type, JsObj *fn_obj, bool is_inline) {
    if (!n || !type || !fn_obj) return;
    /* Replace existing inline listener or avoid duplicate identical listener */
    for (DomListener *ls = n->listeners; ls; ls = ls->next) {
        if (strcmp(ls->type, type) == 0) {
            if (is_inline && ls->is_inline) {
                ls->js_fn = fn_obj;
                return;
            }
            if (!is_inline && ls->js_fn == fn_obj) return;
        }
    }
    DomListener *nl = (DomListener *)tb_calloc(1, sizeof(DomListener));
    if (!nl) return;
    nl->type      = tb_strdup(type);
    nl->js_fn     = fn_obj;
    nl->is_inline = is_inline;

    /* Append at tail to preserve registration order */
    if (!n->listeners) {
        n->listeners = nl;
    } else {
        DomListener *tail = n->listeners;
        while (tail->next) tail = tail->next;
        tail->next = nl;
    }
}

static void remove_node_listener(DomNode *n, const char *type, JsObj *fn_obj) {
    if (!n || !type) return;
    DomListener **prev = &n->listeners;
    DomListener *cur   = n->listeners;
    while (cur) {
        if (strcmp(cur->type, type) == 0 && (fn_obj == NULL || cur->js_fn == fn_obj)) {
            DomListener *dead = cur;
            cur   = cur->next;
            *prev = cur;
            tb_free(dead->type);
            tb_free(dead);
            if (fn_obj != NULL) return;
        } else {
            prev = &cur->next;
            cur  = cur->next;
        }
    }
}

/* Virtual Getters & Setters on DOM / Window / Style / Location / Performance / Storage */
bool js_dom_get_virtual(JsVm *vm, JsMapObj *m, const char *key, JsVal *out) {
    JsNativeTag tag = (JsNativeTag)m->hdr.native_tag;

    if (tag == NATIVE_TAG_SET) {
        if (strcmp(key, "size") == 0) {
            JsVal vv = js_get_prop(vm, js_obj_val((JsObj *)m), "_vals");
            if (vv.type == JS_OBJECT && vv.u.obj && vv.u.obj->obj_type == OBJ_ARRAY) {
                *out = js_num((double)((JsArrObj *)vv.u.obj)->len);
                return true;
            }
            *out = js_num(0);
            return true;
        }
        return false;
    }

    if (tag == NATIVE_TAG_MAP || tag == NATIVE_TAG_URL_PARAMS) {
        if (strcmp(key, "size") == 0) {
            JsVal kv = js_get_prop(vm, js_obj_val((JsObj *)m), "_keys");
            if (kv.type == JS_OBJECT && kv.u.obj && kv.u.obj->obj_type == OBJ_ARRAY) {
                *out = js_num((double)((JsArrObj *)kv.u.obj)->len);
                return true;
            }
            *out = js_num(0);
            return true;
        }
        return false;
    }

    if (tag == NATIVE_TAG_WINDOW) {
        if (strcmp(key, "innerWidth") == 0)  { *out = js_num(vm->viewport_w > 0 ? vm->viewport_w : 80); return true; }
        if (strcmp(key, "innerHeight") == 0) { *out = js_num(vm->viewport_h > 0 ? vm->viewport_h : 24); return true; }
        if (strcmp(key, "scrollY") == 0 || strcmp(key, "pageYOffset") == 0) {
            int sy = vm->scroll_y_ptr ? *vm->scroll_y_ptr : vm->scroll_y;
            *out = js_num((double)sy);
            return true;
        }
        if (strcmp(key, "scrollX") == 0 || strcmp(key, "pageXOffset") == 0) {
            *out = js_num(0);
            return true;
        }
        return false;
    }

    if (tag == NATIVE_TAG_STORAGE) {
        /* Handled in js_stdlib.c storage methods or backing _store */
        uint32_t pos = 0;
        for (uint32_t i = 0; i < m->count; i++) {
            if (strcmp(m->props[i].key->data, key) == 0) {
                *out = m->props[i].val;
                return true;
            }
            if (strcmp(m->props[i].key->data, "_store") == 0 &&
                m->props[i].val.type == JS_OBJECT && m->props[i].val.u.obj &&
                m->props[i].val.u.obj->obj_type == OBJ_OBJECT) {
                JsMapObj *sm = (JsMapObj *)m->props[i].val.u.obj;
                if (strcmp(key, "length") == 0) {
                    *out = js_num((double)sm->count);
                    return true;
                }
                for (pos = 0; pos < sm->count; pos++) {
                    if (strcmp(sm->props[pos].key->data, key) == 0) {
                        *out = sm->props[pos].val;
                        return true;
                    }
                }
            }
        }
        return false;
    }

    if (tag == NATIVE_TAG_PERF) {
        if (strcmp(key, "memory") == 0) {
            TbMemStats ms;
            tb_mem_stats(&ms);
            vm->gc_pause++;
            JsObj *mo = js_map_new(vm, vm->object_proto);
            if (mo) {
                js_set_prop(vm, js_obj_val(mo), "rssBytes", js_num((double)(ms.vm_rss_kb * 1024UL)));
                js_set_prop(vm, js_obj_val(mo), "anonBytes", js_num((double)(ms.rss_anon_kb * 1024UL)));
                js_set_prop(vm, js_obj_val(mo), "fileBytes", js_num((double)(ms.rss_file_kb * 1024UL)));
                js_set_prop(vm, js_obj_val(mo), "hwmBytes", js_num((double)(ms.vm_hwm_kb * 1024UL)));
                js_set_prop(vm, js_obj_val(mo), "heapLiveBytes", js_num((double)ms.heap_live));
                js_set_prop(vm, js_obj_val(mo), "heapLimitBytes", js_num((double)ms.heap_limit));
                js_set_prop(vm, js_obj_val(mo), "usedJSHeapSize", js_num((double)vm->gc_bytes));
                js_set_prop(vm, js_obj_val(mo), "totalJSHeapSize", js_num((double)vm->gc_threshold));
                js_set_prop(vm, js_obj_val(mo), "jsHeapSizeLimit", js_num((double)vm->gc_max_bytes));
                js_set_prop(vm, js_obj_val(mo), "jsObjectCount", js_num((double)vm->gc_obj_count));
            }
            vm->gc_pause--;
            *out = js_obj_val(mo);
            return true;
        }
        return false;
    }

    if (tag == NATIVE_TAG_LOCATION) {
        const char *u_raw = (vm->pushed_url[0] != '\0') ? vm->pushed_url : (vm->current_url ? vm->current_url : "about:blank");
        TbUrl u;
        bool ok = tb_url_parse(u_raw, &u);
        if (strcmp(key, "href") == 0) {
            *out = js_obj_val((JsObj *)js_str_cstr(vm, u_raw));
            return true;
        }
        if (strcmp(key, "protocol") == 0) {
            char pb[24];
            snprintf(pb, sizeof(pb), "%s:", ok ? u.scheme : "about");
            *out = js_obj_val((JsObj *)js_str_cstr(vm, pb));
            return true;
        }
        if (strcmp(key, "hostname") == 0) {
            *out = js_obj_val((JsObj *)js_str_cstr(vm, ok ? u.host : ""));
            return true;
        }
        if (strcmp(key, "port") == 0) {
            char port_b[16] = "";
            if (ok && u.port != 0 &&
                !((strcmp(u.scheme, "http") == 0 && u.port == 80) ||
                  (strcmp(u.scheme, "https") == 0 && u.port == 443))) {
                snprintf(port_b, sizeof(port_b), "%u", (unsigned)u.port);
            }
            *out = js_obj_val((JsObj *)js_str_cstr(vm, port_b));
            return true;
        }
        if (strcmp(key, "host") == 0) {
            char hb[280] = "";
            if (ok) {
                if (u.port != 0 &&
                    !((strcmp(u.scheme, "http") == 0 && u.port == 80) ||
                      (strcmp(u.scheme, "https") == 0 && u.port == 443))) {
                    snprintf(hb, sizeof(hb), "%s:%u", u.host, (unsigned)u.port);
                } else {
                    snprintf(hb, sizeof(hb), "%s", u.host);
                }
            }
            *out = js_obj_val((JsObj *)js_str_cstr(vm, hb));
            return true;
        }
        if (strcmp(key, "origin") == 0) {
            char ob[320] = "null";
            if (ok && u.host[0]) {
                if (u.port != 0 &&
                    !((strcmp(u.scheme, "http") == 0 && u.port == 80) ||
                      (strcmp(u.scheme, "https") == 0 && u.port == 443))) {
                    snprintf(ob, sizeof(ob), "%s://%s:%u", u.scheme, u.host, (unsigned)u.port);
                } else {
                    snprintf(ob, sizeof(ob), "%s://%s", u.scheme, u.host);
                }
            }
            *out = js_obj_val((JsObj *)js_str_cstr(vm, ob));
            return true;
        }
        if (strcmp(key, "pathname") == 0) {
            char path_only[1024] = "";
            if (ok) {
                const char *q = strchr(u.path, '?');
                if (q) {
                    size_t plen = (size_t)(q - u.path);
                    if (plen >= sizeof(path_only)) plen = sizeof(path_only) - 1;
                    memcpy(path_only, u.path, plen);
                    path_only[plen] = '\0';
                } else {
                    snprintf(path_only, sizeof(path_only), "%s", u.path);
                }
            }
            *out = js_obj_val((JsObj *)js_str_cstr(vm, path_only));
            return true;
        }
        if (strcmp(key, "search") == 0) {
            const char *q = ok ? strchr(u.path, '?') : NULL;
            *out = js_obj_val((JsObj *)js_str_cstr(vm, (q && q[1]) ? q : ""));
            return true;
        }
        if (strcmp(key, "hash") == 0) {
            char hb[140] = "";
            if (ok && u.fragment[0]) snprintf(hb, sizeof(hb), "#%s", u.fragment);
            *out = js_obj_val((JsObj *)js_str_cstr(vm, hb));
            return true;
        }
        return false;
    }

    if (tag == NATIVE_TAG_COMPUTED_STYLE) {
        if (strcmp(key, "getPropertyValue") == 0 || strcmp(key, "setProperty") == 0 || strcmp(key, "removeProperty") == 0)
            return false;
        DomNode *n = (DomNode *)m->native_ptr;
        return get_computed_style_prop(vm, n, key, out);
    }

    if (tag == NATIVE_TAG_STYLE) {
        if (strcmp(key, "getPropertyValue") == 0 || strcmp(key, "setProperty") == 0 || strcmp(key, "removeProperty") == 0)
            return false;
        DomNode *n = (DomNode *)m->native_ptr;
        if (!n) { *out = js_obj_val((JsObj *)js_str_cstr(vm, "")); return true; }
        if (strcmp(key, "cssText") == 0) {
            const char *s = dom_get_attr(n, "style");
            *out = js_obj_val((JsObj *)js_str_cstr(vm, s ? s : ""));
            return true;
        }
        char kebab[64];
        if (key[0] == '-' && key[1] == '-') snprintf(kebab, sizeof(kebab), "%s", key);
        else camel_to_kebab(key, kebab, sizeof(kebab));
        const char *inl = dom_get_attr(n, "style");
        if (inl) {
            size_t klen = strlen(kebab);
            const char *p = inl;
            const char *found_val = NULL;
            size_t found_len = 0;
            while (*p) {
                while (*p && (tb_isspace(*p) || *p == ';')) p++;
                if (tb_strncasecmp(p, kebab, klen) == 0 && (p[klen] == ':' || tb_isspace(p[klen]))) {
                    const char *col = strchr(p + klen, ':');
                    if (col) {
                        col++;
                        while (*col && tb_isspace(*col)) col++;
                        const char *semi = strchr(col, ';');
                        size_t vlen = semi ? (size_t)(semi - col) : strlen(col);
                        while (vlen > 0 && tb_isspace(col[vlen - 1])) vlen--;
                        /* Strip trailing !important if present */
                        if (vlen >= 10) {
                            const char *imp = col + vlen - 10;
                            if (tb_strncasecmp(imp, "!important", 10) == 0) {
                                vlen -= 10;
                                while (vlen > 0 && tb_isspace(col[vlen - 1])) vlen--;
                            }
                        }
                        found_val = col;
                        found_len = vlen;
                    }
                }
                const char *semi = strchr(p, ';');
                if (!semi) break;
                p = semi + 1;
            }
            if (found_val) {
                *out = js_obj_val((JsObj *)js_str_new(vm, found_val, found_len));
                return true;
            }
        }
        *out = js_obj_val((JsObj *)js_str_cstr(vm, ""));
        return true;
    }

    if (tag == NATIVE_TAG_DATASET) {
        DomNode *n = (DomNode *)m->native_ptr;
        if (!n) return false;
        char attr_nm[80] = "data-";
        camel_to_kebab(key, attr_nm + 5, sizeof(attr_nm) - 5);
        const char *v = dom_get_attr(n, attr_nm);
        *out = v ? js_obj_val((JsObj *)js_str_cstr(vm, v)) : js_undefined();
        return true;
    }

    if (tag == NATIVE_TAG_DOCUMENT) {
        DomDocument *doc = vm->doc;
        if (!doc) return false;
        if (strcmp(key, "title") == 0) {
            char *t = dom_get_title(doc);
            *out = js_obj_val((JsObj *)js_str_cstr(vm, t ? t : ""));
            tb_free(t);
            return true;
        }
        if (strcmp(key, "cookie") == 0) {
            const char *u_raw = (vm->pushed_url[0] != '\0') ? vm->pushed_url : (vm->current_url ? vm->current_url : "http://localhost/");
            TbUrl cu;
            char cbuf[1024] = "";
            if (tb_url_parse(u_raw, &cu)) {
                tb_cookie_get_for_url(&cu, true, cbuf, sizeof(cbuf));
            }
            *out = js_obj_val((JsObj *)js_str_cstr(vm, cbuf));
            return true;
        }
        if (strcmp(key, "readyState") == 0)      { *out = js_obj_val((JsObj *)js_str_cstr(vm, "complete")); return true; }
        if (strcmp(key, "body") == 0)            { *out = js_wrap_dom_node(vm, doc->body); return true; }
        if (strcmp(key, "head") == 0)            { *out = js_wrap_dom_node(vm, doc->head); return true; }
        if (strcmp(key, "documentElement") == 0) { *out = js_wrap_dom_node(vm, doc->html); return true; }
        if (strcmp(key, "nodeType") == 0)        { *out = js_num(9); return true; }
        return false;
    }

    if (tag == NATIVE_TAG_DOM_NODE) {
        DomNode *n = (DomNode *)m->native_ptr;
        if (!n) return false;

        if (strcmp(key, "tagName") == 0 || strcmp(key, "nodeName") == 0) {
            if (n->type == DOM_NODE_FRAGMENT) {
                *out = js_obj_val((JsObj *)js_str_cstr(vm, "#document-fragment"));
                return true;
            }
            const char *tn = dom_node_tag_name(n);
            char up[64];
            size_t i = 0;
            for (; tn[i] && i + 1 < sizeof(up); i++) up[i] = tb_toupper(tn[i]);
            up[i] = '\0';
            *out = js_obj_val((JsObj *)js_str_cstr(vm, up));
            return true;
        }
        if (strcmp(key, "nodeType") == 0) {
            int nt = 9;
            if (n->type == DOM_NODE_ELEMENT) nt = 1;
            else if (n->type == DOM_NODE_TEXT) nt = 3;
            else if (n->type == DOM_NODE_COMMENT) nt = 8;
            else if (n->type == DOM_NODE_FRAGMENT) nt = 11;
            *out = js_num((double)nt);
            return true;
        }
        if (strcmp(key, "id") == 0) {
            const char *v = dom_get_attr(n, "id");
            *out = js_obj_val((JsObj *)js_str_cstr(vm, v ? v : ""));
            return true;
        }
        if (strcmp(key, "className") == 0) {
            const char *v = dom_get_attr(n, "class");
            *out = js_obj_val((JsObj *)js_str_cstr(vm, v ? v : ""));
            return true;
        }
        if (strcmp(key, "href") == 0) {
            const char *v = dom_get_attr(n, "href");
            *out = js_obj_val((JsObj *)js_str_cstr(vm, v ? v : ""));
            return true;
        }
        if (strcmp(key, "value") == 0) {
            *out = js_obj_val((JsObj *)js_str_cstr(vm, dom_input_get_value(n)));
            return true;
        }
        if (strcmp(key, "checked") == 0) {
            *out = js_bool(dom_input_get_checked(n));
            return true;
        }
        if (strcmp(key, "disabled") == 0) {
            *out = js_bool(dom_has_attr(n, "disabled"));
            return true;
        }
        if (strcmp(key, "hidden") == 0) {
            *out = js_bool(dom_has_attr(n, "hidden"));
            return true;
        }
        if (strcmp(key, "textContent") == 0 || strcmp(key, "innerText") == 0) {
            char *txt = dom_get_text_content(n);
            *out = js_obj_val((JsObj *)js_str_cstr(vm, txt ? txt : ""));
            tb_free(txt);
            return true;
        }
        if (strcmp(key, "innerHTML") == 0) {
            char *h = dom_get_inner_html(n);
            *out = js_obj_val((JsObj *)js_str_cstr(vm, h ? h : ""));
            tb_free(h);
            return true;
        }
        if (strcmp(key, "outerHTML") == 0) {
            char *h = dom_get_outer_html(n);
            *out = js_obj_val((JsObj *)js_str_cstr(vm, h ? h : ""));
            tb_free(h);
            return true;
        }
        /* Layout geometry properties */
        if (strcmp(key, "offsetWidth") == 0 || strcmp(key, "clientWidth") == 0) {
            int w = n->box_w > 0 ? n->box_w : (n->style.width_cols > 0 ? n->style.width_cols : (vm->viewport_w > 0 ? vm->viewport_w : 80));
            if (n->style.display == CSS_DISP_NONE) w = 0;
            *out = js_num((double)w);
            return true;
        }
        if (strcmp(key, "offsetHeight") == 0 || strcmp(key, "clientHeight") == 0) {
            int h = n->box_h > 0 ? n->box_h : (n->style.display == CSS_DISP_NONE ? 0 : 1);
            *out = js_num((double)h);
            return true;
        }
        if (strcmp(key, "offsetLeft") == 0) { *out = js_num((double)n->box_x); return true; }
        if (strcmp(key, "offsetTop") == 0)  { *out = js_num((double)n->box_y); return true; }
        if (strcmp(key, "scrollTop") == 0)  { *out = js_num(0); return true; }
        if (strcmp(key, "scrollLeft") == 0) { *out = js_num(0); return true; }

        if (strcmp(key, "style") == 0)     { *out = js_obj_val(make_proxy_obj(vm, n, NATIVE_TAG_STYLE)); return true; }
        if (strcmp(key, "classList") == 0) { *out = js_obj_val(make_proxy_obj(vm, n, NATIVE_TAG_CLASSLIST)); return true; }
        if (strcmp(key, "dataset") == 0)   { *out = js_obj_val(make_proxy_obj(vm, n, NATIVE_TAG_DATASET)); return true; }

        if (strcmp(key, "parentNode") == 0) {
            *out = js_wrap_dom_node(vm, n->parent);
            return true;
        }
        if (strcmp(key, "parentElement") == 0) {
            *out = (n->parent && n->parent->type == DOM_NODE_ELEMENT)
                       ? js_wrap_dom_node(vm, n->parent)
                       : js_null();
            return true;
        }
        if (strcmp(key, "firstChild") == 0)  { *out = js_wrap_dom_node(vm, n->first_child); return true; }
        if (strcmp(key, "lastChild") == 0)   { *out = js_wrap_dom_node(vm, n->last_child); return true; }
        if (strcmp(key, "nextSibling") == 0) { *out = js_wrap_dom_node(vm, n->next_sibling); return true; }
        if (strcmp(key, "previousSibling") == 0) { *out = js_wrap_dom_node(vm, n->prev_sibling); return true; }

        if (strcmp(key, "firstElementChild") == 0) {
            for (DomNode *c = n->first_child; c; c = c->next_sibling)
                if (c->type == DOM_NODE_ELEMENT) { *out = js_wrap_dom_node(vm, c); return true; }
            *out = js_null();
            return true;
        }
        if (strcmp(key, "lastElementChild") == 0) {
            for (DomNode *c = n->last_child; c; c = c->prev_sibling)
                if (c->type == DOM_NODE_ELEMENT) { *out = js_wrap_dom_node(vm, c); return true; }
            *out = js_null();
            return true;
        }
        if (strcmp(key, "childElementCount") == 0) {
            int cnt = 0;
            for (DomNode *c = n->first_child; c; c = c->next_sibling)
                if (c->type == DOM_NODE_ELEMENT) cnt++;
            *out = js_num((double)cnt);
            return true;
        }
        if (strcmp(key, "nextElementSibling") == 0) {
            for (DomNode *c = n->next_sibling; c; c = c->next_sibling)
                if (c->type == DOM_NODE_ELEMENT) { *out = js_wrap_dom_node(vm, c); return true; }
            *out = js_null();
            return true;
        }
        if (strcmp(key, "previousElementSibling") == 0) {
            for (DomNode *c = n->prev_sibling; c; c = c->prev_sibling)
                if (c->type == DOM_NODE_ELEMENT) { *out = js_wrap_dom_node(vm, c); return true; }
            *out = js_null();
            return true;
        }
        if (strcmp(key, "children") == 0 || strcmp(key, "childNodes") == 0) {
            bool elem_only = (strcmp(key, "children") == 0);
            vm->gc_pause++;
            JsObj *arr = js_arr_new(vm, 4);
            for (DomNode *c = n->first_child; c; c = c->next_sibling) {
                if (!elem_only || c->type == DOM_NODE_ELEMENT) {
                    js_arr_push(vm, arr, js_wrap_dom_node(vm, c));
                }
            }
            vm->gc_pause--;
            *out = js_obj_val(arr);
            return true;
        }
    }
    return false;
}

bool js_dom_set_virtual(JsVm *vm, JsMapObj *m, const char *key, JsVal val) {
    JsNativeTag tag = (JsNativeTag)m->hdr.native_tag;

    if (tag == NATIVE_TAG_STORAGE) {
        if (strcmp(key, "getItem") == 0 || strcmp(key, "setItem") == 0 ||
            strcmp(key, "removeItem") == 0 || strcmp(key, "clear") == 0 ||
            strcmp(key, "key") == 0 || strcmp(key, "_store") == 0) {
            return false;
        }
        for (uint32_t i = 0; i < m->count; i++) {
            if (strcmp(m->props[i].key->data, "_store") == 0 &&
                m->props[i].val.type == JS_OBJECT && m->props[i].val.u.obj) {
                JsStr *vs = js_to_str(vm, val);
                if (vs) js_set_prop(vm, m->props[i].val, key, js_obj_val((JsObj *)vs));
                return true;
            }
        }
        return false;
    }

    if (tag == NATIVE_TAG_LOCATION) {
        if (strcmp(key, "href") == 0) {
            JsStr *s = js_to_str(vm, val);
            if (s) {
                snprintf(vm->pushed_url, sizeof(vm->pushed_url), "%s", s->data);
                if (vm->on_navigate) vm->on_navigate(vm->host_userdata, s->data, false);
            }
            return true;
        }
        if (strcmp(key, "hash") == 0) {
            JsStr *s = js_to_str(vm, val);
            if (s) {
                const char *base = (vm->pushed_url[0] != '\0') ? vm->pushed_url : (vm->current_url ? vm->current_url : "http://localhost/");
                const char *hash_pos = strchr(base, '#');
                size_t blen = hash_pos ? (size_t)(hash_pos - base) : strlen(base);
                char nb[1536];
                const char *h = (s->data[0] == '#') ? s->data + 1 : s->data;
                snprintf(nb, sizeof(nb), "%.*s#%s", (int)blen, base, h);
                snprintf(vm->pushed_url, sizeof(vm->pushed_url), "%s", nb);
            }
            return true;
        }
        return false;
    }

    if (tag == NATIVE_TAG_STYLE) {
        DomNode *n = (DomNode *)m->native_ptr;
        if (!n) return true;
        JsStr *vs = (val.type == JS_NULL || val.type == JS_UNDEFINED) ? NULL : js_to_str(vm, val);
        const char *vstr = vs ? vs->data : "";
        if (strcmp(key, "cssText") == 0) {
            dom_set_attr(n, "style", vstr);
            if (vm->doc) {
                css_compute_document_ex(vm->doc, NULL, vm->viewport_w > 0 ? vm->viewport_w : 80);
            }
            return true;
        }
        char kebab[64];
        if (key[0] == '-' && key[1] == '-') snprintf(kebab, sizeof(kebab), "%s", key);
        else camel_to_kebab(key, kebab, sizeof(kebab));
        size_t klen = strlen(kebab);
        const char *old_s = dom_get_attr(n, "style");
        TbBuf b;
        tb_buf_init(&b);
        if (old_s && *old_s) {
            const char *p = old_s;
            while (*p) {
                while (*p && (tb_isspace(*p) || *p == ';')) p++;
                if (!*p) break;
                const char *semi = strchr(p, ';');
                size_t dlen = semi ? (size_t)(semi - p) : strlen(p);
                bool match = false;
                if (kebab[0] == '-' && kebab[1] == '-') {
                    match = (dlen > klen && strncmp(p, kebab, klen) == 0 &&
                             (p[klen] == ':' || tb_isspace(p[klen])));
                } else {
                    match = (dlen > klen && tb_strncasecmp(p, kebab, klen) == 0 &&
                             (p[klen] == ':' || tb_isspace(p[klen])));
                }
                if (!match) {
                    tb_buf_append(&b, p, dlen);
                    tb_buf_append_char(&b, ';');
                }
                if (!semi) break;
                p = semi + 1;
            }
        }
        if (vstr[0] != '\0') {
            tb_buf_printf(&b, "%s:%s;", kebab, vstr);
        }
        dom_set_attr(n, "style", b.data ? b.data : "");
        tb_buf_free(&b);
        if (vstr[0] != '\0' && !(kebab[0] == '-' && kebab[1] == '-')) {
            css_apply_decl(&n->style, kebab, vstr);
        }
        if (vm->doc) {
            css_compute_document_ex(vm->doc, NULL, vm->viewport_w > 0 ? vm->viewport_w : 80);
        }
        return true;
    }

    if (tag == NATIVE_TAG_DATASET) {
        DomNode *n = (DomNode *)m->native_ptr;
        if (!n) return true;
        char attr_nm[80] = "data-";
        camel_to_kebab(key, attr_nm + 5, sizeof(attr_nm) - 5);
        JsStr *vs = js_to_str(vm, val);
        dom_set_attr(n, attr_nm, vs ? vs->data : "");
        return true;
    }

    if (tag == NATIVE_TAG_DOCUMENT) {
        if (strcmp(key, "title") == 0 && vm->doc) {
            JsStr *vs = js_to_str(vm, val);
            dom_set_title(vm->doc, vs ? vs->data : "");
            return true;
        }
        if (strcmp(key, "cookie") == 0) {
            JsStr *vs = js_to_str(vm, val);
            if (vs) {
                const char *u_raw = (vm->pushed_url[0] != '\0') ? vm->pushed_url : (vm->current_url ? vm->current_url : "http://localhost/");
                TbUrl cu;
                if (tb_url_parse(u_raw, &cu)) {
                    tb_cookie_set_from_header(&cu, vs->data, true);
                }
            }
            return true;
        }
        return false;
    }

    if (tag == NATIVE_TAG_DOM_NODE) {
        DomNode *n = (DomNode *)m->native_ptr;
        if (!n) return true;

        if (strncmp(key, "on", 2) == 0 && key[2] >= 'a' && key[2] <= 'z') {
            const char *ev_type = key + 2;
            remove_node_listener(n, ev_type, NULL);
            if (val.type == JS_OBJECT && val.u.obj &&
                (val.u.obj->obj_type == OBJ_FUNC || val.u.obj->obj_type == OBJ_NATIVE_FN)) {
                add_node_listener(n, ev_type, val.u.obj, true);
            }
            return true;
        }
        if (strcmp(key, "id") == 0) {
            JsStr *s = js_to_str(vm, val);
            dom_set_attr(n, "id", s ? s->data : "");
            return true;
        }
        if (strcmp(key, "className") == 0) {
            JsStr *s = js_to_str(vm, val);
            dom_set_attr(n, "class", s ? s->data : "");
            return true;
        }
        if (strcmp(key, "href") == 0) {
            JsStr *s = js_to_str(vm, val);
            dom_set_attr(n, "href", s ? s->data : "");
            return true;
        }
        if (strcmp(key, "value") == 0) {
            JsStr *s = js_to_str(vm, val);
            dom_input_set_value(n, s ? s->data : "");
            return true;
        }
        if (strcmp(key, "checked") == 0) {
            dom_input_set_checked(n, js_to_bool(val));
            return true;
        }
        if (strcmp(key, "disabled") == 0) {
            if (js_to_bool(val)) dom_set_attr(n, "disabled", "");
            else dom_remove_attr(n, "disabled");
            return true;
        }
        if (strcmp(key, "hidden") == 0) {
            if (js_to_bool(val)) dom_set_attr(n, "hidden", "");
            else dom_remove_attr(n, "hidden");
            return true;
        }
        if (strcmp(key, "textContent") == 0 || strcmp(key, "innerText") == 0) {
            JsStr *s = (val.type == JS_NULL || val.type == JS_UNDEFINED)
                           ? js_str_cstr(vm, "")
                           : js_to_str(vm, val);
            dom_set_text_content(n, s ? s->data : "");
            return true;
        }
        if (strcmp(key, "innerHTML") == 0) {
            JsStr *s = (val.type == JS_NULL || val.type == JS_UNDEFINED)
                           ? js_str_cstr(vm, "")
                           : js_to_str(vm, val);
            dom_set_inner_html(n, s ? s->data : "");
            return true;
        }
        if (strcmp(key, "outerHTML") == 0) {
            JsStr *s = (val.type == JS_NULL || val.type == JS_UNDEFINED)
                           ? js_str_cstr(vm, "")
                           : js_to_str(vm, val);
            dom_set_outer_html(n, s ? s->data : "");
            return true;
        }
    }
    return false;
}

/* Convert a JS value argument into a DomNode (or newly created text node) */
static DomNode *arg_to_dom_node(JsVm *vm, JsVal v) {
    DomNode *dn = unwrap_node(v);
    if (dn) return dn;
    if (!vm->doc) return NULL;
    JsStr *s = js_to_str(vm, v);
    return dom_create_text(vm->doc, s ? s->data : "");
}

/* Document & Element Native Methods */
typedef enum {
    DOM_APPEND_CHILD = 0,
    DOM_INSERT_BEFORE,
    DOM_REMOVE_CHILD,
    DOM_REPLACE_CHILD,
    DOM_REMOVE,
    DOM_CLONE_NODE,
    DOM_GET_ATTRIBUTE,
    DOM_SET_ATTRIBUTE,
    DOM_REMOVE_ATTRIBUTE,
    DOM_HAS_ATTRIBUTE,
    DOM_TOGGLE_ATTRIBUTE,
    DOM_MATCHES,
    DOM_CLOSEST,
    DOM_CONTAINS,
    DOM_APPEND,
    DOM_PREPEND,
    DOM_BEFORE,
    DOM_AFTER,
    DOM_REPLACE_WITH,
    DOM_REPLACE_CHILDREN,
    DOM_INSERT_ADJ_HTML,
    DOM_INSERT_ADJ_ELEMENT,
    DOM_INSERT_ADJ_TEXT,
    DOM_GET_BOUNDING_RECT,
    DOM_ADD_EVENT_LISTENER,
    DOM_REMOVE_EVENT_LISTENER,
    DOM_DISPATCH_EVENT,
    DOM_CLICK,
    DOM_FOCUS_BLUR,
    DOM_GET_ELEMENT_BY_ID = 40,
    DOM_QUERY_SELECTOR,
    DOM_QUERY_SELECTOR_ALL,
    DOM_GET_ELEMENTS_BY_TAG_NAME,
    DOM_GET_ELEMENTS_BY_CLASS_NAME,
    DOM_CREATE_ELEMENT,
    DOM_CREATE_TEXT_NODE,
    DOM_CREATE_DOCUMENT_FRAGMENT,
    DOM_CREATE_COMMENT
} JsDomMethodMagic;

static bool dispatch_event_obj(JsVm *vm, DomNode *target, JsVal ev_val);

static JsVal fn_dom_method(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    DomNode *n = unwrap_node(this_val);
    if (!n && vm->doc && (magic >= DOM_GET_ELEMENT_BY_ID && magic <= DOM_CREATE_COMMENT)) n = vm->doc->root;
    if (!n && this_val.type == JS_OBJECT && this_val.u.obj == vm->global_obj && vm->doc) n = vm->doc->root;
    if (!n) return js_null();

    switch (magic) {
        /* Document creation & queries */
        case DOM_GET_ELEMENT_BY_ID: {
            JsStr *id = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            return id ? js_wrap_dom_node(vm, dom_get_element_by_id(n, id->data)) : js_null();
        }
        case DOM_QUERY_SELECTOR: {
            JsStr *sel = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            return sel ? js_wrap_dom_node(vm, dom_query_selector(n, sel->data)) : js_null();
        }
        case DOM_QUERY_SELECTOR_ALL:
        case DOM_GET_ELEMENTS_BY_TAG_NAME:
        case DOM_GET_ELEMENTS_BY_CLASS_NAME: {
            JsStr *arg = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            vm->gc_pause++;
            JsObj *arr = js_arr_new(vm, 8);
            if (arg && arg->len > 0) {
                char sel_buf[256];
                const char *sel = arg->data;
                if (magic == DOM_GET_ELEMENTS_BY_TAG_NAME) {
                    snprintf(sel_buf, sizeof(sel_buf), "%s", arg->data);
                    sel = sel_buf;
                } else if (magic == DOM_GET_ELEMENTS_BY_CLASS_NAME) {
                    snprintf(sel_buf, sizeof(sel_buf), ".%s", arg->data);
                    sel = sel_buf;
                }
                DomNodeList nl;
                dom_query_selector_all(n, sel, &nl);
                for (size_t i = 0; i < nl.count; i++) {
                    js_arr_push(vm, arr, js_wrap_dom_node(vm, nl.items[i]));
                }
                dom_nodelist_free(&nl);
            }
            vm->gc_pause--;
            return js_obj_val(arr);
        }
        case DOM_CREATE_ELEMENT: {
            if (!vm->doc) return js_null();
            JsStr *tn = argc > 0 ? js_to_str(vm, argv[0]) : js_str_cstr(vm, "div");
            DomNode *el = dom_create_element(vm->doc, tn ? tn->data : "div");
            return js_wrap_dom_node(vm, el);
        }
        case DOM_CREATE_TEXT_NODE: {
            if (!vm->doc) return js_null();
            JsStr *tx = argc > 0 ? js_to_str(vm, argv[0]) : js_str_cstr(vm, "");
            DomNode *tn = dom_create_text(vm->doc, tx ? tx->data : "");
            return js_wrap_dom_node(vm, tn);
        }
        case DOM_CREATE_DOCUMENT_FRAGMENT: {
            if (!vm->doc) return js_null();
            DomNode *df = dom_create_fragment(vm->doc);
            return js_wrap_dom_node(vm, df);
        }
        case DOM_CREATE_COMMENT: {
            if (!vm->doc) return js_null();
            DomNode *cm = dom_create_text(vm->doc, "");
            if (cm) cm->type = DOM_NODE_COMMENT;
            return js_wrap_dom_node(vm, cm);
        }

        /* Node tree mutations */
        case DOM_APPEND_CHILD: {
            DomNode *ch = argc > 0 ? unwrap_node(argv[0]) : NULL;
            if (!ch || !dom_append_child(n, ch)) return js_null();
            return argv[0];
        }
        case DOM_INSERT_BEFORE: {
            DomNode *nn  = argc > 0 ? unwrap_node(argv[0]) : NULL;
            DomNode *ref = (argc > 1 && argv[1].type != JS_NULL && argv[1].type != JS_UNDEFINED) ? unwrap_node(argv[1]) : NULL;
            if (!nn || !dom_insert_before(n, nn, ref)) return js_null();
            return argv[0];
        }
        case DOM_REMOVE_CHILD: {
            DomNode *ch = argc > 0 ? unwrap_node(argv[0]) : NULL;
            if (!ch || !dom_remove_child(n, ch)) return js_null();
            return argv[0];
        }
        case DOM_REPLACE_CHILD: {
            DomNode *nn = argc > 0 ? unwrap_node(argv[0]) : NULL;
            DomNode *on = argc > 1 ? unwrap_node(argv[1]) : NULL;
            if (!nn || !on || !dom_replace_child(n, nn, on)) return js_null();
            return argv[1];
        }
        case DOM_REMOVE: {
            if (n->parent) dom_remove_child(n->parent, n);
            return js_undefined();
        }
        case DOM_CLONE_NODE: {
            bool deep = argc > 0 && js_to_bool(argv[0]);
            DomNode *cl = dom_clone_node(vm->doc, n, deep);
            return js_wrap_dom_node(vm, cl);
        }
        case DOM_CONTAINS: {
            DomNode *other = argc > 0 ? unwrap_node(argv[0]) : NULL;
            return js_bool(dom_contains(n, other));
        }
        case DOM_APPEND: {
            for (int i = 0; i < argc; i++) {
                DomNode *ch = arg_to_dom_node(vm, argv[i]);
                if (ch) dom_append_child(n, ch);
            }
            return js_undefined();
        }
        case DOM_PREPEND: {
            DomNode *first = n->first_child;
            for (int i = 0; i < argc; i++) {
                DomNode *ch = arg_to_dom_node(vm, argv[i]);
                if (ch) dom_insert_before(n, ch, first);
            }
            return js_undefined();
        }
        case DOM_BEFORE: {
            if (!n->parent) return js_undefined();
            for (int i = 0; i < argc; i++) {
                DomNode *ch = arg_to_dom_node(vm, argv[i]);
                if (ch) dom_insert_before(n->parent, ch, n);
            }
            return js_undefined();
        }
        case DOM_AFTER: {
            if (!n->parent) return js_undefined();
            DomNode *ref = n->next_sibling;
            for (int i = 0; i < argc; i++) {
                DomNode *ch = arg_to_dom_node(vm, argv[i]);
                if (ch) dom_insert_before(n->parent, ch, ref);
            }
            return js_undefined();
        }
        case DOM_REPLACE_WITH: {
            DomNode *par = n->parent;
            if (!par) return js_undefined();
            DomNode *ref = n->next_sibling;
            dom_remove_child(par, n);
            for (int i = 0; i < argc; i++) {
                DomNode *ch = arg_to_dom_node(vm, argv[i]);
                if (ch) dom_insert_before(par, ch, ref);
            }
            return js_undefined();
        }
        case DOM_REPLACE_CHILDREN: {
            while (n->first_child) {
                DomNode *ch = n->first_child;
                dom_remove_child(n, ch);
                if (!dom_subtree_has_wrapper(ch)) dom_node_free(ch);
            }
            for (int i = 0; i < argc; i++) {
                DomNode *ch = arg_to_dom_node(vm, argv[i]);
                if (ch) dom_append_child(n, ch);
            }
            return js_undefined();
        }
        case DOM_INSERT_ADJ_HTML: {
            if (argc >= 2) {
                JsStr *pos = js_to_str(vm, argv[0]);
                JsStr *htm = js_to_str(vm, argv[1]);
                if (pos && htm) dom_insert_adjacent_html(n, pos->data, htm->data);
            }
            return js_undefined();
        }
        case DOM_INSERT_ADJ_ELEMENT: {
            if (argc >= 2) {
                JsStr *pos = js_to_str(vm, argv[0]);
                DomNode *el = unwrap_node(argv[1]);
                if (!pos || !el) return js_null();
                if (tb_strcasecmp(pos->data, "beforebegin") == 0) {
                    if (!n->parent || !dom_insert_before(n->parent, el, n)) return js_null();
                } else if (tb_strcasecmp(pos->data, "afterbegin") == 0) {
                    if (!dom_insert_before(n, el, n->first_child)) return js_null();
                } else if (tb_strcasecmp(pos->data, "beforeend") == 0) {
                    if (!dom_append_child(n, el)) return js_null();
                } else if (tb_strcasecmp(pos->data, "afterend") == 0) {
                    if (!n->parent || !dom_insert_before(n->parent, el, n->next_sibling)) return js_null();
                } else {
                    return js_null();
                }
                return argv[1];
            }
            return js_null();
        }
        case DOM_INSERT_ADJ_TEXT: {
            if (argc >= 2 && vm->doc) {
                JsStr *pos = js_to_str(vm, argv[0]);
                JsStr *txt = js_to_str(vm, argv[1]);
                DomNode *tn = dom_create_text(vm->doc, txt ? txt->data : "");
                if (pos && tn) {
                    if (tb_strcasecmp(pos->data, "beforebegin") == 0 && n->parent)
                        dom_insert_before(n->parent, tn, n);
                    else if (tb_strcasecmp(pos->data, "afterbegin") == 0)
                        dom_insert_before(n, tn, n->first_child);
                    else if (tb_strcasecmp(pos->data, "beforeend") == 0)
                        dom_append_child(n, tn);
                    else if (tb_strcasecmp(pos->data, "afterend") == 0 && n->parent)
                        dom_insert_before(n->parent, tn, n->next_sibling);
                    else
                        dom_node_free(tn);
                }
            }
            return js_undefined();
        }
        case DOM_GET_BOUNDING_RECT: {
            if (vm->doc) {
                css_compute_document_ex(vm->doc, NULL, vm->viewport_w > 0 ? vm->viewport_w : 80);
            }
            int x = n->box_x;
            int y = n->box_y;
            int w = n->box_w > 0 ? n->box_w : (n->style.width_cols > 0 ? n->style.width_cols : (vm->viewport_w > 0 ? vm->viewport_w : 80));
            int h = n->box_h > 0 ? n->box_h : (n->style.display == CSS_DISP_NONE ? 0 : 1);
            if (n->style.display == CSS_DISP_NONE) w = 0;
            vm->gc_pause++;
            JsObj *rc = js_map_new(vm, vm->object_proto);
            if (rc) {
                js_set_prop(vm, js_obj_val(rc), "x", js_num((double)x));
                js_set_prop(vm, js_obj_val(rc), "y", js_num((double)y));
                js_set_prop(vm, js_obj_val(rc), "left", js_num((double)x));
                js_set_prop(vm, js_obj_val(rc), "top", js_num((double)y));
                js_set_prop(vm, js_obj_val(rc), "width", js_num((double)w));
                js_set_prop(vm, js_obj_val(rc), "height", js_num((double)h));
                js_set_prop(vm, js_obj_val(rc), "right", js_num((double)(x + w)));
                js_set_prop(vm, js_obj_val(rc), "bottom", js_num((double)(y + h)));
            }
            vm->gc_pause--;
            return js_obj_val(rc);
        }

        /* Attributes & Matching */
        case DOM_GET_ATTRIBUTE: {
            JsStr *nm = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            const char *v = nm ? dom_get_attr(n, nm->data) : NULL;
            return v ? js_obj_val((JsObj *)js_str_cstr(vm, v)) : js_null();
        }
        case DOM_SET_ATTRIBUTE: {
            if (argc >= 2) {
                JsStr *nm = js_to_str(vm, argv[0]);
                JsStr *vl = js_to_str(vm, argv[1]);
                if (nm) dom_set_attr(n, nm->data, vl ? vl->data : "");
            }
            return js_undefined();
        }
        case DOM_REMOVE_ATTRIBUTE: {
            JsStr *nm = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            if (nm) dom_remove_attr(n, nm->data);
            return js_undefined();
        }
        case DOM_HAS_ATTRIBUTE: {
            JsStr *nm = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            return js_bool(nm && dom_has_attr(n, nm->data));
        }
        case DOM_TOGGLE_ATTRIBUTE: {
            if (argc == 0) return js_bool(false);
            JsStr *nm = js_to_str(vm, argv[0]);
            if (!nm) return js_bool(false);
            bool has = dom_has_attr(n, nm->data);
            bool force = (argc > 1 && argv[1].type != JS_UNDEFINED) ? js_to_bool(argv[1]) : !has;
            if (force) {
                if (!has) dom_set_attr(n, nm->data, "");
                return js_bool(true);
            } else {
                if (has) dom_remove_attr(n, nm->data);
                return js_bool(false);
            }
        }
        case DOM_MATCHES: {
            JsStr *sel = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            return js_bool(sel && dom_matches_selector(n, sel->data));
        }
        case DOM_CLOSEST: {
            JsStr *sel = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            if (!sel) return js_null();
            for (DomNode *cur = n; cur && cur->type == DOM_NODE_ELEMENT; cur = cur->parent) {
                if (dom_matches_selector(cur, sel->data)) return js_wrap_dom_node(vm, cur);
            }
            return js_null();
        }

        /* Event Listeners & Programmatic click() / dispatchEvent() */
        case DOM_ADD_EVENT_LISTENER: {
            if (argc >= 2 && argv[1].type == JS_OBJECT && argv[1].u.obj) {
                JsStr *tp = js_to_str(vm, argv[0]);
                if (tp) add_node_listener(n, tp->data, argv[1].u.obj, false);
            }
            return js_undefined();
        }
        case DOM_REMOVE_EVENT_LISTENER: {
            if (argc >= 2 && argv[1].type == JS_OBJECT) {
                JsStr *tp = js_to_str(vm, argv[0]);
                if (tp) remove_node_listener(n, tp->data, argv[1].u.obj);
            }
            return js_undefined();
        }
        case DOM_DISPATCH_EVENT: {
            if (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj) {
                return js_bool(dispatch_event_obj(vm, n, argv[0]));
            }
            return js_bool(true);
        }
        case DOM_CLICK: {
            js_dispatch_dom_event(vm, n, "click", NULL, true);
            return js_undefined();
        }
        case DOM_FOCUS_BLUR:
            return js_undefined();
        default:
            return js_undefined();
    }
}

/* Event object methods: preventDefault() & stopPropagation() */
typedef enum {
    EV_PREVENT_DEFAULT = 0,
    EV_STOP_PROPAGATION,
    EV_STOP_IMMEDIATE,
    EV_CTOR,
    EV_CUSTOM_CTOR
} JsEventCtrlMagic;

static JsVal fn_event_ctrl(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    if (magic == EV_PREVENT_DEFAULT) {
        if (js_to_bool(js_get_prop(vm, this_val, "cancelable"))) {
            js_set_prop(vm, this_val, "defaultPrevented", js_bool(true));
        }
        return js_undefined();
    }
    if (magic == EV_STOP_PROPAGATION) {
        js_set_prop(vm, this_val, "_stopped", js_bool(true));
        return js_undefined();
    }
    if (magic == EV_STOP_IMMEDIATE) {
        js_set_prop(vm, this_val, "_stopped", js_bool(true));
        js_set_prop(vm, this_val, "_stopImmediate", js_bool(true));
        return js_undefined();
    }
    /* EV_CTOR / EV_CUSTOM_CTOR */
    JsObj *ev = (this_val.type == JS_OBJECT && this_val.u.obj && this_val.u.obj != vm->global_obj)
                    ? this_val.u.obj
                    : js_map_new(vm, vm->object_proto);
    if (!ev) return js_undefined();
    JsVal ev_val = js_obj_val(ev);
    JsStr *tp = argc > 0 ? js_to_str(vm, argv[0]) : js_str_cstr(vm, "");
    bool bubbles = false;
    bool cancelable = true;
    JsVal detail = js_null();
    if (argc > 1 && argv[1].type == JS_OBJECT && argv[1].u.obj) {
        JsVal bv = js_get_prop(vm, argv[1], "bubbles");
        if (bv.type != JS_UNDEFINED) bubbles = js_to_bool(bv);
        JsVal cv = js_get_prop(vm, argv[1], "cancelable");
        if (cv.type != JS_UNDEFINED) cancelable = js_to_bool(cv);
        if (magic == EV_CUSTOM_CTOR) {
            JsVal dv = js_get_prop(vm, argv[1], "detail");
            if (dv.type != JS_UNDEFINED) detail = dv;
        }
    }
    vm->gc_pause++;
    js_set_prop(vm, ev_val, "type", js_obj_val((JsObj *)tp));
    js_set_prop(vm, ev_val, "bubbles", js_bool(bubbles));
    js_set_prop(vm, ev_val, "cancelable", js_bool(cancelable));
    js_set_prop(vm, ev_val, "defaultPrevented", js_bool(false));
    js_set_prop(vm, ev_val, "_stopped", js_bool(false));
    js_set_prop(vm, ev_val, "_stopImmediate", js_bool(false));
    if (magic == EV_CUSTOM_CTOR) {
        js_set_prop(vm, ev_val, "detail", detail);
    }
    js_define_native(vm, ev, "preventDefault", fn_event_ctrl, EV_PREVENT_DEFAULT);
    js_define_native(vm, ev, "stopPropagation", fn_event_ctrl, EV_STOP_PROPAGATION);
    js_define_native(vm, ev, "stopImmediatePropagation", fn_event_ctrl, EV_STOP_IMMEDIATE);
    vm->gc_pause--;
    return ev_val;
}

static void ensure_inline_handler_compiled(JsVm *vm, DomNode *n, const char *type) {
    char attr_name[48];
    snprintf(attr_name, sizeof(attr_name), "on%s", type);
    const char *code = dom_get_attr(n, attr_name);
    if (!code || !*code) return;
    for (DomListener *ls = n->listeners; ls; ls = ls->next) {
        if (ls->is_inline && strcmp(ls->type, type) == 0) return;
    }

    TbBuf src;
    tb_buf_init(&src);
    tb_buf_printf(&src, "(function(event){ %s })", code);
    JsVal fn_val = js_undefined();
    if (js_eval(vm, src.data, src.len, &fn_val) &&
        fn_val.type == JS_OBJECT && fn_val.u.obj && fn_val.u.obj->obj_type == OBJ_FUNC) {
        add_node_listener(n, type, fn_val.u.obj, true);
    }
    tb_buf_free(&src);
}

static bool dispatch_event_obj(JsVm *vm, DomNode *target, JsVal ev_val) {
    if (!vm || !target || ev_val.type != JS_OBJECT || !ev_val.u.obj) return true;
    int sp = vm->temp_sp;
    js_temp_push(vm, ev_val);

    JsStr *tp_s = js_to_str(vm, js_get_prop(vm, ev_val, "type"));
    if (!tp_s || tp_s->len == 0) { vm->temp_sp = sp; return true; }
    js_temp_push(vm, js_obj_val((JsObj *)tp_s));
    const char *type = tp_s->data;
    bool bubbles = js_to_bool(js_get_prop(vm, ev_val, "bubbles"));

    js_set_prop(vm, ev_val, "target", js_wrap_dom_node(vm, target));

    /* Snapshot propagation path as wrapped DOM nodes (rooted on temp_roots)
     * before invoking listeners, per W3C DOM Event Dispatch spec. */
    DomNode *path[128];
    int path_len = 0;
    for (DomNode *p = target; p && path_len < 128; p = p->parent) {
        path[path_len++] = p;
        if (!bubbles) break;
    }

    int path_sp = vm->temp_sp;
    int actual_path_len = 0;
    for (int p = 0; p < path_len; p++) {
        JsVal w = js_wrap_dom_node(vm, path[p]);
        if (!js_temp_push(vm, w)) break;
        actual_path_len++;
    }

    for (int p = 0; p < actual_path_len; p++) {
        JsVal cur_wrap = vm->temp_roots[path_sp + p];
        DomNode *cur   = unwrap_node(cur_wrap);
        if (!cur) continue;

        if (cur->type == DOM_NODE_ELEMENT) {
            ensure_inline_handler_compiled(vm, cur, type);
            cur = unwrap_node(cur_wrap);
            if (!cur) continue;
        }
        if (cur->listeners) {
            js_set_prop(vm, ev_val, "currentTarget", cur_wrap);

            int fn_sp = vm->temp_sp;
            int nfns  = 0;
            for (DomListener *ls = cur->listeners; ls && nfns < 32; ls = ls->next) {
                if (strcmp(ls->type, type) == 0 && ls->js_fn) {
                    if (js_temp_push(vm, js_obj_val((JsObj *)ls->js_fn))) {
                        nfns++;
                    }
                }
            }
            for (int i = 0; i < nfns; i++) {
                JsVal fn_val = vm->temp_roots[fn_sp + i];
                vm->steps = 0;
                js_call(vm, fn_val, cur_wrap, 1, &ev_val);
                if (vm->has_thrown) {
                    TbBuf eb;
                    tb_buf_init(&eb);
                    tb_buf_append_cstr(&eb, "Uncaught in event handler: ");
                    js_val_format(vm, vm->thrown_val, &eb, 0);
                    js_log(vm, JS_LOG_ERROR, "%s", eb.data ? eb.data : "Error");
                    tb_buf_free(&eb);
                    vm->has_thrown = false;
                    vm->thrown_val = js_undefined();
                }
                if (js_to_bool(js_get_prop(vm, ev_val, "_stopImmediate"))) break;
            }
            vm->temp_sp = fn_sp;
        }
        if (!bubbles) break;
        JsVal stopped = js_get_prop(vm, ev_val, "_stopped");
        if (js_to_bool(stopped)) break;
    }

    js_drain_microtasks(vm);
    bool prevented = js_to_bool(js_get_prop(vm, ev_val, "defaultPrevented"));
    vm->temp_sp = sp;
    return !prevented;
}

bool js_dispatch_dom_event(JsVm *vm, DomNode *target, const char *type,
                           const char *key_name, bool bubbles) {
    if (!vm || !target || !type) return true;

    int sp = vm->temp_sp;
    vm->gc_pause++;
    JsObj *ev = js_map_new(vm, vm->object_proto);
    JsVal ev_val = js_obj_val(ev);
    js_set_prop(vm, ev_val, "type", js_obj_val((JsObj *)js_str_cstr(vm, type)));
    js_set_prop(vm, ev_val, "target", js_wrap_dom_node(vm, target));
    js_set_prop(vm, ev_val, "bubbles", js_bool(bubbles));
    js_set_prop(vm, ev_val, "cancelable", js_bool(true));
    js_set_prop(vm, ev_val, "defaultPrevented", js_bool(false));
    js_set_prop(vm, ev_val, "_stopped", js_bool(false));
    js_set_prop(vm, ev_val, "_stopImmediate", js_bool(false));
    if (key_name) js_set_prop(vm, ev_val, "key", js_obj_val((JsObj *)js_str_cstr(vm, key_name)));
    js_define_native(vm, ev, "preventDefault", fn_event_ctrl, EV_PREVENT_DEFAULT);
    js_define_native(vm, ev, "stopPropagation", fn_event_ctrl, EV_STOP_PROPAGATION);
    js_define_native(vm, ev, "stopImmediatePropagation", fn_event_ctrl, EV_STOP_IMMEDIATE);
    vm->gc_pause--;

    js_temp_push(vm, ev_val);
    bool res = dispatch_event_obj(vm, target, ev_val);
    vm->temp_sp = sp;
    return res;
}

/* Timers, Window APIs, History, Location & Fetch */
typedef enum {
    WIN_SET_TIMEOUT = 0,
    WIN_SET_INTERVAL,
    WIN_CLEAR_TIMER,
    WIN_RAF,
    WIN_CANCEL_RAF,
    WIN_PERF_NOW,
    WIN_ALERT,
    WIN_SCROLL_TO,
    WIN_GET_COMPUTED_STYLE,
    WIN_MATCH_MEDIA,
    WIN_LOC_RELOAD,
    WIN_LOC_ASSIGN,
    WIN_LOC_REPLACE,
    WIN_LOC_TO_STRING,
    WIN_HIST_PUSH_STATE,
    WIN_HIST_REPLACE_STATE,
    WIN_HIST_BACK,
    WIN_HIST_FORWARD,
    WIN_HIST_GO
} JsWindowApiMagic;

static JsVal fn_window_api(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    switch (magic) {
        case WIN_SET_TIMEOUT:
        case WIN_SET_INTERVAL:
        case WIN_RAF: {
            if (argc == 0 || argv[0].type != JS_OBJECT || !argv[0].u.obj) return js_num(0);
            int64_t delay = (magic == WIN_RAF) ? 16 : (argc > 1 ? (int64_t)js_to_num(vm, argv[1]) : 0);
            if (delay < 0) delay = 0;
            for (int i = 0; i < JS_MAX_TIMERS; i++) {
                if (!vm->timers[i].active) {
                    int id = vm->next_timer_id++;
                    vm->timers[i].id          = id;
                    vm->timers[i].active      = true;
                    vm->timers[i].repeat      = (magic == WIN_SET_INTERVAL);
                    vm->timers[i].is_raf      = (magic == WIN_RAF);
                    vm->timers[i].interval_ms = (magic == WIN_SET_INTERVAL && delay < 10) ? 10 : delay;
                    vm->timers[i].due_ms      = js_now_ms() + delay;
                    vm->timers[i].fn_obj      = argv[0].u.obj;
                    int extra = (magic != WIN_RAF && argc > 2) ? (argc - 2) : 0;
                    if (extra > JS_MAX_TIMER_ARGS) extra = JS_MAX_TIMER_ARGS;
                    vm->timers[i].argc = extra;
                    for (int a = 0; a < extra; a++) {
                        vm->timers[i].args[a] = argv[2 + a];
                    }
                    return js_num((double)id);
                }
            }
            return js_num(0);
        }
        case WIN_CLEAR_TIMER:
        case WIN_CANCEL_RAF: {
            int id = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            for (int i = 0; i < JS_MAX_TIMERS; i++) {
                if (vm->timers[i].active && vm->timers[i].id == id) {
                    vm->timers[i].active = false;
                    vm->timers[i].fn_obj = NULL;
                    vm->timers[i].argc   = 0;
                }
            }
            return js_undefined();
        }
        case WIN_PERF_NOW: {
            return js_num((double)(js_now_ms() - vm->boot_ms));
        }
        case WIN_ALERT: {
            JsStr *s = argc > 0 ? js_to_str(vm, argv[0]) : js_str_cstr(vm, "");
            if (vm->on_alert && s) vm->on_alert(vm->host_userdata, s->data);
            js_log(vm, JS_LOG_INFO, "[alert] %s", s ? s->data : "");
            return js_undefined();
        }
        case WIN_SCROLL_TO: {
            int ny = 0;
            if (argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj) {
                JsVal tv = js_get_prop(vm, argv[0], "top");
                if (tv.type != JS_UNDEFINED) ny = (int)js_to_num(vm, tv);
            } else {
                ny = argc > 1 ? (int)js_to_num(vm, argv[1]) : (argc > 0 ? (int)js_to_num(vm, argv[0]) : 0);
            }
            if (ny < 0) ny = 0;
            vm->scroll_y = ny;
            if (vm->scroll_y_ptr) *vm->scroll_y_ptr = ny;
            return js_undefined();
        }
        case WIN_GET_COMPUTED_STYLE: {
            DomNode *n = argc > 0 ? unwrap_node(argv[0]) : NULL;
            return js_obj_val(make_proxy_obj(vm, n, NATIVE_TAG_COMPUTED_STYLE));
        }
        case WIN_MATCH_MEDIA: {
            JsStr *q = argc > 0 ? js_to_str(vm, argv[0]) : js_str_cstr(vm, "");
            bool matches = css_eval_media_query(q ? q->data : "", vm->viewport_w);
            vm->gc_pause++;
            JsObj *mql = js_map_new(vm, vm->object_proto);
            if (mql) {
                js_set_prop(vm, js_obj_val(mql), "matches", js_bool(matches));
                js_set_prop(vm, js_obj_val(mql), "media", js_obj_val((JsObj *)q));
                js_define_native(vm, mql, "addEventListener", fn_dom_method, DOM_FOCUS_BLUR);
                js_define_native(vm, mql, "removeEventListener", fn_dom_method, DOM_FOCUS_BLUR);
            }
            vm->gc_pause--;
            return js_obj_val(mql);
        }
        case WIN_LOC_RELOAD: {
            const char *u = (vm->pushed_url[0] != '\0') ? vm->pushed_url : vm->current_url;
            if (vm->on_navigate) vm->on_navigate(vm->host_userdata, u, true);
            return js_undefined();
        }
        case WIN_LOC_ASSIGN:
        case WIN_LOC_REPLACE: {
            if (argc > 0) {
                JsStr *s = js_to_str(vm, argv[0]);
                if (s) {
                    snprintf(vm->pushed_url, sizeof(vm->pushed_url), "%s", s->data);
                    if (vm->on_navigate) vm->on_navigate(vm->host_userdata, s->data, false);
                }
            }
            return js_undefined();
        }
        case WIN_LOC_TO_STRING: {
            const char *u_raw = (vm->pushed_url[0] != '\0') ? vm->pushed_url : (vm->current_url ? vm->current_url : "about:blank");
            return js_obj_val((JsObj *)js_str_cstr(vm, u_raw));
        }
        case WIN_HIST_PUSH_STATE:
        case WIN_HIST_REPLACE_STATE: {
            JsVal state = argc > 0 ? argv[0] : js_null();
            if (vm->history_obj) {
                js_set_prop(vm, js_obj_val(vm->history_obj), "state", state);
                if (magic == WIN_HIST_PUSH_STATE) {
                    JsVal lv = js_get_prop(vm, js_obj_val(vm->history_obj), "length");
                    int len = (lv.type == JS_NUMBER) ? (int)lv.u.num : 1;
                    js_set_prop(vm, js_obj_val(vm->history_obj), "length", js_num((double)(len + 1)));
                }
            }
            if (argc > 2 && argv[2].type != JS_UNDEFINED && argv[2].type != JS_NULL) {
                JsStr *us = js_to_str(vm, argv[2]);
                if (us && us->len > 0) {
                    const char *base_str = (vm->pushed_url[0] != '\0') ? vm->pushed_url : (vm->current_url ? vm->current_url : "http://localhost/");
                    TbUrl base_u;
                    if (tb_url_parse(base_str, &base_u)) {
                        char resolved[1536];
                        tb_url_resolve(&base_u, us->data, resolved, sizeof(resolved));
                        snprintf(vm->pushed_url, sizeof(vm->pushed_url), "%s", resolved);
                    } else {
                        snprintf(vm->pushed_url, sizeof(vm->pushed_url), "%s", us->data);
                    }
                }
            }
            return js_undefined();
        }
        case WIN_HIST_BACK:
        case WIN_HIST_FORWARD:
        case WIN_HIST_GO:
            return js_undefined();
        default:
            return js_undefined();
    }
}

typedef enum {
    FETCH_RESP_TEXT = 0,
    FETCH_RESP_JSON
} JsFetchRespMagic;

static JsVal fn_fetch_resp(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)argc; (void)argv;
    JsVal body = js_get_prop(vm, this_val, "_body");
    if (magic == FETCH_RESP_TEXT) return js_obj_val(js_promise_new(vm, 1, body));
    /* FETCH_RESP_JSON */
    JsVal json_obj = js_get_prop(vm, js_obj_val(vm->global_obj), "JSON");
    JsVal parse_fn = js_get_prop(vm, json_obj, "parse");
    JsVal parsed   = js_call(vm, parse_fn, json_obj, 1, &body);
    if (vm->has_thrown) {
        JsVal tv = vm->thrown_val;
        vm->has_thrown = false;
        vm->thrown_val = js_undefined();
        return js_obj_val(js_promise_new(vm, 2, tv));
    }
    return js_obj_val(js_promise_new(vm, 1, parsed));
}

static JsVal fn_fetch(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val; (void)magic;
    if (argc == 0 || !vm->on_fetch) {
        return js_obj_val(js_promise_new(vm, 2, js_obj_val((JsObj *)js_str_cstr(vm, "fetch unavailable"))));
    }
    JsStr *url_s = js_to_str(vm, argv[0]);
    const char *method = "GET";
    const char *body   = NULL;
    JsStr *m_str = NULL, *b_str = NULL;
    TbBuf hdr_buf;
    tb_buf_init(&hdr_buf);
    char ct_buf[128] = "";

    if (argc > 1 && argv[1].type == JS_OBJECT && argv[1].u.obj) {
        JsVal mv = js_get_prop(vm, argv[1], "method");
        if (mv.type != JS_UNDEFINED) { m_str = js_to_str(vm, mv); if (m_str) method = m_str->data; }
        JsVal bv = js_get_prop(vm, argv[1], "body");
        if (bv.type != JS_UNDEFINED && bv.type != JS_NULL) { b_str = js_to_str(vm, bv); if (b_str) body = b_str->data; }

        JsVal hv = js_get_prop(vm, argv[1], "headers");
        if (hv.type == JS_OBJECT && hv.u.obj) {
            JsObj *ho = hv.u.obj;
            if (ho->native_tag == NATIVE_TAG_HEADERS) {
                JsVal mv_map = js_get_prop(vm, hv, "_map");
                if (mv_map.type == JS_OBJECT && mv_map.u.obj && mv_map.u.obj->obj_type == OBJ_OBJECT) {
                    ho = mv_map.u.obj;
                }
            }
            if (ho->obj_type == OBJ_OBJECT) {
                JsMapObj *hm = (JsMapObj *)ho;
                for (uint32_t i = 0; i < hm->count; i++) {
                    const char *hk = hm->props[i].key->data;
                    if (!hk || hk[0] == '\x01' || hk[0] == '_') continue;
                    JsStr *hvs = js_to_str(vm, hm->props[i].val);
                    const char *hv_c = hvs ? hvs->data : "";
                    if (tb_strcasecmp(hk, "content-type") == 0) {
                        snprintf(ct_buf, sizeof(ct_buf), "%s", hv_c);
                    } else {
                        tb_buf_printf(&hdr_buf, "%s: %s\r\n", hk, hv_c);
                    }
                }
            }
        }
    }

    vm->fetch_extra_headers = hdr_buf.len > 0 ? hdr_buf.data : NULL;
    vm->fetch_content_type  = ct_buf[0] != '\0' ? ct_buf : NULL;

    int status = 0;
    char *text = NULL;
    bool ok = vm->on_fetch(vm->host_userdata, url_s ? url_s->data : "", method, body, &status, &text);

    vm->fetch_extra_headers = NULL;
    vm->fetch_content_type  = NULL;
    tb_buf_free(&hdr_buf);

    if (!ok) {
        JsVal err = js_obj_val((JsObj *)js_str_cstr(vm, text ? text : "NetworkError"));
        tb_free(text);
        return js_obj_val(js_promise_new(vm, 2, err));
    }

    vm->gc_pause++;
    JsObj *ro = js_map_new(vm, vm->object_proto);
    JsStr *bs = js_str_cstr(vm, text ? text : "");
    tb_free(text);
    if (ro) {
        js_set_prop(vm, js_obj_val(ro), "status", js_num((double)status));
        js_set_prop(vm, js_obj_val(ro), "ok", js_bool(status >= 200 && status < 300));
        js_set_prop(vm, js_obj_val(ro), "url", js_obj_val((JsObj *)url_s));
        js_set_prop(vm, js_obj_val(ro), "_body", js_obj_val((JsObj *)bs));
        if (vm->headers_proto) {
            JsObj *rh = js_map_new(vm, vm->headers_proto);
            if (rh) {
                rh->native_tag = NATIVE_TAG_HEADERS;
                js_set_prop(vm, js_obj_val(rh), "_map", js_obj_val(js_map_new(vm, NULL)));
                js_set_prop(vm, js_obj_val(ro), "headers", js_obj_val(rh));
            }
        }
        js_define_native(vm, ro, "text", fn_fetch_resp, FETCH_RESP_TEXT);
        js_define_native(vm, ro, "json", fn_fetch_resp, FETCH_RESP_JSON);
    }
    vm->gc_pause--;
    return js_obj_val(js_promise_new(vm, 1, js_obj_val(ro)));
}

bool js_step_next_timer(JsVm *vm) {
    if (!vm) return false;
    int best = -1;
    for (int i = 0; i < JS_MAX_TIMERS; i++) {
        if (vm->timers[i].active && !vm->timers[i].repeat) {
            if (best < 0 || vm->timers[i].due_ms < vm->timers[best].due_ms) {
                best = i;
            }
        }
    }
    if (best < 0) return false;
    JsObj *fn   = vm->timers[best].fn_obj;
    bool is_raf = vm->timers[best].is_raf;
    int targc   = vm->timers[best].argc;
    JsVal targs[JS_MAX_TIMER_ARGS];
    for (int a = 0; a < targc; a++) targs[a] = vm->timers[best].args[a];
    vm->timers[best].active = false;
    vm->timers[best].fn_obj = NULL;
    vm->timers[best].argc   = 0;

    if (fn) {
        int saved_sp = vm->temp_sp;
        js_temp_push(vm, js_obj_val(fn));
        for (int a = 0; a < targc; a++) js_temp_push(vm, targs[a]);
        if (is_raf) {
            JsVal ts = js_num((double)(js_now_ms() - vm->boot_ms));
            (void)js_call(vm, js_obj_val(fn), js_obj_val(vm->global_obj), 1, &ts);
        } else {
            (void)js_call(vm, js_obj_val(fn), js_obj_val(vm->global_obj), targc, targs);
        }
        vm->temp_sp = saved_sp;
        js_drain_microtasks(vm);
    }
    return true;
}

void js_dom_init_timers(JsVm *vm) {
    if (!vm || !vm->global_obj) return;
    JsObj *g = vm->global_obj;
    js_define_native(vm, g, "setTimeout", fn_window_api, WIN_SET_TIMEOUT);
    js_define_native(vm, g, "setInterval", fn_window_api, WIN_SET_INTERVAL);
    js_define_native(vm, g, "clearTimeout", fn_window_api, WIN_CLEAR_TIMER);
    js_define_native(vm, g, "clearInterval", fn_window_api, WIN_CLEAR_TIMER);
    js_define_native(vm, g, "requestAnimationFrame", fn_window_api, WIN_RAF);
    js_define_native(vm, g, "cancelAnimationFrame", fn_window_api, WIN_CANCEL_RAF);
}

int js_run_timers(JsVm *vm) {
    if (!vm) return -1;
    js_drain_microtasks(vm);
    int64_t now = js_now_ms();
    for (int i = 0; i < JS_MAX_TIMERS; i++) {
        if (vm->timers[i].active && vm->timers[i].due_ms <= now) {
            JsObj *fn   = vm->timers[i].fn_obj;
            bool is_raf = vm->timers[i].is_raf;
            int targc   = vm->timers[i].argc;
            JsVal targs[JS_MAX_TIMER_ARGS];
            for (int a = 0; a < targc; a++) targs[a] = vm->timers[i].args[a];
            if (vm->timers[i].repeat) {
                vm->timers[i].due_ms = now + vm->timers[i].interval_ms;
            } else {
                vm->timers[i].active = false;
                vm->timers[i].fn_obj = NULL;
                vm->timers[i].argc   = 0;
            }
            if (fn) {
                vm->steps = 0;
                int saved_sp = vm->temp_sp;
                js_temp_push(vm, js_obj_val(fn));
                for (int a = 0; a < targc; a++) js_temp_push(vm, targs[a]);
                if (is_raf) {
                    JsVal ts = js_num((double)(now - vm->boot_ms));
                    js_call(vm, js_obj_val(fn), js_obj_val(vm->global_obj), 1, &ts);
                } else {
                    js_call(vm, js_obj_val(fn), js_obj_val(vm->global_obj), targc, targs);
                }
                vm->temp_sp = saved_sp;
                js_drain_microtasks(vm);
                if (vm->has_thrown) {
                    TbBuf eb;
                    tb_buf_init(&eb);
                    tb_buf_append_cstr(&eb, "Uncaught in timer: ");
                    js_val_format(vm, vm->thrown_val, &eb, 0);
                    js_log(vm, JS_LOG_ERROR, "%s", eb.data ? eb.data : "Error");
                    tb_buf_free(&eb);
                    vm->has_thrown = false;
                    vm->thrown_val = js_undefined();
                }
            }
            now = js_now_ms();
        }
    }

    int64_t min_wait = -1;
    for (int i = 0; i < JS_MAX_TIMERS; i++) {
        if (vm->timers[i].active) {
            int64_t rem = vm->timers[i].due_ms - now;
            if (rem < 0) rem = 0;
            if (min_wait < 0 || rem < min_wait) min_wait = rem;
        }
    }
    return (min_wait > 60000) ? 60000 : (int)min_wait;
}

void js_bind_document(JsVm *vm, DomDocument *doc, const char *url) {
    if (!vm) return;
    vm->doc           = doc;
    vm->current_url   = url;
    vm->pushed_url[0] = '\0';
    if (doc) {
        doc->on_node_destroy = on_dom_node_destroy;
        doc->userdata        = vm;
    }

    vm->gc_pause++;
    JsObj *g = vm->global_obj;
    g->native_tag = NATIVE_TAG_WINDOW;
    js_set_prop(vm, js_obj_val(g), "window", js_obj_val(g));
    js_set_prop(vm, js_obj_val(g), "self", js_obj_val(g));
    js_set_prop(vm, js_obj_val(g), "globalThis", js_obj_val(g));

    /* Element.prototype methods */
    JsObj *ep = vm->elem_proto;
    js_define_native(vm, ep, "appendChild", fn_dom_method, DOM_APPEND_CHILD);
    js_define_native(vm, ep, "insertBefore", fn_dom_method, DOM_INSERT_BEFORE);
    js_define_native(vm, ep, "removeChild", fn_dom_method, DOM_REMOVE_CHILD);
    js_define_native(vm, ep, "replaceChild", fn_dom_method, DOM_REPLACE_CHILD);
    js_define_native(vm, ep, "remove", fn_dom_method, DOM_REMOVE);
    js_define_native(vm, ep, "cloneNode", fn_dom_method, DOM_CLONE_NODE);
    js_define_native(vm, ep, "contains", fn_dom_method, DOM_CONTAINS);
    js_define_native(vm, ep, "append", fn_dom_method, DOM_APPEND);
    js_define_native(vm, ep, "prepend", fn_dom_method, DOM_PREPEND);
    js_define_native(vm, ep, "before", fn_dom_method, DOM_BEFORE);
    js_define_native(vm, ep, "after", fn_dom_method, DOM_AFTER);
    js_define_native(vm, ep, "replaceWith", fn_dom_method, DOM_REPLACE_WITH);
    js_define_native(vm, ep, "replaceChildren", fn_dom_method, DOM_REPLACE_CHILDREN);
    js_define_native(vm, ep, "insertAdjacentHTML", fn_dom_method, DOM_INSERT_ADJ_HTML);
    js_define_native(vm, ep, "insertAdjacentElement", fn_dom_method, DOM_INSERT_ADJ_ELEMENT);
    js_define_native(vm, ep, "insertAdjacentText", fn_dom_method, DOM_INSERT_ADJ_TEXT);
    js_define_native(vm, ep, "getBoundingClientRect", fn_dom_method, DOM_GET_BOUNDING_RECT);
    js_define_native(vm, ep, "getAttribute", fn_dom_method, DOM_GET_ATTRIBUTE);
    js_define_native(vm, ep, "setAttribute", fn_dom_method, DOM_SET_ATTRIBUTE);
    js_define_native(vm, ep, "removeAttribute", fn_dom_method, DOM_REMOVE_ATTRIBUTE);
    js_define_native(vm, ep, "hasAttribute", fn_dom_method, DOM_HAS_ATTRIBUTE);
    js_define_native(vm, ep, "toggleAttribute", fn_dom_method, DOM_TOGGLE_ATTRIBUTE);
    js_define_native(vm, ep, "matches", fn_dom_method, DOM_MATCHES);
    js_define_native(vm, ep, "closest", fn_dom_method, DOM_CLOSEST);
    js_define_native(vm, ep, "addEventListener", fn_dom_method, DOM_ADD_EVENT_LISTENER);
    js_define_native(vm, ep, "removeEventListener", fn_dom_method, DOM_REMOVE_EVENT_LISTENER);
    js_define_native(vm, ep, "dispatchEvent", fn_dom_method, DOM_DISPATCH_EVENT);
    js_define_native(vm, ep, "click", fn_dom_method, DOM_CLICK);
    js_define_native(vm, ep, "focus", fn_dom_method, DOM_FOCUS_BLUR);
    js_define_native(vm, ep, "blur", fn_dom_method, DOM_FOCUS_BLUR);
    js_define_native(vm, ep, "querySelector", fn_dom_method, DOM_QUERY_SELECTOR);
    js_define_native(vm, ep, "querySelectorAll", fn_dom_method, DOM_QUERY_SELECTOR_ALL);
    js_define_native(vm, ep, "getElementsByTagName", fn_dom_method, DOM_GET_ELEMENTS_BY_TAG_NAME);
    js_define_native(vm, ep, "getElementsByClassName", fn_dom_method, DOM_GET_ELEMENTS_BY_CLASS_NAME);

    /* document object */
    JsMapObj *dobj = (JsMapObj *)js_map_new(vm, ep);
    dobj->hdr.native_tag = NATIVE_TAG_DOCUMENT;
    dobj->native_ptr     = doc ? doc->root : NULL;
    vm->doc_obj          = (JsObj *)dobj;
    js_define_native(vm, vm->doc_obj, "getElementById", fn_dom_method, DOM_GET_ELEMENT_BY_ID);
    js_define_native(vm, vm->doc_obj, "querySelector", fn_dom_method, DOM_QUERY_SELECTOR);
    js_define_native(vm, vm->doc_obj, "querySelectorAll", fn_dom_method, DOM_QUERY_SELECTOR_ALL);
    js_define_native(vm, vm->doc_obj, "getElementsByTagName", fn_dom_method, DOM_GET_ELEMENTS_BY_TAG_NAME);
    js_define_native(vm, vm->doc_obj, "getElementsByClassName", fn_dom_method, DOM_GET_ELEMENTS_BY_CLASS_NAME);
    js_define_native(vm, vm->doc_obj, "createElement", fn_dom_method, DOM_CREATE_ELEMENT);
    js_define_native(vm, vm->doc_obj, "createTextNode", fn_dom_method, DOM_CREATE_TEXT_NODE);
    js_define_native(vm, vm->doc_obj, "createDocumentFragment", fn_dom_method, DOM_CREATE_DOCUMENT_FRAGMENT);
    js_define_native(vm, vm->doc_obj, "createComment", fn_dom_method, DOM_CREATE_COMMENT);
    js_set_prop(vm, js_obj_val(g), "document", js_obj_val(vm->doc_obj));

    /* window timers, rAF, getComputedStyle, matchMedia, Event, CustomEvent, alert, scrollTo, fetch */
    js_define_native(vm, g, "setTimeout", fn_window_api, WIN_SET_TIMEOUT);
    js_define_native(vm, g, "setInterval", fn_window_api, WIN_SET_INTERVAL);
    js_define_native(vm, g, "clearTimeout", fn_window_api, WIN_CLEAR_TIMER);
    js_define_native(vm, g, "clearInterval", fn_window_api, WIN_CLEAR_TIMER);
    js_define_native(vm, g, "requestAnimationFrame", fn_window_api, WIN_RAF);
    js_define_native(vm, g, "cancelAnimationFrame", fn_window_api, WIN_CANCEL_RAF);
    js_define_native(vm, g, "getComputedStyle", fn_window_api, WIN_GET_COMPUTED_STYLE);
    js_define_native(vm, g, "matchMedia", fn_window_api, WIN_MATCH_MEDIA);
    js_define_native(vm, g, "Event", fn_event_ctrl, EV_CTOR);
    js_define_native(vm, g, "CustomEvent", fn_event_ctrl, EV_CUSTOM_CTOR);
    js_define_native(vm, g, "alert", fn_window_api, WIN_ALERT);
    js_define_native(vm, g, "scrollTo", fn_window_api, WIN_SCROLL_TO);
    js_define_native(vm, g, "scrollBy", fn_window_api, WIN_SCROLL_TO);
    js_define_native(vm, g, "fetch", fn_fetch, 0);
    js_define_native(vm, g, "addEventListener", fn_dom_method, DOM_ADD_EVENT_LISTENER);
    js_define_native(vm, g, "removeEventListener", fn_dom_method, DOM_REMOVE_EVENT_LISTENER);
    js_define_native(vm, g, "dispatchEvent", fn_dom_method, DOM_DISPATCH_EVENT);

    /* performance */
    JsObj *perf = js_map_new(vm, vm->object_proto);
    perf->native_tag = NATIVE_TAG_PERF;
    js_define_native(vm, perf, "now", fn_window_api, WIN_PERF_NOW);
    js_set_prop(vm, js_obj_val(g), "performance", js_obj_val(perf));

    /* location */
    JsObj *loc = js_map_new(vm, vm->object_proto);
    loc->native_tag = NATIVE_TAG_LOCATION;
    js_define_native(vm, loc, "reload", fn_window_api, WIN_LOC_RELOAD);
    js_define_native(vm, loc, "assign", fn_window_api, WIN_LOC_ASSIGN);
    js_define_native(vm, loc, "replace", fn_window_api, WIN_LOC_REPLACE);
    js_define_native(vm, loc, "toString", fn_window_api, WIN_LOC_TO_STRING);
    js_set_prop(vm, js_obj_val(g), "location", js_obj_val(loc));
    js_set_prop(vm, js_obj_val(vm->doc_obj), "location", js_obj_val(loc));

    /* history */
    JsObj *hist = js_map_new(vm, vm->object_proto);
    vm->history_obj = hist;
    if (hist) {
        js_set_prop(vm, js_obj_val(hist), "length", js_num(1));
        js_set_prop(vm, js_obj_val(hist), "state", js_null());
        js_define_native(vm, hist, "pushState", fn_window_api, WIN_HIST_PUSH_STATE);
        js_define_native(vm, hist, "replaceState", fn_window_api, WIN_HIST_REPLACE_STATE);
        js_define_native(vm, hist, "back", fn_window_api, WIN_HIST_BACK);
        js_define_native(vm, hist, "forward", fn_window_api, WIN_HIST_FORWARD);
        js_define_native(vm, hist, "go", fn_window_api, WIN_HIST_GO);
        js_set_prop(vm, js_obj_val(g), "history", js_obj_val(hist));
    }

    /* navigator */
    JsObj *nav = js_map_new(vm, vm->object_proto);
    js_set_prop(vm, js_obj_val(nav), "userAgent",
                js_obj_val((JsObj *)js_str_cstr(vm, "TB/1.0 (Linux; TUI; TinyJS; <10MB)")));
    js_set_prop(vm, js_obj_val(nav), "language",
                js_obj_val((JsObj *)js_str_cstr(vm, "en-US")));
    js_set_prop(vm, js_obj_val(nav), "onLine", js_bool(true));
    js_set_prop(vm, js_obj_val(g), "navigator", js_obj_val(nav));

    vm->gc_pause--;
}
