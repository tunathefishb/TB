#include "js.h"
#include "net.h"

static void on_dom_node_destroy(void *userdata, DomNode *node) {
    (void)userdata;
    if (node && node->js_wrapper) {
        JsMapObj *m   = (JsMapObj *)node->js_wrapper;
        m->native_ptr = NULL;
        node->js_wrapper = NULL;
    }
}

static bool subtree_has_any_wrapper(const DomNode *n) {
    if (!n) return false;
    if (n->js_wrapper != NULL) return true;
    for (const DomNode *ch = n->first_child; ch; ch = ch->next_sibling) {
        if (subtree_has_any_wrapper(ch)) return true;
    }
    return false;
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
    if (n->owner_doc && top == n->owner_doc->root) {
        return; /* Attached to live document: keep DomNode alive */
    }
    /* Orphan detached subtree: free once its last JS wrapper is swept */
    if (!subtree_has_any_wrapper(top)) {
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
static JsVal fn_classlist(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    DomNode *n = unwrap_node(this_val);
    if (!n) return magic >= 2 ? js_bool(false) : js_undefined();
    if (magic == 0) { /* add */
        for (int i = 0; i < argc; i++) {
            JsStr *s = js_to_str(vm, argv[i]);
            if (s) dom_class_add(n, s->data);
        }
        return js_undefined();
    }
    if (magic == 1) { /* remove */
        for (int i = 0; i < argc; i++) {
            JsStr *s = js_to_str(vm, argv[i]);
            if (s) dom_class_remove(n, s->data);
        }
        return js_undefined();
    }
    if (magic == 2) { /* toggle */
        if (argc == 0) return js_bool(false);
        JsStr *s  = js_to_str(vm, argv[0]);
        int force = (argc > 1 && argv[1].type != JS_UNDEFINED) ? (js_to_bool(argv[1]) ? 1 : 0) : -1;
        return js_bool(s ? dom_class_toggle(n, s->data, force) : false);
    }
    /* contains */
    if (argc == 0) return js_bool(false);
    JsStr *s = js_to_str(vm, argv[0]);
    return js_bool(s && dom_class_contains(n, s->data));
}

static JsObj *make_proxy_obj(JsVm *vm, DomNode *node, JsNativeTag tag) {
    vm->gc_pause++;
    JsMapObj *m = (JsMapObj *)js_map_new(vm, vm->object_proto);
    if (m) {
        m->hdr.native_tag = (uint8_t)tag;
        m->native_ptr     = node;
        if (tag == NATIVE_TAG_CLASSLIST) {
            js_define_native(vm, (JsObj *)m, "add", fn_classlist, 0);
            js_define_native(vm, (JsObj *)m, "remove", fn_classlist, 1);
            js_define_native(vm, (JsObj *)m, "toggle", fn_classlist, 2);
            js_define_native(vm, (JsObj *)m, "contains", fn_classlist, 3);
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

/* Virtual Getters & Setters on DOM / Window / Style / Location / Performance */
bool js_dom_get_virtual(JsVm *vm, JsMapObj *m, const char *key, JsVal *out) {
    JsNativeTag tag = (JsNativeTag)m->hdr.native_tag;

    if (tag == NATIVE_TAG_WINDOW) {
        if (strcmp(key, "innerWidth") == 0)  { *out = js_num(vm->viewport_w > 0 ? vm->viewport_w : 80); return true; }
        if (strcmp(key, "innerHeight") == 0) { *out = js_num(vm->viewport_h > 0 ? vm->viewport_h : 24); return true; }
        if (strcmp(key, "scrollY") == 0 || strcmp(key, "pageYOffset") == 0) {
            int sy = vm->scroll_y_ptr ? *vm->scroll_y_ptr : vm->scroll_y;
            *out = js_num((double)sy);
            return true;
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
        const char *u_raw = vm->current_url ? vm->current_url : "about:blank";
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
        if (strcmp(key, "host") == 0 || strcmp(key, "hostname") == 0) {
            *out = js_obj_val((JsObj *)js_str_cstr(vm, ok ? u.host : ""));
            return true;
        }
        if (strcmp(key, "pathname") == 0) {
            *out = js_obj_val((JsObj *)js_str_cstr(vm, ok ? u.path : ""));
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

    if (tag == NATIVE_TAG_STYLE) {
        DomNode *n = (DomNode *)m->native_ptr;
        if (!n) { *out = js_obj_val((JsObj *)js_str_cstr(vm, "")); return true; }
        if (strcmp(key, "cssText") == 0) {
            const char *s = dom_get_attr(n, "style");
            *out = js_obj_val((JsObj *)js_str_cstr(vm, s ? s : ""));
            return true;
        }
        char kebab[64];
        camel_to_kebab(key, kebab, sizeof(kebab));
        const char *inl = dom_get_attr(n, "style");
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
            const char *tn = dom_node_tag_name(n);
            char up[64];
            size_t i = 0;
            for (; tn[i] && i + 1 < sizeof(up); i++) up[i] = tb_toupper(tn[i]);
            up[i] = '\0';
            *out = js_obj_val((JsObj *)js_str_cstr(vm, up));
            return true;
        }
        if (strcmp(key, "nodeType") == 0) {
            int nt = (n->type == DOM_NODE_ELEMENT) ? 1 : (n->type == DOM_NODE_TEXT ? 3 : 9);
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

    if (tag == NATIVE_TAG_LOCATION) {
        if (strcmp(key, "href") == 0) {
            JsStr *s = js_to_str(vm, val);
            if (s && vm->on_navigate) vm->on_navigate(vm->host_userdata, s->data, false);
            return true;
        }
        return false;
    }

    if (tag == NATIVE_TAG_STYLE) {
        DomNode *n = (DomNode *)m->native_ptr;
        if (!n) return true;
        JsStr *vs = js_to_str(vm, val);
        const char *vstr = vs ? vs->data : "";
        if (strcmp(key, "cssText") == 0) {
            dom_set_attr(n, "style", vstr);
            return true;
        }
        char kebab[64];
        camel_to_kebab(key, kebab, sizeof(kebab));
        const char *old_s = dom_get_attr(n, "style");
        TbBuf b;
        tb_buf_init(&b);
        if (old_s && *old_s) {
            tb_buf_append_cstr(&b, old_s);
            if (b.len > 0 && b.data[b.len - 1] != ';') tb_buf_append_char(&b, ';');
        }
        tb_buf_printf(&b, "%s:%s;", kebab, vstr);
        dom_set_attr(n, "style", b.data ? b.data : "");
        tb_buf_free(&b);
        css_apply_decl(&n->style, kebab, vstr);
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
    }
    return false;
}

/* Document & Element Native Methods */
static JsVal fn_dom_method(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    DomNode *n = unwrap_node(this_val);
    if (!n && vm->doc && (magic >= 20 && magic <= 28)) n = vm->doc->root;
    if (!n) return js_null();

    switch (magic) {
        /* Document creation & queries */
        case 20: { /* getElementById */
            JsStr *id = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            return id ? js_wrap_dom_node(vm, dom_get_element_by_id(n, id->data)) : js_null();
        }
        case 21: { /* querySelector */
            JsStr *sel = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            return sel ? js_wrap_dom_node(vm, dom_query_selector(n, sel->data)) : js_null();
        }
        case 22:   /* querySelectorAll */
        case 23:   /* getElementsByTagName */
        case 24: { /* getElementsByClassName */
            JsStr *arg = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            vm->gc_pause++;
            JsObj *arr = js_arr_new(vm, 8);
            if (arg && arg->len > 0) {
                char sel_buf[256];
                const char *sel = arg->data;
                if (magic == 23) {
                    snprintf(sel_buf, sizeof(sel_buf), "%s", arg->data);
                    sel = sel_buf;
                } else if (magic == 24) {
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
        case 25: { /* createElement */
            if (!vm->doc) return js_null();
            JsStr *tn = argc > 0 ? js_to_str(vm, argv[0]) : js_str_cstr(vm, "div");
            DomNode *el = dom_create_element(vm->doc, tn ? tn->data : "div");
            return js_wrap_dom_node(vm, el);
        }
        case 26: { /* createTextNode */
            if (!vm->doc) return js_null();
            JsStr *tx = argc > 0 ? js_to_str(vm, argv[0]) : js_str_cstr(vm, "");
            DomNode *tn = dom_create_text(vm->doc, tx ? tx->data : "");
            return js_wrap_dom_node(vm, tn);
        }

        /* Node tree mutations */
        case 0: { /* appendChild */
            DomNode *ch = argc > 0 ? unwrap_node(argv[0]) : NULL;
            if (!ch || !dom_append_child(n, ch)) return js_null();
            return argv[0];
        }
        case 1: { /* insertBefore */
            DomNode *nn  = argc > 0 ? unwrap_node(argv[0]) : NULL;
            DomNode *ref = (argc > 1 && argv[1].type != JS_NULL) ? unwrap_node(argv[1]) : NULL;
            if (!nn || !dom_insert_before(n, nn, ref)) return js_null();
            return argv[0];
        }
        case 2: { /* removeChild */
            DomNode *ch = argc > 0 ? unwrap_node(argv[0]) : NULL;
            if (!ch || !dom_remove_child(n, ch)) return js_null();
            return argv[0];
        }
        case 3: { /* replaceChild */
            DomNode *nn = argc > 0 ? unwrap_node(argv[0]) : NULL;
            DomNode *on = argc > 1 ? unwrap_node(argv[1]) : NULL;
            if (!nn || !on || !dom_replace_child(n, nn, on)) return js_null();
            return argv[1];
        }
        case 4: { /* remove */
            if (n->parent) dom_remove_child(n->parent, n);
            return js_undefined();
        }
        case 5: { /* cloneNode */
            bool deep = argc > 0 && js_to_bool(argv[0]);
            DomNode *cl = dom_clone_node(vm->doc, n, deep);
            return js_wrap_dom_node(vm, cl);
        }

        /* Attributes & Matching */
        case 6: { /* getAttribute */
            JsStr *nm = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            const char *v = nm ? dom_get_attr(n, nm->data) : NULL;
            return v ? js_obj_val((JsObj *)js_str_cstr(vm, v)) : js_null();
        }
        case 7: { /* setAttribute */
            if (argc >= 2) {
                JsStr *nm = js_to_str(vm, argv[0]);
                JsStr *vl = js_to_str(vm, argv[1]);
                if (nm) dom_set_attr(n, nm->data, vl ? vl->data : "");
            }
            return js_undefined();
        }
        case 8: { /* removeAttribute */
            JsStr *nm = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            if (nm) dom_remove_attr(n, nm->data);
            return js_undefined();
        }
        case 9: { /* hasAttribute */
            JsStr *nm = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            return js_bool(nm && dom_has_attr(n, nm->data));
        }
        case 10: { /* matches */
            JsStr *sel = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            return js_bool(sel && dom_matches_selector(n, sel->data));
        }
        case 11: { /* closest */
            JsStr *sel = argc > 0 ? js_to_str(vm, argv[0]) : NULL;
            if (!sel) return js_null();
            for (DomNode *cur = n; cur && cur->type == DOM_NODE_ELEMENT; cur = cur->parent) {
                if (dom_matches_selector(cur, sel->data)) return js_wrap_dom_node(vm, cur);
            }
            return js_null();
        }

        /* Event Listeners & Programmatic click() */
        case 12: { /* addEventListener */
            if (argc >= 2 && argv[1].type == JS_OBJECT && argv[1].u.obj) {
                JsStr *tp = js_to_str(vm, argv[0]);
                if (tp) add_node_listener(n, tp->data, argv[1].u.obj, false);
            }
            return js_undefined();
        }
        case 13: { /* removeEventListener */
            if (argc >= 2 && argv[1].type == JS_OBJECT) {
                JsStr *tp = js_to_str(vm, argv[0]);
                if (tp) remove_node_listener(n, tp->data, argv[1].u.obj);
            }
            return js_undefined();
        }
        case 14: { /* click() */
            js_dispatch_dom_event(vm, n, "click", NULL, true);
            return js_undefined();
        }
        case 15: /* focus() / blur() */
            return js_undefined();
        default:
            return js_undefined();
    }
}

/* Event object methods: preventDefault() & stopPropagation() */
static JsVal fn_event_ctrl(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)argc; (void)argv;
    if (magic == 0) js_set_prop(vm, this_val, "defaultPrevented", js_bool(true));
    else js_set_prop(vm, this_val, "_stopped", js_bool(true));
    return js_undefined();
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
    js_set_prop(vm, ev_val, "defaultPrevented", js_bool(false));
    js_set_prop(vm, ev_val, "_stopped", js_bool(false));
    if (key_name) js_set_prop(vm, ev_val, "key", js_obj_val((JsObj *)js_str_cstr(vm, key_name)));
    js_define_native(vm, ev, "preventDefault", fn_event_ctrl, 0);
    js_define_native(vm, ev, "stopPropagation", fn_event_ctrl, 1);
    vm->gc_pause--;

    js_temp_push(vm, ev_val);

    DomNode *cur = target;
    while (cur) {
        if (cur->type == DOM_NODE_ELEMENT) {
            ensure_inline_handler_compiled(vm, cur, type);
        }
        if (cur->listeners) {
            JsVal cur_wrap = js_wrap_dom_node(vm, cur);
            js_set_prop(vm, ev_val, "currentTarget", cur_wrap);

            /* Snapshot listeners on this node in case handler mutates listeners */
            JsObj *fns[32];
            int nfns = 0;
            for (DomListener *ls = cur->listeners; ls && nfns < 32; ls = ls->next) {
                if (strcmp(ls->type, type) == 0 && ls->js_fn) {
                    fns[nfns++] = (JsObj *)ls->js_fn;
                }
            }
            for (int i = 0; i < nfns; i++) {
                vm->steps = 0;
                js_call(vm, js_obj_val(fns[i]), cur_wrap, 1, &ev_val);
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
            }
        }
        if (!bubbles) break;
        JsVal stopped = js_get_prop(vm, ev_val, "_stopped");
        if (js_to_bool(stopped)) break;
        cur = cur->parent;
    }

    bool prevented = js_to_bool(js_get_prop(vm, ev_val, "defaultPrevented"));
    vm->temp_sp = sp;
    return !prevented;
}

/* Timers & Window APIs & Fetch */
static JsVal fn_window_api(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val;
    switch (magic) {
        case 0:   /* setTimeout */
        case 1: { /* setInterval */
            if (argc == 0 || argv[0].type != JS_OBJECT || !argv[0].u.obj) return js_num(0);
            int64_t delay = argc > 1 ? (int64_t)js_to_num(vm, argv[1]) : 0;
            if (delay < 0) delay = 0;
            for (int i = 0; i < JS_MAX_TIMERS; i++) {
                if (!vm->timers[i].active) {
                    int id = vm->next_timer_id++;
                    vm->timers[i].id          = id;
                    vm->timers[i].active      = true;
                    vm->timers[i].repeat      = (magic == 1);
                    vm->timers[i].interval_ms = (magic == 1 && delay < 10) ? 10 : delay;
                    vm->timers[i].due_ms      = js_now_ms() + delay;
                    vm->timers[i].fn_obj      = argv[0].u.obj;
                    return js_num((double)id);
                }
            }
            return js_num(0);
        }
        case 2: { /* clearTimeout / clearInterval */
            int id = argc > 0 ? (int)js_to_num(vm, argv[0]) : 0;
            for (int i = 0; i < JS_MAX_TIMERS; i++) {
                if (vm->timers[i].active && vm->timers[i].id == id) {
                    vm->timers[i].active = false;
                    vm->timers[i].fn_obj = NULL;
                }
            }
            return js_undefined();
        }
        case 3: { /* performance.now() */
            return js_num((double)(js_now_ms() - vm->boot_ms));
        }
        case 4: { /* alert() */
            JsStr *s = argc > 0 ? js_to_str(vm, argv[0]) : js_str_cstr(vm, "");
            if (vm->on_alert && s) vm->on_alert(vm->host_userdata, s->data);
            js_log(vm, JS_LOG_INFO, "[alert] %s", s ? s->data : "");
            return js_undefined();
        }
        case 5: { /* window.scrollTo(x, y) */
            int ny = argc > 1 ? (int)js_to_num(vm, argv[1]) : (argc > 0 ? (int)js_to_num(vm, argv[0]) : 0);
            if (ny < 0) ny = 0;
            vm->scroll_y = ny;
            if (vm->scroll_y_ptr) *vm->scroll_y_ptr = ny;
            return js_undefined();
        }
        case 6: { /* location.reload() */
            if (vm->on_navigate) vm->on_navigate(vm->host_userdata, vm->current_url, true);
            return js_undefined();
        }
        default:
            return js_undefined();
    }
}

/* Synchronous Promise-like object for fetch() `.then(...).catch(...)` */
static JsVal make_sync_promise(JsVm *vm, JsVal val, bool rejected);

static JsVal fn_promise_chain(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    bool is_rej = js_to_bool(js_get_prop(vm, this_val, "_rej"));
    JsVal cur   = js_get_prop(vm, this_val, "_val");
    if (magic == 0) { /* .then(onFulfilled, onRejected) */
        if (!is_rej && argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj) {
            JsVal nxt = js_call(vm, argv[0], js_undefined(), 1, &cur);
            if (vm->has_thrown) {
                JsVal tv = vm->thrown_val;
                vm->has_thrown = false;
                vm->thrown_val = js_undefined();
                return make_sync_promise(vm, tv, true);
            }
            if (nxt.type == JS_OBJECT && nxt.u.obj &&
                js_to_bool(js_get_prop(vm, nxt, "_isPromise"))) {
                return nxt;
            }
            return make_sync_promise(vm, nxt, false);
        }
        if (is_rej && argc > 1 && argv[1].type == JS_OBJECT && argv[1].u.obj) {
            JsVal nxt = js_call(vm, argv[1], js_undefined(), 1, &cur);
            vm->has_thrown = false;
            return make_sync_promise(vm, nxt, false);
        }
        return this_val;
    }
    /* .catch(onRejected) */
    if (is_rej && argc > 0 && argv[0].type == JS_OBJECT && argv[0].u.obj) {
        JsVal nxt = js_call(vm, argv[0], js_undefined(), 1, &cur);
        vm->has_thrown = false;
        return make_sync_promise(vm, nxt, false);
    }
    return this_val;
}

static JsVal make_sync_promise(JsVm *vm, JsVal val, bool rejected) {
    int sp = vm->temp_sp;
    js_temp_push(vm, val);
    vm->gc_pause++;
    JsObj *p = js_map_new(vm, vm->object_proto);
    if (p) {
        js_set_prop(vm, js_obj_val(p), "_isPromise", js_bool(true));
        js_set_prop(vm, js_obj_val(p), "_rej", js_bool(rejected));
        js_set_prop(vm, js_obj_val(p), "_val", val);
        js_define_native(vm, p, "then", fn_promise_chain, 0);
        js_define_native(vm, p, "catch", fn_promise_chain, 1);
    }
    vm->gc_pause--;
    vm->temp_sp = sp;
    return js_obj_val(p);
}

static JsVal fn_fetch_resp(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)argc; (void)argv;
    JsVal body = js_get_prop(vm, this_val, "_body");
    if (magic == 0) return make_sync_promise(vm, body, false); /* .text() */
    /* .json() */
    JsVal json_obj = js_get_prop(vm, js_obj_val(vm->global_obj), "JSON");
    JsVal parse_fn = js_get_prop(vm, json_obj, "parse");
    JsVal parsed   = js_call(vm, parse_fn, json_obj, 1, &body);
    if (vm->has_thrown) {
        JsVal tv = vm->thrown_val;
        vm->has_thrown = false;
        vm->thrown_val = js_undefined();
        return make_sync_promise(vm, tv, true);
    }
    return make_sync_promise(vm, parsed, false);
}

static JsVal fn_fetch(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic) {
    (void)this_val; (void)magic;
    if (argc == 0 || !vm->on_fetch) {
        return make_sync_promise(vm, js_obj_val((JsObj *)js_str_cstr(vm, "fetch unavailable")), true);
    }
    JsStr *url_s = js_to_str(vm, argv[0]);
    const char *method = "GET";
    const char *body   = NULL;
    JsStr *m_str = NULL, *b_str = NULL;
    if (argc > 1 && argv[1].type == JS_OBJECT && argv[1].u.obj) {
        JsVal mv = js_get_prop(vm, argv[1], "method");
        if (mv.type != JS_UNDEFINED) { m_str = js_to_str(vm, mv); if (m_str) method = m_str->data; }
        JsVal bv = js_get_prop(vm, argv[1], "body");
        if (bv.type != JS_UNDEFINED) { b_str = js_to_str(vm, bv); if (b_str) body = b_str->data; }
    }

    int status = 0;
    char *text = NULL;
    bool ok = vm->on_fetch(vm->host_userdata, url_s ? url_s->data : "", method, body, &status, &text);
    if (!ok) {
        JsVal err = js_obj_val((JsObj *)js_str_cstr(vm, text ? text : "NetworkError"));
        tb_free(text);
        return make_sync_promise(vm, err, true);
    }

    vm->gc_pause++;
    JsObj *ro = js_map_new(vm, vm->object_proto);
    JsStr *bs = js_str_cstr(vm, text ? text : "");
    tb_free(text);
    if (ro) {
        js_set_prop(vm, js_obj_val(ro), "status", js_num((double)status));
        js_set_prop(vm, js_obj_val(ro), "ok", js_bool(status >= 200 && status < 300));
        js_set_prop(vm, js_obj_val(ro), "_body", js_obj_val((JsObj *)bs));
        js_define_native(vm, ro, "text", fn_fetch_resp, 0);
        js_define_native(vm, ro, "json", fn_fetch_resp, 1);
    }
    vm->gc_pause--;
    return make_sync_promise(vm, js_obj_val(ro), false);
}

int js_run_timers(JsVm *vm) {
    if (!vm) return -1;
    int64_t now = js_now_ms();
    for (int i = 0; i < JS_MAX_TIMERS; i++) {
        if (vm->timers[i].active && vm->timers[i].due_ms <= now) {
            JsObj *fn = vm->timers[i].fn_obj;
            if (vm->timers[i].repeat) {
                vm->timers[i].due_ms = now + vm->timers[i].interval_ms;
            } else {
                vm->timers[i].active = false;
                vm->timers[i].fn_obj = NULL;
            }
            if (fn) {
                vm->steps = 0;
                js_call(vm, js_obj_val(fn), js_obj_val(vm->global_obj), 0, NULL);
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
    vm->doc         = doc;
    vm->current_url = url;
    if (doc) {
        doc->on_node_destroy = on_dom_node_destroy;
        doc->userdata        = vm;
    }

    vm->gc_pause++;
    JsObj *g = vm->global_obj;
    g->native_tag = NATIVE_TAG_WINDOW;
    js_set_prop(vm, js_obj_val(g), "window", js_obj_val(g));
    js_set_prop(vm, js_obj_val(g), "self", js_obj_val(g));

    /* Element.prototype methods */
    JsObj *ep = vm->elem_proto;
    js_define_native(vm, ep, "appendChild", fn_dom_method, 0);
    js_define_native(vm, ep, "insertBefore", fn_dom_method, 1);
    js_define_native(vm, ep, "removeChild", fn_dom_method, 2);
    js_define_native(vm, ep, "replaceChild", fn_dom_method, 3);
    js_define_native(vm, ep, "remove", fn_dom_method, 4);
    js_define_native(vm, ep, "cloneNode", fn_dom_method, 5);
    js_define_native(vm, ep, "getAttribute", fn_dom_method, 6);
    js_define_native(vm, ep, "setAttribute", fn_dom_method, 7);
    js_define_native(vm, ep, "removeAttribute", fn_dom_method, 8);
    js_define_native(vm, ep, "hasAttribute", fn_dom_method, 9);
    js_define_native(vm, ep, "matches", fn_dom_method, 10);
    js_define_native(vm, ep, "closest", fn_dom_method, 11);
    js_define_native(vm, ep, "addEventListener", fn_dom_method, 12);
    js_define_native(vm, ep, "removeEventListener", fn_dom_method, 13);
    js_define_native(vm, ep, "click", fn_dom_method, 14);
    js_define_native(vm, ep, "focus", fn_dom_method, 15);
    js_define_native(vm, ep, "blur", fn_dom_method, 15);
    js_define_native(vm, ep, "querySelector", fn_dom_method, 21);
    js_define_native(vm, ep, "querySelectorAll", fn_dom_method, 22);
    js_define_native(vm, ep, "getElementsByTagName", fn_dom_method, 23);
    js_define_native(vm, ep, "getElementsByClassName", fn_dom_method, 24);

    /* document object */
    JsMapObj *dobj = (JsMapObj *)js_map_new(vm, ep);
    dobj->hdr.native_tag = NATIVE_TAG_DOCUMENT;
    dobj->native_ptr     = doc ? doc->root : NULL;
    vm->doc_obj          = (JsObj *)dobj;
    js_define_native(vm, vm->doc_obj, "getElementById", fn_dom_method, 20);
    js_define_native(vm, vm->doc_obj, "querySelector", fn_dom_method, 21);
    js_define_native(vm, vm->doc_obj, "querySelectorAll", fn_dom_method, 22);
    js_define_native(vm, vm->doc_obj, "getElementsByTagName", fn_dom_method, 23);
    js_define_native(vm, vm->doc_obj, "getElementsByClassName", fn_dom_method, 24);
    js_define_native(vm, vm->doc_obj, "createElement", fn_dom_method, 25);
    js_define_native(vm, vm->doc_obj, "createTextNode", fn_dom_method, 26);
    js_set_prop(vm, js_obj_val(g), "document", js_obj_val(vm->doc_obj));

    /* window timers, alert, scrollTo, fetch */
    js_define_native(vm, g, "setTimeout", fn_window_api, 0);
    js_define_native(vm, g, "setInterval", fn_window_api, 1);
    js_define_native(vm, g, "clearTimeout", fn_window_api, 2);
    js_define_native(vm, g, "clearInterval", fn_window_api, 2);
    js_define_native(vm, g, "alert", fn_window_api, 4);
    js_define_native(vm, g, "scrollTo", fn_window_api, 5);
    js_define_native(vm, g, "fetch", fn_fetch, 0);
    js_define_native(vm, g, "addEventListener", fn_dom_method, 12);

    /* performance */
    JsObj *perf = js_map_new(vm, vm->object_proto);
    perf->native_tag = NATIVE_TAG_PERF;
    js_define_native(vm, perf, "now", fn_window_api, 3);
    js_set_prop(vm, js_obj_val(g), "performance", js_obj_val(perf));

    /* location */
    JsObj *loc = js_map_new(vm, vm->object_proto);
    loc->native_tag = NATIVE_TAG_LOCATION;
    js_define_native(vm, loc, "reload", fn_window_api, 6);
    js_set_prop(vm, js_obj_val(g), "location", js_obj_val(loc));

    /* navigator */
    JsObj *nav = js_map_new(vm, vm->object_proto);
    js_set_prop(vm, js_obj_val(nav), "userAgent",
                js_obj_val((JsObj *)js_str_cstr(vm, "TB/1.0 (Linux; TUI; TinyJS; <10MB)")));
    js_set_prop(vm, js_obj_val(g), "navigator", js_obj_val(nav));

    vm->gc_pause--;
}
