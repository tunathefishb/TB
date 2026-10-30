#include "browser.h"

static void clear_console_logs(TbBrowser *b) {
    for (int i = 0; i < b->console_count; i++) {
        tb_free(b->console_logs[i].text);
        b->console_logs[i].text = NULL;
    }
    b->console_count = 0;
}

void tb_browser_log(TbBrowser *b, JsLogLevel level, const char *msg) {
    if (!b) return;
    if (level == JS_LOG_CLEAR) {
        clear_console_logs(b);
        return;
    }
    if (b->console_count >= TB_CONSOLE_MAX) {
        tb_free(b->console_logs[0].text);
        memmove(&b->console_logs[0], &b->console_logs[1],
                (TB_CONSOLE_MAX - 1) * sizeof(TbConsoleEntry));
        b->console_count = TB_CONSOLE_MAX - 1;
    }
    b->console_logs[b->console_count].level = level;
    b->console_logs[b->console_count].text  = tb_strdup(msg ? msg : "");
    b->console_count++;
}

static void cb_console(void *ud, JsLogLevel level, const char *msg) {
    tb_browser_log((TbBrowser *)ud, level, msg);
}

static void cb_alert(void *ud, const char *msg) {
    TbBrowser *b = (TbBrowser *)ud;
    snprintf(b->status_msg, sizeof(b->status_msg), "ALERT: %s", msg ? msg : "");
}

static void cb_navigate(void *ud, const char *url, bool reload) {
    TbBrowser *b = (TbBrowser *)ud;
    if (!b) return;
    b->pending_nav    = true;
    b->pending_reload = reload;
    if (reload || !url || !*url) {
        snprintf(b->pending_url, sizeof(b->pending_url), "%s", b->current_url);
    } else {
        TbUrl base;
        if (tb_url_parse(b->current_url, &base)) {
            tb_url_resolve(&base, url, b->pending_url, sizeof(b->pending_url));
        } else {
            tb_url_normalize_input(url, b->pending_url, sizeof(b->pending_url));
        }
    }
}

static bool cb_fetch(void *ud, const char *url, const char *method,
                     const char *body, int *out_status, char **out_text) {
    TbBrowser *b = (TbBrowser *)ud;
    char resolved[1536];
    TbUrl base;
    if (tb_url_parse(b->current_url, &base)) {
        tb_url_resolve(&base, url, resolved, sizeof(resolved));
    } else {
        tb_url_normalize_input(url, resolved, sizeof(resolved));
    }

    TbResponse resp;
    if (!tb_fetch(resolved, method, body, "application/json", b->insecure_tls, &resp)) {
        *out_status = 0;
        *out_text   = tb_strdup(resp.error);
        tb_response_free(&resp);
        return false;
    }
    *out_status = resp.status;
    *out_text   = resp.body;
    resp.body   = NULL; /* Transfer ownership */
    tb_response_free(&resp);
    return true;
}

void tb_browser_init(TbBrowser *b, int vw, int vh, bool insecure_tls) {
    memset(b, 0, sizeof(*b));
    b->viewport_w   = vw > 20 ? vw : 80;
    b->viewport_h   = vh > 6 ? vh : 24;
    b->insecure_tls = insecure_tls;
    b->focused_hit  = -1;
    b->hist_index   = -1;
    layout_init(&b->layout);
}

static void teardown_current_page(TbBrowser *b) {
    b->editing_node = NULL;
    b->edit_cursor  = 0;
    b->focused_hit  = -1;
    if (b->vm) {
        js_vm_free(b->vm);
        b->vm = NULL;
    }
    if (b->doc) {
        dom_doc_free(b->doc);
        b->doc = NULL;
    }
    layout_free(&b->layout);
    layout_init(&b->layout);
    tb_mem_trim();
}

void tb_browser_free(TbBrowser *b) {
    if (!b) return;
    teardown_current_page(b);
    layout_free(&b->layout);
    clear_console_logs(b);
    tb_net_cleanup();
    tb_mem_trim();
}

static void collect_scripts_rec(DomNode *n, DomNodeList *out) {
    if (!n) return;
    if (n->type == DOM_NODE_ELEMENT && n->tag == TAG_SCRIPT) {
        dom_nodelist_push(out, n);
        return;
    }
    for (DomNode *ch = n->first_child; ch; ch = ch->next_sibling) {
        collect_scripts_rec(ch, out);
    }
}

static void execute_page_scripts(TbBrowser *b) {
    if (!b->doc || !b->vm) return;
    DomNodeList scripts;
    dom_nodelist_init(&scripts);
    collect_scripts_rec(b->doc->root, &scripts);

    int ext_loaded = 0;
    TbUrl base_url;
    bool has_base = tb_url_parse(b->current_url, &base_url);

    for (size_t i = 0; i < scripts.count; i++) {
        DomNode *sn = scripts.items[i];
        const char *type = dom_get_attr(sn, "type");
        if (type && *type &&
            tb_strcasecmp(type, "text/javascript") != 0 &&
            tb_strcasecmp(type, "application/javascript") != 0 &&
            tb_strcasecmp(type, "module") != 0) {
            continue; /* Skip application/ld+json etc. */
        }

        const char *src = dom_get_attr(sn, "src");
        if (src && *src) {
            if (ext_loaded >= 8) continue;
            char s_url[1536];
            if (has_base) tb_url_resolve(&base_url, src, s_url, sizeof(s_url));
            else tb_url_normalize_input(src, s_url, sizeof(s_url));

            TbResponse sresp;
            if (tb_fetch(s_url, "GET", NULL, NULL, b->insecure_tls, &sresp) &&
                sresp.status >= 200 && sresp.status < 400 && sresp.body) {
                ext_loaded++;
                js_eval(b->vm, sresp.body, sresp.body_len, NULL);
            } else {
                tb_browser_log(b, JS_LOG_WARN, "Failed loading external script");
            }
            tb_response_free(&sresp);
        } else {
            char *code = dom_get_text_content(sn);
            if (code && *code) {
                js_eval(b->vm, code, strlen(code), NULL);
            }
            tb_free(code);
        }
    }
    dom_nodelist_free(&scripts);

    /* Fire DOMContentLoaded & load events + run 0ms timers */
    js_dispatch_dom_event(b->vm, b->doc->root, "DOMContentLoaded", NULL, false);
    if (b->doc->body) {
        js_dispatch_dom_event(b->vm, b->doc->body, "load", NULL, false);
    }
    js_run_timers(b->vm);
}

static void sync_page_title(TbBrowser *b) {
    if (!b->doc) {
        snprintf(b->page_title, sizeof(b->page_title), "TB");
        return;
    }
    char *t = dom_get_title(b->doc);
    if (t && *t) snprintf(b->page_title, sizeof(b->page_title), "%.255s", t);
    else snprintf(b->page_title, sizeof(b->page_title), "%.255s", b->current_url);
    tb_free(t);
}

static void process_pending_nav(TbBrowser *b) {
    int guard = 0;
    while (b->pending_nav && guard++ < 4) {
        b->pending_nav = false;
        bool rel = b->pending_reload;
        b->pending_reload = false;
        char target[1536];
        snprintf(target, sizeof(target), "%s", b->pending_url);
        tb_browser_navigate(b, target, !rel);
    }
}

void tb_browser_relayout_if_needed(TbBrowser *b, bool force) {
    if (!b || !b->doc) return;
    DomNode *focused_node = (b->focused_hit >= 0 && b->focused_hit < b->layout.hit_count)
                                ? b->layout.hits[b->focused_hit].node
                                : NULL;
    if (force || b->doc->dirty_style || b->doc->dirty_layout ||
        b->layout.viewport_w != b->viewport_w) {
        if (b->vm) {
            b->vm->viewport_w = b->viewport_w;
            b->vm->viewport_h = b->viewport_h;
        }
        layout_build(&b->layout, b->doc, b->viewport_w, b->editing_node, b->edit_cursor);
        sync_page_title(b);
        if (focused_node) {
            b->focused_hit = layout_find_node_hit(&b->layout, focused_node);
        } else if (b->focused_hit >= b->layout.hit_count) {
            b->focused_hit = b->layout.hit_count - 1;
        }
    }
}

static bool navigate_with_method(TbBrowser *b, const char *raw_url, const char *method,
                                 const char *post_body, bool push_history) {
    char norm[1536];
    tb_url_normalize_input(raw_url, norm, sizeof(norm));

    /* Save current scroll position in history before leaving */
    if (b->hist_index >= 0 && b->hist_index < b->hist_count) {
        b->history[b->hist_index].scroll_y = b->scroll_y;
    }

    /* Free previous page BEFORE fetching new page so peak memory never doubles */
    teardown_current_page(b);

    TbResponse resp;
    bool ok = tb_fetch(norm, method, post_body, "application/x-www-form-urlencoded",
                       b->insecure_tls, &resp);
    if (!ok) {
        snprintf(b->current_url, sizeof(b->current_url), "%s", norm);
        snprintf(b->status_msg, sizeof(b->status_msg), "Error: %.240s", resp.error);
        TbBuf err_html;
        tb_buf_init(&err_html);
        tb_buf_printf(&err_html,
                      "<html><head><title>Navigation Error</title></head><body>"
                      "<div style='border:1px solid #f87171; padding:1 2; margin:1 2;'>"
                      "<h1 style='color:#f87171'>Navigation Failed</h1>"
                      "<p><strong>URL:</strong> %s</p>"
                      "<p><strong>Reason:</strong> %s</p>"
                      "<p><a href='about:home'>Return to about:home</a></p>"
                      "</div></body></html>",
                      norm, resp.error);
        b->doc = dom_parse_html(err_html.data, err_html.len);
        tb_buf_free(&err_html);
        b->http_status = 0;
    } else {
        snprintf(b->current_url, sizeof(b->current_url), "%s", resp.final_url);
        b->http_status = resp.status;
        snprintf(b->status_msg, sizeof(b->status_msg), "HTTP %d (%zu bytes)",
                 resp.status, resp.body_len);

        if (strstr(resp.content_type, "text/plain") || strstr(resp.content_type, "application/json")) {
            TbBuf pre;
            tb_buf_init(&pre);
            tb_buf_append_cstr(&pre, "<html><body><pre>");
            for (size_t i = 0; i < resp.body_len; i++) {
                char c = resp.body[i];
                if (c == '<') tb_buf_append_cstr(&pre, "&lt;");
                else if (c == '>') tb_buf_append_cstr(&pre, "&gt;");
                else if (c == '&') tb_buf_append_cstr(&pre, "&amp;");
                else tb_buf_append_char(&pre, c);
            }
            tb_buf_append_cstr(&pre, "</pre></body></html>");
            b->doc = dom_parse_html(pre.data, pre.len);
            tb_buf_free(&pre);
        } else {
            b->doc = dom_parse_html(resp.body, resp.body_len);
        }
    }
    /* Free raw HTML buffer immediately now that DOM is constructed */
    tb_response_free(&resp);

    b->scroll_y = 0;
    b->vm       = js_vm_new();
    if (b->vm && b->doc) {
        b->vm->viewport_w    = b->viewport_w;
        b->vm->viewport_h    = b->viewport_h;
        b->vm->scroll_y_ptr  = &b->scroll_y;
        b->vm->on_console    = cb_console;
        b->vm->on_alert      = cb_alert;
        b->vm->on_navigate   = cb_navigate;
        b->vm->on_fetch      = cb_fetch;
        b->vm->host_userdata = b;

        js_bind_document(b->vm, b->doc, b->current_url);
        execute_page_scripts(b);
        js_gc_collect(b->vm);
    }

    if (push_history) {
        if (b->hist_index + 1 < TB_HISTORY_MAX) {
            b->hist_index++;
        } else {
            memmove(&b->history[0], &b->history[1],
                    (TB_HISTORY_MAX - 1) * sizeof(TbHistItem));
            b->hist_index = TB_HISTORY_MAX - 1;
        }
        memcpy(b->history[b->hist_index].url, b->current_url, sizeof(b->history[0].url));
        b->history[b->hist_index].scroll_y = 0;
        b->hist_count = b->hist_index + 1;
    }

    tb_browser_relayout_if_needed(b, true);

    /* Scroll to #fragment target if URL has one */
    TbUrl pu;
    if (b->doc && tb_url_parse(b->current_url, &pu) && pu.fragment[0]) {
        DomNode *anchor = dom_get_element_by_id(b->doc->root, pu.fragment);
        int hit = layout_find_node_hit(&b->layout, anchor);
        if (hit >= 0) b->scroll_y = b->layout.hits[hit].line_y;
    }

    tb_mem_trim();
    process_pending_nav(b);
    return ok;
}

bool tb_browser_navigate(TbBrowser *b, const char *url_or_input, bool push_history) {
    if (!b || !url_or_input) return false;
    if (tb_strncasecmp(url_or_input, "javascript:", 11) == 0) {
        return tb_browser_eval_repl(b, url_or_input + 11);
    }
    return navigate_with_method(b, url_or_input, "GET", NULL, push_history);
}

bool tb_browser_back(TbBrowser *b) {
    if (!b || b->hist_index <= 0) return false;
    b->history[b->hist_index].scroll_y = b->scroll_y;
    b->hist_index--;
    int saved_scroll = b->history[b->hist_index].scroll_y;
    bool ok = tb_browser_navigate(b, b->history[b->hist_index].url, false);
    b->scroll_y = saved_scroll;
    return ok;
}

bool tb_browser_forward(TbBrowser *b) {
    if (!b || b->hist_index + 1 >= b->hist_count) return false;
    b->history[b->hist_index].scroll_y = b->scroll_y;
    b->hist_index++;
    int saved_scroll = b->history[b->hist_index].scroll_y;
    bool ok = tb_browser_navigate(b, b->history[b->hist_index].url, false);
    b->scroll_y = saved_scroll;
    return ok;
}

bool tb_browser_reload(TbBrowser *b) {
    if (!b || !b->current_url[0]) return false;
    int saved_scroll = b->scroll_y;
    char url[1536];
    snprintf(url, sizeof(url), "%s", b->current_url);
    bool ok = tb_browser_navigate(b, url, false);
    b->scroll_y = saved_scroll;
    return ok;
}

int tb_browser_tick(TbBrowser *b) {
    if (!b || !b->vm) return -1;
    int wait_ms = js_run_timers(b->vm);
    process_pending_nav(b);
    tb_browser_relayout_if_needed(b, false);
    return wait_ms;
}

static void url_encode_append(TbBuf *out, const char *s) {
    for (; s && *s; s++) {
        uint8_t c = (uint8_t)*s;
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            tb_buf_append_char(out, (char)c);
        } else if (c == ' ') {
            tb_buf_append_char(out, '+');
        } else {
            tb_buf_printf(out, "%%%02X", c);
        }
    }
}

static void collect_form_fields(DomNode *n, TbBuf *q) {
    if (!n) return;
    if (n->type == DOM_NODE_ELEMENT &&
        (n->tag == TAG_INPUT || n->tag == TAG_TEXTAREA || n->tag == TAG_SELECT)) {
        const char *name = dom_get_attr(n, "name");
        const char *type = dom_get_attr(n, "type");
        if (!type) type = "text";
        if (name && *name && !dom_has_attr(n, "disabled")) {
            bool include = true;
            const char *val = dom_input_get_value(n);
            if (tb_strcasecmp(type, "checkbox") == 0 || tb_strcasecmp(type, "radio") == 0) {
                include = dom_input_get_checked(n);
                if (!val || !*val) val = "on";
            } else if (tb_strcasecmp(type, "submit") == 0 || tb_strcasecmp(type, "button") == 0) {
                include = false;
            }
            if (include) {
                if (q->len > 0) tb_buf_append_char(q, '&');
                url_encode_append(q, name);
                tb_buf_append_char(q, '=');
                url_encode_append(q, val);
            }
        }
    }
    for (DomNode *ch = n->first_child; ch; ch = ch->next_sibling) {
        collect_form_fields(ch, q);
    }
}

static void submit_enclosing_form(TbBrowser *b, DomNode *control) {
    DomNode *form = control;
    while (form && !(form->type == DOM_NODE_ELEMENT && form->tag == TAG_FORM)) {
        form = form->parent;
    }
    if (!form) return;

    if (b->vm && !js_dispatch_dom_event(b->vm, form, "submit", NULL, true)) {
        process_pending_nav(b);
        tb_browser_relayout_if_needed(b, false);
        return; /* preventDefault() handled form in JS! */
    }

    const char *action = dom_get_attr(form, "action");
    const char *method = dom_get_attr(form, "method");
    bool is_post = (method && tb_strcasecmp(method, "POST") == 0);

    char target_url[1536];
    TbUrl base;
    if (tb_url_parse(b->current_url, &base)) {
        tb_url_resolve(&base, action ? action : "", target_url, sizeof(target_url));
    } else {
        snprintf(target_url, sizeof(target_url), "%s", b->current_url);
    }

    TbBuf query;
    tb_buf_init(&query);
    collect_form_fields(form, &query);

    if (is_post) {
        navigate_with_method(b, target_url, "POST", query.data ? query.data : "", true);
    } else {
        char *qmark = strchr(target_url, '?');
        if (qmark) *qmark = '\0';
        TbBuf full;
        tb_buf_init(&full);
        if (query.len > 0) tb_buf_printf(&full, "%s?%s", target_url, query.data);
        else tb_buf_append_cstr(&full, target_url);
        navigate_with_method(b, full.data, "GET", NULL, true);
        tb_buf_free(&full);
    }
    tb_buf_free(&query);
}

void tb_browser_activate_hit(TbBrowser *b, int hit_idx) {
    if (!b || !b->doc || hit_idx < 0 || hit_idx >= b->layout.hit_count) return;
    b->focused_hit = hit_idx;
    HitBox hb      = b->layout.hits[hit_idx];
    DomNode *node  = hb.node;
    if (!node || dom_has_attr(node, "disabled")) return;

    if (hb.kind == HIT_INPUT_TEXT) {
        b->editing_node = node;
        b->edit_cursor  = strlen(dom_input_get_value(node));
        tb_browser_relayout_if_needed(b, true);
        return;
    }

    b->editing_node = NULL;

    if (hb.kind == HIT_CHECKBOX) {
        const char *type = dom_get_attr(node, "type");
        if (type && tb_strcasecmp(type, "radio") == 0) {
            const char *rname = dom_get_attr(node, "name");
            if (rname && *rname && b->doc->root) {
                DomNodeList radios;
                dom_query_selector_all(b->doc->root, "input", &radios);
                for (size_t i = 0; i < radios.count; i++) {
                    const char *rn = dom_get_attr(radios.items[i], "name");
                    if (rn && strcmp(rn, rname) == 0) {
                        dom_input_set_checked(radios.items[i], radios.items[i] == node);
                    }
                }
                dom_nodelist_free(&radios);
            } else {
                dom_input_set_checked(node, true);
            }
        } else {
            dom_input_set_checked(node, !dom_input_get_checked(node));
        }
        if (b->vm) {
            js_dispatch_dom_event(b->vm, node, "click", NULL, true);
            js_dispatch_dom_event(b->vm, node, "change", NULL, true);
        }
        process_pending_nav(b);
        tb_browser_relayout_if_needed(b, true);
        return;
    }

    if (hb.kind == HIT_SELECT) {
        /* Cycle through <option> children */
        const char *cur_v = dom_input_get_value(node);
        DomNode *first_opt = NULL;
        DomNode *next_opt  = NULL;
        bool saw_cur = false;
        for (DomNode *ch = node->first_child; ch; ch = ch->next_sibling) {
            if (ch->tag != TAG_OPTION) continue;
            if (!first_opt) first_opt = ch;
            const char *ov = dom_get_attr(ch, "value");
            char *ot = ov ? NULL : dom_get_text_content(ch);
            const char *eff = ov ? ov : (ot ? ot : "");
            if (saw_cur && !next_opt) {
                next_opt = ch;
            } else if (strcmp(eff, cur_v) == 0) {
                saw_cur = true;
            }
            tb_free(ot);
        }
        DomNode *pick = next_opt ? next_opt : first_opt;
        if (pick) {
            const char *ov = dom_get_attr(pick, "value");
            if (ov) {
                dom_input_set_value(node, ov);
            } else {
                char *ot = dom_get_text_content(pick);
                dom_input_set_value(node, ot ? ot : "");
                tb_free(ot);
            }
            if (b->vm) js_dispatch_dom_event(b->vm, node, "change", NULL, true);
        }
        process_pending_nav(b);
        tb_browser_relayout_if_needed(b, true);
        return;
    }

    /* Dispatch JS click event first; honor preventDefault() */
    bool allow_default = true;
    if (b->vm) {
        allow_default = js_dispatch_dom_event(b->vm, node, "click", NULL, true);
    }
    process_pending_nav(b);
    tb_browser_relayout_if_needed(b, false);
    if (!allow_default) return;

    if (hb.kind == HIT_LINK) {
        const char *href = dom_get_attr(node, "href");
        if (href && *href) {
            if (href[0] == '#') {
                DomNode *anc = dom_get_element_by_id(b->doc->root, href + 1);
                int ahit = layout_find_node_hit(&b->layout, anc);
                if (ahit >= 0) b->scroll_y = b->layout.hits[ahit].line_y;
                return;
            }
            char target[1536];
            TbUrl base;
            if (tb_url_parse(b->current_url, &base)) {
                tb_url_resolve(&base, href, target, sizeof(target));
            } else {
                tb_url_normalize_input(href, target, sizeof(target));
            }
            tb_browser_navigate(b, target, true);
        }
        return;
    }

    if (hb.kind == HIT_BUTTON) {
        const char *type = dom_get_attr(node, "type");
        bool is_submit = (node->tag == TAG_INPUT && type && tb_strcasecmp(type, "submit") == 0) ||
                         (node->tag == TAG_BUTTON && (!type || tb_strcasecmp(type, "submit") == 0));
        if (is_submit) {
            submit_enclosing_form(b, node);
        }
    }
}

void tb_browser_edit_key(TbBrowser *b, uint32_t cp, int special_key) {
    if (!b || !b->editing_node) return;
    DomNode *n = b->editing_node;
    const char *cur = dom_input_get_value(n);
    size_t len = strlen(cur);
    if (b->edit_cursor > len) b->edit_cursor = len;

    if (special_key == 1) { /* Left */
        if (b->edit_cursor > 0) b->edit_cursor--;
        tb_browser_relayout_if_needed(b, true);
        return;
    }
    if (special_key == 2) { /* Right */
        if (b->edit_cursor < len) b->edit_cursor++;
        tb_browser_relayout_if_needed(b, true);
        return;
    }

    if (special_key == 13) { /* Enter inside <input> */
        bool allow = true;
        if (b->vm) allow = js_dispatch_dom_event(b->vm, n, "keydown", "Enter", true);
        tb_browser_stop_editing(b);
        if (allow) submit_enclosing_form(b, n);
        return;
    }

    TbBuf nb;
    tb_buf_init(&nb);
    bool changed = false;
    size_t cpos = b->edit_cursor;
    if (cpos > len) cpos = len;

    if (special_key == 8) { /* Backspace */
        if (cpos > 0) {
            tb_buf_append(&nb, cur, cpos - 1);
            tb_buf_append_cstr(&nb, cur + cpos);
            b->edit_cursor = cpos - 1;
            changed = true;
        }
    } else if (special_key == 127) { /* Delete */
        if (cpos < len) {
            tb_buf_append(&nb, cur, cpos);
            tb_buf_append_cstr(&nb, cur + cpos + 1);
            changed = true;
        }
    } else if ((cp >= 32 && cp != 127) || (cp == '\n' && n->tag == TAG_TEXTAREA)) {
        char u8[4];
        size_t un = tb_utf8_encode(cp, u8);
        tb_buf_append(&nb, cur, cpos);
        tb_buf_append(&nb, u8, un);
        tb_buf_append_cstr(&nb, cur + cpos);
        b->edit_cursor = cpos + un;
        changed = true;
    }

    if (changed) {
        dom_input_set_value(n, nb.data ? nb.data : "");
        if (b->vm) js_dispatch_dom_event(b->vm, n, "input", NULL, true);
        process_pending_nav(b);
    }
    tb_buf_free(&nb);
    tb_browser_relayout_if_needed(b, true);
}

void tb_browser_stop_editing(TbBrowser *b) {
    if (!b || !b->editing_node) return;
    DomNode *n = b->editing_node;
    b->editing_node = NULL;
    if (b->vm) js_dispatch_dom_event(b->vm, n, "change", NULL, true);
    process_pending_nav(b);
    tb_browser_relayout_if_needed(b, true);
}

bool tb_browser_eval_repl(TbBrowser *b, const char *js_code) {
    if (!b || !b->vm || !js_code) return false;
    TbBuf cmd_log;
    tb_buf_init(&cmd_log);
    tb_buf_printf(&cmd_log, "› %s", js_code);
    tb_browser_log(b, JS_LOG_INFO, cmd_log.data);
    tb_buf_free(&cmd_log);

    JsVal res = js_undefined();
    bool ok   = js_eval(b->vm, js_code, strlen(js_code), &res);
    if (ok) {
        TbBuf out;
        tb_buf_init(&out);
        tb_buf_append_cstr(&out, "← ");
        js_val_format(b->vm, res, &out, 0);
        tb_browser_log(b, JS_LOG_INFO, out.data);
        tb_buf_free(&out);
    }
    process_pending_nav(b);
    tb_browser_relayout_if_needed(b, false);
    return ok;
}

void tb_browser_force_gc(TbBrowser *b) {
    size_t swept = (b && b->vm) ? js_gc_collect(b->vm) : 0;
    tb_mem_trim();
    if (b) {
        TbMemStats ms;
        tb_mem_stats(&ms);
        snprintf(b->status_msg, sizeof(b->status_msg),
                 "GC swept %zu JS objects | VmRSS: %.2f MB (RssAnon: %zu KB)",
                 swept, (double)ms.vm_rss_kb / 1024.0, ms.rss_anon_kb);
    }
}
