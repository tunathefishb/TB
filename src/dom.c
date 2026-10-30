#include "dom.h"
#include "common.h"

static const char *TAG_NAMES[TAG_COUNT] = {
    [TAG_UNKNOWN] = "unknown",
    [TAG_HTML] = "html", [TAG_HEAD] = "head", [TAG_TITLE] = "title",
    [TAG_META] = "meta", [TAG_LINK] = "link", [TAG_STYLE] = "style",
    [TAG_SCRIPT] = "script", [TAG_NOSCRIPT] = "noscript",
    [TAG_BODY] = "body", [TAG_DIV] = "div", [TAG_SPAN] = "span",
    [TAG_P] = "p", [TAG_A] = "a",
    [TAG_H1] = "h1", [TAG_H2] = "h2", [TAG_H3] = "h3",
    [TAG_H4] = "h4", [TAG_H5] = "h5", [TAG_H6] = "h6",
    [TAG_UL] = "ul", [TAG_OL] = "ol", [TAG_LI] = "li",
    [TAG_DL] = "dl", [TAG_DT] = "dt", [TAG_DD] = "dd",
    [TAG_PRE] = "pre", [TAG_CODE] = "code", [TAG_BLOCKQUOTE] = "blockquote",
    [TAG_HR] = "hr", [TAG_BR] = "br", [TAG_IMG] = "img",
    [TAG_STRONG] = "strong", [TAG_B] = "b", [TAG_EM] = "em",
    [TAG_I] = "i", [TAG_U] = "u", [TAG_S] = "s", [TAG_DEL] = "del",
    [TAG_MARK] = "mark", [TAG_SMALL] = "small", [TAG_SUB] = "sub", [TAG_SUP] = "sup",
    [TAG_TABLE] = "table", [TAG_THEAD] = "thead", [TAG_TBODY] = "tbody",
    [TAG_TFOOT] = "tfoot", [TAG_TR] = "tr", [TAG_TH] = "th", [TAG_TD] = "td",
    [TAG_FORM] = "form", [TAG_INPUT] = "input", [TAG_BUTTON] = "button",
    [TAG_TEXTAREA] = "textarea", [TAG_SELECT] = "select", [TAG_OPTION] = "option",
    [TAG_LABEL] = "label",
    [TAG_HEADER] = "header", [TAG_NAV] = "nav", [TAG_MAIN] = "main",
    [TAG_SECTION] = "section", [TAG_ARTICLE] = "article", [TAG_ASIDE] = "aside",
    [TAG_FOOTER] = "footer", [TAG_DETAILS] = "details", [TAG_SUMMARY] = "summary",
    [TAG_FIGURE] = "figure", [TAG_FIGCAPTION] = "figcaption"
};

DomTag dom_tag_from_name(const char *name, size_t len) {
    if (!name || len == 0 || len > 16) return TAG_UNKNOWN;
    char low[17];
    for (size_t i = 0; i < len; i++) low[i] = tb_tolower(name[i]);
    low[len] = '\0';
    for (int i = 1; i < TAG_COUNT; i++) {
        if (strcmp(low, TAG_NAMES[i]) == 0) return (DomTag)i;
    }
    return TAG_UNKNOWN;
}

const char *dom_tag_name(DomTag tag) {
    if (tag > TAG_UNKNOWN && tag < TAG_COUNT) return TAG_NAMES[tag];
    return "unknown";
}

const char *dom_node_tag_name(const DomNode *node) {
    if (!node) return "";
    if (node->type == DOM_NODE_DOCUMENT) return "#document";
    if (node->type == DOM_NODE_TEXT) return "#text";
    if (node->type == DOM_NODE_COMMENT) return "#comment";
    if (node->tag != TAG_UNKNOWN) return TAG_NAMES[node->tag];
    return node->tag_name ? node->tag_name : "unknown";
}

static bool is_void_tag(DomTag tag, const char *raw_name) {
    switch (tag) {
        case TAG_BR: case TAG_HR: case TAG_IMG: case TAG_INPUT:
        case TAG_META: case TAG_LINK:
            return true;
        case TAG_UNKNOWN:
            if (!raw_name) return false;
            return tb_strcasecmp(raw_name, "area") == 0 ||
                   tb_strcasecmp(raw_name, "base") == 0 ||
                   tb_strcasecmp(raw_name, "col") == 0 ||
                   tb_strcasecmp(raw_name, "embed") == 0 ||
                   tb_strcasecmp(raw_name, "param") == 0 ||
                   tb_strcasecmp(raw_name, "source") == 0 ||
                   tb_strcasecmp(raw_name, "track") == 0 ||
                   tb_strcasecmp(raw_name, "wbr") == 0;
        default:
            return false;
    }
}

static bool is_p_closing_block(DomTag tag) {
    switch (tag) {
        case TAG_P: case TAG_DIV: case TAG_H1: case TAG_H2: case TAG_H3:
        case TAG_H4: case TAG_H5: case TAG_H6: case TAG_UL: case TAG_OL:
        case TAG_PRE: case TAG_BLOCKQUOTE: case TAG_TABLE: case TAG_HR:
        case TAG_FORM: case TAG_HEADER: case TAG_NAV: case TAG_MAIN:
        case TAG_SECTION: case TAG_ARTICLE: case TAG_ASIDE: case TAG_FOOTER:
        case TAG_DETAILS: case TAG_DL:
            return true;
        default:
            return false;
    }
}

static void mark_doc_dirty(DomNode *n, bool style_too) {
    if (n && n->owner_doc) {
        n->owner_doc->dirty_layout = true;
        if (style_too) n->owner_doc->dirty_style = true;
    }
}

static DomNode *alloc_node(DomDocument *doc, DomNodeType type) {
    if (doc && doc->node_count >= DOM_MAX_NODES) return NULL;
    DomNode *n = (DomNode *)tb_calloc(1, sizeof(DomNode));
    if (!n) return NULL;
    n->type      = type;
    n->owner_doc = doc;
    if (doc) {
        n->node_id = ++doc->next_id;
        doc->node_count++;
    }
    return n;
}

DomDocument *dom_doc_new(void) {
    DomDocument *doc = (DomDocument *)tb_calloc(1, sizeof(DomDocument));
    if (!doc) return NULL;
    doc->root = alloc_node(doc, DOM_NODE_DOCUMENT);
    if (!doc->root) {
        tb_free(doc);
        return NULL;
    }
    doc->dirty_style  = true;
    doc->dirty_layout = true;
    return doc;
}

void dom_node_free(DomNode *node) {
    if (!node) return;
    if (node->owner_doc && node->owner_doc->on_node_destroy) {
        node->owner_doc->on_node_destroy(node->owner_doc->userdata, node);
    }
    DomNode *ch = node->first_child;
    while (ch) {
        DomNode *next = ch->next_sibling;
        dom_node_free(ch);
        ch = next;
    }
    for (uint16_t i = 0; i < node->attr_count; i++) {
        tb_free(node->attrs[i].name);
        tb_free(node->attrs[i].value);
    }
    tb_free(node->attrs);
    tb_free(node->tag_name);
    tb_free(node->text);
    tb_free(node->form_value);

    DomListener *ls = node->listeners;
    while (ls) {
        DomListener *next = ls->next;
        tb_free(ls->type);
        tb_free(ls);
        ls = next;
    }

    if (node->owner_doc && node->owner_doc->node_count > 0) {
        node->owner_doc->node_count--;
    }
    tb_free(node);
}

void dom_doc_free(DomDocument *doc) {
    if (!doc) return;
    dom_node_free(doc->root);
    tb_free(doc);
}

DomNode *dom_create_element(DomDocument *doc, const char *tag_name) {
    if (!tag_name) tag_name = "div";
    DomNode *n = alloc_node(doc, DOM_NODE_ELEMENT);
    if (!n) return NULL;
    size_t len = strlen(tag_name);
    n->tag = dom_tag_from_name(tag_name, len);
    if (n->tag == TAG_UNKNOWN) {
        n->tag_name = tb_strndup(tag_name, len);
        if (n->tag_name) {
            for (size_t i = 0; n->tag_name[i]; i++)
                n->tag_name[i] = tb_tolower(n->tag_name[i]);
        }
    }
    return n;
}

DomNode *dom_create_text(DomDocument *doc, const char *text) {
    DomNode *n = alloc_node(doc, DOM_NODE_TEXT);
    if (!n) return NULL;
    n->text = tb_strdup(text ? text : "");
    return n;
}

static bool is_ancestor_or_self(const DomNode *anc, const DomNode *node) {
    for (const DomNode *cur = node; cur; cur = cur->parent) {
        if (cur == anc) return true;
    }
    return false;
}

static void detach_node(DomNode *child) {
    DomNode *p = child->parent;
    if (!p) return;
    if (child->prev_sibling) child->prev_sibling->next_sibling = child->next_sibling;
    else p->first_child = child->next_sibling;
    if (child->next_sibling) child->next_sibling->prev_sibling = child->prev_sibling;
    else p->last_child = child->prev_sibling;
    child->parent       = NULL;
    child->prev_sibling = NULL;
    child->next_sibling = NULL;
}

bool dom_append_child(DomNode *parent, DomNode *child) {
    if (!parent || !child || is_ancestor_or_self(child, parent)) return false;
    detach_node(child);
    child->owner_doc = parent->owner_doc;
    child->parent    = parent;
    if (parent->last_child) {
        parent->last_child->next_sibling = child;
        child->prev_sibling              = parent->last_child;
        parent->last_child               = child;
    } else {
        parent->first_child = child;
        parent->last_child  = child;
    }
    mark_doc_dirty(parent, true);
    return true;
}

bool dom_insert_before(DomNode *parent, DomNode *new_node, DomNode *ref_node) {
    if (!parent || !new_node) return false;
    if (!ref_node) return dom_append_child(parent, new_node);
    if (ref_node->parent != parent || is_ancestor_or_self(new_node, parent)) return false;
    if (new_node == ref_node) return true;
    detach_node(new_node);
    new_node->owner_doc    = parent->owner_doc;
    new_node->parent       = parent;
    new_node->next_sibling = ref_node;
    new_node->prev_sibling = ref_node->prev_sibling;
    if (ref_node->prev_sibling) ref_node->prev_sibling->next_sibling = new_node;
    else parent->first_child = new_node;
    ref_node->prev_sibling = new_node;
    mark_doc_dirty(parent, true);
    return true;
}

DomNode *dom_remove_child(DomNode *parent, DomNode *child) {
    if (!parent || !child || child->parent != parent) return NULL;
    detach_node(child);
    mark_doc_dirty(parent, true);
    return child;
}

bool dom_replace_child(DomNode *parent, DomNode *new_node, DomNode *old_node) {
    if (!parent || !new_node || !old_node || old_node->parent != parent) return false;
    if (!dom_insert_before(parent, new_node, old_node)) return false;
    detach_node(old_node);
    return true;
}

void dom_clear_children(DomNode *parent) {
    if (!parent) return;
    DomNode *ch = parent->first_child;
    parent->first_child = NULL;
    parent->last_child  = NULL;
    while (ch) {
        DomNode *next = ch->next_sibling;
        ch->parent       = NULL;
        ch->prev_sibling = NULL;
        ch->next_sibling = NULL;
        dom_node_free(ch);
        ch = next;
    }
    mark_doc_dirty(parent, true);
}

DomNode *dom_clone_node(DomDocument *doc, const DomNode *src, bool deep) {
    if (!src) return NULL;
    DomNode *dst = NULL;
    if (src->type == DOM_NODE_ELEMENT) {
        dst = dom_create_element(doc, dom_node_tag_name(src));
        if (!dst) return NULL;
        for (uint16_t i = 0; i < src->attr_count; i++) {
            dom_set_attr(dst, src->attrs[i].name, src->attrs[i].value);
        }
        if (src->form_value_set && src->form_value) {
            dom_input_set_value(dst, src->form_value);
        }
        if (src->form_checked_set) {
            dom_input_set_checked(dst, src->form_checked);
        }
    } else if (src->type == DOM_NODE_TEXT) {
        dst = dom_create_text(doc, src->text);
    } else {
        dst = alloc_node(doc, src->type);
        if (dst && src->text) dst->text = tb_strdup(src->text);
    }
    if (!dst) return NULL;
    if (deep) {
        for (const DomNode *ch = src->first_child; ch; ch = ch->next_sibling) {
            DomNode *cclone = dom_clone_node(doc, ch, true);
            if (cclone) dom_append_child(dst, cclone);
        }
    }
    return dst;
}

const char *dom_get_attr(const DomNode *node, const char *name) {
    if (!node || !name) return NULL;
    for (uint16_t i = 0; i < node->attr_count; i++) {
        if (tb_strcasecmp(node->attrs[i].name, name) == 0) {
            return node->attrs[i].value;
        }
    }
    return NULL;
}

bool dom_has_attr(const DomNode *node, const char *name) {
    return dom_get_attr(node, name) != NULL;
}

void dom_set_attr(DomNode *node, const char *name, const char *value) {
    if (!node || !name || !*name) return;
    if (!value) value = "";
    for (uint16_t i = 0; i < node->attr_count; i++) {
        if (tb_strcasecmp(node->attrs[i].name, name) == 0) {
            char *nv = tb_strdup(value);
            if (!nv) return;
            tb_free(node->attrs[i].value);
            node->attrs[i].value = nv;
            mark_doc_dirty(node, true);
            return;
        }
    }
    if (node->attr_count >= node->attr_cap) {
        uint16_t ncap = node->attr_cap ? (uint16_t)(node->attr_cap * 2) : 4;
        DomAttr *na   = (DomAttr *)tb_realloc(node->attrs, ncap * sizeof(DomAttr));
        if (!na) return;
        node->attrs    = na;
        node->attr_cap = ncap;
    }
    char *nn = tb_strdup(name);
    char *nv = tb_strdup(value);
    if (!nn || !nv) {
        tb_free(nn);
        tb_free(nv);
        return;
    }
    for (size_t i = 0; nn[i]; i++) nn[i] = tb_tolower(nn[i]);
    node->attrs[node->attr_count].name  = nn;
    node->attrs[node->attr_count].value = nv;
    node->attr_count++;
    mark_doc_dirty(node, true);
}

void dom_remove_attr(DomNode *node, const char *name) {
    if (!node || !name) return;
    for (uint16_t i = 0; i < node->attr_count; i++) {
        if (tb_strcasecmp(node->attrs[i].name, name) == 0) {
            tb_free(node->attrs[i].name);
            tb_free(node->attrs[i].value);
            for (uint16_t j = i; j + 1 < node->attr_count; j++) {
                node->attrs[j] = node->attrs[j + 1];
            }
            node->attr_count--;
            mark_doc_dirty(node, true);
            return;
        }
    }
}

/* HTML Entity Decoding */
char *dom_decode_entities(const char *src, size_t len) {
    TbBuf b;
    tb_buf_init(&b);
    if (!tb_buf_reserve(&b, len)) return tb_strdup("");

    static const struct { const char *name; uint32_t cp; } ents[] = {
        {"amp", '&'}, {"lt", '<'}, {"gt", '>'}, {"quot", '"'}, {"apos", '\''},
        {"nbsp", ' '}, {"copy", 0x00A9}, {"reg", 0x00AE}, {"trade", 0x2122},
        {"mdash", 0x2014}, {"ndash", 0x2013}, {"hellip", 0x2026}, {"bull", 0x2022},
        {"middot", 0x00B7}, {"rarr", 0x2192}, {"larr", 0x2190}, {"uarr", 0x2191},
        {"darr", 0x2193}, {"times", 0x00D7}, {"divide", 0x00F7}, {"plusmn", 0x00B1},
        {"laquo", 0x00AB}, {"raquo", 0x00BB}, {"lsquo", 0x2018}, {"rsquo", 0x2019},
        {"ldquo", 0x201C}, {"rdquo", 0x201D}, {"euro", 0x20AC}, {"pound", 0x00A3},
        {"yen", 0x00A5}, {"check", 0x2713}
    };

    size_t i = 0;
    while (i < len) {
        if (src[i] == '&') {
            size_t semi = i + 1;
            while (semi < len && semi - i <= 12 && src[semi] != ';' &&
                   src[semi] != '&' && !tb_isspace(src[semi])) {
                semi++;
            }
            if (semi < len && src[semi] == ';' && semi > i + 1) {
                const char *ename = src + i + 1;
                size_t elen       = semi - (i + 1);
                uint32_t cp       = 0;
                bool matched      = false;
                if (ename[0] == '#') {
                    char numbuf[16];
                    if (elen - 1 < sizeof(numbuf)) {
                        memcpy(numbuf, ename + 1, elen - 1);
                        numbuf[elen - 1] = '\0';
                        char *endp = NULL;
                        unsigned long v = (numbuf[0] == 'x' || numbuf[0] == 'X')
                                              ? strtoul(numbuf + 1, &endp, 16)
                                              : strtoul(numbuf, &endp, 10);
                        if (endp && *endp == '\0' && v > 0 && v <= 0x10FFFF) {
                            cp = (uint32_t)(v == 0xA0 ? ' ' : v);
                            matched = true;
                        }
                    }
                } else {
                    for (size_t k = 0; k < sizeof(ents) / sizeof(ents[0]); k++) {
                        if (strlen(ents[k].name) == elen &&
                            strncmp(ename, ents[k].name, elen) == 0) {
                            cp = ents[k].cp;
                            matched = true;
                            break;
                        }
                    }
                }
                if (matched) {
                    char u8[4];
                    size_t un = tb_utf8_encode(cp, u8);
                    tb_buf_append(&b, u8, un);
                    i = semi + 1;
                    continue;
                }
            }
        }
        tb_buf_append_char(&b, src[i++]);
    }
    return tb_buf_detach(&b, NULL);
}

static void collect_text_rec(const DomNode *n, TbBuf *b) {
    if (!n) return;
    if (n->type == DOM_NODE_TEXT) {
        if (n->text) tb_buf_append_cstr(b, n->text);
        return;
    }
    if (n->type == DOM_NODE_COMMENT) return;
    for (const DomNode *ch = n->first_child; ch; ch = ch->next_sibling) {
        collect_text_rec(ch, b);
    }
}

char *dom_get_text_content(const DomNode *node) {
    TbBuf b;
    tb_buf_init(&b);
    collect_text_rec(node, &b);
    return tb_buf_detach(&b, NULL);
}

void dom_set_text_content(DomNode *node, const char *text) {
    if (!node) return;
    if (node->type == DOM_NODE_TEXT || node->type == DOM_NODE_COMMENT) {
        char *nt = tb_strdup(text ? text : "");
        if (!nt) return;
        tb_free(node->text);
        node->text = nt;
        mark_doc_dirty(node, false);
        return;
    }
    dom_clear_children(node);
    if (text && *text) {
        DomNode *tn = dom_create_text(node->owner_doc, text);
        if (tn) dom_append_child(node, tn);
    }
    mark_doc_dirty(node, true);
}

static void append_escaped_html(TbBuf *b, const char *s, bool is_attr) {
    if (!s) return;
    for (; *s; s++) {
        if (*s == '&') tb_buf_append_cstr(b, "&amp;");
        else if (*s == '<') tb_buf_append_cstr(b, "&lt;");
        else if (*s == '>') tb_buf_append_cstr(b, "&gt;");
        else if (is_attr && *s == '"') tb_buf_append_cstr(b, "&quot;");
        else tb_buf_append_char(b, *s);
    }
}

static void serialize_node_rec(const DomNode *n, TbBuf *b) {
    if (!n) return;
    if (n->type == DOM_NODE_TEXT) {
        append_escaped_html(b, n->text, false);
        return;
    }
    if (n->type == DOM_NODE_COMMENT) {
        tb_buf_append_cstr(b, "<!--");
        tb_buf_append_cstr(b, n->text ? n->text : "");
        tb_buf_append_cstr(b, "-->");
        return;
    }
    if (n->type == DOM_NODE_ELEMENT) {
        const char *tname = dom_node_tag_name(n);
        tb_buf_append_char(b, '<');
        tb_buf_append_cstr(b, tname);
        for (uint16_t i = 0; i < n->attr_count; i++) {
            tb_buf_append_char(b, ' ');
            tb_buf_append_cstr(b, n->attrs[i].name);
            tb_buf_append_cstr(b, "=\"");
            append_escaped_html(b, n->attrs[i].value, true);
            tb_buf_append_char(b, '"');
        }
        tb_buf_append_char(b, '>');
        if (is_void_tag(n->tag, n->tag_name)) return;
        for (const DomNode *ch = n->first_child; ch; ch = ch->next_sibling) {
            serialize_node_rec(ch, b);
        }
        tb_buf_append_cstr(b, "</");
        tb_buf_append_cstr(b, tname);
        tb_buf_append_char(b, '>');
    }
}

char *dom_get_inner_html(const DomNode *node) {
    TbBuf b;
    tb_buf_init(&b);
    if (node) {
        for (const DomNode *ch = node->first_child; ch; ch = ch->next_sibling) {
            serialize_node_rec(ch, &b);
        }
    }
    return tb_buf_detach(&b, NULL);
}

/* HTML Tokenizer + Tree Builder */
static void parse_into_container(DomDocument *doc, DomNode *container,
                                 const char *html, size_t len, bool is_fragment) {
    DomNode *stack[256];
    int sp = 0;
    stack[sp++] = container;

    size_t pos = 0;
    while (pos < len && doc->node_count < DOM_MAX_NODES) {
        if (html[pos] != '<') {
            size_t start = pos;
            while (pos < len && html[pos] != '<') pos++;
            char *decoded = dom_decode_entities(html + start, pos - start);
            if (decoded && decoded[0] != '\0') {
                DomNode *top = stack[sp - 1];
                if (top->last_child && top->last_child->type == DOM_NODE_TEXT) {
                    /* Coalesce adjacent text nodes */
                    size_t l1 = strlen(top->last_child->text);
                    size_t l2 = strlen(decoded);
                    char *merged = (char *)tb_realloc(top->last_child->text, l1 + l2 + 1);
                    if (merged) {
                        memcpy(merged + l1, decoded, l2 + 1);
                        top->last_child->text = merged;
                    }
                    tb_free(decoded);
                } else {
                    DomNode *tn = alloc_node(doc, DOM_NODE_TEXT);
                    if (tn) {
                        tn->text = decoded;
                        dom_append_child(top, tn);
                    } else {
                        tb_free(decoded);
                    }
                }
            } else {
                tb_free(decoded);
            }
            continue;
        }

        /* Comment: <!-- ... --> */
        if (pos + 4 <= len && strncmp(html + pos, "<!--", 4) == 0) {
            pos += 4;
            const char *endc = strstr(html + pos, "-->");
            if (!endc || (size_t)(endc - html) >= len) break;
            pos = (size_t)(endc - html) + 3;
            continue;
        }

        /* Doctype / Declaration: <! ... > or <? ... > */
        if (pos + 2 <= len && (html[pos + 1] == '!' || html[pos + 1] == '?')) {
            const char *gt = memchr(html + pos, '>', len - pos);
            pos = gt ? (size_t)(gt - html) + 1 : len;
            continue;
        }

        /* Closing tag: </tag> */
        if (pos + 2 <= len && html[pos + 1] == '/') {
            pos += 2;
            while (pos < len && tb_isspace(html[pos])) pos++;
            size_t tstart = pos;
            while (pos < len && !tb_isspace(html[pos]) && html[pos] != '>') pos++;
            size_t tlen = pos - tstart;
            const char *gt = memchr(html + pos, '>', len - pos);
            pos = gt ? (size_t)(gt - html) + 1 : len;

            if (tlen > 0) {
                DomTag ctag = dom_tag_from_name(html + tstart, tlen);
                for (int i = sp - 1; i >= 1; i--) {
                    bool match = false;
                    if (ctag != TAG_UNKNOWN) {
                        match = (stack[i]->tag == ctag);
                    } else if (stack[i]->tag_name && strlen(stack[i]->tag_name) == tlen &&
                               tb_strncasecmp(stack[i]->tag_name, html + tstart, tlen) == 0) {
                        match = true;
                    }
                    if (match) {
                        sp = i;
                        break;
                    }
                }
            }
            continue;
        }

        /* Opening tag: <tag attr="val" ...> */
        if (pos + 1 >= len || !((html[pos + 1] >= 'a' && html[pos + 1] <= 'z') ||
                                (html[pos + 1] >= 'A' && html[pos + 1] <= 'Z'))) {
            /* Stray '<' in text */
            DomNode *tn = dom_create_text(doc, "<");
            if (tn) dom_append_child(stack[sp - 1], tn);
            pos++;
            continue;
        }

        pos++; /* skip '<' */
        size_t tstart = pos;
        while (pos < len && !tb_isspace(html[pos]) && html[pos] != '>' && html[pos] != '/') pos++;
        size_t tlen = pos - tstart;
        char tname_buf[64];
        size_t cplen = tlen < sizeof(tname_buf) - 1 ? tlen : sizeof(tname_buf) - 1;
        memcpy(tname_buf, html + tstart, cplen);
        tname_buf[cplen] = '\0';

        /* Reuse top-level html/head/body in full document mode instead of duplicating */
        DomTag otag = dom_tag_from_name(tname_buf, cplen);
        DomNode *el = NULL;
        bool reused_structural = false;
        if (!is_fragment && otag == TAG_HTML && doc->html) {
            el = doc->html;
            reused_structural = true;
        } else if (!is_fragment && otag == TAG_HEAD && doc->head) {
            el = doc->head;
            reused_structural = true;
        } else if (!is_fragment && otag == TAG_BODY && doc->body) {
            el = doc->body;
            reused_structural = true;
            /* Ensure stack points to body */
            sp = 1;
            if (doc->html) stack[sp++] = doc->html;
            stack[sp++] = doc->body;
        } else {
            el = dom_create_element(doc, tname_buf);
        }

        bool self_closing = false;
        while (pos < len) {
            while (pos < len && tb_isspace(html[pos])) pos++;
            if (pos >= len) break;
            if (html[pos] == '>') { pos++; break; }
            if (html[pos] == '/') {
                self_closing = true;
                pos++;
                if (pos < len && html[pos] == '>') { pos++; break; }
                continue;
            }
            size_t astart = pos;
            while (pos < len && !tb_isspace(html[pos]) &&
                   html[pos] != '=' && html[pos] != '>' && html[pos] != '/') {
                pos++;
            }
            size_t alen = pos - astart;
            if (alen == 0) { pos++; continue; }
            char *aname = tb_strndup(html + astart, alen);
            while (pos < len && tb_isspace(html[pos])) pos++;
            char *aval = NULL;
            if (pos < len && html[pos] == '=') {
                pos++;
                while (pos < len && tb_isspace(html[pos])) pos++;
                if (pos < len && (html[pos] == '"' || html[pos] == '\'')) {
                    char q = html[pos++];
                    size_t vstart = pos;
                    while (pos < len && html[pos] != q) pos++;
                    aval = dom_decode_entities(html + vstart, pos - vstart);
                    if (pos < len && html[pos] == q) pos++;
                } else {
                    size_t vstart = pos;
                    while (pos < len && !tb_isspace(html[pos]) && html[pos] != '>') pos++;
                    aval = dom_decode_entities(html + vstart, pos - vstart);
                }
            } else {
                aval = tb_strdup("");
            }
            if (el && aname) dom_set_attr(el, aname, aval ? aval : "");
            tb_free(aname);
            tb_free(aval);
        }

        if (!el) break;

        if (!reused_structural) {
            /* Forgiving implicit close rules */
            if (is_p_closing_block(el->tag)) {
                for (int i = sp - 1; i >= 1; i--) {
                    if (stack[i]->tag == TAG_P) { sp = i; break; }
                }
            } else if (el->tag == TAG_LI) {
                for (int i = sp - 1; i >= 1; i--) {
                    if (stack[i]->tag == TAG_UL || stack[i]->tag == TAG_OL) break;
                    if (stack[i]->tag == TAG_LI) { sp = i; break; }
                }
            } else if (el->tag == TAG_TD || el->tag == TAG_TH) {
                for (int i = sp - 1; i >= 1; i--) {
                    if (stack[i]->tag == TAG_TR || stack[i]->tag == TAG_TABLE) break;
                    if (stack[i]->tag == TAG_TD || stack[i]->tag == TAG_TH) { sp = i; break; }
                }
            } else if (el->tag == TAG_TR) {
                for (int i = sp - 1; i >= 1; i--) {
                    if (stack[i]->tag == TAG_TABLE || stack[i]->tag == TAG_TBODY ||
                        stack[i]->tag == TAG_THEAD || stack[i]->tag == TAG_TFOOT) break;
                    if (stack[i]->tag == TAG_TR) { sp = i; break; }
                }
            } else if (el->tag == TAG_OPTION) {
                if (stack[sp - 1]->tag == TAG_OPTION && sp > 1) sp--;
            }

            /* Route <head>-only tags to doc->head if we are at root/html level */
            DomNode *parent = stack[sp - 1];
            if (!is_fragment && doc->head &&
                (el->tag == TAG_TITLE || el->tag == TAG_META || el->tag == TAG_LINK || el->tag == TAG_STYLE) &&
                (parent == doc->root || parent == doc->html)) {
                parent = doc->head;
            } else if (!is_fragment && doc->body &&
                       (parent == doc->root || parent == doc->html) &&
                       el->tag != TAG_HTML && el->tag != TAG_HEAD && el->tag != TAG_BODY) {
                parent = doc->body;
            }
            dom_append_child(parent, el);

            if (!is_fragment) {
                if (el->tag == TAG_HTML && !doc->html) doc->html = el;
                else if (el->tag == TAG_HEAD && !doc->head) doc->head = el;
                else if (el->tag == TAG_BODY && !doc->body) doc->body = el;
            }
        }

        /* Raw text tags: <script>, <style>, <textarea>, <title> */
        if (!self_closing && (el->tag == TAG_SCRIPT || el->tag == TAG_STYLE ||
                              el->tag == TAG_TEXTAREA || el->tag == TAG_TITLE)) {
            const char *raw_tag = dom_tag_name(el->tag);
            size_t rlen = strlen(raw_tag);
            size_t rstart = pos;
            size_t rend   = len;
            while (pos < len) {
                if (html[pos] == '<' && pos + 2 + rlen < len && html[pos + 1] == '/' &&
                    tb_strncasecmp(html + pos + 2, raw_tag, rlen) == 0 &&
                    (html[pos + 2 + rlen] == '>' || tb_isspace(html[pos + 2 + rlen]))) {
                    rend = pos;
                    const char *gt = memchr(html + pos, '>', len - pos);
                    pos = gt ? (size_t)(gt - html) + 1 : len;
                    break;
                }
                pos++;
            }
            if (rend > rstart) {
                char *txt = (el->tag == TAG_SCRIPT || el->tag == TAG_STYLE)
                                ? tb_strndup(html + rstart, rend - rstart)
                                : dom_decode_entities(html + rstart, rend - rstart);
                if (txt) {
                    DomNode *tn = alloc_node(doc, DOM_NODE_TEXT);
                    if (tn) {
                        tn->text = txt;
                        dom_append_child(el, tn);
                    } else {
                        tb_free(txt);
                    }
                }
            }
            continue;
        }

        if (!self_closing && !is_void_tag(el->tag, el->tag_name) && !reused_structural) {
            if (sp < 255) stack[sp++] = el;
        } else if (reused_structural && el == doc->head) {
            if (sp < 255) stack[sp++] = el;
        }
    }
}

DomDocument *dom_parse_html(const char *html, size_t len) {
    DomDocument *doc = dom_doc_new();
    if (!doc) return NULL;
    doc->html = dom_create_element(doc, "html");
    doc->head = dom_create_element(doc, "head");
    doc->body = dom_create_element(doc, "body");
    if (doc->html) dom_append_child(doc->root, doc->html);
    if (doc->html && doc->head) dom_append_child(doc->html, doc->head);
    if (doc->html && doc->body) dom_append_child(doc->html, doc->body);

    if (html && len > 0) {
        parse_into_container(doc, doc->body ? doc->body : doc->root, html, len, false);
    }
    doc->dirty_style  = true;
    doc->dirty_layout = true;
    return doc;
}

void dom_set_inner_html(DomNode *node, const char *html) {
    if (!node || node->type != DOM_NODE_ELEMENT) return;
    dom_clear_children(node);
    if (html && *html) {
        parse_into_container(node->owner_doc, node, html, strlen(html), true);
    }
    mark_doc_dirty(node, true);
}

/* ClassList helpers */
bool dom_class_contains(const DomNode *node, const char *cls) {
    if (!node || !cls || !*cls) return false;
    const char *attr = dom_get_attr(node, "class");
    if (!attr) return false;
    size_t clen = strlen(cls);
    const char *p = attr;
    while (*p) {
        while (*p && tb_isspace(*p)) p++;
        const char *start = p;
        while (*p && !tb_isspace(*p)) p++;
        if ((size_t)(p - start) == clen && strncmp(start, cls, clen) == 0) return true;
    }
    return false;
}

void dom_class_add(DomNode *node, const char *cls) {
    if (!node || !cls || !*cls || dom_class_contains(node, cls)) return;
    const char *attr = dom_get_attr(node, "class");
    if (!attr || !*attr) {
        dom_set_attr(node, "class", cls);
        return;
    }
    TbBuf b;
    tb_buf_init(&b);
    tb_buf_printf(&b, "%s %s", attr, cls);
    dom_set_attr(node, "class", b.data ? b.data : cls);
    tb_buf_free(&b);
}

void dom_class_remove(DomNode *node, const char *cls) {
    if (!node || !cls || !*cls) return;
    const char *attr = dom_get_attr(node, "class");
    if (!attr) return;
    size_t clen = strlen(cls);
    TbBuf b;
    tb_buf_init(&b);
    const char *p = attr;
    while (*p) {
        while (*p && tb_isspace(*p)) p++;
        const char *start = p;
        while (*p && !tb_isspace(*p)) p++;
        size_t len = (size_t)(p - start);
        if (len > 0 && !(len == clen && strncmp(start, cls, clen) == 0)) {
            if (b.len > 0) tb_buf_append_char(&b, ' ');
            tb_buf_append(&b, start, len);
        }
    }
    dom_set_attr(node, "class", b.data ? b.data : "");
    tb_buf_free(&b);
}

bool dom_class_toggle(DomNode *node, const char *cls, int force) {
    bool has = dom_class_contains(node, cls);
    bool should_have = (force < 0) ? !has : (force != 0);
    if (should_have) dom_class_add(node, cls);
    else dom_class_remove(node, cls);
    return should_have;
}

/* Form control state helpers */
const char *dom_input_get_value(DomNode *node) {
    if (!node) return "";
    if (!node->form_value_set) {
        if (node->tag == TAG_TEXTAREA) {
            node->form_value = dom_get_text_content(node);
        } else if (node->tag == TAG_SELECT) {
            const DomNode *selected = NULL;
            const DomNode *first_opt = NULL;
            for (const DomNode *ch = node->first_child; ch; ch = ch->next_sibling) {
                if (ch->tag == TAG_OPTION) {
                    if (!first_opt) first_opt = ch;
                    if (dom_has_attr(ch, "selected")) { selected = ch; break; }
                }
            }
            const DomNode *pick = selected ? selected : first_opt;
            if (pick) {
                const char *v = dom_get_attr(pick, "value");
                node->form_value = v ? tb_strdup(v) : dom_get_text_content(pick);
            } else {
                node->form_value = tb_strdup("");
            }
        } else {
            const char *v = dom_get_attr(node, "value");
            node->form_value = tb_strdup(v ? v : "");
        }
        node->form_value_set = true;
    }
    return node->form_value ? node->form_value : "";
}

void dom_input_set_value(DomNode *node, const char *val) {
    if (!node) return;
    char *nv = tb_strdup(val ? val : "");
    if (!nv) return;
    tb_free(node->form_value);
    node->form_value     = nv;
    node->form_value_set = true;
    mark_doc_dirty(node, false);
}

bool dom_input_get_checked(DomNode *node) {
    if (!node) return false;
    if (!node->form_checked_set) {
        node->form_checked     = dom_has_attr(node, "checked");
        node->form_checked_set = true;
    }
    return node->form_checked;
}

void dom_input_set_checked(DomNode *node, bool checked) {
    if (!node) return;
    node->form_checked     = checked;
    node->form_checked_set = true;
    mark_doc_dirty(node, true);
}

/* Title & Query Selectors */
static DomNode *find_first_tag_rec(DomNode *n, DomTag tag) {
    if (!n) return NULL;
    if (n->type == DOM_NODE_ELEMENT && n->tag == tag) return n;
    for (DomNode *ch = n->first_child; ch; ch = ch->next_sibling) {
        DomNode *hit = find_first_tag_rec(ch, tag);
        if (hit) return hit;
    }
    return NULL;
}

char *dom_get_title(const DomDocument *doc) {
    if (!doc || !doc->root) return tb_strdup("");
    DomNode *t = find_first_tag_rec(doc->root, TAG_TITLE);
    if (!t) return tb_strdup("");
    char *raw = dom_get_text_content(t);
    if (!raw) return tb_strdup("");
    /* Collapse whitespace in title */
    size_t r = 0, w = 0;
    while (raw[r] && tb_isspace(raw[r])) r++;
    while (raw[r]) {
        if (tb_isspace(raw[r])) {
            while (raw[r] && tb_isspace(raw[r])) r++;
            if (raw[r]) raw[w++] = ' ';
        } else {
            raw[w++] = raw[r++];
        }
    }
    raw[w] = '\0';
    return raw;
}

void dom_set_title(DomDocument *doc, const char *title) {
    if (!doc || !doc->root) return;
    DomNode *t = find_first_tag_rec(doc->root, TAG_TITLE);
    if (!t) {
        t = dom_create_element(doc, "title");
        if (!t) return;
        dom_append_child(doc->head ? doc->head : doc->root, t);
    }
    dom_set_text_content(t, title);
}

DomNode *dom_get_element_by_id(const DomNode *root, const char *id) {
    if (!root || !id || !*id) return NULL;
    if (root->type == DOM_NODE_ELEMENT) {
        const char *nid = dom_get_attr(root, "id");
        if (nid && strcmp(nid, id) == 0) return (DomNode *)root;
    }
    for (const DomNode *ch = root->first_child; ch; ch = ch->next_sibling) {
        DomNode *hit = dom_get_element_by_id(ch, id);
        if (hit) return hit;
    }
    return NULL;
}

/* CSS Selector matching: supports comma lists, descendant ' ', child '>',
 * tag, *, #id, .class, [attr], [attr=v], [attr^=v], [attr$=v], [attr*=v],
 * :first-child, :last-child, :checked, :disabled */
static bool match_compound(const DomNode *node, const char *s, size_t len) {
    if (!node || node->type != DOM_NODE_ELEMENT || len == 0) return false;
    size_t i = 0;
    while (i < len) {
        char c = s[i];
        if (c == '*') {
            i++;
        } else if (c == '#' || c == '.') {
            i++;
            size_t start = i;
            while (i < len && s[i] != '#' && s[i] != '.' && s[i] != '[' && s[i] != ':') i++;
            size_t ilen = i - start;
            if (ilen == 0) return false;
            char tok[128];
            if (ilen >= sizeof(tok)) return false;
            memcpy(tok, s + start, ilen);
            tok[ilen] = '\0';
            if (c == '#') {
                const char *id = dom_get_attr(node, "id");
                if (!id || strcmp(id, tok) != 0) return false;
            } else {
                if (!dom_class_contains(node, tok)) return false;
            }
        } else if (c == '[') {
            i++;
            while (i < len && tb_isspace(s[i])) i++;
            size_t astart = i;
            while (i < len && s[i] != ']' && s[i] != '=' && s[i] != '^' &&
                   s[i] != '$' && s[i] != '*' && !tb_isspace(s[i])) i++;
            char aname[64];
            size_t alen = i - astart;
            if (alen == 0 || alen >= sizeof(aname)) return false;
            memcpy(aname, s + astart, alen);
            aname[alen] = '\0';
            while (i < len && tb_isspace(s[i])) i++;
            const char *aval = dom_get_attr(node, aname);
            if (i < len && s[i] == ']') {
                i++;
                if (!aval) return false;
            } else {
                char op = '=';
                if (i + 1 < len && (s[i] == '^' || s[i] == '$' || s[i] == '*') && s[i + 1] == '=') {
                    op = s[i];
                    i += 2;
                } else if (i < len && s[i] == '=') {
                    i++;
                } else {
                    return false;
                }
                while (i < len && tb_isspace(s[i])) i++;
                char q = 0;
                if (i < len && (s[i] == '"' || s[i] == '\'')) q = s[i++];
                size_t vstart = i;
                while (i < len && (q ? s[i] != q : (s[i] != ']' && !tb_isspace(s[i])))) i++;
                size_t vlen = i - vstart;
                if (q && i < len && s[i] == q) i++;
                while (i < len && s[i] != ']') i++;
                if (i < len && s[i] == ']') i++;
                if (!aval) return false;
                size_t avlen = strlen(aval);
                if (op == '=') {
                    if (avlen != vlen || strncmp(aval, s + vstart, vlen) != 0) return false;
                } else if (op == '^') {
                    if (avlen < vlen || strncmp(aval, s + vstart, vlen) != 0) return false;
                } else if (op == '$') {
                    if (avlen < vlen || strncmp(aval + avlen - vlen, s + vstart, vlen) != 0) return false;
                } else if (op == '*') {
                    char needle[128];
                    if (vlen >= sizeof(needle)) return false;
                    memcpy(needle, s + vstart, vlen);
                    needle[vlen] = '\0';
                    if (!strstr(aval, needle)) return false;
                }
            }
        } else if (c == ':') {
            i++;
            if (i < len && s[i] == ':') i++;
            size_t pstart = i;
            while (i < len && s[i] != '#' && s[i] != '.' && s[i] != '[' && s[i] != ':') {
                if (s[i] == '(') {
                    while (i < len && s[i] != ')') i++;
                }
                if (i < len) i++;
            }
            size_t plen = i - pstart;
            if (plen == 11 && tb_strncasecmp(s + pstart, "first-child", 11) == 0) {
                for (const DomNode *p = node->prev_sibling; p; p = p->prev_sibling)
                    if (p->type == DOM_NODE_ELEMENT) return false;
            } else if (plen == 10 && tb_strncasecmp(s + pstart, "last-child", 10) == 0) {
                for (const DomNode *p = node->next_sibling; p; p = p->next_sibling)
                    if (p->type == DOM_NODE_ELEMENT) return false;
            } else if (plen == 7 && tb_strncasecmp(s + pstart, "checked", 7) == 0) {
                if (!dom_input_get_checked((DomNode *)node)) return false;
            } else if (plen == 8 && tb_strncasecmp(s + pstart, "disabled", 8) == 0) {
                if (!dom_has_attr(node, "disabled")) return false;
            } else {
                /* Unknown pseudo-class (e.g. :hover in non-hovered state) does not match */
                return false;
            }
        } else {
            size_t tstart = i;
            while (i < len && s[i] != '#' && s[i] != '.' && s[i] != '[' && s[i] != ':') i++;
            size_t tlen = i - tstart;
            const char *nt = dom_node_tag_name(node);
            if (strlen(nt) != tlen || tb_strncasecmp(nt, s + tstart, tlen) != 0) return false;
        }
    }
    return true;
}

typedef struct {
    const char *ptr;
    size_t      len;
    char        comb_to_next; /* ' ' descendant, '>' direct child, 0 rightmost */
} SelPart;

static bool match_single_chain(const DomNode *node, const char *sel, size_t len) {
    SelPart parts[32];
    int nparts = 0;
    size_t i = 0;

    while (i < len && nparts < 32) {
        while (i < len && tb_isspace(sel[i])) i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && !tb_isspace(sel[i]) && sel[i] != '>') {
            if (sel[i] == '[') {
                while (i < len && sel[i] != ']') i++;
            }
            if (i < len) i++;
        }
        size_t plen = i - start;
        if (plen == 0) break;
        char comb = 0;
        size_t j = i;
        while (j < len && tb_isspace(sel[j])) j++;
        if (j < len && sel[j] == '>') {
            comb = '>';
            j++;
            while (j < len && tb_isspace(sel[j])) j++;
            i = j;
        } else if (j < len) {
            comb = ' ';
            i = j;
        }
        parts[nparts].ptr          = sel + start;
        parts[nparts].len          = plen;
        parts[nparts].comb_to_next = comb;
        nparts++;
    }
    if (nparts == 0) return false;

    if (!match_compound(node, parts[nparts - 1].ptr, parts[nparts - 1].len)) return false;
    const DomNode *cur = node;
    for (int p = nparts - 2; p >= 0; p--) {
        char comb = parts[p].comb_to_next;
        if (comb == '>') {
            cur = cur->parent;
            if (!cur || cur->type != DOM_NODE_ELEMENT) return false;
            if (!match_compound(cur, parts[p].ptr, parts[p].len)) return false;
        } else {
            cur = cur->parent;
            bool found = false;
            while (cur && cur->type == DOM_NODE_ELEMENT) {
                if (match_compound(cur, parts[p].ptr, parts[p].len)) {
                    found = true;
                    break;
                }
                cur = cur->parent;
            }
            if (!found) return false;
        }
    }
    return true;
}

bool dom_matches_selector(const DomNode *node, const char *selector) {
    if (!node || node->type != DOM_NODE_ELEMENT || !selector) return false;
    const char *p = selector;
    while (*p) {
        const char *start = p;
        int bracket = 0;
        while (*p && !(*p == ',' && bracket == 0)) {
            if (*p == '[') bracket++;
            else if (*p == ']' && bracket > 0) bracket--;
            p++;
        }
        if (match_single_chain(node, start, (size_t)(p - start))) return true;
        if (*p == ',') p++;
    }
    return false;
}

static DomNode *query_one_rec(const DomNode *root, const char *selector, bool check_self) {
    if (!root) return NULL;
    if (check_self && root->type == DOM_NODE_ELEMENT && dom_matches_selector(root, selector)) {
        return (DomNode *)root;
    }
    for (const DomNode *ch = root->first_child; ch; ch = ch->next_sibling) {
        DomNode *hit = query_one_rec(ch, selector, true);
        if (hit) return hit;
    }
    return NULL;
}

DomNode *dom_query_selector(const DomNode *root, const char *selector) {
    return query_one_rec(root, selector, false);
}

void dom_nodelist_init(DomNodeList *nl) {
    nl->items = NULL;
    nl->count = 0;
    nl->cap   = 0;
}

void dom_nodelist_push(DomNodeList *nl, DomNode *n) {
    if (nl->count >= nl->cap) {
        size_t ncap = nl->cap ? nl->cap * 2 : 16;
        DomNode **ni = (DomNode **)tb_realloc(nl->items, ncap * sizeof(DomNode *));
        if (!ni) return;
        nl->items = ni;
        nl->cap   = ncap;
    }
    nl->items[nl->count++] = n;
}

void dom_nodelist_free(DomNodeList *nl) {
    tb_free(nl->items);
    nl->items = NULL;
    nl->count = 0;
    nl->cap   = 0;
}

static void query_all_rec(const DomNode *root, const char *selector, bool check_self, DomNodeList *out) {
    if (!root) return;
    if (check_self && root->type == DOM_NODE_ELEMENT && dom_matches_selector(root, selector)) {
        dom_nodelist_push(out, (DomNode *)root);
    }
    for (const DomNode *ch = root->first_child; ch; ch = ch->next_sibling) {
        query_all_rec(ch, selector, true, out);
    }
}

void dom_query_selector_all(const DomNode *root, const char *selector, DomNodeList *out) {
    dom_nodelist_init(out);
    if (!root || !selector || !*selector) return;
    query_all_rec(root, selector, false, out);
}
