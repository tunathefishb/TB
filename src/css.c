#include "css.h"
#include "common.h"
#include "dom.h"

void css_stylesheet_init(CssStylesheet *ss) {
    memset(ss, 0, sizeof(*ss));
    tb_arena_init(&ss->arena, 8192);
}

void css_stylesheet_reset(CssStylesheet *ss) {
    tb_arena_reset(&ss->arena);
    ss->rules_head = NULL;
    ss->rules_tail = NULL;
    ss->rule_count = 0;
}

void css_stylesheet_free(CssStylesheet *ss) {
    tb_arena_destroy(&ss->arena);
    ss->rules_head = NULL;
    ss->rules_tail = NULL;
    ss->rule_count = 0;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

bool css_parse_color(const char *str, CssColor *out) {
    if (!str || !out) return false;
    while (*str && tb_isspace(*str)) str++;
    size_t len = strlen(str);
    while (len > 0 && (tb_isspace(str[len - 1]) || str[len - 1] == ';')) len--;
    if (len == 0) return false;

    /* Strip !important if attached */
    const char *bang = memchr(str, '!', len);
    if (bang) {
        len = (size_t)(bang - str);
        while (len > 0 && tb_isspace(str[len - 1])) len--;
    }

    if (str[0] == '#') {
        if (len == 4) {
            int r = hex_nibble(str[1]), g = hex_nibble(str[2]), b = hex_nibble(str[3]);
            if (r >= 0 && g >= 0 && b >= 0) {
                *out = css_rgb((uint8_t)(r * 17), (uint8_t)(g * 17), (uint8_t)(b * 17));
                return true;
            }
        } else if (len >= 7) {
            int r1 = hex_nibble(str[1]), r2 = hex_nibble(str[2]);
            int g1 = hex_nibble(str[3]), g2 = hex_nibble(str[4]);
            int b1 = hex_nibble(str[5]), b2 = hex_nibble(str[6]);
            if (r1 >= 0 && r2 >= 0 && g1 >= 0 && g2 >= 0 && b1 >= 0 && b2 >= 0) {
                *out = css_rgb((uint8_t)((r1 << 4) | r2),
                               (uint8_t)((g1 << 4) | g2),
                               (uint8_t)((b1 << 4) | b2));
                return true;
            }
        }
        return false;
    }

    if ((len > 4 && tb_strncasecmp(str, "rgb(", 4) == 0) ||
        (len > 5 && tb_strncasecmp(str, "rgba(", 5) == 0)) {
        const char *p = strchr(str, '(') + 1;
        int r = atoi(p);
        const char *c1 = strchr(p, ',');
        if (!c1) return false;
        int g = atoi(c1 + 1);
        const char *c2 = strchr(c1 + 1, ',');
        if (!c2) return false;
        int b = atoi(c2 + 1);
        if (r < 0) r = 0; else if (r > 255) r = 255;
        if (g < 0) g = 0; else if (g > 255) g = 255;
        if (b < 0) b = 0; else if (b > 255) b = 255;
        *out = css_rgb((uint8_t)r, (uint8_t)g, (uint8_t)b);
        return true;
    }

    if ((len == 11 && tb_strncasecmp(str, "transparent", 11) == 0) ||
        (len == 7 && tb_strncasecmp(str, "initial", 7) == 0)) {
        out->mode = CSS_COLOR_DEFAULT;
        return true;
    }
    if (len == 7 && tb_strncasecmp(str, "inherit", 7) == 0) {
        out->mode = CSS_COLOR_INHERIT;
        return true;
    }

    static const struct { const char *name; uint8_t r, g, b; } named[] = {
        {"black", 15, 23, 42}, {"white", 248, 250, 252},
        {"red", 248, 113, 113}, {"green", 74, 222, 128}, {"blue", 96, 165, 250},
        {"yellow", 250, 204, 21}, {"cyan", 56, 189, 248}, {"aqua", 56, 189, 248},
        {"magenta", 232, 121, 249}, {"fuchsia", 232, 121, 249},
        {"gray", 148, 163, 184}, {"grey", 148, 163, 184},
        {"darkgray", 100, 116, 139}, {"darkgrey", 100, 116, 139},
        {"lightgray", 203, 213, 225}, {"lightgrey", 203, 213, 225},
        {"silver", 192, 192, 192}, {"orange", 251, 146, 60},
        {"purple", 168, 85, 247}, {"violet", 192, 132, 252},
        {"pink", 244, 114, 182}, {"teal", 45, 212, 191},
        {"navy", 30, 58, 138}, {"lime", 132, 204, 22},
        {"gold", 251, 191, 36}, {"coral", 251, 113, 133},
        {"crimson", 220, 38, 38}, {"tomato", 248, 113, 113},
        {"indigo", 99, 102, 241}, {"steelblue", 70, 130, 180},
        {"dodgerblue", 59, 130, 246}, {"olive", 163, 163, 20},
        {"maroon", 153, 27, 27}, {"brown", 180, 83, 9}
    };
    for (size_t i = 0; i < sizeof(named) / sizeof(named[0]); i++) {
        if (strlen(named[i].name) == len && tb_strncasecmp(str, named[i].name, len) == 0) {
            *out = css_rgb(named[i].r, named[i].g, named[i].b);
            return true;
        }
    }
    return false;
}

static int parse_css_space_unit(const char *val, bool horizontal) {
    while (*val && tb_isspace(*val)) val++;
    if (!*val) return 0;
    char *endp = NULL;
    double num = strtod(val, &endp);
    if (endp == val) return 0;
    if (tb_strncasecmp(endp, "px", 2) == 0) {
        int cells = (int)(num / (horizontal ? 8.0 : 16.0) + (num > 0 ? 0.5 : 0.0));
        if (num > 0 && cells == 0) cells = 1;
        return cells > 16 ? 16 : (cells < 0 ? 0 : cells);
    }
    if (tb_strncasecmp(endp, "em", 2) == 0 || tb_strncasecmp(endp, "rem", 3) == 0) {
        int cells = (int)(num * (horizontal ? 2.0 : 1.0) + 0.4);
        if (num > 0 && cells == 0) cells = 1;
        return cells > 16 ? 16 : (cells < 0 ? 0 : cells);
    }
    int cells = (int)num;
    return cells > 16 ? 16 : (cells < 0 ? 0 : cells);
}

static void parse_box_shorthand(const char *val, int8_t *top, int8_t *right,
                                int8_t *bottom, int8_t *left) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", val);
    char *bang = strchr(buf, '!');
    if (bang) *bang = '\0';

    char *toks[4];
    int n = 0;
    char *save = NULL;
    for (char *t = strtok_r(buf, " \t\r\n", &save); t && n < 4; t = strtok_r(NULL, " \t\r\n", &save)) {
        toks[n++] = t;
    }
    if (n == 1) {
        *top = *bottom = (int8_t)parse_css_space_unit(toks[0], false);
        *left = *right = (int8_t)parse_css_space_unit(toks[0], true);
    } else if (n == 2) {
        *top = *bottom = (int8_t)parse_css_space_unit(toks[0], false);
        *left = *right = (int8_t)parse_css_space_unit(toks[1], true);
    } else if (n == 3) {
        *top    = (int8_t)parse_css_space_unit(toks[0], false);
        *left   = *right = (int8_t)parse_css_space_unit(toks[1], true);
        *bottom = (int8_t)parse_css_space_unit(toks[2], false);
    } else if (n == 4) {
        *top    = (int8_t)parse_css_space_unit(toks[0], false);
        *right  = (int8_t)parse_css_space_unit(toks[1], true);
        *bottom = (int8_t)parse_css_space_unit(toks[2], false);
        *left   = (int8_t)parse_css_space_unit(toks[3], true);
    }
}

void css_apply_decl(CssStyle *st, const char *prop, const char *val) {
    if (!st || !prop || !val) return;
    while (*prop && tb_isspace(*prop)) prop++;
    while (*val && tb_isspace(*val)) val++;

    char vclean[128];
    snprintf(vclean, sizeof(vclean), "%s", val);
    char *bang = strchr(vclean, '!');
    if (bang) *bang = '\0';
    size_t vlen = strlen(vclean);
    while (vlen > 0 && tb_isspace(vclean[vlen - 1])) vclean[--vlen] = '\0';

    if (tb_strcasecmp(prop, "display") == 0) {
        if (tb_strcasecmp(vclean, "none") == 0) st->display = CSS_DISP_NONE;
        else if (tb_strcasecmp(vclean, "inline") == 0) st->display = CSS_DISP_INLINE;
        else if (tb_strcasecmp(vclean, "list-item") == 0) st->display = CSS_DISP_LIST_ITEM;
        else if (tb_strcasecmp(vclean, "table") == 0) st->display = CSS_DISP_TABLE;
        else if (tb_strcasecmp(vclean, "table-row") == 0) st->display = CSS_DISP_TABLE_ROW;
        else if (tb_strcasecmp(vclean, "table-cell") == 0) st->display = CSS_DISP_TABLE_CELL;
        else st->display = CSS_DISP_BLOCK;
    } else if (tb_strcasecmp(prop, "color") == 0) {
        CssColor c;
        if (css_parse_color(vclean, &c)) {
            st->fg     = c;
            st->fg_set = (c.mode == CSS_COLOR_RGB);
        }
    } else if (tb_strcasecmp(prop, "background") == 0 ||
               tb_strcasecmp(prop, "background-color") == 0) {
        /* Try each whitespace token in background shorthand */
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "%s", vclean);
        CssColor c;
        if (css_parse_color(tmp, &c)) {
            st->bg     = c;
            st->bg_set = (c.mode == CSS_COLOR_RGB);
        } else {
            char *save = NULL;
            for (char *t = strtok_r(tmp, " \t", &save); t; t = strtok_r(NULL, " \t", &save)) {
                if (css_parse_color(t, &c)) {
                    st->bg     = c;
                    st->bg_set = (c.mode == CSS_COLOR_RGB);
                    break;
                }
            }
        }
    } else if (tb_strcasecmp(prop, "font-weight") == 0) {
        st->bold = (tb_strcasecmp(vclean, "bold") == 0 ||
                    tb_strcasecmp(vclean, "bolder") == 0 ||
                    atoi(vclean) >= 600) ? 1 : 0;
    } else if (tb_strcasecmp(prop, "font-style") == 0) {
        st->italic = (tb_strcasecmp(vclean, "italic") == 0 ||
                      tb_strcasecmp(vclean, "oblique") == 0) ? 1 : 0;
    } else if (tb_strcasecmp(prop, "text-decoration") == 0) {
        if (tb_strcasecmp(vclean, "none") == 0) {
            st->underline = 0;
            st->strike    = 0;
        } else {
            if (strstr(vclean, "underline")) st->underline = 1;
            if (strstr(vclean, "line-through")) st->strike = 1;
        }
    } else if (tb_strcasecmp(prop, "text-align") == 0) {
        if (tb_strcasecmp(vclean, "center") == 0) st->text_align = 1;
        else if (tb_strcasecmp(vclean, "right") == 0) st->text_align = 2;
        else st->text_align = 0;
    } else if (tb_strcasecmp(prop, "text-transform") == 0) {
        if (tb_strcasecmp(vclean, "uppercase") == 0) st->text_transform = 1;
        else if (tb_strcasecmp(vclean, "lowercase") == 0) st->text_transform = 2;
        else st->text_transform = 0;
    } else if (tb_strcasecmp(prop, "white-space") == 0) {
        st->pre = (tb_strncasecmp(vclean, "pre", 3) == 0) ? 1 : 0;
    } else if (tb_strcasecmp(prop, "border") == 0) {
        if (tb_strcasecmp(vclean, "none") == 0 || strcmp(vclean, "0") == 0) {
            st->border = 0;
        } else {
            st->border = 1;
            char tmp[128];
            snprintf(tmp, sizeof(tmp), "%s", vclean);
            char *save = NULL;
            for (char *t = strtok_r(tmp, " \t", &save); t; t = strtok_r(NULL, " \t", &save)) {
                CssColor bc;
                if (css_parse_color(t, &bc) && bc.mode == CSS_COLOR_RGB) {
                    st->border_color = bc;
                }
            }
        }
    } else if (tb_strcasecmp(prop, "border-color") == 0) {
        CssColor bc;
        if (css_parse_color(vclean, &bc)) st->border_color = bc;
    } else if (tb_strcasecmp(prop, "margin") == 0) {
        parse_box_shorthand(vclean, &st->margin_top, &st->margin_right,
                            &st->margin_bottom, &st->margin_left);
    } else if (tb_strcasecmp(prop, "margin-top") == 0) {
        st->margin_top = (int8_t)parse_css_space_unit(vclean, false);
    } else if (tb_strcasecmp(prop, "margin-bottom") == 0) {
        st->margin_bottom = (int8_t)parse_css_space_unit(vclean, false);
    } else if (tb_strcasecmp(prop, "margin-left") == 0) {
        st->margin_left = (int8_t)parse_css_space_unit(vclean, true);
    } else if (tb_strcasecmp(prop, "margin-right") == 0) {
        st->margin_right = (int8_t)parse_css_space_unit(vclean, true);
    } else if (tb_strcasecmp(prop, "padding") == 0) {
        parse_box_shorthand(vclean, &st->padding_top, &st->padding_right,
                            &st->padding_bottom, &st->padding_left);
    } else if (tb_strcasecmp(prop, "padding-top") == 0) {
        st->padding_top = (int8_t)parse_css_space_unit(vclean, false);
    } else if (tb_strcasecmp(prop, "padding-bottom") == 0) {
        st->padding_bottom = (int8_t)parse_css_space_unit(vclean, false);
    } else if (tb_strcasecmp(prop, "padding-left") == 0) {
        st->padding_left = (int8_t)parse_css_space_unit(vclean, true);
    } else if (tb_strcasecmp(prop, "padding-right") == 0) {
        st->padding_right = (int8_t)parse_css_space_unit(vclean, true);
    } else if (tb_strcasecmp(prop, "width") == 0 || tb_strcasecmp(prop, "max-width") == 0) {
        char *endp = NULL;
        double num = strtod(vclean, &endp);
        if (endp != vclean && num > 0) {
            if (*endp == '%') {
                int pct = (int)num;
                if (pct > 100) pct = 100;
                st->width_cols = (int16_t)(-pct);
            } else if (tb_strncasecmp(endp, "px", 2) == 0) {
                int cols = (int)(num / 8.0 + 0.5);
                st->width_cols = (int16_t)(cols > 500 ? 500 : cols);
            } else {
                int cols = (int)num;
                st->width_cols = (int16_t)(cols > 500 ? 500 : cols);
            }
        }
    }
}

void css_parse_inline(CssStyle *st, const char *inline_css) {
    if (!st || !inline_css) return;
    const char *p = inline_css;
    while (*p) {
        while (*p && (tb_isspace(*p) || *p == ';')) p++;
        if (!*p) break;
        const char *colon = strchr(p, ':');
        if (!colon) break;
        size_t plen = (size_t)(colon - p);
        while (plen > 0 && tb_isspace(p[plen - 1])) plen--;
        const char *vstart = colon + 1;
        while (*vstart && tb_isspace(*vstart)) vstart++;
        const char *semi = strchr(vstart, ';');
        size_t vlen = semi ? (size_t)(semi - vstart) : strlen(vstart);
        while (vlen > 0 && tb_isspace(vstart[vlen - 1])) vlen--;

        char prop[64], val[128];
        if (plen > 0 && plen < sizeof(prop) && vlen < sizeof(val)) {
            memcpy(prop, p, plen);
            prop[plen] = '\0';
            memcpy(val, vstart, vlen);
            val[vlen] = '\0';
            css_apply_decl(st, prop, val);
        }
        p = semi ? semi + 1 : vstart + strlen(vstart);
    }
}

static uint32_t compute_specificity(const char *sel, size_t len) {
    uint32_t ids = 0, classes = 0, tags = 0;
    size_t i = 0;
    while (i < len) {
        while (i < len && (tb_isspace(sel[i]) || sel[i] == '>')) i++;
        if (i >= len) break;
        if (sel[i] == '#') {
            ids++;
            i++;
            while (i < len && !tb_isspace(sel[i]) && sel[i] != '#' &&
                   sel[i] != '.' && sel[i] != '[' && sel[i] != ':' && sel[i] != '>') i++;
        } else if (sel[i] == '.') {
            classes++;
            i++;
            while (i < len && !tb_isspace(sel[i]) && sel[i] != '#' &&
                   sel[i] != '.' && sel[i] != '[' && sel[i] != ':' && sel[i] != '>') i++;
        } else if (sel[i] == '[') {
            classes++;
            while (i < len && sel[i] != ']') i++;
            if (i < len) i++;
        } else if (sel[i] == ':') {
            classes++;
            i++;
            while (i < len && !tb_isspace(sel[i]) && sel[i] != '#' &&
                   sel[i] != '.' && sel[i] != '[' && sel[i] != ':' && sel[i] != '>') i++;
        } else if (sel[i] == '*') {
            i++;
        } else {
            tags++;
            while (i < len && !tb_isspace(sel[i]) && sel[i] != '#' &&
                   sel[i] != '.' && sel[i] != '[' && sel[i] != ':' && sel[i] != '>') i++;
        }
    }
    return (ids << 16) | (classes << 8) | tags;
}

static char *strip_css_comments(const char *css) {
    if (!css) return NULL;
    size_t len = strlen(css);
    char *out  = (char *)tb_malloc(len + 1);
    if (!out) return NULL;
    size_t r = 0, w = 0;
    while (r < len) {
        if (r + 1 < len && css[r] == '/' && css[r + 1] == '*') {
            r += 2;
            while (r + 1 < len && !(css[r] == '*' && css[r + 1] == '/')) r++;
            r += 2;
            out[w++] = ' ';
        } else {
            out[w++] = css[r++];
        }
    }
    out[w] = '\0';
    return out;
}

void css_stylesheet_parse(CssStylesheet *ss, const char *css_text) {
    if (!ss || !css_text) return;
    char *clean = strip_css_comments(css_text);
    if (!clean) return;

    const char *p = clean;
    while (*p && ss->rule_count < 2048) {
        while (*p && tb_isspace(*p)) p++;
        if (!*p) break;
        if (*p == '@') {
            /* Skip @import / @charset; unwrap @media (screen/all) or skip @keyframes */
            const char *brace = strchr(p, '{');
            const char *semi  = strchr(p, ';');
            if (semi && (!brace || semi < brace)) {
                p = semi + 1;
                continue;
            }
            if (!brace) break;
            bool is_media = (tb_strncasecmp(p, "@media", 6) == 0 &&
                             !strstr(p, "print"));
            int depth = 1;
            const char *inner_start = brace + 1;
            const char *q = inner_start;
            while (*q && depth > 0) {
                if (*q == '{') depth++;
                else if (*q == '}') depth--;
                q++;
            }
            if (is_media && q > inner_start + 1) {
                char *sub = tb_strndup(inner_start, (size_t)(q - 1 - inner_start));
                if (sub) {
                    css_stylesheet_parse(ss, sub);
                    tb_free(sub);
                }
            }
            p = q;
            continue;
        }

        const char *lbrace = strchr(p, '{');
        if (!lbrace) break;
        const char *rbrace = strchr(lbrace + 1, '}');
        if (!rbrace) break;

        /* Parse declaration block once into arena */
        CssDecl *decls_head = NULL;
        CssDecl *decls_tail = NULL;
        const char *dp = lbrace + 1;
        while (dp < rbrace) {
            while (dp < rbrace && (tb_isspace(*dp) || *dp == ';')) dp++;
            if (dp >= rbrace) break;
            const char *colon = memchr(dp, ':', (size_t)(rbrace - dp));
            if (!colon) break;
            size_t plen = (size_t)(colon - dp);
            while (plen > 0 && tb_isspace(dp[plen - 1])) plen--;
            const char *vs = colon + 1;
            while (vs < rbrace && tb_isspace(*vs)) vs++;
            const char *semi = memchr(vs, ';', (size_t)(rbrace - vs));
            const char *ve = semi ? semi : rbrace;
            size_t vlen = (size_t)(ve - vs);
            while (vlen > 0 && tb_isspace(vs[vlen - 1])) vlen--;

            if (plen > 0 && vlen > 0) {
                CssDecl *d = (CssDecl *)tb_arena_alloc(&ss->arena, sizeof(CssDecl));
                if (d) {
                    d->prop = tb_arena_strndup(&ss->arena, dp, plen);
                    d->val  = tb_arena_strndup(&ss->arena, vs, vlen);
                    d->next = NULL;
                    if (!decls_head) decls_head = d;
                    else decls_tail->next = d;
                    decls_tail = d;
                }
            }
            dp = semi ? semi + 1 : rbrace;
        }

        /* Split comma-separated selectors so each gets its own specificity */
        if (decls_head) {
            const char *sp = p;
            while (sp < lbrace) {
                while (sp < lbrace && tb_isspace(*sp)) sp++;
                const char *sstart = sp;
                int br = 0;
                while (sp < lbrace && !(*sp == ',' && br == 0)) {
                    if (*sp == '[') br++;
                    else if (*sp == ']' && br > 0) br--;
                    sp++;
                }
                size_t slen = (size_t)(sp - sstart);
                while (slen > 0 && tb_isspace(sstart[slen - 1])) slen--;
                if (slen > 0) {
                    CssRule *rule = (CssRule *)tb_arena_alloc(&ss->arena, sizeof(CssRule));
                    if (rule) {
                        rule->selector    = tb_arena_strndup(&ss->arena, sstart, slen);
                        rule->specificity = compute_specificity(sstart, slen);
                        rule->order       = ss->rule_count++;
                        rule->decls       = decls_head;
                        rule->next        = NULL;
                        if (!ss->rules_head) ss->rules_head = rule;
                        else ss->rules_tail->next = rule;
                        ss->rules_tail = rule;
                    }
                }
                if (sp < lbrace && *sp == ',') sp++;
            }
        }
        p = rbrace + 1;
    }
    tb_free(clean);
}

static void init_ua_defaults(DomNode *node, const CssStyle *parent_st) {
    CssStyle *st = &node->style;
    memset(st, 0, sizeof(*st));

    /* Inherited properties from parent */
    if (parent_st) {
        st->fg             = parent_st->fg;
        st->fg_set         = parent_st->fg_set;
        st->bold           = parent_st->bold;
        st->italic         = parent_st->italic;
        st->underline      = parent_st->underline;
        st->strike         = parent_st->strike;
        st->pre            = parent_st->pre;
        st->text_align     = parent_st->text_align;
        st->text_transform = parent_st->text_transform;
    }

    st->display = CSS_DISP_INLINE;
    switch (node->tag) {
        case TAG_HEAD: case TAG_TITLE: case TAG_META: case TAG_LINK:
        case TAG_STYLE: case TAG_SCRIPT: case TAG_NOSCRIPT:
            st->display = CSS_DISP_NONE;
            break;
        case TAG_HTML: case TAG_BODY: case TAG_DIV: case TAG_FORM:
        case TAG_HEADER: case TAG_NAV: case TAG_MAIN: case TAG_SECTION:
        case TAG_ARTICLE: case TAG_ASIDE: case TAG_FOOTER: case TAG_DETAILS:
        case TAG_SUMMARY: case TAG_FIGURE: case TAG_FIGCAPTION:
        case TAG_DL: case TAG_DT: case TAG_HR:
            st->display = CSS_DISP_BLOCK;
            break;
        case TAG_DD:
            st->display     = CSS_DISP_BLOCK;
            st->margin_left = 4;
            break;
        case TAG_P:
            st->display       = CSS_DISP_BLOCK;
            st->margin_bottom = 1;
            break;
        case TAG_H1:
            st->display       = CSS_DISP_BLOCK;
            st->bold          = 1;
            st->fg            = css_rgb(56, 189, 248);
            st->fg_set        = 1;
            st->margin_top    = 1;
            st->margin_bottom = 1;
            break;
        case TAG_H2:
            st->display       = CSS_DISP_BLOCK;
            st->bold          = 1;
            st->fg            = css_rgb(167, 139, 250);
            st->fg_set        = 1;
            st->margin_top    = 1;
            st->margin_bottom = 1;
            break;
        case TAG_H3: case TAG_H4: case TAG_H5: case TAG_H6:
            st->display       = CSS_DISP_BLOCK;
            st->bold          = 1;
            st->fg            = css_rgb(251, 191, 36);
            st->fg_set        = 1;
            st->margin_top    = 1;
            break;
        case TAG_UL: case TAG_OL:
            st->display       = CSS_DISP_BLOCK;
            st->margin_bottom = 1;
            break;
        case TAG_LI:
            st->display = CSS_DISP_LIST_ITEM;
            break;
        case TAG_PRE:
            st->display       = CSS_DISP_BLOCK;
            st->pre           = 1;
            st->bg            = css_rgb(15, 23, 42);
            st->bg_set        = 1;
            st->border        = 1;
            st->border_color  = css_rgb(51, 65, 85);
            st->padding_left  = 1;
            st->padding_right = 1;
            st->margin_bottom = 1;
            break;
        case TAG_BLOCKQUOTE:
            st->display       = CSS_DISP_BLOCK;
            st->italic        = 1;
            st->fg            = css_rgb(148, 163, 184);
            st->fg_set        = 1;
            st->margin_left   = 2;
            st->margin_bottom = 1;
            break;
        case TAG_CODE:
            if (!parent_st || !parent_st->pre) {
                st->fg     = css_rgb(244, 114, 182);
                st->fg_set = 1;
            }
            break;
        case TAG_A:
            if (dom_has_attr(node, "href")) {
                st->fg        = css_rgb(56, 189, 248);
                st->fg_set    = 1;
                st->underline = 1;
            }
            break;
        case TAG_STRONG: case TAG_B:
            st->bold = 1;
            break;
        case TAG_EM: case TAG_I:
            st->italic = 1;
            break;
        case TAG_U:
            st->underline = 1;
            break;
        case TAG_S: case TAG_DEL:
            st->strike = 1;
            break;
        case TAG_MARK:
            st->bg     = css_rgb(133, 77, 14);
            st->bg_set = 1;
            st->fg     = css_rgb(254, 240, 138);
            st->fg_set = 1;
            break;
        case TAG_TABLE:
            st->display       = CSS_DISP_TABLE;
            st->margin_bottom = 1;
            break;
        case TAG_THEAD: case TAG_TBODY: case TAG_TFOOT:
            st->display = CSS_DISP_BLOCK;
            break;
        case TAG_TR:
            st->display = CSS_DISP_TABLE_ROW;
            break;
        case TAG_TH:
            st->display = CSS_DISP_TABLE_CELL;
            st->bold    = 1;
            st->fg      = css_rgb(56, 189, 248);
            st->fg_set  = 1;
            break;
        case TAG_TD:
            st->display = CSS_DISP_TABLE_CELL;
            break;
        case TAG_INPUT: {
            const char *t = dom_get_attr(node, "type");
            if (t && tb_strcasecmp(t, "hidden") == 0) st->display = CSS_DISP_NONE;
            break;
        }
        default:
            break;
    }

    if (dom_has_attr(node, "hidden")) {
        st->display = CSS_DISP_NONE;
    }
}

typedef struct {
    const CssRule *rule;
} MatchedRule;

static int cmp_matched_rules(const void *a, const void *b) {
    const CssRule *ra = ((const MatchedRule *)a)->rule;
    const CssRule *rb = ((const MatchedRule *)b)->rule;
    if (ra->specificity != rb->specificity)
        return (ra->specificity < rb->specificity) ? -1 : 1;
    return (ra->order < rb->order) ? -1 : 1;
}

static void compute_node_rec(DomNode *node, const CssStyle *parent_st, const CssStylesheet *ss) {
    if (!node) return;
    if (node->type != DOM_NODE_ELEMENT) {
        for (DomNode *ch = node->first_child; ch; ch = ch->next_sibling) {
            compute_node_rec(ch, parent_st, ss);
        }
        return;
    }

    init_ua_defaults(node, parent_st);

    if (ss && ss->rules_head && node->style.display != CSS_DISP_NONE) {
        MatchedRule matches[128];
        size_t mcount = 0;
        for (const CssRule *r = ss->rules_head; r; r = r->next) {
            if (dom_matches_selector(node, r->selector)) {
                if (mcount < 128) matches[mcount++].rule = r;
            }
        }
        if (mcount > 1) {
            qsort(matches, mcount, sizeof(MatchedRule), cmp_matched_rules);
        }
        for (size_t i = 0; i < mcount; i++) {
            for (const CssDecl *d = matches[i].rule->decls; d; d = d->next) {
                css_apply_decl(&node->style, d->prop, d->val);
            }
        }
    }

    /* Inline style="..." overrides stylesheet rules */
    const char *inl = dom_get_attr(node, "style");
    if (inl && *inl) {
        css_parse_inline(&node->style, inl);
    }

    if (node->style.display == CSS_DISP_NONE) return;

    for (DomNode *ch = node->first_child; ch; ch = ch->next_sibling) {
        compute_node_rec(ch, &node->style, ss);
    }
}

static void collect_styles_rec(const DomNode *n, CssStylesheet *ss) {
    if (!n) return;
    if (n->type == DOM_NODE_ELEMENT && n->tag == TAG_STYLE) {
        char *css = dom_get_text_content(n);
        if (css) {
            css_stylesheet_parse(ss, css);
            tb_free(css);
        }
        return;
    }
    for (const DomNode *ch = n->first_child; ch; ch = ch->next_sibling) {
        collect_styles_rec(ch, ss);
    }
}

void css_compute_document(DomDocument *doc, const CssStylesheet *external_ss) {
    if (!doc || !doc->root) return;
    CssStylesheet local_ss;
    const CssStylesheet *active_ss = external_ss;
    if (!active_ss) {
        css_stylesheet_init(&local_ss);
        collect_styles_rec(doc->root, &local_ss);
        active_ss = &local_ss;
    }
    compute_node_rec(doc->root, NULL, active_ss);
    if (!external_ss) {
        css_stylesheet_free(&local_ss);
    }
    doc->dirty_style = false;
}
