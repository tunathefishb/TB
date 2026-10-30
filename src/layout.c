#define _GNU_SOURCE
#include "layout.h"

#include <stdlib.h>

void layout_init(LayoutDoc *ld) {
    memset(ld, 0, sizeof(*ld));
    tb_arena_init(&ld->arena, 16384);
}

void layout_free(LayoutDoc *ld) {
    if (!ld) return;
    tb_arena_destroy(&ld->arena);
    tb_free(ld->lines);
    tb_free(ld->hits);
    memset(ld, 0, sizeof(*ld));
}

typedef struct {
    CssColor fg;
    CssColor bg;
    uint8_t  bold : 1;
    uint8_t  italic : 1;
    uint8_t  underline : 1;
    uint8_t  strike : 1;
    uint8_t  text_transform;
    int      hit_index;
} PenStyle;

typedef struct {
    CssColor border_fg;
    CssColor fill_bg;
    int      left_col;
    int      right_col;
    bool     has_border;
    bool     is_quote;
} BoxDecor;

typedef struct {
    LayoutDoc *ld;
    DomNode   *editing_node;
    size_t     edit_cursor;

    int        left_margin;
    int        right_limit;
    int        cur_line;
    int        cur_col;
    bool       at_line_start;
    uint8_t    text_align;
    int        pending_blank_lines;

    BoxDecor   decors[16];
    int        decor_depth;
} LayoutCtx;

static int utf8_display_width(const char *s, size_t len) {
    int w = 0;
    size_t i = 0;
    while (i < len) {
        uint32_t cp = 0;
        size_t n = tb_utf8_decode(s + i, len - i, &cp);
        if (n == 0) break;
        w += tb_unicode_width(cp);
        i += n;
    }
    return w;
}

static int ensure_line(LayoutDoc *ld, int idx) {
    while (idx >= ld->line_cap) {
        int ncap = ld->line_cap ? ld->line_cap * 2 : 128;
        LayoutLine *nl = (LayoutLine *)tb_realloc(ld->lines, (size_t)ncap * sizeof(LayoutLine));
        if (!nl) return ld->line_count > 0 ? ld->line_count - 1 : 0;
        memset(nl + ld->line_cap, 0, (size_t)(ncap - ld->line_cap) * sizeof(LayoutLine));
        ld->lines    = nl;
        ld->line_cap = ncap;
    }
    if (idx >= ld->line_count) {
        ld->line_count = idx + 1;
    }
    return idx;
}

static int add_hit(LayoutDoc *ld, int line_y, int col_start, int col_end,
                   HitKind kind, DomNode *node) {
    if (ld->hit_count >= ld->hit_cap) {
        int ncap = ld->hit_cap ? ld->hit_cap * 2 : 32;
        HitBox *nh = (HitBox *)tb_realloc(ld->hits, (size_t)ncap * sizeof(HitBox));
        if (!nh) return -1;
        ld->hits    = nh;
        ld->hit_cap = ncap;
    }
    int idx = ld->hit_count++;
    ld->hits[idx].line_y    = line_y;
    ld->hits[idx].col_start = col_start;
    ld->hits[idx].col_end   = col_end;
    ld->hits[idx].kind      = kind;
    ld->hits[idx].node      = node;
    return idx;
}

static void append_span_raw(LayoutDoc *ld, int line_idx, int col, const char *text,
                            size_t byte_len, int width, PenStyle pen) {
    if (byte_len == 0 || width <= 0) return;
    line_idx = ensure_line(ld, line_idx);
    LayoutLine *ln = &ld->lines[line_idx];

    LayoutSpan *sp = (LayoutSpan *)tb_arena_alloc(&ld->arena, sizeof(LayoutSpan));
    char *copy     = tb_arena_strndup(&ld->arena, text, byte_len);
    if (!sp || !copy) return;

    if (pen.text_transform == 1) {
        for (size_t i = 0; i < byte_len; i++) copy[i] = tb_toupper(copy[i]);
    } else if (pen.text_transform == 2) {
        for (size_t i = 0; i < byte_len; i++) copy[i] = tb_tolower(copy[i]);
    }

    sp->col       = col;
    sp->width     = width;
    sp->text      = copy;
    sp->byte_len  = (uint32_t)byte_len;
    sp->fg        = pen.fg;
    sp->bg        = pen.bg;
    sp->bold      = pen.bold;
    sp->italic    = pen.italic;
    sp->underline = pen.underline;
    sp->strike    = pen.strike;
    sp->hit_index = pen.hit_index;
    sp->next      = NULL;

    /* Insert ordered by column (side borders may be stamped after content) */
    if (!ln->first_span || col >= ln->last_span->col) {
        if (!ln->first_span) ln->first_span = sp;
        else ln->last_span->next = sp;
        ln->last_span = sp;
    } else {
        LayoutSpan **prev = &ln->first_span;
        LayoutSpan *cur   = ln->first_span;
        while (cur && cur->col <= col) {
            prev = &cur->next;
            cur  = cur->next;
        }
        sp->next = cur;
        *prev    = sp;
    }

    if (pen.hit_index >= 0 && pen.hit_index < ld->hit_count) {
        HitBox *hb = &ld->hits[pen.hit_index];
        if (hb->line_y < 0) {
            hb->line_y    = line_idx;
            hb->col_start = col;
            hb->col_end   = col + width;
        } else if (hb->line_y == line_idx) {
            if (col < hb->col_start) hb->col_start = col;
            if (col + width > hb->col_end) hb->col_end = col + width;
        }
    }
}

static void stamp_line_decors(LayoutCtx *ctx, int line_idx) {
    ensure_line(ctx->ld, line_idx);
    LayoutLine *ln = &ctx->ld->lines[line_idx];
    for (int i = 0; i < ctx->decor_depth; i++) {
        const BoxDecor *d = &ctx->decors[i];
        if (d->fill_bg.mode == CSS_COLOR_RGB) {
            ln->fill_bg    = d->fill_bg;
            ln->fill_start = d->left_col;
            ln->fill_end   = d->right_col;
        }
        PenStyle bp;
        memset(&bp, 0, sizeof(bp));
        bp.fg        = d->border_fg;
        bp.bg        = d->fill_bg;
        bp.hit_index = -1;
        if (d->has_border) {
            append_span_raw(ctx->ld, line_idx, d->left_col, "│", 3, 1, bp);
            if (d->right_col > d->left_col) {
                append_span_raw(ctx->ld, line_idx, d->right_col, "│", 3, 1, bp);
            }
        } else if (d->is_quote) {
            append_span_raw(ctx->ld, line_idx, d->left_col, "▎", 3, 1, bp);
        }
    }
}

static void align_finished_line(LayoutCtx *ctx, int line_idx) {
    if (ctx->text_align == 0 || line_idx < 0 || line_idx >= ctx->ld->line_count) return;
    int avail = ctx->right_limit - ctx->left_margin;
    int used  = ctx->cur_col - ctx->left_margin;
    if (used <= 0 || used >= avail) return;
    int shift = (ctx->text_align == 1) ? (avail - used) / 2 : (avail - used);
    if (shift <= 0) return;

    LayoutLine *ln = &ctx->ld->lines[line_idx];
    for (LayoutSpan *sp = ln->first_span; sp; sp = sp->next) {
        if (sp->col >= ctx->left_margin && sp->col < ctx->right_limit) {
            sp->col += shift;
            if (sp->hit_index >= 0 && sp->hit_index < ctx->ld->hit_count) {
                HitBox *hb = &ctx->ld->hits[sp->hit_index];
                if (hb->line_y == line_idx) {
                    hb->col_start += shift;
                    hb->col_end   += shift;
                }
            }
        }
    }
}

static void newline(LayoutCtx *ctx) {
    if (!ctx->at_line_start) {
        align_finished_line(ctx, ctx->cur_line);
        ctx->cur_line++;
        ctx->cur_col       = ctx->left_margin;
        ctx->at_line_start = true;
    }
}

static void flush_pending_blanks(LayoutCtx *ctx) {
    while (ctx->pending_blank_lines > 0) {
        if (ctx->cur_line > 0 || !ctx->at_line_start) {
            newline(ctx);
            stamp_line_decors(ctx, ctx->cur_line);
            ctx->cur_line++;
            ctx->cur_col       = ctx->left_margin;
            ctx->at_line_start = true;
        }
        ctx->pending_blank_lines--;
    }
}

static void start_content_on_line(LayoutCtx *ctx) {
    flush_pending_blanks(ctx);
    if (ctx->at_line_start) {
        stamp_line_decors(ctx, ctx->cur_line);
        ctx->cur_col       = ctx->left_margin;
        ctx->at_line_start = false;
    }
}

static void emit_inline_text(LayoutCtx *ctx, const char *text, size_t len,
                             PenStyle pen, bool preformatted) {
    if (!text || len == 0) return;

    if (preformatted) {
        size_t pos = 0;
        while (pos < len) {
            const char *nl = memchr(text + pos, '\n', len - pos);
            size_t seg_len = nl ? (size_t)(nl - (text + pos)) : (len - pos);
            if (seg_len > 0 && text[pos + seg_len - 1] == '\r') seg_len--;
            start_content_on_line(ctx);

            /* Emit slice clipped/wrapped to right_limit */
            size_t i = 0;
            while (i < seg_len) {
                size_t chunk_start = i;
                int chunk_w = 0;
                int avail = ctx->right_limit - ctx->cur_col;
                if (avail < 1) avail = 1;
                while (i < seg_len) {
                    uint32_t cp = 0;
                    size_t cn = tb_utf8_decode(text + pos + i, seg_len - i, &cp);
                    if (cn == 0) break;
                    int cw = (cp == '\t') ? 4 : tb_unicode_width(cp);
                    if (chunk_w + cw > avail && chunk_w > 0) break;
                    chunk_w += cw;
                    i += cn;
                }
                if (i > chunk_start) {
                    append_span_raw(ctx->ld, ctx->cur_line, ctx->cur_col,
                                    text + pos + chunk_start, i - chunk_start, chunk_w, pen);
                    ctx->cur_col += chunk_w;
                }
                if (i < seg_len) {
                    newline(ctx);
                    start_content_on_line(ctx);
                }
            }
            if (nl) {
                if (ctx->at_line_start) start_content_on_line(ctx);
                newline(ctx);
                pos = (size_t)(nl - text) + 1;
            } else {
                break;
            }
        }
        return;
    }

    /* Normal whitespace-collapsing word-wrap */
    size_t i = 0;
    while (i < len) {
        if (tb_isspace(text[i])) {
            while (i < len && tb_isspace(text[i])) i++;
            if (!ctx->at_line_start && ctx->cur_col > ctx->left_margin &&
                ctx->cur_col < ctx->right_limit) {
                append_span_raw(ctx->ld, ctx->cur_line, ctx->cur_col, " ", 1, 1, pen);
                ctx->cur_col += 1;
            }
            continue;
        }
        size_t wstart = i;
        while (i < len && !tb_isspace(text[i])) i++;
        size_t wlen = i - wstart;
        int ww      = utf8_display_width(text + wstart, wlen);
        int line_max = ctx->right_limit - ctx->left_margin;
        if (line_max < 4) line_max = 4;

        if (!ctx->at_line_start && ctx->cur_col > ctx->left_margin &&
            ctx->cur_col + ww > ctx->right_limit) {
            newline(ctx);
        }

        /* Handle words wider than the entire available line width */
        size_t woff = 0;
        while (woff < wlen) {
            start_content_on_line(ctx);
            int avail = ctx->right_limit - ctx->cur_col;
            if (avail < 1) avail = 1;
            if (ww <= avail && woff == 0) {
                append_span_raw(ctx->ld, ctx->cur_line, ctx->cur_col,
                                text + wstart, wlen, ww, pen);
                ctx->cur_col += ww;
                break;
            }
            size_t sub_end = woff;
            int sub_w = 0;
            while (sub_end < wlen) {
                uint32_t cp = 0;
                size_t cn = tb_utf8_decode(text + wstart + sub_end, wlen - sub_end, &cp);
                if (cn == 0) break;
                int cw = tb_unicode_width(cp);
                if (sub_w + cw > avail && sub_w > 0) break;
                sub_w   += cw;
                sub_end += cn;
            }
            append_span_raw(ctx->ld, ctx->cur_line, ctx->cur_col,
                            text + wstart + woff, sub_end - woff, sub_w, pen);
            ctx->cur_col += sub_w;
            woff = sub_end;
            if (woff < wlen) newline(ctx);
        }
    }
}

static bool node_has_click_handler(const DomNode *n) {
    if (!n || n->type != DOM_NODE_ELEMENT) return false;
    if (dom_has_attr(n, "onclick")) return true;
    for (const DomListener *ls = n->listeners; ls; ls = ls->next) {
        if (strcmp(ls->type, "click") == 0) return true;
    }
    return false;
}

static PenStyle pen_from_node(const DomNode *n, PenStyle parent_pen, int hit_idx) {
    PenStyle p = parent_pen;
    const CssStyle *st = &n->style;
    if (st->fg_set && st->fg.mode == CSS_COLOR_RGB) p.fg = st->fg;
    if (st->bg_set && st->bg.mode == CSS_COLOR_RGB && st->display == CSS_DISP_INLINE) p.bg = st->bg;
    if (st->bold) p.bold = 1;
    if (st->italic) p.italic = 1;
    if (st->underline) p.underline = 1;
    if (st->strike) p.strike = 1;
    if (st->text_transform) p.text_transform = st->text_transform;
    if (hit_idx >= 0) p.hit_index = hit_idx;
    return p;
}

static void draw_horiz_border(LayoutCtx *ctx, int left_col, int right_col,
                              const char *lch, const char *rch, CssColor fg, CssColor bg) {
    if (right_col <= left_col) return;
    newline(ctx);
    flush_pending_blanks(ctx);
    stamp_line_decors(ctx, ctx->cur_line);

    PenStyle bp;
    memset(&bp, 0, sizeof(bp));
    bp.fg        = fg.mode == CSS_COLOR_RGB ? fg : css_rgb(71, 85, 105);
    bp.bg        = bg;
    bp.hit_index = -1;

    TbBuf b;
    tb_buf_init(&b);
    tb_buf_append_cstr(&b, lch);
    int inner = right_col - left_col - 1;
    for (int i = 0; i < inner; i++) tb_buf_append_cstr(&b, "─");
    tb_buf_append_cstr(&b, rch);

    append_span_raw(ctx->ld, ctx->cur_line, left_col, b.data, b.len, right_col - left_col + 1, bp);
    tb_buf_free(&b);

    ctx->cur_line++;
    ctx->cur_col       = ctx->left_margin;
    ctx->at_line_start = true;
}

static void layout_node(LayoutCtx *ctx, DomNode *node, PenStyle parent_pen, int list_ord);

/* Table layout: auto-sizes columns and renders crisp Unicode grid */
static void collect_table_rows(DomNode *n, DomNode **rows, int *nrow, int max_rows) {
    if (!n || *nrow >= max_rows) return;
    if (n->type == DOM_NODE_ELEMENT && n->style.display == CSS_DISP_NONE) return;
    if (n->type == DOM_NODE_ELEMENT && n->tag == TAG_TR) {
        rows[(*nrow)++] = n;
        return;
    }
    for (DomNode *ch = n->first_child; ch; ch = ch->next_sibling) {
        collect_table_rows(ch, rows, nrow, max_rows);
    }
}

static void layout_table(LayoutCtx *ctx, DomNode *table_node, PenStyle parent_pen) {
    DomNode *rows[256];
    int nrow = 0;
    collect_table_rows(table_node, rows, &nrow, 256);
    if (nrow == 0) return;

    int ncols = 0;
    int col_w[32] = {0};
    for (int r = 0; r < nrow; r++) {
        int c = 0;
        for (DomNode *cell = rows[r]->first_child; cell && c < 32; cell = cell->next_sibling) {
            if (cell->type != DOM_NODE_ELEMENT ||
                (cell->tag != TAG_TD && cell->tag != TAG_TH)) continue;
            char *txt = dom_get_text_content(cell);
            int w     = txt ? utf8_display_width(txt, strlen(txt)) : 0;
            tb_free(txt);
            if (w > col_w[c]) col_w[c] = w;
            c++;
        }
        if (c > ncols) ncols = c;
    }
    if (ncols == 0) return;

    int avail = ctx->right_limit - ctx->left_margin - (ncols * 3 + 1);
    if (avail < ncols * 3) avail = ncols * 3;
    int total_w = 0;
    for (int c = 0; c < ncols; c++) {
        if (col_w[c] < 3) col_w[c] = 3;
        total_w += col_w[c];
    }
    while (total_w > avail) {
        int widest = 0;
        for (int c = 1; c < ncols; c++) {
            if (col_w[c] > col_w[widest]) widest = c;
        }
        if (col_w[widest] <= 4) break;
        col_w[widest]--;
        total_w--;
    }

    newline(ctx);
    flush_pending_blanks(ctx);

    PenStyle grid_pen = parent_pen;
    grid_pen.fg        = css_rgb(100, 116, 139);
    grid_pen.bold      = 0;
    grid_pen.underline = 0;
    grid_pen.hit_index = -1;

    /* Helper to draw table horizontal divider */
    for (int r = 0; r <= nrow; r++) {
        bool is_top = (r == 0);
        bool is_bot = (r == nrow);
        bool draw_div = is_top || is_bot || (r == 1 && rows[0]->first_child && rows[0]->first_child->tag == TAG_TH);
        if (draw_div) {
            TbBuf div;
            tb_buf_init(&div);
            tb_buf_append_cstr(&div, is_top ? "┌" : (is_bot ? "└" : "├"));
            int dw = 1;
            for (int c = 0; c < ncols; c++) {
                for (int k = 0; k < col_w[c] + 2; k++) { tb_buf_append_cstr(&div, "─"); dw++; }
                if (c + 1 < ncols) {
                    tb_buf_append_cstr(&div, is_top ? "┬" : (is_bot ? "┴" : "┼"));
                    dw++;
                }
            }
            tb_buf_append_cstr(&div, is_top ? "┐" : (is_bot ? "┘" : "┤"));
            dw++;

            stamp_line_decors(ctx, ctx->cur_line);
            append_span_raw(ctx->ld, ctx->cur_line, ctx->left_margin, div.data, div.len, dw, grid_pen);
            tb_buf_free(&div);
            ctx->cur_line++;
            ctx->at_line_start = true;
        }
        if (is_bot) break;

        /* Render cells on this row */
        stamp_line_decors(ctx, ctx->cur_line);
        int x = ctx->left_margin;
        append_span_raw(ctx->ld, ctx->cur_line, x, "│", 3, 1, grid_pen);
        x += 1;

        DomNode *cell = rows[r]->first_child;
        for (int c = 0; c < ncols; c++) {
            while (cell && (cell->type != DOM_NODE_ELEMENT ||
                            (cell->tag != TAG_TD && cell->tag != TAG_TH))) {
                cell = cell->next_sibling;
            }
            append_span_raw(ctx->ld, ctx->cur_line, x, " ", 1, 1, grid_pen);
            x += 1;

            int cw = col_w[c];
            int drawn = 0;
            if (cell) {
                int hit = -1;
                DomNode *link = (cell->first_child && cell->first_child->tag == TAG_A)
                                    ? cell->first_child : NULL;
                if (link && dom_has_attr(link, "href")) {
                    hit = add_hit(ctx->ld, ctx->cur_line, x, x + cw, HIT_LINK, link);
                } else if (node_has_click_handler(cell)) {
                    hit = add_hit(ctx->ld, ctx->cur_line, x, x + cw, HIT_CLICKABLE, cell);
                }
                PenStyle cp = pen_from_node(link ? link : cell, parent_pen, hit);
                char *raw = dom_get_text_content(cell);
                if (raw) {
                    /* Collapse whitespace & truncate to cw */
                    TbBuf cb;
                    tb_buf_init(&cb);
                    size_t ri = 0;
                    while (raw[ri] && tb_isspace(raw[ri])) ri++;
                    while (raw[ri] && drawn < cw) {
                        if (tb_isspace(raw[ri])) {
                            while (raw[ri] && tb_isspace(raw[ri])) ri++;
                            if (raw[ri] && drawn + 1 <= cw) {
                                tb_buf_append_char(&cb, ' ');
                                drawn++;
                            }
                        } else {
                            uint32_t ucp = 0;
                            size_t un = tb_utf8_decode(raw + ri, strlen(raw + ri), &ucp);
                            int uw = tb_unicode_width(ucp);
                            if (drawn + uw > cw) break;
                            tb_buf_append(&cb, raw + ri, un);
                            drawn += uw;
                            ri += un;
                        }
                    }
                    if (cb.len > 0) {
                        append_span_raw(ctx->ld, ctx->cur_line, x, cb.data, cb.len, drawn, cp);
                    }
                    tb_buf_free(&cb);
                    tb_free(raw);
                }
                cell = cell->next_sibling;
            }
            if (drawn < cw) {
                char pad[64];
                int rem = cw - drawn;
                if (rem > (int)sizeof(pad) - 1) rem = (int)sizeof(pad) - 1;
                memset(pad, ' ', (size_t)rem);
                append_span_raw(ctx->ld, ctx->cur_line, x + drawn, pad, (size_t)rem, rem, grid_pen);
            }
            x += cw;
            append_span_raw(ctx->ld, ctx->cur_line, x, " │", 4, 2, grid_pen);
            x += 2;
        }
        ctx->cur_line++;
        ctx->at_line_start = true;
    }

    if (table_node->style.margin_bottom > ctx->pending_blank_lines) {
        ctx->pending_blank_lines = table_node->style.margin_bottom;
    }
}

static void layout_form_control(LayoutCtx *ctx, DomNode *node, PenStyle parent_pen) {
    PenStyle wp = pen_from_node(node, parent_pen, -1);

    if (node->tag == TAG_BUTTON) {
        char *lbl = dom_get_text_content(node);
        const char *s = (lbl && *lbl) ? lbl : "Button";
        TbBuf b;
        tb_buf_init(&b);
        tb_buf_printf(&b, "[ %s ]", s);
        tb_free(lbl);

        int w = utf8_display_width(b.data, b.len);
        if (!ctx->at_line_start && ctx->cur_col + w > ctx->right_limit) newline(ctx);
        start_content_on_line(ctx);
        int hit = add_hit(ctx->ld, ctx->cur_line, ctx->cur_col, ctx->cur_col + w, HIT_BUTTON, node);
        wp.hit_index = hit;
        wp.bold      = 1;
        if (wp.fg.mode != CSS_COLOR_RGB) wp.fg = css_rgb(56, 189, 248);
        if (wp.bg.mode != CSS_COLOR_RGB) wp.bg = css_rgb(30, 41, 59);
        append_span_raw(ctx->ld, ctx->cur_line, ctx->cur_col, b.data, b.len, w, wp);
        ctx->cur_col += w;
        tb_buf_free(&b);
        return;
    }

    if (node->tag == TAG_SELECT) {
        const char *val = dom_input_get_value(node);
        TbBuf b;
        tb_buf_init(&b);
        tb_buf_printf(&b, "‹ %s ▾ ›", (val && *val) ? val : "Select");
        int w = utf8_display_width(b.data, b.len);
        if (!ctx->at_line_start && ctx->cur_col + w > ctx->right_limit) newline(ctx);
        start_content_on_line(ctx);
        wp.hit_index = add_hit(ctx->ld, ctx->cur_line, ctx->cur_col, ctx->cur_col + w, HIT_SELECT, node);
        wp.fg        = css_rgb(250, 204, 21);
        wp.bg        = css_rgb(30, 41, 59);
        append_span_raw(ctx->ld, ctx->cur_line, ctx->cur_col, b.data, b.len, w, wp);
        ctx->cur_col += w;
        tb_buf_free(&b);
        return;
    }

    /* <input> or <textarea> */
    const char *type = (node->tag == TAG_TEXTAREA) ? "textarea" : dom_get_attr(node, "type");
    if (!type || !*type) type = "text";

    if (tb_strcasecmp(type, "button") == 0 ||
        tb_strcasecmp(type, "submit") == 0 ||
        tb_strcasecmp(type, "reset") == 0) {
        const char *v = dom_get_attr(node, "value");
        if (!v || !*v) v = (tb_strcasecmp(type, "submit") == 0) ? "Submit" : "Button";
        TbBuf b;
        tb_buf_init(&b);
        tb_buf_printf(&b, "[ %s ]", v);
        int w = utf8_display_width(b.data, b.len);
        if (!ctx->at_line_start && ctx->cur_col + w > ctx->right_limit) newline(ctx);
        start_content_on_line(ctx);
        wp.hit_index = add_hit(ctx->ld, ctx->cur_line, ctx->cur_col, ctx->cur_col + w, HIT_BUTTON, node);
        wp.bold      = 1;
        wp.fg        = css_rgb(56, 189, 248);
        wp.bg        = css_rgb(30, 41, 59);
        append_span_raw(ctx->ld, ctx->cur_line, ctx->cur_col, b.data, b.len, w, wp);
        ctx->cur_col += w;
        tb_buf_free(&b);
        return;
    }

    if (tb_strcasecmp(type, "checkbox") == 0 || tb_strcasecmp(type, "radio") == 0) {
        bool chk = dom_input_get_checked(node);
        const char *box = (tb_strcasecmp(type, "radio") == 0)
                              ? (chk ? "(•)" : "( )")
                              : (chk ? "[✓]" : "[ ]");
        int w = 3;
        if (!ctx->at_line_start && ctx->cur_col + w > ctx->right_limit) newline(ctx);
        start_content_on_line(ctx);
        wp.hit_index = add_hit(ctx->ld, ctx->cur_line, ctx->cur_col, ctx->cur_col + w, HIT_CHECKBOX, node);
        wp.fg        = chk ? css_rgb(74, 222, 128) : css_rgb(148, 163, 184);
        wp.bold      = 1;
        append_span_raw(ctx->ld, ctx->cur_line, ctx->cur_col, box, strlen(box), w, wp);
        ctx->cur_col += w;
        return;
    }

    /* Text / Password / Search / Textarea input box */
    const char *val = dom_input_get_value(node);
    const char *ph  = dom_get_attr(node, "placeholder");
    bool is_pw      = (tb_strcasecmp(type, "password") == 0);
    bool is_editing = (ctx->editing_node == node);
    int box_w       = 26;
    const char *sz_attr = dom_get_attr(node, "size");
    if (sz_attr && atoi(sz_attr) > 4 && atoi(sz_attr) < 60) box_w = atoi(sz_attr) + 2;
    if (box_w > ctx->right_limit - ctx->left_margin - 2) {
        box_w = ctx->right_limit - ctx->left_margin - 2;
    }
    if (box_w < 8) box_w = 8;

    TbBuf b;
    tb_buf_init(&b);
    tb_buf_append_char(&b, '[');
    int inner_w = box_w - 2;
    int filled  = 0;

    if (val && *val) {
        size_t vlen = strlen(val);
        size_t start_off = 0;
        if ((int)vlen > inner_w - 1) start_off = vlen - (size_t)(inner_w - 1);
        for (size_t i = start_off; i < vlen && filled < inner_w; i++) {
            if (is_editing && i == ctx->edit_cursor && filled < inner_w) {
                tb_buf_append_cstr(&b, "▏");
                filled++;
            }
            if (filled < inner_w) {
                tb_buf_append_char(&b, is_pw ? '*' : (val[i] == '\n' ? ' ' : val[i]));
                filled++;
            }
        }
        if (is_editing && ctx->edit_cursor >= vlen && filled < inner_w) {
            tb_buf_append_cstr(&b, "▏");
            filled++;
        }
        wp.fg = is_editing ? css_rgb(254, 240, 138) : css_rgb(226, 232, 240);
    } else {
        if (is_editing) {
            tb_buf_append_cstr(&b, "▏");
            filled++;
            wp.fg = css_rgb(254, 240, 138);
        } else if (ph && *ph) {
            for (size_t i = 0; ph[i] && filled < inner_w; i++) {
                tb_buf_append_char(&b, ph[i]);
                filled++;
            }
            wp.fg = css_rgb(100, 116, 139);
        }
    }
    while (filled < inner_w) {
        tb_buf_append_char(&b, is_editing ? ' ' : '_');
        filled++;
    }
    tb_buf_append_char(&b, ']');

    if (!ctx->at_line_start && ctx->cur_col + box_w > ctx->right_limit) newline(ctx);
    start_content_on_line(ctx);
    wp.hit_index = add_hit(ctx->ld, ctx->cur_line, ctx->cur_col, ctx->cur_col + box_w, HIT_INPUT_TEXT, node);
    wp.bg        = is_editing ? css_rgb(30, 58, 138) : css_rgb(15, 23, 42);
    append_span_raw(ctx->ld, ctx->cur_line, ctx->cur_col, b.data, b.len, box_w, wp);
    ctx->cur_col += box_w;
    tb_buf_free(&b);
}

static void layout_node(LayoutCtx *ctx, DomNode *node, PenStyle parent_pen, int list_ord) {
    if (!node) return;

    if (node->type == DOM_NODE_TEXT) {
        bool pre = (node->parent && node->parent->style.pre);
        emit_inline_text(ctx, node->text, node->text ? strlen(node->text) : 0, parent_pen, pre);
        return;
    }
    if (node->type == DOM_NODE_COMMENT) return;
    if (node->type == DOM_NODE_DOCUMENT) {
        DomNode *start = node->owner_doc && node->owner_doc->html ? node->owner_doc->html : node->first_child;
        for (DomNode *ch = start; ch; ch = ch->next_sibling) {
            layout_node(ctx, ch, parent_pen, 0);
        }
        return;
    }

    /* Element Node */
    const CssStyle *st = &node->style;
    if (st->display == CSS_DISP_NONE) return;

    if (node->tag == TAG_BR) {
        if (ctx->at_line_start) start_content_on_line(ctx);
        newline(ctx);
        return;
    }
    if (node->tag == TAG_HR) {
        draw_horiz_border(ctx, ctx->left_margin, ctx->right_limit - 1, "─", "─",
                          css_rgb(71, 85, 105), (CssColor){0});
        return;
    }
    if (node->tag == TAG_IMG) {
        const char *alt = dom_get_attr(node, "alt");
        if (alt && *alt) {
            TbBuf b;
            tb_buf_init(&b);
            tb_buf_printf(&b, "[🖼 %s]", alt);
            PenStyle ip = parent_pen;
            ip.fg = css_rgb(148, 163, 184);
            emit_inline_text(ctx, b.data, b.len, ip, false);
            tb_buf_free(&b);
        }
        return;
    }
    if (node->tag == TAG_BUTTON || node->tag == TAG_INPUT ||
        node->tag == TAG_SELECT || node->tag == TAG_TEXTAREA) {
        layout_form_control(ctx, node, parent_pen);
        return;
    }
    if (st->display == CSS_DISP_TABLE || node->tag == TAG_TABLE) {
        layout_table(ctx, node, parent_pen);
        return;
    }

    /* Determine interactivity hit box if link or clickable element */
    int hit_idx = parent_pen.hit_index;
    if (node->tag == TAG_A && dom_has_attr(node, "href")) {
        hit_idx = add_hit(ctx->ld, -1, 0, 0, HIT_LINK, node);
    } else if (node_has_click_handler(node)) {
        hit_idx = add_hit(ctx->ld, -1, 0, 0, HIT_CLICKABLE, node);
    }
    PenStyle my_pen = pen_from_node(node, parent_pen, hit_idx);

    if (st->display == CSS_DISP_INLINE) {
        for (DomNode *ch = node->first_child; ch; ch = ch->next_sibling) {
            layout_node(ctx, ch, my_pen, 0);
        }
        return;
    }

    /* Block or List-Item Container */
    newline(ctx);
    if (st->margin_top > ctx->pending_blank_lines) {
        ctx->pending_blank_lines = st->margin_top;
    }

    int saved_left  = ctx->left_margin;
    int saved_right = ctx->right_limit;
    uint8_t saved_align = ctx->text_align;

    ctx->left_margin += st->margin_left;
    ctx->right_limit -= st->margin_right;
    if (st->width_cols > 0 && ctx->left_margin + st->width_cols < ctx->right_limit) {
        ctx->right_limit = ctx->left_margin + st->width_cols;
    } else if (st->width_cols < 0) {
        int pct = -st->width_cols;
        int w   = ((ctx->right_limit - ctx->left_margin) * pct) / 100;
        if (w >= 10) ctx->right_limit = ctx->left_margin + w;
    }
    if (ctx->right_limit - ctx->left_margin < 8) {
        ctx->right_limit = ctx->left_margin + 8;
    }

    int box_left  = ctx->left_margin;
    int box_right = ctx->right_limit - 1;
    bool pushed_decor = false;

    if (st->border || node->tag == TAG_BLOCKQUOTE || (st->bg_set && st->bg.mode == CSS_COLOR_RGB)) {
        flush_pending_blanks(ctx);
        if (st->border) {
            draw_horiz_border(ctx, box_left, box_right, "┌", "┐",
                              st->border_color, st->bg_set ? st->bg : (CssColor){0});
        }
        if (ctx->decor_depth < 16) {
            BoxDecor *d   = &ctx->decors[ctx->decor_depth++];
            d->border_fg  = st->border_color.mode == CSS_COLOR_RGB ? st->border_color : css_rgb(71, 85, 105);
            d->fill_bg    = st->bg_set ? st->bg : (CssColor){0};
            d->left_col   = box_left;
            d->right_col  = box_right;
            d->has_border = (st->border != 0);
            d->is_quote   = (node->tag == TAG_BLOCKQUOTE && !st->border);
            pushed_decor  = true;
        }
        if (st->border) {
            ctx->left_margin += 1;
            ctx->right_limit -= 1;
        } else if (node->tag == TAG_BLOCKQUOTE) {
            ctx->left_margin += 2;
        }
    }

    ctx->left_margin += st->padding_left;
    ctx->right_limit -= st->padding_right;
    if (ctx->right_limit - ctx->left_margin < 4) ctx->right_limit = ctx->left_margin + 4;
    ctx->cur_col    = ctx->left_margin;
    ctx->text_align = st->text_align;

    for (int pt = 0; pt < st->padding_top; pt++) {
        stamp_line_decors(ctx, ctx->cur_line);
        ctx->cur_line++;
        ctx->at_line_start = true;
    }
    if (pushed_decor || st->padding_top > 0) {
        ctx->pending_blank_lines = 0;
    }

    if (st->display == CSS_DISP_LIST_ITEM) {
        start_content_on_line(ctx);
        PenStyle bp = parent_pen;
        bp.fg        = css_rgb(56, 189, 248);
        bp.bold      = 1;
        bp.hit_index = -1;
        char marker[24];
        if (list_ord > 0) snprintf(marker, sizeof(marker), "%d. ", list_ord);
        else snprintf(marker, sizeof(marker), " • ");
        int mw = utf8_display_width(marker, strlen(marker));
        append_span_raw(ctx->ld, ctx->cur_line, ctx->cur_col, marker, strlen(marker), mw, bp);
        ctx->cur_col     += mw;
        ctx->left_margin += mw;
    }

    int child_ord = (node->tag == TAG_OL) ? 1 : 0;
    for (DomNode *ch = node->first_child; ch; ch = ch->next_sibling) {
        int pass_ord = 0;
        if (ch->type == DOM_NODE_ELEMENT && ch->style.display == CSS_DISP_LIST_ITEM) {
            pass_ord = (node->tag == TAG_OL) ? child_ord++ : 0;
        }
        layout_node(ctx, ch, my_pen, pass_ord);
    }

    newline(ctx);
    if (pushed_decor || st->padding_bottom > 0) {
        ctx->pending_blank_lines = 0;
    }
    for (int pb = 0; pb < st->padding_bottom; pb++) {
        stamp_line_decors(ctx, ctx->cur_line);
        ctx->cur_line++;
        ctx->at_line_start = true;
    }

    if (pushed_decor) {
        ctx->decor_depth--;
        if (st->border) {
            draw_horiz_border(ctx, box_left, box_right, "└", "┘",
                              st->border_color, st->bg_set ? st->bg : (CssColor){0});
        }
    }

    ctx->left_margin = saved_left;
    ctx->right_limit = saved_right;
    ctx->cur_col     = saved_left;
    ctx->text_align  = saved_align;

    if (st->margin_bottom > ctx->pending_blank_lines) {
        ctx->pending_blank_lines = st->margin_bottom;
    }
}

void layout_build(LayoutDoc *ld, DomDocument *doc, int viewport_w,
                  DomNode *editing_node, size_t edit_cursor) {
    if (!ld) return;
    tb_arena_reset(&ld->arena);
    if (ld->lines && ld->line_cap > 0) {
        memset(ld->lines, 0, (size_t)ld->line_cap * sizeof(LayoutLine));
    }
    ld->line_count = 0;
    ld->hit_count  = 0;
    if (viewport_w < 20) viewport_w = 20;
    ld->viewport_w = viewport_w;

    if (!doc || !doc->root) return;
    if (doc->dirty_style) css_compute_document(doc, NULL);

    LayoutCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ld            = ld;
    ctx.editing_node  = editing_node;
    ctx.edit_cursor   = edit_cursor;
    ctx.left_margin   = 0;
    ctx.right_limit   = viewport_w;
    ctx.cur_line      = 0;
    ctx.cur_col       = 0;
    ctx.at_line_start = true;

    PenStyle root_pen;
    memset(&root_pen, 0, sizeof(root_pen));
    root_pen.fg        = css_rgb(226, 232, 240);
    root_pen.hit_index = -1;

    layout_node(&ctx, doc->body ? doc->body : doc->root, root_pen, 0);
    newline(&ctx);

    /* Materialize compact plain-text line cache for fast `/` search */
    TbBuf pb;
    tb_buf_init(&pb);
    for (int i = 0; i < ld->line_count; i++) {
        tb_buf_clear(&pb);
        int col = 0;
        for (const LayoutSpan *sp = ld->lines[i].first_span; sp; sp = sp->next) {
            while (col < sp->col) { tb_buf_append_char(&pb, ' '); col++; }
            tb_buf_append(&pb, sp->text, sp->byte_len);
            col += sp->width;
        }
        ld->lines[i].plain = tb_arena_strndup(&ld->arena, pb.data ? pb.data : "", pb.len);
    }
    tb_buf_free(&pb);
    doc->dirty_layout = false;
}

int layout_hit_test(const LayoutDoc *ld, int doc_y, int doc_x) {
    if (!ld || doc_y < 0 || doc_y >= ld->line_count) return -1;
    for (int i = 0; i < ld->hit_count; i++) {
        const HitBox *h = &ld->hits[i];
        if (h->line_y == doc_y && doc_x >= h->col_start && doc_x < h->col_end) {
            return i;
        }
    }
    return -1;
}

int layout_find_node_hit(const LayoutDoc *ld, const DomNode *node) {
    if (!ld || !node) return -1;
    for (int i = 0; i < ld->hit_count; i++) {
        if (ld->hits[i].node == node) return i;
    }
    return -1;
}

static void emit_ansi_sgr(TbBuf *out, const LayoutSpan *sp, CssColor line_bg, bool focused) {
    tb_buf_append_cstr(out, "\x1b[0");
    if (sp->bold || focused) tb_buf_append_cstr(out, ";1");
    if (sp->italic) tb_buf_append_cstr(out, ";3");
    if (sp->underline) tb_buf_append_cstr(out, ";4");
    if (sp->strike) tb_buf_append_cstr(out, ";9");
    if (focused) {
        tb_buf_append_cstr(out, ";38;2;15;23;42;48;2;56;189;248m");
        return;
    }
    if (sp->fg.mode == CSS_COLOR_RGB) {
        tb_buf_printf(out, ";38;2;%u;%u;%u", sp->fg.r, sp->fg.g, sp->fg.b);
    }
    CssColor bg = (sp->bg.mode == CSS_COLOR_RGB) ? sp->bg : line_bg;
    if (bg.mode == CSS_COLOR_RGB) {
        tb_buf_printf(out, ";48;2;%u;%u;%u", bg.r, bg.g, bg.b);
    }
    tb_buf_append_char(out, 'm');
}

void layout_render_line_ansi(const LayoutDoc *ld, int line_idx, int focused_hit,
                             int max_cols, bool use_color, const char *search_query,
                             TbBuf *out) {
    if (!ld || line_idx < 0 || line_idx >= ld->line_count) return;
    const LayoutLine *ln = &ld->lines[line_idx];
    bool has_search_hit = false;
    if (search_query && *search_query && ln->plain) {
        if (strcasestr(ln->plain, search_query) != NULL) has_search_hit = true;
    }

    int col = 0;
    for (const LayoutSpan *sp = ln->first_span; sp; sp = sp->next) {
        if (max_cols > 0 && sp->col >= max_cols) break;
        if (sp->col < col) continue; /* Overlap guard */

        while (col < sp->col && (max_cols <= 0 || col < max_cols)) {
            if (use_color && ln->fill_bg.mode == CSS_COLOR_RGB &&
                col >= ln->fill_start && col <= ln->fill_end) {
                tb_buf_printf(out, "\x1b[48;2;%u;%u;%um \x1b[0m",
                              ln->fill_bg.r, ln->fill_bg.g, ln->fill_bg.b);
            } else {
                tb_buf_append_char(out, ' ');
            }
            col++;
        }

        bool focused = (focused_hit >= 0 && sp->hit_index == focused_hit);
        CssColor eff_bg = (ln->fill_bg.mode == CSS_COLOR_RGB &&
                           col >= ln->fill_start && col <= ln->fill_end)
                              ? ln->fill_bg
                              : (CssColor){0};
        if (has_search_hit && !focused && eff_bg.mode != CSS_COLOR_RGB) {
            eff_bg = css_rgb(113, 63, 18);
        }

        if (use_color) emit_ansi_sgr(out, sp, eff_bg, focused);

        if (max_cols > 0 && col + sp->width > max_cols) {
            size_t i = 0;
            while (i < sp->byte_len && col < max_cols) {
                uint32_t cp = 0;
                size_t n = tb_utf8_decode(sp->text + i, sp->byte_len - i, &cp);
                int w = tb_unicode_width(cp);
                if (col + w > max_cols) break;
                tb_buf_append(out, sp->text + i, n);
                col += w;
                i   += n;
            }
        } else {
            tb_buf_append(out, sp->text, sp->byte_len);
            col += sp->width;
        }
        if (use_color) tb_buf_append_cstr(out, "\x1b[0m");
    }

    if (use_color && ln->fill_bg.mode == CSS_COLOR_RGB) {
        int end = ln->fill_end;
        if (max_cols > 0 && end >= max_cols) end = max_cols - 1;
        if (col <= end) {
            tb_buf_printf(out, "\x1b[48;2;%u;%u;%um", ln->fill_bg.r, ln->fill_bg.g, ln->fill_bg.b);
            while (col <= end) { tb_buf_append_char(out, ' '); col++; }
            tb_buf_append_cstr(out, "\x1b[0m");
        }
    }
}

void layout_render_document(const LayoutDoc *ld, bool use_color, TbBuf *out) {
    if (!ld || !out) return;
    for (int i = 0; i < ld->line_count; i++) {
        layout_render_line_ansi(ld, i, -1, ld->viewport_w, use_color, NULL, out);
        tb_buf_append_char(out, '\n');
    }
}
