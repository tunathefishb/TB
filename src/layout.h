#ifndef TB_LAYOUT_H
#define TB_LAYOUT_H

#include "common.h"
#include "dom.h"

typedef enum {
    HIT_LINK = 0,
    HIT_BUTTON,
    HIT_INPUT_TEXT,
    HIT_CHECKBOX,
    HIT_SELECT,
    HIT_CLICKABLE
} HitKind;

typedef struct {
    int      line_y;
    int      col_start;
    int      col_end;
    HitKind  kind;
    DomNode *node;
} HitBox;

typedef struct LayoutSpan {
    int                col;
    int                width;
    const char        *text;
    uint32_t           byte_len;
    CssColor           fg;
    CssColor           bg;
    uint8_t            bold : 1;
    uint8_t            italic : 1;
    uint8_t            underline : 1;
    uint8_t            strike : 1;
    int                hit_index; /* -1 if non-interactive */
    struct LayoutSpan *next;
} LayoutSpan;

typedef struct {
    LayoutSpan *first_span;
    LayoutSpan *last_span;
    const char *plain;
    CssColor    fill_bg;
    int         fill_start;
    int         fill_end;
} LayoutLine;

typedef struct {
    TbArena     arena;
    int         viewport_w;
    LayoutLine *lines;
    int         line_count;
    int         line_cap;
    HitBox     *hits;
    int         hit_count;
    int         hit_cap;
} LayoutDoc;

void layout_init(LayoutDoc *ld);
void layout_free(LayoutDoc *ld);
void layout_build(LayoutDoc *ld, DomDocument *doc, int viewport_w,
                  DomNode *editing_node, size_t edit_cursor);

int  layout_hit_test(const LayoutDoc *ld, int doc_y, int doc_x);
int  layout_find_node_hit(const LayoutDoc *ld, const DomNode *node);

void layout_render_line_ansi(const LayoutDoc *ld, int line_idx, int focused_hit,
                             int max_cols, bool use_color, const char *search_query,
                             TbBuf *out);
void layout_render_document(const LayoutDoc *ld, bool use_color, TbBuf *out);

#endif /* TB_LAYOUT_H */
