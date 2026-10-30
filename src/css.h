#ifndef TB_CSS_H
#define TB_CSS_H

#include "mem.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct DomNode;
struct DomDocument;

typedef enum {
    CSS_COLOR_INHERIT = 0,
    CSS_COLOR_DEFAULT,
    CSS_COLOR_RGB
} CssColorMode;

typedef struct {
    uint8_t mode;
    uint8_t r, g, b;
} CssColor;

typedef enum {
    CSS_DISP_INLINE = 0,
    CSS_DISP_BLOCK,
    CSS_DISP_LIST_ITEM,
    CSS_DISP_TABLE,
    CSS_DISP_TABLE_ROW,
    CSS_DISP_TABLE_CELL,
    CSS_DISP_NONE
} CssDisplay;

typedef struct {
    CssDisplay display;
    CssColor   fg;
    CssColor   bg;
    CssColor   border_color;
    uint8_t    bold : 1;
    uint8_t    italic : 1;
    uint8_t    underline : 1;
    uint8_t    strike : 1;
    uint8_t    border : 1;
    uint8_t    pre : 1;
    uint8_t    fg_set : 1;
    uint8_t    bg_set : 1;
    uint8_t    text_align;     /* 0=left, 1=center, 2=right */
    uint8_t    text_transform; /* 0=none, 1=uppercase, 2=lowercase */
    int8_t     margin_top, margin_bottom, margin_left, margin_right;
    int8_t     padding_top, padding_bottom, padding_left, padding_right;
    int16_t    width_cols;     /* 0=auto, >0=cols, <0=-percent */
} CssStyle;

typedef struct CssDecl {
    const char     *prop;
    const char     *val;
    struct CssDecl *next;
} CssDecl;

typedef struct CssRule {
    const char     *selector;
    uint32_t        specificity;
    uint32_t        order;
    CssDecl        *decls;
    struct CssRule *next;
} CssRule;

typedef struct {
    TbArena   arena;
    CssRule  *rules_head;
    CssRule  *rules_tail;
    uint32_t  rule_count;
} CssStylesheet;

static inline CssColor css_rgb(uint8_t r, uint8_t g, uint8_t b) {
    CssColor c = { CSS_COLOR_RGB, r, g, b };
    return c;
}

void css_stylesheet_init(CssStylesheet *ss);
void css_stylesheet_reset(CssStylesheet *ss);
void css_stylesheet_free(CssStylesheet *ss);
void css_stylesheet_parse(CssStylesheet *ss, const char *css_text);

bool css_parse_color(const char *str, CssColor *out);
void css_apply_decl(CssStyle *st, const char *prop, const char *val);
void css_parse_inline(CssStyle *st, const char *inline_css);
void css_compute_document(struct DomDocument *doc, const CssStylesheet *ss);

#endif /* TB_CSS_H */
