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
    CSS_DISP_FLEX,
    CSS_DISP_NONE
} CssDisplay;

typedef enum {
    CSS_ALIGN_LEFT   = 0,
    CSS_ALIGN_CENTER = 1,
    CSS_ALIGN_RIGHT  = 2
} CssTextAlign;

typedef enum {
    CSS_JUSTIFY_START         = 0,
    CSS_JUSTIFY_CENTER        = 1,
    CSS_JUSTIFY_END           = 2,
    CSS_JUSTIFY_SPACE_BETWEEN = 3,
    CSS_JUSTIFY_SPACE_AROUND  = 4
} CssJustifyContent;

typedef enum {
    CSS_TRANSFORM_NONE  = 0,
    CSS_TRANSFORM_UPPER = 1,
    CSS_TRANSFORM_LOWER = 2
} CssTextTransform;

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
    uint8_t    text_align;      /* CssTextAlign */
    uint8_t    text_transform;  /* CssTextTransform */
    uint8_t    justify_content; /* CssJustifyContent */
    int8_t     gap;
    int8_t     margin_top, margin_bottom, margin_left, margin_right;
    int8_t     padding_top, padding_bottom, padding_left, padding_right;
    int16_t    width_cols;      /* 0=auto, >0=cols, <0=-percent */
    uint32_t   important_mask;
} CssStyle;

typedef struct CssDecl {
    const char     *prop;
    const char     *val;
    bool            important;
    struct CssDecl *next;
} CssDecl;

typedef struct CssRule {
    const char     *selector;
    uint32_t        specificity;
    uint32_t        order;
    int16_t         media_min_px;
    int16_t         media_max_px;
    int8_t          media_scheme; /* 0=any, 1=dark, 2=light */
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
void css_apply_decl_ex(CssStyle *st, const char *prop, const char *val, bool important);
void css_parse_inline(CssStyle *st, const char *inline_css);
void css_compute_document(struct DomDocument *doc, const CssStylesheet *ss);
void css_compute_document_ex(struct DomDocument *doc, const CssStylesheet *ss, int viewport_w);

#endif /* TB_CSS_H */
