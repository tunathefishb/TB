#ifndef TB_DOM_H
#define TB_DOM_H

#include "css.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DOM_MAX_NODES 16384

typedef enum {
    DOM_NODE_DOCUMENT = 0,
    DOM_NODE_ELEMENT,
    DOM_NODE_TEXT,
    DOM_NODE_COMMENT
} DomNodeType;

typedef enum {
    TAG_UNKNOWN = 0,
    TAG_HTML, TAG_HEAD, TAG_TITLE, TAG_META, TAG_LINK, TAG_STYLE, TAG_SCRIPT, TAG_NOSCRIPT,
    TAG_BODY, TAG_DIV, TAG_SPAN, TAG_P, TAG_A,
    TAG_H1, TAG_H2, TAG_H3, TAG_H4, TAG_H5, TAG_H6,
    TAG_UL, TAG_OL, TAG_LI, TAG_DL, TAG_DT, TAG_DD,
    TAG_PRE, TAG_CODE, TAG_BLOCKQUOTE, TAG_HR, TAG_BR, TAG_IMG,
    TAG_STRONG, TAG_B, TAG_EM, TAG_I, TAG_U, TAG_S, TAG_DEL, TAG_MARK, TAG_SMALL, TAG_SUB, TAG_SUP,
    TAG_TABLE, TAG_THEAD, TAG_TBODY, TAG_TFOOT, TAG_TR, TAG_TH, TAG_TD,
    TAG_FORM, TAG_INPUT, TAG_BUTTON, TAG_TEXTAREA, TAG_SELECT, TAG_OPTION, TAG_LABEL,
    TAG_HEADER, TAG_NAV, TAG_MAIN, TAG_SECTION, TAG_ARTICLE, TAG_ASIDE, TAG_FOOTER,
    TAG_DETAILS, TAG_SUMMARY, TAG_FIGURE, TAG_FIGCAPTION,
    TAG_COUNT
} DomTag;

typedef struct {
    char *name;
    char *value;
} DomAttr;

typedef struct DomListener {
    char               *type;
    void               *js_fn;       /* JsObj* function pointer managed with GC */
    bool                is_inline;   /* Created from onclick="..." attribute */
    struct DomListener *next;
} DomListener;

typedef struct DomNode {
    DomNodeType     type;
    DomTag          tag;
    uint32_t        node_id;
    char           *tag_name;     /* Lowercase tag string for TAG_UNKNOWN, NULL otherwise */
    char           *text;         /* Text content for TEXT / COMMENT nodes */
    DomAttr        *attrs;
    uint16_t        attr_count;
    uint16_t        attr_cap;

    struct DomDocument *owner_doc;
    struct DomNode     *parent;
    struct DomNode     *first_child;
    struct DomNode     *last_child;
    struct DomNode     *prev_sibling;
    struct DomNode     *next_sibling;

    CssStyle        style;

    /* Live form control state */
    char           *form_value;
    bool            form_value_set;
    bool            form_checked;
    bool            form_checked_set;

    /* JS Engine Bridge */
    void           *js_wrapper;   /* Cached JsObj* wrapper (1:1 identity) */
    DomListener    *listeners;
} DomNode;

typedef void (*DomNodeDestroyCb)(void *userdata, DomNode *node);

typedef struct DomDocument {
    DomNode         *root;        /* DOM_NODE_DOCUMENT */
    DomNode         *html;
    DomNode         *head;
    DomNode         *body;
    uint32_t         node_count;
    uint32_t         next_id;
    bool             dirty_style;
    bool             dirty_layout;
    DomNodeDestroyCb on_node_destroy;
    void            *userdata;
} DomDocument;

typedef struct {
    DomNode **items;
    size_t    count;
    size_t    cap;
} DomNodeList;

DomTag      dom_tag_from_name(const char *name, size_t len);
const char *dom_tag_name(DomTag tag);
const char *dom_node_tag_name(const DomNode *node);

DomDocument *dom_doc_new(void);
void         dom_doc_free(DomDocument *doc);
DomDocument *dom_parse_html(const char *html, size_t len);

DomNode *dom_create_element(DomDocument *doc, const char *tag_name);
DomNode *dom_create_text(DomDocument *doc, const char *text);
void     dom_node_free(DomNode *node);

bool     dom_append_child(DomNode *parent, DomNode *child);
bool     dom_insert_before(DomNode *parent, DomNode *new_node, DomNode *ref_node);
DomNode *dom_remove_child(DomNode *parent, DomNode *child);
bool     dom_replace_child(DomNode *parent, DomNode *new_node, DomNode *old_node);
void     dom_clear_children(DomNode *parent);
DomNode *dom_clone_node(DomDocument *doc, const DomNode *src, bool deep);

const char *dom_get_attr(const DomNode *node, const char *name);
bool        dom_has_attr(const DomNode *node, const char *name);
void        dom_set_attr(DomNode *node, const char *name, const char *value);
void        dom_remove_attr(DomNode *node, const char *name);

char *dom_get_text_content(const DomNode *node);
void  dom_set_text_content(DomNode *node, const char *text);
char *dom_get_inner_html(const DomNode *node);
void  dom_set_inner_html(DomNode *node, const char *html);
char *dom_decode_entities(const char *src, size_t len);

/* Class list helpers */
bool dom_class_contains(const DomNode *node, const char *cls);
void dom_class_add(DomNode *node, const char *cls);
void dom_class_remove(DomNode *node, const char *cls);
bool dom_class_toggle(DomNode *node, const char *cls, int force /* -1=auto, 0=off, 1=on */);

/* Form control state helpers */
const char *dom_input_get_value(DomNode *node);
void        dom_input_set_value(DomNode *node, const char *val);
bool        dom_input_get_checked(DomNode *node);
void        dom_input_set_checked(DomNode *node, bool checked);

/* Queries & CSS Selectors */
char    *dom_get_title(const DomDocument *doc);
void     dom_set_title(DomDocument *doc, const char *title);
DomNode *dom_get_element_by_id(const DomNode *root, const char *id);
bool     dom_matches_selector(const DomNode *node, const char *selector);
DomNode *dom_query_selector(const DomNode *root, const char *selector);
void     dom_query_selector_all(const DomNode *root, const char *selector, DomNodeList *out);

void dom_nodelist_init(DomNodeList *nl);
void dom_nodelist_push(DomNodeList *nl, DomNode *n);
void dom_nodelist_free(DomNodeList *nl);

#endif /* TB_DOM_H */
