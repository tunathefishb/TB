#ifndef TB_BROWSER_H
#define TB_BROWSER_H

#include "dom.h"
#include "js.h"
#include "layout.h"
#include "net.h"

#define TB_HISTORY_MAX 32
#define TB_CONSOLE_MAX 128

typedef struct {
    JsLogLevel level;
    char      *text;
} TbConsoleEntry;

typedef struct {
    char url[1536];
    int  scroll_y;
} TbHistItem;

typedef struct {
    /* Current active page (single active DOM+VM to keep RAM < 10 MB) */
    char         current_url[1536];
    char         page_title[256];
    int          http_status;
    bool         insecure_tls;

    DomDocument *doc;
    JsVm        *vm;
    LayoutDoc    layout;

    /* Viewport & interaction state */
    int          viewport_w;
    int          viewport_h;
    int          scroll_y;
    int          focused_hit;
    DomNode     *editing_node;
    size_t       edit_cursor;

    /* Deferred navigation (safe when triggered inside JS execution) */
    bool         pending_nav;
    bool         pending_reload;
    char         pending_url[1536];

    /* History ring */
    TbHistItem   history[TB_HISTORY_MAX];
    int          hist_count;
    int          hist_index;

    /* Status / Alert toast & JS Console log ring */
    char           status_msg[256];
    TbConsoleEntry console_logs[TB_CONSOLE_MAX];
    int            console_count;
} TbBrowser;

void tb_browser_init(TbBrowser *b, int vw, int vh, bool insecure_tls);
void tb_browser_free(TbBrowser *b);

bool tb_browser_navigate(TbBrowser *b, const char *url_or_input, bool push_history);
bool tb_browser_back(TbBrowser *b);
bool tb_browser_forward(TbBrowser *b);
bool tb_browser_reload(TbBrowser *b);

void tb_browser_relayout_if_needed(TbBrowser *b, bool force);
int  tb_browser_tick(TbBrowser *b);

/* Interactive widget & REPL actions */
void tb_browser_activate_hit(TbBrowser *b, int hit_idx);
void tb_browser_edit_key(TbBrowser *b, uint32_t cp, int special_key /* 8=bs, 127=del, 1=left, 2=right */);
void tb_browser_stop_editing(TbBrowser *b);
bool tb_browser_eval_repl(TbBrowser *b, const char *js_code);
void tb_browser_force_gc(TbBrowser *b);
void tb_browser_log(TbBrowser *b, JsLogLevel level, const char *msg);

#endif /* TB_BROWSER_H */
