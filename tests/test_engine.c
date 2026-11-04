#include "test_harness.h"
#include "browser.h"
#include "css.h"
#include "dom.h"
#include "js.h"
#include "layout.h"
#include "mem.h"

/* ── Test 4: HTML5 Parser, Entities, CSS Specificity Cascade, & Selectors ── */
void test_dom_and_css(void) {
    printf("[4/14] Testing HTML5 parser, entities, CSS specificity cascade, & selectors...\n");
    const char *html =
        "<!DOCTYPE html><html><head><title>  DOM &amp; CSS &mdash; Test  </title>"
        "<style>"
        "  p { color: #112233; }"
        "  .highlight { color: #445566; font-weight: bold; }"
        "  #hero { color: #ff0088; }"
        "  .ghost { display: none; }"
        "</style></head><body>"
        "<div class='card'><p id='hero' class='highlight'>Alpha &copy; &#65;</p>"
        "<ul><li data-role='js-item' class='active'>One<li>Two</ul>"
        "<span class='ghost' style='display:block; color: rgb(10, 20, 30)'>Override</span>"
        "</div></body></html>";

    DomDocument *doc = dom_parse_html(html, strlen(html));
    ASSERT_TRUE(doc != NULL, "dom_parse_html succeeds");
    char *title = dom_get_title(doc);
    ASSERT_STR_EQ(title, "DOM & CSS \xe2\x80\x94 Test", "Entity decode + whitespace collapse in <title>");
    tb_free(title);

    css_compute_document(doc, NULL);
    DomNode *hero = dom_get_element_by_id(doc->root, "hero");
    ASSERT_TRUE(hero != NULL, "getElementById('hero')");
    ASSERT_TRUE(hero->style.fg.r == 0xff && hero->style.fg.g == 0x00 && hero->style.fg.b == 0x88,
                "#id specificity beats .class and tag");
    ASSERT_TRUE(hero->style.bold == 1, ".highlight font-weight cascades alongside #hero color");

    DomNode *ov = dom_query_selector(doc->root, "div.card span.ghost");
    ASSERT_TRUE(ov != NULL && ov->style.display == CSS_DISP_BLOCK && ov->style.fg.g == 20,
                "Inline style overrides stylesheet display:none and rgb()");

    DomNode *li = dom_query_selector(doc->root, "div.card > ul li.active[data-role^='js']:first-child");
    ASSERT_TRUE(li != NULL, "Complex combinator + attribute + :first-child selector");
    dom_doc_free(doc);
}

/* ── Test 7: Full Browser Controller, Interactive Widgets, History, & Demos ── */
void test_browser_lifecycle(void) {
    printf("[7/14] Testing browser navigation, widget events, input editing, & history...\n");
    TbBrowser b;
    tb_browser_init(&b, 92, 28, false);

    /* 1. about:home interactive buttons */
    ASSERT_TRUE(tb_browser_navigate(&b, "about:home", true), "Navigate to about:home");
    bool ok = tb_browser_eval_repl(&b,
        "document.getElementById('btn-inc').click();"
        "document.getElementById('btn-inc').click();"
        "document.getElementById('btn-fib').click();");
    ASSERT_TRUE(ok, "Click #btn-inc x2 and #btn-fib on about:home");
    DomNode *cnt = dom_get_element_by_id(b.doc->root, "cnt");
    char *cnt_txt = dom_get_text_content(cnt);
    ASSERT_STR_EQ(cnt_txt, "2", "#cnt updated to 2");
    tb_free(cnt_txt);

    /* 2. about:demo reactive Todo input editing + expression calculator */
    ASSERT_TRUE(tb_browser_navigate(&b, "about:demo", true), "Navigate to about:demo");
    DomNode *todo_in = dom_get_element_by_id(b.doc->root, "todo-in");
    int in_hit = layout_find_node_hit(&b.layout, todo_in);
    ASSERT_TRUE(in_hit >= 0, "Locate #todo-in HitBox in layout");
    dom_input_set_value(todo_in, "Zero leak");
    tb_browser_activate_hit(&b, in_hit);
    tb_browser_edit_key(&b, '!', 0);
    tb_browser_stop_editing(&b);
    ASSERT_STR_EQ(dom_input_get_value(todo_in), "Zero leak!", "Live cursor typing updated <input>");

    DomNode *todo_add = dom_get_element_by_id(b.doc->root, "todo-add");
    int add_hit = layout_find_node_hit(&b.layout, todo_add);
    ASSERT_TRUE(add_hit >= 0, "Locate #todo-add HitBox");
    tb_browser_activate_hit(&b, add_hit);

    TbBuf dump;
    tb_buf_init(&dump);
    layout_render_document(&b.layout, false, &dump);
    ASSERT_TRUE(dump.data && strstr(dump.data, "Zero leak!") != NULL,
                "Newly added Todo item appears in rendered TUI layout");
    tb_buf_free(&dump);

    /* 2b. Toggle Todo item button (whose click handler sets ul.innerHTML='' and frees the clicked button mid-dispatch!) */
    ASSERT_TRUE(tb_browser_eval_repl(&b,
        "window._todoBubbled = 0; "
        "document.getElementById('todo-list').addEventListener('click', function(){ window._todoBubbled++; });"),
        "Attach bubbling click listener on #todo-list");
    DomNode *todo_btn0 = dom_query_selector(b.doc->root, "#todo-list button");
    int btn0_hit = layout_find_node_hit(&b.layout, todo_btn0);
    ASSERT_TRUE(btn0_hit >= 0, "Locate first #todo-list button HitBox");
    tb_browser_activate_hit(&b, btn0_hit);

    DomNode *todo_stats = dom_get_element_by_id(b.doc->root, "todo-stats");
    char *stats_txt = dom_get_text_content(todo_stats);
    ASSERT_STR_EQ(stats_txt, "3 remaining of 4 tasks",
                  "Toggling first Todo button via HitBox updated #todo-stats without UAF/segfault");
    tb_free(stats_txt);

    JsVal bub_v = js_undefined();
    ASSERT_TRUE(js_eval(b.vm, "window._todoBubbled", 19, &bub_v) &&
                bub_v.type == JS_NUMBER && (int)bub_v.u.num == 1,
                "Click event still bubbles to parent #todo-list after target <button> is destroyed by innerHTML=''");

    /* Toggle again and click #todo-clear */
    DomNode *todo_btn1 = dom_query_selector(b.doc->root, "#todo-list button");
    int btn1_hit = layout_find_node_hit(&b.layout, todo_btn1);
    ASSERT_TRUE(btn1_hit >= 0, "Locate re-rendered #todo-list button HitBox");
    tb_browser_activate_hit(&b, btn1_hit);

    DomNode *todo_clear = dom_get_element_by_id(b.doc->root, "todo-clear");
    int clear_hit = layout_find_node_hit(&b.layout, todo_clear);
    ASSERT_TRUE(clear_hit >= 0, "Locate #todo-clear HitBox");
    tb_browser_activate_hit(&b, clear_hit);

    todo_stats = dom_get_element_by_id(b.doc->root, "todo-stats");
    stats_txt = dom_get_text_content(todo_stats);
    ASSERT_STR_EQ(stats_txt, "2 remaining of 2 tasks",
                  "Clicking #todo-clear removed completed Todo items cleanly");
    tb_free(stats_txt);

    /* 3. about:memory churn button & demos/index.html external script + history back */
    ASSERT_TRUE(tb_browser_navigate(&b, "about:memory", true), "Navigate to about:memory");
    ASSERT_TRUE(tb_browser_eval_repl(&b, "document.getElementById('btn-churn').click()"),
                "Run 5,000-object churn button in about:memory");

    ASSERT_TRUE(tb_browser_navigate(&b, "demos/index.html", true), "Navigate to demos/index.html");
    JsVal ext_ok = js_undefined();
    ASSERT_TRUE(js_eval(b.vm, "Boolean(window.TBExternalWidgetLoaded)", 38, &ext_ok) &&
                ext_ok.type == JS_BOOL && ext_ok.u.boolean,
                "External <script src='widget.js'> executed on demos/index.html");

    ASSERT_TRUE(tb_browser_back(&b) && strcmp(b.current_url, "about:memory") == 0,
                "History Back restored about:memory");
    ASSERT_TRUE(tb_browser_forward(&b) && strstr(b.current_url, "demos/index.html") != NULL,
                "History Forward restored demos/index.html");

    tb_browser_free(&b);
}
