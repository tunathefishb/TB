#define _GNU_SOURCE
#include "tui.h"
#include "common.h"
#include "mem.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

static struct termios        g_orig_tios;
static bool                  g_tios_active = false;
static volatile sig_atomic_t g_resized     = 1;
static volatile sig_atomic_t g_quit_sig    = 0;

static void write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n > 0) {
            off += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
}

static void tui_restore_tty(void) {
    if (!g_tios_active) return;
    const char *seq = "\x1b[0m\x1b[?1000l\x1b[?1006l\x1b[?25h\x1b[?1049l";
    write_all(STDOUT_FILENO, seq, strlen(seq));
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_tios);
    g_tios_active = false;
}

static void on_sigwinch(int sig) {
    (void)sig;
    g_resized = 1;
}

static void on_sigterm(int sig) {
    (void)sig;
    g_quit_sig = 1;
}

static bool tui_enter_raw(void) {
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) return false;
    if (tcgetattr(STDIN_FILENO, &g_orig_tios) < 0) return false;

    struct termios raw = g_orig_tios;
    raw.c_iflag &= ~(tcflag_t)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= ~(tcflag_t)(OPOST);
    raw.c_cflag |= (tcflag_t)(CS8);
    raw.c_lflag &= ~(tcflag_t)(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) return false;
    g_tios_active = true;
    atexit(tui_restore_tty);

    struct sigaction sa_winch;
    memset(&sa_winch, 0, sizeof(sa_winch));
    sa_winch.sa_handler = on_sigwinch;
    sigaction(SIGWINCH, &sa_winch, NULL);

    struct sigaction sa_term;
    memset(&sa_term, 0, sizeof(sa_term));
    sa_term.sa_handler = on_sigterm;
    sigaction(SIGTERM, &sa_term, NULL);
    sigaction(SIGHUP, &sa_term, NULL);
    sigaction(SIGINT, &sa_term, NULL);

    /* Enter alternate screen, hide cursor, enable SGR mouse tracking */
    const char *init_seq = "\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1006h\x1b[2J";
    write_all(STDOUT_FILENO, init_seq, strlen(init_seq));
    return true;
}

static void tui_query_size(int *cols, int *rows) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        *cols = (int)ws.ws_col;
        *rows = (int)ws.ws_row;
    } else {
        *cols = 96;
        *rows = 30;
    }
    if (*cols < 40) *cols = 40;
    if (*rows < 10) *rows = 10;
}

/* Append UTF-8 string truncated to max_cols display columns; returns columns written */
static int buf_append_trunc(TbBuf *out, const char *s, int max_cols) {
    if (!s || max_cols <= 0) return 0;
    size_t len = strlen(s);
    size_t pos = 0;
    int    col = 0;
    while (pos < len && col < max_cols) {
        uint32_t cp = 0;
        size_t   adv = tb_utf8_decode(s + pos, len - pos, &cp);
        if (adv == 0) break;
        if (cp == '\n' || cp == '\r' || cp == '\t') {
            tb_buf_append_char(out, ' ');
            col += 1;
            pos += adv;
            continue;
        }
        int w = tb_unicode_width(cp);
        if (w <= 0) {
            pos += adv;
            continue;
        }
        if (col + w > max_cols) break;
        tb_buf_append(out, s + pos, adv);
        col += w;
        pos += adv;
    }
    return col;
}

static bool str_contains_ci(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return false;
    size_t nlen = strlen(needle);
    size_t hlen = strlen(hay);
    if (nlen > hlen) return false;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (tb_strncasecmp(hay + i, needle, nlen) == 0) return true;
    }
    return false;
}

typedef enum {
    PROMPT_NONE = 0,
    PROMPT_URL,
    PROMPT_SEARCH,
    PROMPT_REPL
} TuiPromptMode;

typedef enum {
    KEY_NONE = 0,
    KEY_CHAR,
    KEY_ENTER,
    KEY_ESC,
    KEY_TAB,
    KEY_SHIFT_TAB,
    KEY_BACKSPACE,
    KEY_DELETE,
    KEY_UP,
    KEY_DOWN,
    KEY_LEFT,
    KEY_RIGHT,
    KEY_PGUP,
    KEY_PGDN,
    KEY_HOME,
    KEY_END,
    KEY_CTRL_C,
    KEY_CTRL_L,
    KEY_MOUSE
} TuiKeyKind;

typedef struct {
    TuiKeyKind kind;
    uint32_t   cp;
    int        mouse_btn;
    int        mouse_x; /* 1-based */
    int        mouse_y; /* 1-based */
    bool       mouse_press;
} TuiEvent;

/* Decode next key or mouse event from input byte buffer; returns bytes consumed */
static size_t tui_decode_event(const char *buf, size_t len, TuiEvent *ev) {
    memset(ev, 0, sizeof(*ev));
    if (len == 0) return 0;

    unsigned char b0 = (unsigned char)buf[0];
    if (b0 == 0x03) { ev->kind = KEY_CTRL_C;    return 1; }
    if (b0 == 0x0C) { ev->kind = KEY_CTRL_L;    return 1; }
    if (b0 == '\r' || b0 == '\n') { ev->kind = KEY_ENTER; return 1; }
    if (b0 == '\t') { ev->kind = KEY_TAB;       return 1; }
    if (b0 == 0x7F || b0 == 0x08) { ev->kind = KEY_BACKSPACE; return 1; }

    if (b0 == 0x1B) {
        if (len == 1) {
            ev->kind = KEY_ESC;
            return 1;
        }
        if (buf[1] == '[') {
            /* SGR mouse: \x1b[<btn;x;yM or m */
            if (len >= 6 && buf[2] == '<') {
                size_t i = 3;
                int vals[3] = {0, 0, 0};
                int vi = 0;
                while (i < len && vi < 3) {
                    if (buf[i] >= '0' && buf[i] <= '9') {
                        vals[vi] = vals[vi] * 10 + (buf[i] - '0');
                        i++;
                    } else if (buf[i] == ';') {
                        vi++;
                        i++;
                    } else {
                        break;
                    }
                }
                if (i < len && (buf[i] == 'M' || buf[i] == 'm')) {
                    ev->kind        = KEY_MOUSE;
                    ev->mouse_btn   = vals[0];
                    ev->mouse_x     = vals[1];
                    ev->mouse_y     = vals[2];
                    ev->mouse_press = (buf[i] == 'M');
                    return i + 1;
                }
            }
            /* Standard CSI sequences */
            if (len >= 3) {
                char c = buf[2];
                if (c == 'A') { ev->kind = KEY_UP;        return 3; }
                if (c == 'B') { ev->kind = KEY_DOWN;      return 3; }
                if (c == 'C') { ev->kind = KEY_RIGHT;     return 3; }
                if (c == 'D') { ev->kind = KEY_LEFT;      return 3; }
                if (c == 'H') { ev->kind = KEY_HOME;      return 3; }
                if (c == 'F') { ev->kind = KEY_END;       return 3; }
                if (c == 'Z') { ev->kind = KEY_SHIFT_TAB; return 3; }
                if (c >= '0' && c <= '9') {
                    size_t i = 2;
                    int num = 0;
                    while (i < len && buf[i] >= '0' && buf[i] <= '9') {
                        num = num * 10 + (buf[i] - '0');
                        i++;
                    }
                    /* Skip optional ;modifier */
                    while (i < len && buf[i] != '~' &&
                           !((buf[i] >= 'A' && buf[i] <= 'Z') || (buf[i] >= 'a' && buf[i] <= 'z'))) {
                        i++;
                    }
                    if (i < len) {
                        char term = buf[i];
                        if (term == '~') {
                            if (num == 1 || num == 7) ev->kind = KEY_HOME;
                            else if (num == 3)        ev->kind = KEY_DELETE;
                            else if (num == 4 || num == 8) ev->kind = KEY_END;
                            else if (num == 5)        ev->kind = KEY_PGUP;
                            else if (num == 6)        ev->kind = KEY_PGDN;
                        }
                        return i + 1;
                    }
                }
            }
        } else if (buf[1] == 'O' && len >= 3) {
            char c = buf[2];
            if (c == 'A') { ev->kind = KEY_UP;    return 3; }
            if (c == 'B') { ev->kind = KEY_DOWN;  return 3; }
            if (c == 'C') { ev->kind = KEY_RIGHT; return 3; }
            if (c == 'D') { ev->kind = KEY_LEFT;  return 3; }
            if (c == 'H') { ev->kind = KEY_HOME;  return 3; }
            if (c == 'F') { ev->kind = KEY_END;   return 3; }
        }
        ev->kind = KEY_ESC;
        return 1;
    }

    if (b0 < 32) {
        return 1; /* Ignore unhandled control char */
    }

    uint32_t cp = 0;
    size_t adv = tb_utf8_decode(buf, len, &cp);
    if (adv == 0) return 1;
    ev->kind = KEY_CHAR;
    ev->cp   = cp;
    return adv;
}

static void ensure_hit_visible(TbBrowser *b, int doc_rows) {
    if (b->focused_hit < 0 || b->focused_hit >= b->layout.hit_count) return;
    int hy = b->layout.hits[b->focused_hit].line_y;
    if (hy < b->scroll_y) {
        b->scroll_y = hy > 1 ? hy - 1 : 0;
    } else if (hy >= b->scroll_y + doc_rows) {
        b->scroll_y = hy - doc_rows + 2;
    }
}

static void search_jump(TbBrowser *b, const char *query, int dir, int doc_rows) {
    if (!query || !*query || b->layout.line_count <= 0) return;
    int n = b->layout.line_count;
    int start = b->scroll_y + (dir > 0 ? 1 : -1);
    for (int step = 0; step < n; step++) {
        int idx = ((start + step * dir) % n + n) % n;
        if (str_contains_ci(b->layout.lines[idx].plain, query)) {
            b->scroll_y = idx > 1 ? idx - 1 : 0;
            int max_scroll = b->layout.line_count - doc_rows;
            if (max_scroll < 0) max_scroll = 0;
            if (b->scroll_y > max_scroll) b->scroll_y = max_scroll;
            snprintf(b->status_msg, sizeof(b->status_msg),
                     "Match for \"%s\" at line %d/%d", query, idx + 1, n);
            return;
        }
    }
    snprintf(b->status_msg, sizeof(b->status_msg), "Pattern not found: \"%s\"", query);
}

static void tui_render(TbBrowser *b, int cols, int rows, bool console_open,
                       TuiPromptMode prompt_mode, const char *prompt_buf,
                       const char *search_query, TbBuf *frame) {
    tb_buf_clear(frame);
    /* Synchronized update start + hide cursor during draw */
    tb_buf_append_cstr(frame, "\x1b[?2026h\x1b[?25l");

    int drawer_h = console_open ? 8 : 0;
    if (rows - 2 - drawer_h < 4) drawer_h = 0;
    int doc_rows = rows - 2 - drawer_h;

    if (b->viewport_w != cols || b->viewport_h != doc_rows) {
        b->viewport_w = cols;
        b->viewport_h = doc_rows;
        tb_browser_relayout_if_needed(b, true);
    } else {
        tb_browser_relayout_if_needed(b, false);
    }

    int max_scroll = b->layout.line_count - doc_rows;
    if (max_scroll < 0) max_scroll = 0;
    if (b->scroll_y > max_scroll) b->scroll_y = max_scroll;
    if (b->scroll_y < 0) b->scroll_y = 0;
    if (b->vm) b->vm->scroll_y = b->scroll_y;

    /* ── 1. Top Chrome + Live Kernel VmRSS Gauge (Row 1) ── */
    TbMemStats ms;
    tb_mem_stats(&ms);
    double rss_mb = (double)ms.vm_rss_kb / 1024.0;
    size_t js_kb  = b->vm ? (b->vm->gc_bytes / 1024) : 0;

    int filled = (int)((rss_mb / 10.0) * 6.0 + 0.5);
    if (filled < 1 && ms.vm_rss_kb > 0) filled = 1;
    if (filled > 6) filled = 6;

    char gauge_plain[80];
    snprintf(gauge_plain, sizeof(gauge_plain), " RSS %.2f/10MB [######] JS %zuK ", rss_mb, js_kb);
    int gauge_cols = (int)strlen(gauge_plain);
    int left_budget = cols - gauge_cols;
    if (left_budget < 12) left_budget = 12;

    tb_buf_append_cstr(frame, "\x1b[1;1H\x1b[0;48;2;20;28;44;38;2;226;232;240m");
    int used_left = 0;
    bool can_back = (b->hist_index > 0);
    bool can_fwd  = (b->hist_index + 1 < b->hist_count);
    tb_buf_append_cstr(frame, can_back ? " \x1b[1;38;2;56;189;248m<\x1b[22m" : " \x1b[38;2;100;116;139m<");
    tb_buf_append_cstr(frame, can_fwd  ? "\x1b[1;38;2;56;189;248m>\x1b[22m " : "\x1b[38;2;100;116;139m> ");
    used_left += 4;

    if (strncmp(b->current_url, "https://", 8) == 0) {
        tb_buf_append_cstr(frame, "\x1b[1;38;2;52;211;153m[TLS]\x1b[22;38;2;226;232;240m ");
        used_left += 6;
    } else if (strncmp(b->current_url, "about:", 6) == 0) {
        tb_buf_append_cstr(frame, "\x1b[1;38;2;56;189;248m[APP]\x1b[22;38;2;226;232;240m ");
        used_left += 6;
    } else if (strncmp(b->current_url, "http://", 7) == 0) {
        tb_buf_append_cstr(frame, "\x1b[1;38;2;251;191;36m[HTTP]\x1b[22;38;2;226;232;240m ");
        used_left += 7;
    } else {
        tb_buf_append_cstr(frame, "\x1b[1;38;2;167;139;250m[LOC]\x1b[22;38;2;226;232;240m ");
        used_left += 6;
    }

    char title_url[1850];
    if (b->page_title[0]) {
        snprintf(title_url, sizeof(title_url), "%s — %s", b->page_title, b->current_url);
    } else {
        snprintf(title_url, sizeof(title_url), "%s", b->current_url);
    }
    if (left_budget > used_left) {
        used_left += buf_append_trunc(frame, title_url, left_budget - used_left);
    }
    while (used_left < left_budget) {
        tb_buf_append_char(frame, ' ');
        used_left++;
    }

    if (used_left + gauge_cols <= cols) {
        const char *bar_color = "\x1b[1;38;2;52;211;153m"; /* Emerald < 6.5 MB */
        if (rss_mb >= 8.5)      bar_color = "\x1b[1;38;2;248;113;113m"; /* Red */
        else if (rss_mb >= 6.5) bar_color = "\x1b[1;38;2;251;191;36m";  /* Amber */

        tb_buf_printf(frame, "\x1b[48;2;15;23;42;38;2;203;213;225m RSS %s%.2f\x1b[22;38;2;148;163;184m/10MB [",
                      bar_color, rss_mb);
        tb_buf_append_cstr(frame, bar_color);
        for (int i = 0; i < 6; i++) {
            if (i < filled) tb_buf_append_cstr(frame, "█");
            else            tb_buf_append_cstr(frame, "\x1b[22;38;2;71;85;105m░");
        }
        tb_buf_printf(frame, "\x1b[22;38;2;148;163;184m] JS \x1b[38;2;56;189;248m%zuK \x1b[0m\x1b[K", js_kb);
    } else {
        tb_buf_append_cstr(frame, "\x1b[0m\x1b[K");
    }

    /* ── 2. Main Document Viewport ── */
    const char *hl_search = (search_query && search_query[0]) ? search_query : NULL;
    for (int r = 0; r < doc_rows; r++) {
        int doc_y = b->scroll_y + r;
        tb_buf_printf(frame, "\x1b[%d;1H\x1b[0m", r + 2);
        if (doc_y >= 0 && doc_y < b->layout.line_count) {
            layout_render_line_ansi(&b->layout, doc_y, b->focused_hit, cols, true, hl_search, frame);
        }
        tb_buf_append_cstr(frame, "\x1b[0m\x1b[K");
    }

    /* ── 3. Optional Split-Pane JS Console & Live REPL Drawer ── */
    if (drawer_h > 0) {
        int top_row = 2 + doc_rows;
        tb_buf_printf(frame, "\x1b[%d;1H\x1b[0;1;48;2;30;41;59;38;2;56;189;248m", top_row);
        char hdr[256];
        snprintf(hdr, sizeof(hdr),
                 " ── JS Console & Live REPL (: eval, c hide, G force-GC) ── JS Objects: %u | DOM Nodes: %u ",
                 b->vm ? b->vm->gc_obj_count : 0U,
                 b->doc ? b->doc->node_count : 0U);
        int hc = buf_append_trunc(frame, hdr, cols);
        while (hc < cols) { tb_buf_append_char(frame, ' '); hc++; }
        tb_buf_append_cstr(frame, "\x1b[0m\x1b[K");

        int log_slots = drawer_h - 1;
        int start_idx = b->console_count - log_slots;
        if (start_idx < 0) start_idx = 0;
        for (int i = 0; i < log_slots; i++) {
            int row = top_row + 1 + i;
            int li  = start_idx + i;
            tb_buf_printf(frame, "\x1b[%d;1H\x1b[0;48;2;12;17;29m", row);
            if (li < b->console_count && b->console_logs[li].text) {
                JsLogLevel lv = b->console_logs[li].level;
                if (lv == JS_LOG_ERROR)      tb_buf_append_cstr(frame, " \x1b[1;38;2;248;113;113m✖ ");
                else if (lv == JS_LOG_WARN)  tb_buf_append_cstr(frame, " \x1b[1;38;2;251;191;36m▲ ");
                else                         tb_buf_append_cstr(frame, " \x1b[38;2;148;163;184m› \x1b[38;2;226;232;240m");
                int lc = 3 + buf_append_trunc(frame, b->console_logs[li].text, cols - 4);
                while (lc < cols) { tb_buf_append_char(frame, ' '); lc++; }
            } else {
                for (int c = 0; c < cols; c++) tb_buf_append_char(frame, ' ');
            }
            tb_buf_append_cstr(frame, "\x1b[0m\x1b[K");
        }
    }

    /* ── 4. Bottom Status / Omnibar / Search / REPL Prompt Bar ── */
    tb_buf_printf(frame, "\x1b[%d;1H", rows);
    if (prompt_mode != PROMPT_NONE) {
        const char *prefix = " URL > ";
        const char *bg_col = "\x1b[0;1;48;2;30;58;138;38;2;255;255;255m";
        if (prompt_mode == PROMPT_SEARCH) {
            prefix = " Search / ";
            bg_col = "\x1b[0;1;48;2;6;78;59;38;2;255;255;255m";
        } else if (prompt_mode == PROMPT_REPL) {
            prefix = " :js > ";
            bg_col = "\x1b[0;1;48;2;76;29;149;38;2;255;255;255m";
        }
        tb_buf_append_cstr(frame, bg_col);
        int pc = buf_append_trunc(frame, prefix, cols - 2);
        tb_buf_append_cstr(frame, "\x1b[22m");
        int avail = cols - pc - 1;
        const char *view = prompt_buf;
        size_t plen = strlen(prompt_buf);
        if ((int)plen > avail && avail > 0) {
            view = prompt_buf + (plen - (size_t)avail);
        }
        int vc = buf_append_trunc(frame, view, avail);
        int cursor_col = pc + vc + 1;
        for (int c = pc + vc; c < cols; c++) tb_buf_append_char(frame, ' ');
        tb_buf_printf(frame, "\x1b[0m\x1b[%d;%dH\x1b[?25h", rows, cursor_col);
    } else if (b->editing_node) {
        tb_buf_append_cstr(frame, "\x1b[0;1;48;2;120;53;15;38;2;254;243;199m");
        char msg[256];
        snprintf(msg, sizeof(msg),
                 " [INPUT EDITING] Type text | Enter: submit/done | Esc: finish | Value: \"%s\"",
                 b->editing_node->form_value ? b->editing_node->form_value : "");
        int mc = buf_append_trunc(frame, msg, cols);
        while (mc < cols) { tb_buf_append_char(frame, ' '); mc++; }
        tb_buf_append_cstr(frame, "\x1b[0m");
    } else {
        tb_buf_append_cstr(frame, "\x1b[0;48;2;20;28;44;38;2;148;163;184m ");
        char left_info[512];
        left_info[0] = '\0';
        if (b->focused_hit >= 0 && b->focused_hit < b->layout.hit_count) {
            HitBox *hb = &b->layout.hits[b->focused_hit];
            if (hb->kind == HIT_LINK && hb->node) {
                const char *href = dom_get_attr(hb->node, "href");
                if (href) snprintf(left_info, sizeof(left_info), "Link -> %s", href);
            }
        }
        if (!left_info[0]) {
            snprintf(left_info, sizeof(left_info), "%s", b->status_msg);
        }

        int pct = 100;
        if (max_scroll > 0) pct = (b->scroll_y * 100) / max_scroll;
        char right_info[128];
        snprintf(right_info, sizeof(right_info),
                 " [Hit %d/%d] [%3d%%] [g:URL /:Find c:JS ::REPL q:Quit] ",
                 b->layout.hit_count > 0 ? (b->focused_hit + 1) : 0,
                 b->layout.hit_count, pct);
        int rcols = (int)strlen(right_info);
        int lbudget = cols - 1 - rcols;
        if (lbudget < 8) lbudget = 8;

        tb_buf_append_cstr(frame, "\x1b[38;2;226;232;240m");
        int lc = 1 + buf_append_trunc(frame, left_info, lbudget);
        while (lc < cols - rcols) { tb_buf_append_char(frame, ' '); lc++; }
        if (lc + rcols <= cols) {
            tb_buf_append_cstr(frame, "\x1b[38;2;148;163;184m");
            tb_buf_append_cstr(frame, right_info);
        }
        tb_buf_append_cstr(frame, "\x1b[0m");
    }

    tb_buf_append_cstr(frame, "\x1b[?2026l");
    write_all(STDOUT_FILENO, frame->data, frame->len);
}

int tb_tui_run(TbBrowser *b) {
    if (!tui_enter_raw()) {
        fprintf(stderr, "tb: standard input/output is not an interactive terminal (use --dump)\n");
        return 1;
    }

    int cols = 96, rows = 30;
    bool console_open = false;
    TuiPromptMode prompt_mode = PROMPT_NONE;
    char prompt_buf[1536] = {0};
    char search_query[256] = {0};

    TbBuf frame;
    tb_buf_init(&frame);

    char inbuf[256];
    size_t inlen = 0;
    bool running = true;

    while (running && !g_quit_sig) {
        if (g_resized) {
            g_resized = 0;
            tui_query_size(&cols, &rows);
        }

        int timer_ms = tb_browser_tick(b);
        int drawer_h = (console_open && rows - 2 - 8 >= 4) ? 8 : 0;
        int doc_rows = rows - 2 - drawer_h;

        tui_render(b, cols, rows, console_open, prompt_mode, prompt_buf, search_query, &frame);

        int wait_ms = (timer_ms >= 0 && timer_ms < 250) ? timer_ms : 250;
        struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, wait_ms);
        if (pr <= 0 || !(pfd.revents & POLLIN)) {
            continue;
        }

        ssize_t nr = read(STDIN_FILENO, inbuf + inlen, sizeof(inbuf) - inlen);
        if (nr <= 0) continue;
        inlen += (size_t)nr;

        size_t pos = 0;
        while (pos < inlen && running) {
            TuiEvent ev;
            size_t used = tui_decode_event(inbuf + pos, inlen - pos, &ev);
            if (used == 0) break;
            pos += used;

            if (ev.kind == KEY_CTRL_C) {
                running = false;
                break;
            }

            /* ── Mode A: Active Prompt (URL / Search / Live JS REPL) ── */
            if (prompt_mode != PROMPT_NONE) {
                if (ev.kind == KEY_ESC) {
                    prompt_mode = PROMPT_NONE;
                    prompt_buf[0] = '\0';
                } else if (ev.kind == KEY_ENTER) {
                    TuiPromptMode finished = prompt_mode;
                    prompt_mode = PROMPT_NONE;
                    if (finished == PROMPT_URL && prompt_buf[0]) {
                        tb_browser_navigate(b, prompt_buf, true);
                    } else if (finished == PROMPT_SEARCH) {
                        snprintf(search_query, sizeof(search_query), "%s", prompt_buf);
                        if (search_query[0]) search_jump(b, search_query, 1, doc_rows);
                    } else if (finished == PROMPT_REPL && prompt_buf[0]) {
                        tb_browser_eval_repl(b, prompt_buf);
                    }
                    prompt_buf[0] = '\0';
                } else if (ev.kind == KEY_BACKSPACE) {
                    size_t plen = strlen(prompt_buf);
                    while (plen > 0) {
                        plen--;
                        unsigned char c = (unsigned char)prompt_buf[plen];
                        prompt_buf[plen] = '\0';
                        if ((c & 0xC0) != 0x80) break;
                    }
                } else if (ev.kind == KEY_CHAR && ev.cp >= 32) {
                    char u8[4];
                    size_t ulen = tb_utf8_encode(ev.cp, u8);
                    size_t plen = strlen(prompt_buf);
                    if (plen + ulen + 1 < sizeof(prompt_buf)) {
                        memcpy(prompt_buf + plen, u8, ulen);
                        prompt_buf[plen + ulen] = '\0';
                    }
                }
                continue;
            }

            /* ── Mode B: Mouse Events (Wheel + Click Hit-Testing) ── */
            if (ev.kind == KEY_MOUSE) {
                if (ev.mouse_btn == 64) {
                    b->scroll_y -= 3;
                } else if (ev.mouse_btn == 65) {
                    b->scroll_y += 3;
                } else if (ev.mouse_btn == 0 && ev.mouse_press) {
                    if (ev.mouse_y == 1) {
                        /* Click on top omnibar opens URL prompt */
                        prompt_mode = PROMPT_URL;
                        snprintf(prompt_buf, sizeof(prompt_buf), "%s", b->current_url);
                    } else if (ev.mouse_y >= 2 && ev.mouse_y < 2 + doc_rows) {
                        int doc_y = b->scroll_y + (ev.mouse_y - 2);
                        int doc_x = ev.mouse_x - 1;
                        int hit = layout_hit_test(&b->layout, doc_y, doc_x);
                        if (hit >= 0) {
                            if (b->editing_node && b->layout.hits[hit].node != b->editing_node) {
                                tb_browser_stop_editing(b);
                            }
                            b->focused_hit = hit;
                            tb_browser_activate_hit(b, hit);
                        } else if (b->editing_node) {
                            tb_browser_stop_editing(b);
                        }
                    }
                }
                continue;
            }

            /* ── Mode C: Live <input> / <textarea> Editing ── */
            if (b->editing_node) {
                if (ev.kind == KEY_ESC) {
                    tb_browser_stop_editing(b);
                } else if (ev.kind == KEY_TAB) {
                    tb_browser_stop_editing(b);
                    if (b->layout.hit_count > 0) {
                        b->focused_hit = (b->focused_hit + 1) % b->layout.hit_count;
                        ensure_hit_visible(b, doc_rows);
                    }
                } else if (ev.kind == KEY_ENTER) {
                    DomNode *ed = b->editing_node;
                    if (ed->tag == TAG_TEXTAREA) {
                        tb_browser_edit_key(b, '\n', 0);
                    } else {
                        tb_browser_edit_key(b, 0, 13);
                    }
                } else if (ev.kind == KEY_BACKSPACE) {
                    tb_browser_edit_key(b, 0, 8);
                } else if (ev.kind == KEY_DELETE) {
                    tb_browser_edit_key(b, 0, 127);
                } else if (ev.kind == KEY_LEFT) {
                    tb_browser_edit_key(b, 0, 1);
                } else if (ev.kind == KEY_RIGHT) {
                    tb_browser_edit_key(b, 0, 2);
                } else if (ev.kind == KEY_CHAR) {
                    tb_browser_edit_key(b, ev.cp, 0);
                }
                continue;
            }

            /* ── Mode D: Normal Navigation Mode ── */
            if (ev.kind == KEY_UP) {
                b->scroll_y -= 1;
            } else if (ev.kind == KEY_DOWN) {
                b->scroll_y += 1;
            } else if (ev.kind == KEY_PGUP) {
                b->scroll_y -= (doc_rows > 2 ? doc_rows - 2 : 1);
            } else if (ev.kind == KEY_PGDN) {
                b->scroll_y += (doc_rows > 2 ? doc_rows - 2 : 1);
            } else if (ev.kind == KEY_HOME) {
                b->scroll_y = 0;
            } else if (ev.kind == KEY_END) {
                b->scroll_y = b->layout.line_count;
            } else if (ev.kind == KEY_TAB) {
                if (b->layout.hit_count > 0) {
                    b->focused_hit = (b->focused_hit + 1) % b->layout.hit_count;
                    ensure_hit_visible(b, doc_rows);
                }
            } else if (ev.kind == KEY_SHIFT_TAB) {
                if (b->layout.hit_count > 0) {
                    b->focused_hit = (b->focused_hit <= 0)
                                         ? (b->layout.hit_count - 1)
                                         : (b->focused_hit - 1);
                    ensure_hit_visible(b, doc_rows);
                }
            } else if (ev.kind == KEY_ENTER) {
                if (b->focused_hit >= 0 && b->focused_hit < b->layout.hit_count) {
                    tb_browser_activate_hit(b, b->focused_hit);
                }
            } else if (ev.kind == KEY_CTRL_L) {
                prompt_mode = PROMPT_URL;
                snprintf(prompt_buf, sizeof(prompt_buf), "%s", b->current_url);
            } else if (ev.kind == KEY_ESC) {
                search_query[0] = '\0';
            } else if (ev.kind == KEY_CHAR) {
                switch (ev.cp) {
                    case 'q':
                    case 'Q':
                        running = false;
                        break;
                    case 'j':
                        b->scroll_y += 1;
                        break;
                    case 'k':
                        b->scroll_y -= 1;
                        break;
                    case ' ':
                        b->scroll_y += (doc_rows > 2 ? doc_rows - 2 : 1);
                        break;
                    case 'g':
                        prompt_mode = PROMPT_URL;
                        prompt_buf[0] = '\0';
                        break;
                    case '/':
                        prompt_mode = PROMPT_SEARCH;
                        prompt_buf[0] = '\0';
                        break;
                    case 'n':
                        search_jump(b, search_query, 1, doc_rows);
                        break;
                    case 'N':
                        search_jump(b, search_query, -1, doc_rows);
                        break;
                    case 'b':
                    case 'H':
                        tb_browser_back(b);
                        break;
                    case 'F':
                        tb_browser_forward(b);
                        break;
                    case 'r':
                        tb_browser_reload(b);
                        break;
                    case 'c':
                    case '`':
                        console_open = !console_open;
                        break;
                    case ':':
                        console_open = true;
                        prompt_mode = PROMPT_REPL;
                        prompt_buf[0] = '\0';
                        break;
                    case 'G':
                        tb_browser_force_gc(b);
                        break;
                    default:
                        break;
                }
            }
        }

        if (pos < inlen) {
            memmove(inbuf, inbuf + pos, inlen - pos);
            inlen -= pos;
        } else {
            inlen = 0;
        }
    }

    tb_buf_free(&frame);
    tui_restore_tty();
    return 0;
}
