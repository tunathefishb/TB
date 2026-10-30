#include "browser.h"
#include "common.h"
#include "js.h"
#include "layout.h"
#include "mem.h"
#include "tui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_help(const char *prog) {
    printf(
        "TB (TinyBrowser) — Sub-10 MB TUI Web Browser & ES6+ JavaScript Engine\n"
        "\n"
        "Usage:\n"
        "  %s [options] [url-or-file]\n"
        "\n"
        "Options:\n"
        "  --dump               Headless load, execute JS, render page to stdout, and exit\n"
        "  --color              Enable 24-bit ANSI colors in --dump output\n"
        "  -w, --width <cols>   Set viewport width for --dump / initial layout (default: 92)\n"
        "  -e, --eval <js>      Evaluate JavaScript after page load and print result\n"
        "  --mem                Print live /proc/self/status VmRSS & GC memory telemetry\n"
        "  -k, --insecure       Skip TLS certificate verification for self-signed HTTPS\n"
        "  --max-mem-mb <mb>    Override C heap hard cap in MB (default: 7.5 MB)\n"
        "  -h, --help           Show this help message\n"
        "\n"
        "Built-in Interactive Pages:\n"
        "  about:home           Dashboard, JS counter/benchmark, and live memory telemetry\n"
        "  about:demo           Interactive JS Todo app, expression calculator, sortable table\n"
        "  about:memory         Mark-and-Sweep GC stress lab & kernel VmRSS inspector\n"
        "  about:help           Keyboard & mouse reference\n",
        prog);
}

static void print_mem_report(const TbBrowser *b) {
    TbMemStats ms;
    tb_mem_stats(&ms);
    double rss_mb  = (double)ms.vm_rss_kb / 1024.0;
    double anon_mb = (double)ms.rss_anon_kb / 1024.0;
    double hwm_mb  = (double)ms.vm_hwm_kb / 1024.0;
    size_t js_used = b->vm ? b->vm->gc_bytes : 0;
    size_t js_thr  = b->vm ? b->vm->gc_threshold : 0;
    uint32_t js_n  = b->vm ? b->vm->gc_obj_count : 0;
    uint32_t dom_n = b->doc ? b->doc->node_count : 0;

    printf("\n"
           "┌── TB Kernel & Engine Memory Telemetry (/proc/self/status) ──────────┐\n"
           "│ Kernel VmRSS (Active Resident) : %6zu KB (%5.2f MB)  [< 10.00 MB] │\n"
           "│ Kernel RssAnon (Private RAM)   : %6zu KB (%5.2f MB)               │\n"
           "│ Kernel RssFile (Shared Libs)   : %6zu KB                          │\n"
           "│ Kernel VmHWM (Peak Resident)   : %6zu KB (%5.2f MB)               │\n"
           "│ Tracked C Heap (Live / Limit)  : %6.1f KB / %6.1f KB (Peak %5.1fK)│\n"
           "│ TinyJS GC Heap (Live / Thresh) : %6.1f KB / %6.1f KB (%5u objs) │\n"
           "│ Active DOM Nodes / Layout Lines: %6u nodes / %5d lines         │\n"
           "│ Budget Verdict                 : %-34s │\n"
           "└─────────────────────────────────────────────────────────────────────┘\n",
           ms.vm_rss_kb, rss_mb,
           ms.rss_anon_kb, anon_mb,
           ms.rss_file_kb,
           ms.vm_hwm_kb, hwm_mb,
           (double)ms.heap_live / 1024.0,
           (double)ms.heap_limit / 1024.0,
           (double)ms.heap_peak / 1024.0,
           (double)js_used / 1024.0,
           (double)js_thr / 1024.0,
           js_n,
           dom_n, b->layout.line_count,
           (ms.vm_rss_kb < 10240) ? "PASS (Strictly < 10 MB VmRSS)"
                                  : ((ms.vm_rss_kb < 51200) ? "PASS (< 50 MB, > 10 MB)"
                                                            : "EXCEEDED 50 MB"));
}

int main(int argc, char **argv) {
    bool        dump_mode    = false;
    bool        use_color    = false;
    bool        show_mem     = false;
    bool        insecure_tls = false;
    int         width        = 92;
    size_t      heap_limit   = TB_DEFAULT_HEAP_LIMIT;
    const char *eval_code    = NULL;
    const char *target_url   = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(a, "--dump") == 0) {
            dump_mode = true;
        } else if (strcmp(a, "--color") == 0) {
            use_color = true;
        } else if (strcmp(a, "--no-color") == 0) {
            use_color = false;
        } else if (strcmp(a, "--mem") == 0) {
            show_mem = true;
        } else if (strcmp(a, "-k") == 0 || strcmp(a, "--insecure") == 0) {
            insecure_tls = true;
        } else if ((strcmp(a, "-w") == 0 || strcmp(a, "--width") == 0) && i + 1 < argc) {
            width = atoi(argv[++i]);
            if (width < 32) width = 32;
            if (width > 300) width = 300;
        } else if ((strcmp(a, "-e") == 0 || strcmp(a, "--eval") == 0) && i + 1 < argc) {
            eval_code = argv[++i];
        } else if (strcmp(a, "--max-mem-mb") == 0 && i + 1 < argc) {
            double mb = atof(argv[++i]);
            if (mb >= 1.0 && mb <= 512.0) {
                heap_limit = (size_t)(mb * 1024.0 * 1024.0);
            }
        } else if (a[0] == '-') {
            fprintf(stderr, "tb: unknown option '%s' (try --help)\n", a);
            return 2;
        } else {
            target_url = a;
        }
    }

    tb_mem_init(heap_limit);

    if (!target_url) {
        target_url = (eval_code && !dump_mode) ? "about:blank" : "about:home";
    }

    if (!eval_code && !dump_mode && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
        dump_mode = true;
    }

    TbBrowser browser;
    tb_browser_init(&browser, width, 30, insecure_tls);
    tb_browser_navigate(&browser, target_url, true);

    int exit_code = 0;

    if (eval_code) {
        JsVal res = js_undefined();
        bool ok = browser.vm && js_eval(browser.vm, eval_code, strlen(eval_code), &res);
        tb_browser_tick(&browser);
        if (!ok) {
            fprintf(stderr, "Uncaught JS Error: %s\n",
                    browser.vm ? browser.vm->last_error : "VM unavailable");
            exit_code = 1;
        } else if (!dump_mode) {
            TbBuf out;
            tb_buf_init(&out);
            js_val_format(browser.vm, res, &out, 0);
            printf("%s\n", out.data ? out.data : "undefined");
            tb_buf_free(&out);
        }
    }

    if (dump_mode) {
        tb_browser_relayout_if_needed(&browser, false);
        TbBuf rendered;
        tb_buf_init(&rendered);
        layout_render_document(&browser.layout, use_color, &rendered);
        if (rendered.data && rendered.len > 0) {
            fwrite(rendered.data, 1, rendered.len, stdout);
        }
        tb_buf_free(&rendered);
    } else if (!eval_code) {
        exit_code = tb_tui_run(&browser);
    }

    if (show_mem) {
        print_mem_report(&browser);
    }

    tb_browser_free(&browser);
    return exit_code;
}
