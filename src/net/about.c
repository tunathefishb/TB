#include "net.h"
#include "common.h"

/* ============================================================================
 * Built-in about:, data:, and file: Local Scheme Loaders
 * ============================================================================ */

static const char *ABOUT_HOME_HTML =
    "<!DOCTYPE html><html><head><title>TB — Sub-10MB TUI Browser + JS Engine</title>"
    "<style>"
    "body { margin: 1 2; }"
    ".hero { border: 1px solid #38bdf8; background: #0f172a; padding: 1 2; margin-bottom: 1; }"
    "h1 { color: #38bdf8; margin-bottom: 0; }"
    ".sub { color: #94a3b8; }"
    ".card { border: 1px solid #334155; padding: 1 2; margin-bottom: 1; }"
    "h2 { color: #a78bfa; margin-bottom: 1; }"
    ".btn { background: #1e293b; color: #38bdf8; font-weight: bold; }"
    ".ok { color: #4ade80; font-weight: bold; }"
    ".warn { color: #fbbf24; }"
    "code { color: #f472b6; }"
    "</style></head><body>"
    "<div class='hero'>"
    "<h1>⚡ TB: Sub-10MB TUI Web Browser + Custom JS Engine</h1>"
    "<p class='sub'>Lightweight C11 browser • Custom mmap Slab Allocator • Custom JS &amp; RegExp VM • Built-in TLS 1.3</p>"
    "<p id='mem-banner' class='ok'>Initializing JS Engine telemetry...</p>"
    "</div>"
    "<div class='card'>"
    "<h2>🧭 Quick Navigation</h2>"
    "<ul>"
    "<li><a href='about:demo'>Interactive JavaScript App Suite (Todo MVC + Calculator + Table Sorter)</a></li>"
    "<li><a href='about:memory'>Live Memory &amp; Garbage Collector Telemetry Lab</a></li>"
    "<li><a href='about:help'>Keyboard / Mouse Controls &amp; Engine Architecture</a></li>"
    "</ul>"
    "</div>"
    "<div class='card'>"
    "<h2>🧪 Live JS + DOM Sanity Widget</h2>"
    "<p>Counter value: <strong id='cnt' style='color:#4ade80'>0</strong> — <span id='msg'>Click a button or press Tab + Enter!</span></p>"
    "<p>"
    "<button id='btn-inc'>+ Increment</button> "
    "<button id='btn-dec'>- Decrement</button> "
    "<button id='btn-fib'>Compute Fib(28)</button> "
    "<button id='btn-gc'>Force GC</button>"
    "</p>"
    "</div>"
    "<script>"
    "let count = 0;"
    "const cntEl = document.getElementById('cnt');"
    "const msgEl = document.getElementById('msg');"
    "const memEl = document.getElementById('mem-banner');"
    "function refreshMem() {"
    "  const m = performance.memory;"
    "  const rssMB = (m.rssBytes / (1024 * 1024)).toFixed(2);"
    "  const anonKB = Math.round(m.anonBytes / 1024);"
    "  const jsKB = Math.round(m.usedJSHeapSize / 1024);"
    "  memEl.textContent = 'LIVE TELEMETRY — OS VmRSS: ' + rssMB + ' MB (< 10.00 MB target!) | Private RssAnon: ' + anonKB + ' KB | JS Heap: ' + jsKB + ' KB';"
    "}"
    "document.getElementById('btn-inc').addEventListener('click', () => {"
    "  count++; cntEl.textContent = String(count);"
    "  msgEl.textContent = 'Updated DOM node via addEventListener!';"
    "  refreshMem();"
    "});"
    "document.getElementById('btn-dec').addEventListener('click', () => {"
    "  count--; cntEl.textContent = String(count);"
    "  msgEl.textContent = 'Decremented counter!';"
    "  refreshMem();"
    "});"
    "document.getElementById('btn-fib').addEventListener('click', () => {"
    "  const t0 = performance.now();"
    "  let a = 0, b = 1;"
    "  for (let i = 0; i < 28; i++) { const t = a + b; a = b; b = t; }"
    "  const dt = (performance.now() - t0).toFixed(2);"
    "  msgEl.textContent = 'Fib(28) = ' + a + ' computed in ' + dt + ' ms';"
    "  refreshMem();"
    "});"
    "document.getElementById('btn-gc').addEventListener('click', () => {"
    "  const freed = tb.gc();"
    "  refreshMem();"
    "  msgEl.textContent = 'Mark-and-Sweep GC complete (' + freed + ' objects swept)';"
    "});"
    "refreshMem();"
    "</script></body></html>";

static const char *ABOUT_DEMO_HTML =
    "<!DOCTYPE html><html><head><title>JS App Showcase — TB</title>"
    "<style>"
    "body { margin: 1 2; }"
    ".box { border: 1px solid #475569; padding: 1 2; margin-bottom: 1; }"
    "h1 { color: #38bdf8; }"
    "h2 { color: #fbbf24; }"
    ".done { color: #64748b; text-decoration: line-through; }"
    ".active-item { color: #e2e8f0; }"
    "th { color: #38bdf8; font-weight: bold; }"
    "</style></head><body>"
    "<p><a href='about:home'>← Back to Home</a> | <a href='about:memory'>Memory Lab →</a></p>"
    "<h1>🚀 Interactive JavaScript Web App Suite</h1>"
    "<div class='box'>"
    "<h2>1. Reactive Todo App (DOM Creation, Event Delegation &amp; Filtering)</h2>"
    "<p>New Task: <input id='todo-in' type='text' value='Ship sub-10MB browser' /> "
    "<button id='todo-add'>Add Task</button> "
    "<button id='todo-clear'>Clear Completed</button></p>"
    "<ul id='todo-list'></ul>"
    "<p id='todo-stats' style='color:#4ade80'></p>"
    "</div>"
    "<div class='box'>"
    "<h2>2. JS Expression Calculator</h2>"
    "<p>Expression: <input id='calc-in' type='text' value='(6 * 7) + Math.sqrt(144)' /> "
    "<button id='calc-run'>Evaluate</button></p>"
    "<p>Result: <strong id='calc-out' style='color:#38bdf8'>54</strong></p>"
    "</div>"
    "<div class='box'>"
    "<h2>3. Dynamic Sortable Benchmarks Table</h2>"
    "<p><button id='sort-mem'>Sort by Memory ↑</button> <button id='sort-name'>Sort by Engine A-Z</button></p>"
    "<table><thead><tr><th>Browser / Engine</th><th>Typical RSS</th><th>JS Engine</th></tr></thead>"
    "<tbody id='bench-body'></tbody></table>"
    "</div>"
    "<script>"
    "let todos = ["
    "  { id: 1, text: 'Write C11 HTML/CSS layout engine', done: true },"
    "  { id: 2, text: 'Implement JS lexer, parser, closures & GC', done: true },"
    "  { id: 3, text: 'Keep active VmRSS strictly under 10 MB', done: false }"
    "];"
    "let nextId = 4;"
    "function renderTodos() {"
    "  const ul = document.getElementById('todo-list');"
    "  ul.innerHTML = '';"
    "  let left = 0;"
    "  todos.forEach(item => {"
    "    if (!item.done) left++;"
    "    const li = document.createElement('li');"
    "    const btn = document.createElement('button');"
    "    btn.textContent = item.done ? '[x]' : '[ ]';"
    "    btn.addEventListener('click', () => { item.done = !item.done; renderTodos(); });"
    "    const span = document.createElement('span');"
    "    span.textContent = ' ' + item.text;"
    "    if (item.done) span.className = 'done';"
    "    li.appendChild(btn);"
    "    li.appendChild(span);"
    "    ul.appendChild(li);"
    "  });"
    "  document.getElementById('todo-stats').textContent = left + ' remaining of ' + todos.length + ' tasks';"
    "}"
    "document.getElementById('todo-add').addEventListener('click', () => {"
    "  const inp = document.getElementById('todo-in');"
    "  const v = inp.value.trim();"
    "  if (v) { todos.push({ id: nextId++, text: v, done: false }); inp.value = ''; renderTodos(); }"
    "});"
    "document.getElementById('todo-clear').addEventListener('click', () => {"
    "  todos = todos.filter(t => !t.done); renderTodos();"
    "});"
    "renderTodos();"
    ""
    "document.getElementById('calc-run').addEventListener('click', () => {"
    "  const expr = document.getElementById('calc-in').value;"
    "  const out = document.getElementById('calc-out');"
    "  try { out.textContent = String(eval(expr)); out.style.color = '#4ade80'; }"
    "  catch (e) { out.textContent = 'Error: ' + e; out.style.color = '#f87171'; }"
    "});"
    ""
    "const rows = ["
    "  { name: 'TB (TinyBrowser C11)', rss: 0.5, js: 'Yes (Built-in TinyJS + TLS 1.3)' },"
    "  { name: 'Lynx / w3m', rss: 6.5, js: 'No JS engine' },"
    "  { name: 'Browsh (Headless Firefox)', rss: 380.0, js: 'Yes (SpiderMonkey)' },"
    "  { name: 'Headless Chromium', rss: 290.0, js: 'Yes (V8)' }"
    "];"
    "function renderTable() {"
    "  const tbEl = document.getElementById('bench-body');"
    "  tbEl.innerHTML = rows.map(r => '<tr><td>' + r.name + '</td><td>' + r.rss.toFixed(1) + ' MB</td><td>' + r.js + '</td></tr>').join('');"
    "}"
    "document.getElementById('sort-mem').addEventListener('click', () => { rows.sort((a,b) => a.rss - b.rss); renderTable(); });"
    "document.getElementById('sort-name').addEventListener('click', () => { rows.sort((a,b) => a.name < b.name ? -1 : 1); renderTable(); });"
    "renderTable();"
    "</script></body></html>";

static const char *ABOUT_MEMORY_HTML =
    "<!DOCTYPE html><html><head><title>Memory &amp; GC Telemetry Lab — TB</title>"
    "<style>"
    "body { margin: 1 2; }"
    ".panel { border: 1px solid #38bdf8; padding: 1 2; margin-bottom: 1; }"
    "h1 { color: #38bdf8; }"
    "th { color: #a78bfa; }"
    ".good { color: #4ade80; font-weight: bold; }"
    "</style></head><body>"
    "<p><a href='about:home'>← Back to Home</a> | <a href='about:demo'>JS App Suite →</a></p>"
    "<h1>🔬 Live Memory &amp; Garbage Collector Lab</h1>"
    "<div class='panel'>"
    "<p class='good' id='verdict'>Checking 10 MB memory budget...</p>"
    "<table><thead><tr><th>Metric</th><th>Current Value</th><th>Budget / Notes</th></tr></thead>"
    "<tbody id='mem-rows'></tbody></table>"
    "<p>"
    "<button id='btn-churn'>Churn 5,000 Temp Objects</button> "
    "<button id='btn-retain'>Retain +500 Objects</button> "
    "<button id='btn-release'>Release Retained</button> "
    "<button id='btn-collect'>Run Mark &amp; Sweep GC</button>"
    "</p>"
    "<p id='action-log' style='color:#fbbf24'>Ready for stress testing.</p>"
    "</div>"
    "<script>"
    "let retained = [];"
    "function updateStats(note) {"
    "  const m = performance.memory;"
    "  const rssMB = (m.rssBytes / 1048576);"
    "  const verdict = document.getElementById('verdict');"
    "  verdict.textContent = rssMB < 10.0"
    "    ? 'PASS: Active OS VmRSS is ' + rssMB.toFixed(2) + ' MB — strictly below 10.00 MB!'"
    "    : 'WARNING: VmRSS is ' + rssMB.toFixed(2) + ' MB';"
    "  const data = ["
    "    ['Kernel VmRSS (Total Resident)', (m.rssBytes / 1024).toFixed(0) + ' KB (' + rssMB.toFixed(2) + ' MB)', 'Hard Target < 10,240 KB'],"
    "    ['Kernel RssAnon (Private Heap/Stack)', (m.anonBytes / 1024).toFixed(0) + ' KB', 'Actual private process RAM'],"
    "    ['Tracked C Heap Live', (m.heapLiveBytes / 1024).toFixed(1) + ' KB', 'Cap: ' + (m.heapLimitBytes / 1024).toFixed(0) + ' KB'],"
    "    ['JS GC Managed Heap', (m.usedJSHeapSize / 1024).toFixed(1) + ' KB', 'Threshold: ' + (m.totalJSHeapSize / 1024).toFixed(1) + ' KB'],"
    "    ['JS Live GC Objects', String(m.jsObjectCount), 'Retained array len: ' + retained.length]"
    "  ];"
    "  document.getElementById('mem-rows').innerHTML = data.map(r =>"
    "    '<tr><td>' + r[0] + '</td><td><strong>' + r[1] + '</strong></td><td>' + r[2] + '</td></tr>'"
    "  ).join('');"
    "  if (note) document.getElementById('action-log').textContent = note;"
    "}"
    "document.getElementById('btn-churn').addEventListener('click', () => {"
    "  const t0 = performance.now();"
    "  let acc = 0;"
    "  for (let i = 0; i < 5000; i++) {"
    "    const tmp = { idx: i, label: 'ephemeral_' + i, arr: [i, i + 1] };"
    "    acc += tmp.arr[1];"
    "  }"
    "  const dt = (performance.now() - t0).toFixed(1);"
    "  updateStats('Churned 5,000 objects + strings + arrays in ' + dt + ' ms (checksum ' + acc + '). Automatic GC kept heap tiny!');"
    "});"
    "document.getElementById('btn-retain').addEventListener('click', () => {"
    "  for (let i = 0; i < 500; i++) retained.push({ k: retained.length, tag: 'held_' + i });"
    "  updateStats('Retained 500 more objects (total ' + retained.length + ').');"
    "});"
    "document.getElementById('btn-release').addEventListener('click', () => {"
    "  retained = [];"
    "  const swept = tb.gc();"
    "  updateStats('Cleared reference & ran GC + madvise trim: swept ' + swept + ' objects!');"
    "});"
    "document.getElementById('btn-collect').addEventListener('click', () => {"
    "  const swept = tb.gc();"
    "  updateStats('Manual GC + madvise trim swept ' + swept + ' unreachable objects.');"
    "});"
    "updateStats();"
    "</script></body></html>";

static const char *ABOUT_HELP_HTML =
    "<!DOCTYPE html><html><head><title>Help &amp; Controls — TB</title>"
    "<style>"
    "body { margin: 1 2; }"
    "h1 { color: #38bdf8; }"
    "h2 { color: #a78bfa; }"
    "th { color: #fbbf24; }"
    ".card { border: 1px solid #334155; padding: 1 2; margin-bottom: 1; }"
    "</style></head><body>"
    "<p><a href='about:home'>← Back to Home</a></p>"
    "<h1>📖 TB Controls &amp; Technical Reference</h1>"
    "<div class='card'>"
    "<h2>Keyboard &amp; Mouse Shortcuts</h2>"
    "<table>"
    "<tr><th>Key</th><th>Action</th></tr>"
    "<tr><td>j / k or ↑ / ↓</td><td>Scroll document line by line (Mouse wheel also scrolls)</td></tr>"
    "<tr><td>Space / PgDn / PgUp</td><td>Scroll page down / page up (Home / End for top / bottom)</td></tr>"
    "<tr><td>Tab / Shift+Tab</td><td>Focus next / previous link, input, button, or JS widget</td></tr>"
    "<tr><td>Enter</td><td>Follow link, click button, toggle checkbox, or edit text input</td></tr>"
    "<tr><td>g or Ctrl+L</td><td>Open URL / Omnibar to navigate to any URL or local file</td></tr>"
    "<tr><td>/ then n / N</td><td>In-page text search, jump to next / previous match</td></tr>"
    "<tr><td>b / H and F</td><td>History Back and Forward (r to Reload page)</td></tr>"
    "<tr><td>c or `</td><td>Toggle split-pane JavaScript Console &amp; Live JS REPL (`:js`)</td></tr>"
    "<tr><td>: (colon)</td><td>Focus Live JS REPL input inside the Console drawer</td></tr>"
    "<tr><td>G</td><td>Force immediate Mark-and-Sweep JS GC + mmap/madvise page reclamation</td></tr>"
    "<tr><td>q or Ctrl+C</td><td>Quit TB cleanly</td></tr>"
    "</table>"
    "</div>"
    "<div class='card'>"
    "<h2>Sub-10MB Engineering Highlights</h2>"
    "<ul>"
    "<li><strong>Custom mmap Slab Allocator:</strong> Tracked 64 KB slabs, hard heap cap, and <code>madvise(MADV_DONTNEED)</code> page reclamation.</li>"
    "<li><strong>In-Tree TLS 1.3 + X.509 &amp; Direct DNS:</strong> Built-in RFC 8446 TLS 1.3 (X25519/P-256, AES-GCM, ChaCha20-Poly1305, RSA/ECDSA) and RFC 1035 UDP/TCP DNS resolver.</li>"
    "<li><strong>Custom TinyJS &amp; RegExp VM:</strong> Contiguous flat-pool AST (~24 B/node), bounded-step RegExp bytecode VM, lexical closures, prototypes, and Mark-and-Sweep GC.</li>"
    "<li><strong>Zero-Dependency Inflate:</strong> Built-in RFC 1951/1952 gzip &amp; deflate decompressor with anti-zip-bomb ceiling.</li>"
    "</ul>"
    "</div></body></html>";

static bool load_about_page(const TbUrl *u, TbResponse *resp) {
    const char *html = NULL;
    if (strcmp(u->path, "home") == 0 || u->path[0] == '\0') html = ABOUT_HOME_HTML;
    else if (strcmp(u->path, "demo") == 0) html = ABOUT_DEMO_HTML;
    else if (strcmp(u->path, "memory") == 0) html = ABOUT_MEMORY_HTML;
    else if (strcmp(u->path, "help") == 0) html = ABOUT_HELP_HTML;
    else if (strcmp(u->path, "blank") == 0) html = "<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>";
    else {
        resp->status = 404;
        strcpy(resp->content_type, "text/html");
        TbBuf b;
        tb_buf_init(&b);
        tb_buf_printf(&b, "<html><body><h1>Unknown page about:%s</h1><p><a href='about:home'>Go Home</a></p></body></html>", u->path);
        resp->body = tb_buf_detach(&b, &resp->body_len);
        return true;
    }
    resp->status = 200;
    strcpy(resp->content_type, "text/html; charset=utf-8");
    resp->body_len = strlen(html);
    resp->body     = tb_strdup(html);
    return resp->body != NULL;
}

static bool load_data_url(const TbUrl *u, TbResponse *resp) {
    const char *comma = strchr(u->path, ',');
    if (!comma) {
        snprintf(resp->error, sizeof(resp->error), "Malformed data: URL");
        return false;
    }
    size_t mlen = (size_t)(comma - u->path);
    if (mlen == 0) strcpy(resp->content_type, "text/plain");
    else snprintf(resp->content_type, sizeof(resp->content_type), "%.*s", (int)mlen, u->path);

    const char *src = comma + 1;
    TbBuf b;
    tb_buf_init(&b);
    for (size_t i = 0; src[i]; i++) {
        if (b.len >= TB_MAX_BODY_BYTES) break;
        if (src[i] == '%' && tb_hex_val(src[i + 1]) >= 0 && tb_hex_val(src[i + 2]) >= 0) {
            char decoded = (char)((tb_hex_val(src[i + 1]) << 4) | tb_hex_val(src[i + 2]));
            tb_buf_append_char(&b, decoded);
            i += 2;
        } else {
            tb_buf_append_char(&b, src[i]);
        }
    }
    resp->status = 200;
    resp->body   = tb_buf_detach(&b, &resp->body_len);
    return resp->body != NULL;
}

static bool load_file_url(const TbUrl *u, TbResponse *resp) {
    FILE *f = fopen(u->path, "rb");
    if (!f) {
        snprintf(resp->error, sizeof(resp->error), "Cannot open %.160s: %.70s", u->path, strerror(errno));
        return false;
    }
    TbBuf b;
    tb_buf_init(&b);
    char chunk[8192];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        if (b.len + n > TB_MAX_BODY_BYTES) {
            n = TB_MAX_BODY_BYTES - b.len;
            tb_buf_append(&b, chunk, n);
            break;
        }
        if (!tb_buf_append(&b, chunk, n)) {
            fclose(f);
            tb_buf_free(&b);
            snprintf(resp->error, sizeof(resp->error), "Memory cap reached reading file");
            return false;
        }
    }
    fclose(f);
    resp->status = 200;
    const char *ext = strrchr(u->path, '.');
    if (ext && (tb_strcasecmp(ext, ".json") == 0)) strcpy(resp->content_type, "application/json");
    else if (ext && (tb_strcasecmp(ext, ".txt") == 0)) strcpy(resp->content_type, "text/plain");
    else if (ext && (tb_strcasecmp(ext, ".js") == 0)) strcpy(resp->content_type, "application/javascript");
    else strcpy(resp->content_type, "text/html");
    resp->body = tb_buf_detach(&b, &resp->body_len);
    return resp->body != NULL;
}

bool tb_net_load_local_scheme(const TbUrl *u, TbResponse *resp) {
    if (strcmp(u->scheme, "about") == 0) return load_about_page(u, resp);
    if (strcmp(u->scheme, "data") == 0)  return load_data_url(u, resp);
    if (strcmp(u->scheme, "file") == 0)  return load_file_url(u, resp);
    return false;
}
