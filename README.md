# TB (TinyBrowser)

> **Status:** Experimental / Work in Progress

**TB** is a freestanding, zero-dependency terminal web browser and ES6+ JavaScript engine written in C11, engineered to run under a strict **< 10 MB `VmRSS`** memory budget.

By default (`FREESTANDING=1 TLS=builtin`), `tb` compiles with `-ffreestanding -nostdlib -static` directly against Linux `x86_64` syscalls—linking zero external libraries (`ldd tb` -> *not a dynamic executable*).

## Architecture & Module Layout

- **`src/core/` — Freestanding Runtime & Core Primitives:**
  - [`src/core/common.h`](src/core/common.h): Shared byte-order helpers, hex/IPv4/IPv6 parsers, dynamic byte buffers (`TbBuf`), UTF-8 codec, and FNV-1a hashing.
  - [`src/core/sys_syscall.c`](src/core/sys_syscall.c), [`src/core/sys_stdio.c`](src/core/sys_stdio.c), [`src/core/sys_stdlib.c`](src/core/sys_stdlib.c): Custom Linux `x86_64` `_start` entry point, raw syscalls, formatted I/O, and freestanding C standard library (`strtod`, `qsort`, string/memory routines).
  - [`src/core/mem.c`](src/core/mem.c): Custom `mmap` page-bucketed allocator with hard memory caps, arena allocator (`TbArena`), and `/proc/self/status` telemetry.
  - [`src/core/math_tb.c`](src/core/math_tb.c): Freestanding IEEE-754 double-precision math library.
  - [`src/core/regex_tb.c`](src/core/regex_tb.c): Non-backtracking NFA/PikeVM regular expression engine.
  - [`src/core/inflate.c`](src/core/inflate.c): Zero-dependency RFC 1951/1952 `deflate`/`gzip` decompressor.
- **`src/net/` — Networking & Protocol Stack:**
  - [`src/net/url.c`](src/net/url.c): URL parser, relative URL resolver, and user input normalizer.
  - [`src/net/about.c`](src/net/about.c): Built-in `about:home`, `about:demo`, `about:memory`, and `about:help` pages and `file://` loader.
  - [`src/net/dns.c`](src/net/dns.c): Custom UDP/TCP DNS stub resolver (`/etc/hosts` + `/etc/resolv.conf`).
  - [`src/net/http.c`](src/net/http.c): HTTP/1.1 client with redirect handling, chunked transfer encoding, and transparent decompression.
- **`src/tls/` — Built-in TLS 1.3 & X.509 Stack:**
  - [`src/tls/tls_sym.c`](src/tls/tls_sym.c): SHA-256, SHA-384, SHA-512, HMAC, HKDF (RFC 5869), ChaCha20-Poly1305 (RFC 8439), and AES-GCM.
  - [`src/tls/tls_asym.c`](src/tls/tls_asym.c): X25519 key exchange (RFC 7748), P-256 ECDHE/ECDSA, and RSA PKCS#1 v1.5 / PSS verification.
  - [`src/tls/tls_x509.c`](src/tls/tls_x509.c): ASN.1 DER parser, hostname/SAN verifier, and system CA bundle trust-chain validator.
  - [`src/tls/tls_conn.c`](src/tls/tls_conn.c): TLS 1.3 client state machine and record layer.
- **`src/engine/` — HTML5 DOM, CSS Cascade & Terminal Layout:**
  - [`src/engine/dom.c`](src/engine/dom.c): Forgiving HTML5 tokenizer/tree builder and CSS selector query engine.
  - [`src/engine/css.c`](src/engine/css.c): CSS stylesheet parser, specificity cascade, and box-model style computation.
  - [`src/engine/layout.c`](src/engine/layout.c): Unicode/ANSI box-drawing layout engine, table auto-sizer, and interactive hit-testing.
- **`src/js/` — ES6+ JavaScript Engine (TinyJS):**
  - [`src/js/js_parse.c`](src/js/js_parse.c): Lexer and recursive-descent ES6+ AST parser.
  - [`src/js/js_eval.c`](src/js/js_eval.c): Tree-walking evaluator, lexical closures, prototypes, and microtask/timer queues.
  - [`src/js/js_gc.c`](src/js/js_gc.c): Mark-and-sweep garbage collector.
  - [`src/js/js_stdlib.c`](src/js/js_stdlib.c) & [`src/js/js_json.c`](src/js/js_json.c): Built-in `Object`, `Array`, `String`, `Number`, `Math`, `Date`, `RegExp`, and `JSON` intrinsics.
  - [`src/js/js_dom.c`](src/js/js_dom.c): Live DOM, `Event`, `Promise`, `fetch`, `localStorage`, and `window`/`document` bindings.
- **`src/ui/` — Browser Controller, TUI & CLI:**
  - [`src/ui/browser.c`](src/ui/browser.c): Navigation controller, history ring, form submission, and script lifecycle.
  - [`src/ui/tui.c`](src/ui/tui.c): Interactive terminal UI with live `VmRSS` gauge, mouse tracking, and split-pane JS REPL drawer.
  - [`src/ui/main.c`](src/ui/main.c): CLI argument parser, headless `--dump` renderer, and entry point.
- **`tests/` — Verification & Memory Stress Suite:**
  - [`tests/test_harness.h`](tests/test_harness.h) & [`tests/test_main.c`](tests/test_main.c): Shared assertion macros, compression fixtures, and CLI test runner.
  - [`tests/test_core.c`](tests/test_core.c), [`tests/test_engine.c`](tests/test_engine.c), [`tests/test_js.c`](tests/test_js.c), [`tests/test_net.c`](tests/test_net.c), [`tests/test_tls.c`](tests/test_tls.c): Per-subsystem unit, loopback integration, GC stress, and `< 10 MB VmRSS` / `< 1 MB` freestanding post-HTTPS memory tests.

## Build & Test

Requires Linux `x86_64` and `gcc` (or `clang`):

```bash
# Build freestanding static binary (default: FREESTANDING=1 TLS=builtin)
make

# Run full test suite (or filter by group/suite: core, engine, js, net, tls)
make test
make test FILTER=js
```

For portable libc builds on non-`x86_64` hosts or with dynamic OpenSSL fallback:

```bash
make FREESTANDING=0 TLS=builtin
# or
make FREESTANDING=0 TLS=openssl
```

## Usage

```bash
# Launch interactive TUI browser (defaults to about:home)
./tb

# Open a live URL or local HTML file
./tb https://example.com
./tb demos/index.html

# Headless render to stdout with 24-bit ANSI color and memory telemetry
./tb --dump --color --mem demos/index.html

# Evaluate JavaScript against a page
./tb --dump -e "document.title" demos/index.html
```

Built-in pages: `about:home`, `about:demo`, `about:memory`, `about:help`.

## Security & Experimental Disclaimer

TB's built-in TLS 1.3 stack ([`src/tls/tls_conn.c`](src/tls/tls_conn.c)), X.509 certificate verifier ([`src/tls/tls_x509.c`](src/tls/tls_x509.c)), and cryptographic primitives ([`src/tls/tls_sym.c`](src/tls/tls_sym.c), [`src/tls/tls_asym.c`](src/tls/tls_asym.c)) are written from scratch for educational and experimental purposes. They have **not** undergone a formal security audit—do not rely on them for high-assurance or production security-critical workloads.

## License

Released under the [MIT License](LICENSE).
