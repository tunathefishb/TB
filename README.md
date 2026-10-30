# TB (TinyBrowser)

> **Status:** Experimental / Work in Progress

**TB** is a freestanding, zero-dependency terminal web browser and ES6+ JavaScript engine written in C11, engineered to run under a strict **< 10 MB `VmRSS`** memory budget.

By default (`FREESTANDING=1 TLS=builtin`), `tb` compiles with `-ffreestanding -nostdlib -static` directly against Linux `x86_64` syscalls—linking zero external libraries (`ldd tb` -> *not a dynamic executable*).

## Highlights

- **Zero External Dependencies:** Custom Linux `x86_64` syscall/runtime layer ([`src/sys.c`](src/sys.c)), custom `mmap` allocator with hard memory caps ([`src/mem.c`](src/mem.c)), IEEE-754 math library ([`src/math_tb.c`](src/math_tb.c)), and PikeVM regular expression engine ([`src/regex_tb.c`](src/regex_tb.c)).
- **Built-in TLS 1.3 & Networking:** Native TLS 1.3 client ([`src/tls.c`](src/tls.c), [`src/tls_crypto.c`](src/tls_crypto.c), [`src/tls_x509.c`](src/tls_x509.c)), UDP/TCP DNS resolver, HTTP/1.1 client, and RFC 1951/1952 `gzip`/`deflate` decompressor ([`src/inflate.c`](src/inflate.c)).
- **HTML5 / CSS / Layout Engine:** Forgiving HTML/DOM parser ([`src/dom.c`](src/dom.c)), CSS cascade & selector engine ([`src/css.c`](src/css.c)), and Unicode/ANSI box-drawing layout renderer ([`src/layout.c`](src/layout.c), [`src/tui.c`](src/tui.c)).
- **ES6+ JavaScript Engine (TinyJS):** Lexer/AST parser ([`src/js_parse.c`](src/js_parse.c)), tree-walking evaluator ([`src/js_eval.c`](src/js_eval.c)), mark-and-sweep garbage collector ([`src/js_gc.c`](src/js_gc.c)), standard library ([`src/js_stdlib.c`](src/js_stdlib.c)), and live DOM bindings ([`src/js_dom.c`](src/js_dom.c)).

## Build & Test

Requires Linux `x86_64` and `gcc` (or `clang`):

```bash
# Build freestanding static binary (default: FREESTANDING=1 TLS=builtin)
make

# Run test suite
make test
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

TB's built-in TLS 1.3 stack ([`src/tls.c`](src/tls.c)), X.509 certificate verifier ([`src/tls_x509.c`](src/tls_x509.c)), and cryptographic primitives ([`src/tls_crypto.c`](src/tls_crypto.c)) are written from scratch for educational and experimental purposes. They have **not** undergone a formal security audit—do not rely on them for high-assurance or production security-critical workloads.

## License

Released under the [MIT License](LICENSE).

