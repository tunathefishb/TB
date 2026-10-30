#include "js.h"

#include <ctype.h>
#include <stdlib.h>

typedef enum {
    TOK_EOF = 0,
    TOK_NUM,
    TOK_STR,
    TOK_REGEX,
    TOK_BACKTICK,
    TOK_IDENT,
    /* Keywords */
    TOK_VAR, TOK_LET, TOK_CONST, TOK_FUNCTION, TOK_RETURN,
    TOK_IF, TOK_ELSE, TOK_WHILE, TOK_DO, TOK_FOR, TOK_IN, TOK_OF,
    TOK_SWITCH, TOK_CASE, TOK_DEFAULT, TOK_BREAK, TOK_CONTINUE,
    TOK_TRY, TOK_CATCH, TOK_FINALLY, TOK_THROW,
    TOK_NEW, TOK_THIS, TOK_TYPEOF, TOK_VOID, TOK_DELETE, TOK_INSTANCEOF,
    TOK_TRUE, TOK_FALSE, TOK_NULL, TOK_UNDEFINED,
    /* Punctuation & Operators */
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACK, TOK_RBRACK, TOK_LBRACE, TOK_RBRACE,
    TOK_SEMI, TOK_COMMA, TOK_DOT, TOK_OPT_CHAIN, TOK_SPREAD,
    TOK_COLON, TOK_QUESTION, TOK_ARROW,
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_POW, TOK_SLASH, TOK_PERCENT,
    TOK_INC, TOK_DEC,
    TOK_AMP, TOK_PIPE, TOK_CARET, TOK_TILDE,
    TOK_SHL, TOK_SHR, TOK_USHR,
    TOK_AND, TOK_OR, TOK_NULLISH, TOK_BANG,
    TOK_LT, TOK_LE, TOK_GT, TOK_GE,
    TOK_EQ, TOK_NE, TOK_STRICT_EQ, TOK_STRICT_NE,
    TOK_ASSIGN,
    TOK_ADD_ASSIGN, TOK_SUB_ASSIGN, TOK_MUL_ASSIGN, TOK_DIV_ASSIGN, TOK_MOD_ASSIGN,
    TOK_AND_ASSIGN, TOK_OR_ASSIGN, TOK_XOR_ASSIGN,
    TOK_SHL_ASSIGN, TOK_SHR_ASSIGN, TOK_USHR_ASSIGN,
    TOK_LAND_ASSIGN, TOK_LOR_ASSIGN, TOK_NULLISH_ASSIGN
} TokKind;

typedef struct {
    TokKind  kind;
    bool     had_newline;
    double   num;
    uint32_t str_id;
    uint32_t str_id2; /* regex flags */
    int      line;
} Token;

typedef struct {
    const char *src;
    size_t      len;
    size_t      pos;
    int         line;
    bool        prev_can_end_expr;
} Lexer;

typedef struct {
    JsVm    *vm;
    JsChunk *chunk;
    Lexer    lx;
    Token    cur;
    bool     has_err;
    char     err[256];
} Parser;

static void set_parse_err(Parser *p, const char *msg) {
    if (!p->has_err) {
        p->has_err = true;
        snprintf(p->err, sizeof(p->err), "SyntaxError (line %d): %s", p->cur.line, msg);
    }
}

static uint32_t chunk_intern_str(Parser *p, const char *s, size_t len) {
    JsChunk *c = p->chunk;
    for (uint32_t i = 0; i < c->str_count; i++) {
        if (c->str_lens[i] == len && memcmp(c->strs[i], s, len) == 0) return i;
    }
    if (c->str_count >= c->str_cap) {
        uint32_t ncap = c->str_cap ? c->str_cap * 2 : 32;
        char **ns = (char **)tb_realloc(c->strs, ncap * sizeof(char *));
        uint32_t *nl = (uint32_t *)tb_realloc(c->str_lens, ncap * sizeof(uint32_t));
        if (!ns || !nl) {
            if (ns) c->strs = ns;
            if (nl) c->str_lens = nl;
            set_parse_err(p, "Out of memory interning string");
            return 0;
        }
        c->strs     = ns;
        c->str_lens = nl;
        c->str_cap  = ncap;
    }
    char *copy = (char *)tb_malloc(len + 1);
    if (!copy) {
        set_parse_err(p, "Out of memory copying string");
        return 0;
    }
    memcpy(copy, s, len);
    copy[len] = '\0';
    uint32_t id = c->str_count++;
    c->strs[id]     = copy;
    c->str_lens[id] = (uint32_t)len;
    p->vm->gc_bytes += len + 1 + sizeof(char *) + sizeof(uint32_t);
    return id;
}

static uint32_t chunk_add_num(Parser *p, double num) {
    JsChunk *c = p->chunk;
    if (c->num_count >= c->num_cap) {
        uint32_t ncap = c->num_cap ? c->num_cap * 2 : 32;
        double *nn = (double *)tb_realloc(c->nums, ncap * sizeof(double));
        if (!nn) {
            set_parse_err(p, "Out of memory storing number");
            return 0;
        }
        c->nums    = nn;
        c->num_cap = ncap;
        p->vm->gc_bytes += (ncap - c->num_count) * sizeof(double);
    }
    uint32_t id = c->num_count++;
    c->nums[id] = num;
    return id;
}

static uint32_t emit_node(Parser *p, AstKind kind, AstOp op, uint16_t flags,
                          uint32_t a, uint32_t b, uint32_t c) {
    JsChunk *ch = p->chunk;
    if (ch->node_count >= ch->node_cap) {
        uint32_t old_cap = ch->node_cap;
        uint32_t ncap    = old_cap ? old_cap * 2 : 128;
        AstNode *nn      = (AstNode *)tb_realloc(ch->nodes, ncap * sizeof(AstNode));
        if (!nn) {
            set_parse_err(p, "Out of memory allocating AST nodes");
            return 0;
        }
        ch->nodes    = nn;
        ch->node_cap = ncap;
        p->vm->gc_bytes += (ncap - old_cap) * sizeof(AstNode);
    }
    uint32_t idx = ch->node_count++;
    AstNode *n   = &ch->nodes[idx];
    n->kind  = (uint8_t)kind;
    n->op    = (uint8_t)op;
    n->flags = flags;
    n->a     = a;
    n->b     = b;
    n->c     = c;
    n->next  = 0;
    return idx;
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool is_ident_start(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           c == '_' || c == '$' || (uint8_t)c >= 0x80;
}

static bool is_ident_part(char c) {
    return is_ident_start(c) || (c >= '0' && c <= '9');
}

static TokKind keyword_lookup(const char *s, size_t len) {
    static const struct { const char *kw; TokKind kind; } kws[] = {
        {"var", TOK_VAR}, {"let", TOK_LET}, {"const", TOK_CONST},
        {"function", TOK_FUNCTION}, {"return", TOK_RETURN},
        {"if", TOK_IF}, {"else", TOK_ELSE}, {"while", TOK_WHILE},
        {"do", TOK_DO}, {"for", TOK_FOR}, {"in", TOK_IN}, {"of", TOK_OF},
        {"switch", TOK_SWITCH}, {"case", TOK_CASE}, {"default", TOK_DEFAULT},
        {"break", TOK_BREAK}, {"continue", TOK_CONTINUE},
        {"try", TOK_TRY}, {"catch", TOK_CATCH}, {"finally", TOK_FINALLY},
        {"throw", TOK_THROW}, {"new", TOK_NEW}, {"this", TOK_THIS},
        {"typeof", TOK_TYPEOF}, {"void", TOK_VOID}, {"delete", TOK_DELETE},
        {"instanceof", TOK_INSTANCEOF}, {"true", TOK_TRUE}, {"false", TOK_FALSE},
        {"null", TOK_NULL}, {"undefined", TOK_UNDEFINED}
    };
    for (size_t i = 0; i < sizeof(kws) / sizeof(kws[0]); i++) {
        if (strlen(kws[i].kw) == len && memcmp(s, kws[i].kw, len) == 0) {
            return kws[i].kind;
        }
    }
    return TOK_IDENT;
}

static bool tok_can_end_expr(TokKind k) {
    switch (k) {
        case TOK_NUM: case TOK_STR: case TOK_REGEX: case TOK_IDENT:
        case TOK_TRUE: case TOK_FALSE: case TOK_NULL: case TOK_UNDEFINED:
        case TOK_THIS: case TOK_RPAREN: case TOK_RBRACK: case TOK_RBRACE:
        case TOK_INC: case TOK_DEC:
            return true;
        default:
            return false;
    }
}

static void decode_js_escape(Lexer *lx, TbBuf *b) {
    if (lx->pos >= lx->len) return;
    char e = lx->src[lx->pos++];
    switch (e) {
        case 'n': tb_buf_append_char(b, '\n'); break;
        case 'r': tb_buf_append_char(b, '\r'); break;
        case 't': tb_buf_append_char(b, '\t'); break;
        case 'b': tb_buf_append_char(b, '\b'); break;
        case 'f': tb_buf_append_char(b, '\f'); break;
        case 'v': tb_buf_append_char(b, '\v'); break;
        case '0': tb_buf_append_char(b, '\0'); break;
        case '\\': case '\'': case '"': case '`': case '$':
            tb_buf_append_char(b, e);
            break;
        case '\n':
            lx->line++;
            break;
        case 'x': {
            if (lx->pos + 2 <= lx->len) {
                int h1 = hex_digit(lx->src[lx->pos]);
                int h2 = hex_digit(lx->src[lx->pos + 1]);
                if (h1 >= 0 && h2 >= 0) {
                    tb_buf_append_char(b, (char)((h1 << 4) | h2));
                    lx->pos += 2;
                    break;
                }
            }
            tb_buf_append_char(b, 'x');
            break;
        }
        case 'u': {
            uint32_t cp = 0;
            bool ok = false;
            if (lx->pos < lx->len && lx->src[lx->pos] == '{') {
                lx->pos++;
                while (lx->pos < lx->len && lx->src[lx->pos] != '}') {
                    int h = hex_digit(lx->src[lx->pos]);
                    if (h < 0) break;
                    cp = (cp << 4) | (uint32_t)h;
                    lx->pos++;
                    ok = true;
                }
                if (lx->pos < lx->len && lx->src[lx->pos] == '}') lx->pos++;
            } else if (lx->pos + 4 <= lx->len) {
                int h0 = hex_digit(lx->src[lx->pos]);
                int h1 = hex_digit(lx->src[lx->pos + 1]);
                int h2 = hex_digit(lx->src[lx->pos + 2]);
                int h3 = hex_digit(lx->src[lx->pos + 3]);
                if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0) {
                    cp = (uint32_t)((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
                    lx->pos += 4;
                    ok = true;
                }
            }
            if (ok) {
                char u8[4];
                size_t n = tb_utf8_encode(cp, u8);
                tb_buf_append(b, u8, n);
            } else {
                tb_buf_append_char(b, 'u');
            }
            break;
        }
        default:
            tb_buf_append_char(b, e);
            break;
    }
}

static void next_token(Parser *p) {
    Lexer *lx = &p->lx;
    bool had_nl = false;

    /* Skip whitespace and comments */
    while (lx->pos < lx->len) {
        char c = lx->src[lx->pos];
        if (c == ' ' || c == '\t' || c == '\f' || c == '\v') {
            lx->pos++;
        } else if (c == '\n') {
            lx->pos++;
            lx->line++;
            had_nl = true;
        } else if (c == '\r') {
            lx->pos++;
            if (lx->pos < lx->len && lx->src[lx->pos] == '\n') lx->pos++;
            lx->line++;
            had_nl = true;
        } else if ((uint8_t)c == 0xC2 && lx->pos + 1 < lx->len && (uint8_t)lx->src[lx->pos + 1] == 0xA0) {
            lx->pos += 2; /* UTF-8 NBSP */
        } else if (c == '/' && lx->pos + 1 < lx->len && lx->src[lx->pos + 1] == '/') {
            lx->pos += 2;
            while (lx->pos < lx->len && lx->src[lx->pos] != '\n' && lx->src[lx->pos] != '\r') lx->pos++;
        } else if (c == '/' && lx->pos + 1 < lx->len && lx->src[lx->pos + 1] == '*') {
            lx->pos += 2;
            while (lx->pos + 1 < lx->len && !(lx->src[lx->pos] == '*' && lx->src[lx->pos + 1] == '/')) {
                if (lx->src[lx->pos] == '\n') { lx->line++; had_nl = true; }
                lx->pos++;
            }
            lx->pos += 2;
        } else if (c == '<' && lx->pos + 4 <= lx->len && strncmp(lx->src + lx->pos, "<!--", 4) == 0) {
            lx->pos += 4;
            while (lx->pos < lx->len && lx->src[lx->pos] != '\n') lx->pos++;
        } else {
            break;
        }
    }

    Token t;
    memset(&t, 0, sizeof(t));
    t.had_newline = had_nl;
    t.line        = lx->line;

    if (lx->pos >= lx->len) {
        t.kind = TOK_EOF;
        p->cur = t;
        return;
    }

    char c  = lx->src[lx->pos];
    char c1 = (lx->pos + 1 < lx->len) ? lx->src[lx->pos + 1] : '\0';
    char c2 = (lx->pos + 2 < lx->len) ? lx->src[lx->pos + 2] : '\0';
    char c3 = (lx->pos + 3 < lx->len) ? lx->src[lx->pos + 3] : '\0';

    /* Numbers */
    if ((c >= '0' && c <= '9') || (c == '.' && c1 >= '0' && c1 <= '9')) {
        size_t start = lx->pos;
        double val   = 0.0;
        if (c == '0' && (c1 == 'x' || c1 == 'X')) {
            lx->pos += 2;
            while (lx->pos < lx->len && (hex_digit(lx->src[lx->pos]) >= 0 || lx->src[lx->pos] == '_')) {
                if (lx->src[lx->pos] != '_') val = val * 16.0 + hex_digit(lx->src[lx->pos]);
                lx->pos++;
            }
        } else if (c == '0' && (c1 == 'b' || c1 == 'B')) {
            lx->pos += 2;
            while (lx->pos < lx->len && (lx->src[lx->pos] == '0' || lx->src[lx->pos] == '1' || lx->src[lx->pos] == '_')) {
                if (lx->src[lx->pos] != '_') val = val * 2.0 + (lx->src[lx->pos] - '0');
                lx->pos++;
            }
        } else if (c == '0' && (c1 == 'o' || c1 == 'O')) {
            lx->pos += 2;
            while (lx->pos < lx->len && ((lx->src[lx->pos] >= '0' && lx->src[lx->pos] <= '7') || lx->src[lx->pos] == '_')) {
                if (lx->src[lx->pos] != '_') val = val * 8.0 + (lx->src[lx->pos] - '0');
                lx->pos++;
            }
        } else {
            char nbuf[64];
            size_t nw = 0;
            while (lx->pos < lx->len) {
                char nc = lx->src[lx->pos];
                if (nc == '_') { lx->pos++; continue; }
                if ((nc >= '0' && nc <= '9') || nc == '.') {
                    if (nw + 1 < sizeof(nbuf)) nbuf[nw++] = nc;
                    lx->pos++;
                } else if ((nc == 'e' || nc == 'E') && nw > 0) {
                    if (nw + 1 < sizeof(nbuf)) nbuf[nw++] = nc;
                    lx->pos++;
                    if (lx->pos < lx->len && (lx->src[lx->pos] == '+' || lx->src[lx->pos] == '-')) {
                        if (nw + 1 < sizeof(nbuf)) nbuf[nw++] = lx->src[lx->pos];
                        lx->pos++;
                    }
                } else {
                    break;
                }
            }
            nbuf[nw] = '\0';
            (void)start;
            val = strtod(nbuf, NULL);
        }
        t.kind = TOK_NUM;
        t.num  = val;
        lx->prev_can_end_expr = true;
        p->cur = t;
        return;
    }

    /* Strings */
    if (c == '"' || c == '\'') {
        char q = lx->src[lx->pos++];
        TbBuf b;
        tb_buf_init(&b);
        while (lx->pos < lx->len && lx->src[lx->pos] != q) {
            if (lx->src[lx->pos] == '\\') {
                lx->pos++;
                decode_js_escape(lx, &b);
            } else {
                if (lx->src[lx->pos] == '\n') lx->line++;
                tb_buf_append_char(&b, lx->src[lx->pos++]);
            }
        }
        if (lx->pos < lx->len && lx->src[lx->pos] == q) lx->pos++;
        else set_parse_err(p, "Unterminated string literal");
        t.kind   = TOK_STR;
        t.str_id = chunk_intern_str(p, b.data ? b.data : "", b.len);
        tb_buf_free(&b);
        lx->prev_can_end_expr = true;
        p->cur = t;
        return;
    }

    /* Template literal start */
    if (c == '`') {
        lx->pos++;
        t.kind = TOK_BACKTICK;
        lx->prev_can_end_expr = false;
        p->cur = t;
        return;
    }

    /* Regex literal `/pattern/flags` when expression cannot end before `/` */
    if (c == '/' && !lx->prev_can_end_expr) {
        lx->pos++; /* skip opening '/' */
        TbBuf pat;
        tb_buf_init(&pat);
        bool in_class = false;
        while (lx->pos < lx->len) {
            char rc = lx->src[lx->pos++];
            if (rc == '\\' && lx->pos < lx->len) {
                tb_buf_append_char(&pat, rc);
                tb_buf_append_char(&pat, lx->src[lx->pos++]);
                continue;
            }
            if (rc == '[') in_class = true;
            else if (rc == ']') in_class = false;
            else if (rc == '/' && !in_class) break;
            else if (rc == '\n' || rc == '\r') {
                set_parse_err(p, "Unterminated RegExp literal");
                break;
            }
            tb_buf_append_char(&pat, rc);
        }
        size_t fstart = lx->pos;
        while (lx->pos < lx->len && is_ident_part(lx->src[lx->pos])) lx->pos++;
        t.kind    = TOK_REGEX;
        t.str_id  = chunk_intern_str(p, pat.data ? pat.data : "", pat.len);
        t.str_id2 = chunk_intern_str(p, lx->src + fstart, lx->pos - fstart);
        tb_buf_free(&pat);
        lx->prev_can_end_expr = true;
        p->cur = t;
        return;
    }

    /* Identifiers & Keywords */
    if (is_ident_start(c)) {
        size_t start = lx->pos++;
        while (lx->pos < lx->len && is_ident_part(lx->src[lx->pos])) lx->pos++;
        size_t ilen = lx->pos - start;
        t.kind = keyword_lookup(lx->src + start, ilen);
        t.str_id = chunk_intern_str(p, lx->src + start, ilen);
        lx->prev_can_end_expr = tok_can_end_expr(t.kind);
        p->cur = t;
        return;
    }

    /* Multi-char operators */
    if (c == '>' && c1 == '>' && c2 == '>' && c3 == '=') { lx->pos += 4; t.kind = TOK_USHR_ASSIGN; goto done; }
    if (c == '>' && c1 == '>' && c2 == '>') { lx->pos += 3; t.kind = TOK_USHR; goto done; }
    if (c == '<' && c1 == '<' && c2 == '=') { lx->pos += 3; t.kind = TOK_SHL_ASSIGN; goto done; }
    if (c == '>' && c1 == '>' && c2 == '=') { lx->pos += 3; t.kind = TOK_SHR_ASSIGN; goto done; }
    if (c == '=' && c1 == '=' && c2 == '=') { lx->pos += 3; t.kind = TOK_STRICT_EQ; goto done; }
    if (c == '!' && c1 == '=' && c2 == '=') { lx->pos += 3; t.kind = TOK_STRICT_NE; goto done; }
    if (c == '.' && c1 == '.' && c2 == '.') { lx->pos += 3; t.kind = TOK_SPREAD; goto done; }
    if (c == '&' && c1 == '&' && c2 == '=') { lx->pos += 3; t.kind = TOK_LAND_ASSIGN; goto done; }
    if (c == '|' && c1 == '|' && c2 == '=') { lx->pos += 3; t.kind = TOK_LOR_ASSIGN; goto done; }
    if (c == '?' && c1 == '?' && c2 == '=') { lx->pos += 3; t.kind = TOK_NULLISH_ASSIGN; goto done; }

    if (c == '?' && c1 == '.' && !(c2 >= '0' && c2 <= '9')) { lx->pos += 2; t.kind = TOK_OPT_CHAIN; goto done; }
    if (c == '?' && c1 == '?') { lx->pos += 2; t.kind = TOK_NULLISH; goto done; }
    if (c == '=' && c1 == '>') { lx->pos += 2; t.kind = TOK_ARROW; goto done; }
    if (c == '+' && c1 == '+') { lx->pos += 2; t.kind = TOK_INC; goto done; }
    if (c == '-' && c1 == '-') { lx->pos += 2; t.kind = TOK_DEC; goto done; }
    if (c == '*' && c1 == '*') { lx->pos += 2; t.kind = TOK_POW; goto done; }
    if (c == '<' && c1 == '<') { lx->pos += 2; t.kind = TOK_SHL; goto done; }
    if (c == '>' && c1 == '>') { lx->pos += 2; t.kind = TOK_SHR; goto done; }
    if (c == '&' && c1 == '&') { lx->pos += 2; t.kind = TOK_AND; goto done; }
    if (c == '|' && c1 == '|') { lx->pos += 2; t.kind = TOK_OR; goto done; }
    if (c == '<' && c1 == '=') { lx->pos += 2; t.kind = TOK_LE; goto done; }
    if (c == '>' && c1 == '=') { lx->pos += 2; t.kind = TOK_GE; goto done; }
    if (c == '=' && c1 == '=') { lx->pos += 2; t.kind = TOK_EQ; goto done; }
    if (c == '!' && c1 == '=') { lx->pos += 2; t.kind = TOK_NE; goto done; }
    if (c == '+' && c1 == '=') { lx->pos += 2; t.kind = TOK_ADD_ASSIGN; goto done; }
    if (c == '-' && c1 == '=') { lx->pos += 2; t.kind = TOK_SUB_ASSIGN; goto done; }
    if (c == '*' && c1 == '=') { lx->pos += 2; t.kind = TOK_MUL_ASSIGN; goto done; }
    if (c == '/' && c1 == '=') { lx->pos += 2; t.kind = TOK_DIV_ASSIGN; goto done; }
    if (c == '%' && c1 == '=') { lx->pos += 2; t.kind = TOK_MOD_ASSIGN; goto done; }
    if (c == '&' && c1 == '=') { lx->pos += 2; t.kind = TOK_AND_ASSIGN; goto done; }
    if (c == '|' && c1 == '=') { lx->pos += 2; t.kind = TOK_OR_ASSIGN; goto done; }
    if (c == '^' && c1 == '=') { lx->pos += 2; t.kind = TOK_XOR_ASSIGN; goto done; }

    lx->pos++;
    switch (c) {
        case '(': t.kind = TOK_LPAREN; break;
        case ')': t.kind = TOK_RPAREN; break;
        case '[': t.kind = TOK_LBRACK; break;
        case ']': t.kind = TOK_RBRACK; break;
        case '{': t.kind = TOK_LBRACE; break;
        case '}': t.kind = TOK_RBRACE; break;
        case ';': t.kind = TOK_SEMI; break;
        case ',': t.kind = TOK_COMMA; break;
        case '.': t.kind = TOK_DOT; break;
        case ':': t.kind = TOK_COLON; break;
        case '?': t.kind = TOK_QUESTION; break;
        case '+': t.kind = TOK_PLUS; break;
        case '-': t.kind = TOK_MINUS; break;
        case '*': t.kind = TOK_STAR; break;
        case '/': t.kind = TOK_SLASH; break;
        case '%': t.kind = TOK_PERCENT; break;
        case '&': t.kind = TOK_AMP; break;
        case '|': t.kind = TOK_PIPE; break;
        case '^': t.kind = TOK_CARET; break;
        case '~': t.kind = TOK_TILDE; break;
        case '!': t.kind = TOK_BANG; break;
        case '<': t.kind = TOK_LT; break;
        case '>': t.kind = TOK_GT; break;
        case '=': t.kind = TOK_ASSIGN; break;
        default:
            set_parse_err(p, "Unexpected character");
            t.kind = TOK_EOF;
            break;
    }

done:
    lx->prev_can_end_expr = tok_can_end_expr(t.kind);
    p->cur = t;
}

static bool match_tok(Parser *p, TokKind k) {
    if (p->cur.kind == k) {
        next_token(p);
        return true;
    }
    return false;
}

static bool expect_tok(Parser *p, TokKind k, const char *err_msg) {
    if (p->cur.kind == k) {
        next_token(p);
        return true;
    }
    set_parse_err(p, err_msg);
    return false;
}

static void consume_asi(Parser *p) {
    if (p->cur.kind == TOK_SEMI) {
        next_token(p);
        return;
    }
    if (p->cur.kind == TOK_RBRACE || p->cur.kind == TOK_EOF || p->cur.had_newline) {
        return;
    }
    set_parse_err(p, "Expected ';' or newline");
}

/* Forward declarations */
static uint32_t parse_expr(Parser *p, bool allow_in);
static uint32_t parse_assign(Parser *p, bool allow_in);
static uint32_t parse_stmt(Parser *p);
static uint32_t parse_block(Parser *p);
static uint32_t parse_binding_target(Parser *p);

static uint32_t parse_param_list(Parser *p) {
    uint32_t head = 0, tail = 0;
    while (!p->has_err && p->cur.kind != TOK_RPAREN && p->cur.kind != TOK_EOF) {
        uint16_t flags = 0;
        if (match_tok(p, TOK_SPREAD)) flags |= 1;
        uint32_t name_id = 0;
        uint32_t pat_idx = 0;
        if (p->cur.kind == TOK_IDENT) {
            name_id = p->cur.str_id;
            next_token(p);
        } else if (!(flags & 1) && (p->cur.kind == TOK_LBRACE || p->cur.kind == TOK_LBRACK)) {
            flags |= 2;
            pat_idx = parse_binding_target(p);
        } else {
            set_parse_err(p, "Expected parameter name");
            break;
        }
        uint32_t def_expr = 0;
        if (match_tok(p, TOK_ASSIGN)) {
            def_expr = parse_assign(p, true);
        }
        uint32_t param = emit_node(p, AST_PARAM, OP_NONE, flags, name_id, def_expr, pat_idx);
        if (!head) head = param;
        else p->chunk->nodes[tail].next = param;
        tail = param;
        if (!match_tok(p, TOK_COMMA)) break;
    }
    expect_tok(p, TOK_RPAREN, "Expected ')' after parameters");
    return head;
}

static uint32_t parse_function_common(Parser *p, bool require_name) {
    uint32_t name_id = UINT32_MAX;
    if (p->cur.kind == TOK_IDENT) {
        name_id = p->cur.str_id;
        next_token(p);
    } else if (require_name) {
        set_parse_err(p, "Expected function name");
        return 0;
    }
    if (!expect_tok(p, TOK_LPAREN, "Expected '(' in function")) return 0;
    uint32_t params = parse_param_list(p);
    uint32_t body   = parse_block(p);
    return emit_node(p, AST_FUNC, OP_NONE, 0, name_id, params, body);
}

static uint32_t parse_template_literal(Parser *p) {
    /* Current token is TOK_BACKTICK, p->lx.pos is first char inside template */
    uint32_t head = 0, tail = 0;
    Lexer *lx = &p->lx;

    for (;;) {
        TbBuf seg;
        tb_buf_init(&seg);
        bool has_expr = false;
        while (lx->pos < lx->len) {
            char c = lx->src[lx->pos];
            if (c == '`') {
                lx->pos++;
                break;
            }
            if (c == '$' && lx->pos + 1 < lx->len && lx->src[lx->pos + 1] == '{') {
                lx->pos += 2;
                has_expr = true;
                break;
            }
            if (c == '\\') {
                lx->pos++;
                decode_js_escape(lx, &seg);
            } else {
                if (c == '\n') lx->line++;
                tb_buf_append_char(&seg, lx->src[lx->pos++]);
            }
        }
        uint32_t sid  = chunk_intern_str(p, seg.data ? seg.data : "", seg.len);
        tb_buf_free(&seg);
        uint32_t snod = emit_node(p, AST_STR, OP_NONE, 0, sid, 0, 0);
        if (!head) head = snod;
        else p->chunk->nodes[tail].next = snod;
        tail = snod;

        if (!has_expr) break;

        lx->prev_can_end_expr = false;
        next_token(p);
        uint32_t expr = parse_expr(p, true);
        if (p->cur.kind != TOK_RBRACE) {
            set_parse_err(p, "Expected '}' in template literal");
            break;
        }
        p->chunk->nodes[tail].next = expr;
        tail = expr;
        /* Now p->cur is TOK_RBRACE and lx->pos is right after '}' in template! */
    }
    lx->prev_can_end_expr = true;
    next_token(p);
    return emit_node(p, AST_TEMPLATE, OP_NONE, 0, head, 0, 0);
}

static bool is_arrow_after_lparen(Parser *p) {
    Lexer saved_lx  = p->lx;
    Token saved_cur = p->cur;
    bool  saved_err = p->has_err;

    int depth = 1;
    while (depth > 0 && p->cur.kind != TOK_EOF && !p->has_err) {
        if (p->cur.kind == TOK_LPAREN) depth++;
        else if (p->cur.kind == TOK_RPAREN) {
            depth--;
            if (depth == 0) {
                next_token(p);
                break;
            }
        }
        next_token(p);
    }
    bool is_arrow = (depth == 0 && p->cur.kind == TOK_ARROW && !p->cur.had_newline);

    p->lx      = saved_lx;
    p->cur     = saved_cur;
    p->has_err = saved_err;
    return is_arrow;
}

static uint32_t parse_arg_list(Parser *p) {
    uint32_t head = 0, tail = 0;
    while (!p->has_err && p->cur.kind != TOK_RPAREN && p->cur.kind != TOK_EOF) {
        uint32_t arg = 0;
        if (match_tok(p, TOK_SPREAD)) {
            uint32_t inner = parse_assign(p, true);
            arg = emit_node(p, AST_SPREAD, OP_NONE, 0, inner, 0, 0);
        } else {
            arg = parse_assign(p, true);
        }
        if (!head) head = arg;
        else p->chunk->nodes[tail].next = arg;
        tail = arg;
        if (!match_tok(p, TOK_COMMA)) break;
    }
    expect_tok(p, TOK_RPAREN, "Expected ')' after arguments");
    return head;
}

static uint32_t parse_object_literal(Parser *p) {
    uint32_t head = 0, tail = 0;
    while (!p->has_err && p->cur.kind != TOK_RBRACE && p->cur.kind != TOK_EOF) {
        if (match_tok(p, TOK_SPREAD)) {
            uint32_t sp = parse_assign(p, true);
            uint32_t pn = emit_node(p, AST_PROP, OP_NONE, PROP_FLAG_SPREAD, sp, 0, 0);
            if (!head) head = pn;
            else p->chunk->nodes[tail].next = pn;
            tail = pn;
            if (!match_tok(p, TOK_COMMA)) break;
            continue;
        }

        uint16_t flags = 0;
        uint32_t key_a = 0;
        bool was_ident = false;
        if (match_tok(p, TOK_LBRACK)) {
            flags |= PROP_FLAG_COMPUTED;
            key_a = parse_assign(p, true);
            expect_tok(p, TOK_RBRACK, "Expected ']' in computed property");
        } else if (p->cur.kind == TOK_STR) {
            key_a = p->cur.str_id;
            next_token(p);
        } else if (p->cur.kind == TOK_NUM) {
            char nbuf[64];
            snprintf(nbuf, sizeof(nbuf), "%.15g", p->cur.num);
            key_a = chunk_intern_str(p, nbuf, strlen(nbuf));
            next_token(p);
        } else if (p->cur.kind >= TOK_IDENT && p->cur.kind <= TOK_UNDEFINED) {
            key_a     = p->cur.str_id;
            was_ident = (p->cur.kind == TOK_IDENT);
            next_token(p);
        } else {
            set_parse_err(p, "Expected property name in object literal");
            break;
        }

        uint32_t val_b = 0;
        if (match_tok(p, TOK_COLON)) {
            val_b = parse_assign(p, true);
        } else if (match_tok(p, TOK_LPAREN)) {
            /* Concise method syntax `{ foo(a, b) { ... } }` */
            uint32_t params = parse_param_list(p);
            uint32_t body   = parse_block(p);
            val_b = emit_node(p, AST_FUNC, OP_NONE, 0, UINT32_MAX, params, body);
        } else if (was_ident && !(flags & PROP_FLAG_COMPUTED)) {
            /* Shorthand `{ x }` -> `{ x: x }` */
            val_b = emit_node(p, AST_IDENT, OP_NONE, 0, key_a, 0, 0);
        } else {
            set_parse_err(p, "Expected ':' in object literal");
            break;
        }

        uint32_t pn = emit_node(p, AST_PROP, OP_NONE, flags, key_a, val_b, 0);
        if (!head) head = pn;
        else p->chunk->nodes[tail].next = pn;
        tail = pn;
        if (!match_tok(p, TOK_COMMA)) break;
    }
    expect_tok(p, TOK_RBRACE, "Expected '}' after object literal");
    return emit_node(p, AST_OBJECT, OP_NONE, 0, head, 0, 0);
}

static uint32_t parse_primary(Parser *p) {
    TokKind k = p->cur.kind;
    if (k == TOK_NUM) {
        uint32_t nid = chunk_add_num(p, p->cur.num);
        next_token(p);
        return emit_node(p, AST_NUM, OP_NONE, 0, nid, 0, 0);
    }
    if (k == TOK_STR) {
        uint32_t sid = p->cur.str_id;
        next_token(p);
        return emit_node(p, AST_STR, OP_NONE, 0, sid, 0, 0);
    }
    if (k == TOK_REGEX) {
        uint32_t pat = p->cur.str_id;
        uint32_t flg = p->cur.str_id2;
        next_token(p);
        return emit_node(p, AST_REGEX, OP_NONE, 0, pat, flg, 0);
    }
    if (k == TOK_BACKTICK) {
        return parse_template_literal(p);
    }
    if (k == TOK_TRUE || k == TOK_FALSE) {
        next_token(p);
        return emit_node(p, AST_BOOL, OP_NONE, 0, k == TOK_TRUE ? 1 : 0, 0, 0);
    }
    if (k == TOK_NULL) {
        next_token(p);
        return emit_node(p, AST_NULL, OP_NONE, 0, 0, 0, 0);
    }
    if (k == TOK_UNDEFINED) {
        next_token(p);
        return emit_node(p, AST_UNDEFINED, OP_NONE, 0, 0, 0, 0);
    }
    if (k == TOK_THIS) {
        next_token(p);
        return emit_node(p, AST_THIS, OP_NONE, 0, 0, 0, 0);
    }
    if (k == TOK_FUNCTION) {
        next_token(p);
        return parse_function_common(p, false);
    }
    if (k == TOK_IDENT) {
        uint32_t sid = p->cur.str_id;
        next_token(p);
        /* Single-parameter arrow function `x => ...` */
        if (p->cur.kind == TOK_ARROW && !p->cur.had_newline) {
            next_token(p);
            uint32_t param = emit_node(p, AST_PARAM, OP_NONE, 0, sid, 0, 0);
            uint16_t fflags = FUNC_FLAG_ARROW;
            uint32_t body   = 0;
            if (p->cur.kind == TOK_LBRACE) {
                body = parse_block(p);
            } else {
                fflags |= FUNC_FLAG_EXPR_BODY;
                body = parse_assign(p, true);
            }
            return emit_node(p, AST_FUNC, OP_NONE, fflags, UINT32_MAX, param, body);
        }
        return emit_node(p, AST_IDENT, OP_NONE, 0, sid, 0, 0);
    }
    if (k == TOK_LPAREN) {
        next_token(p);
        if (is_arrow_after_lparen(p)) {
            uint32_t params = parse_param_list(p);
            expect_tok(p, TOK_ARROW, "Expected '=>'");
            uint16_t fflags = FUNC_FLAG_ARROW;
            uint32_t body   = 0;
            if (p->cur.kind == TOK_LBRACE) {
                body = parse_block(p);
            } else {
                fflags |= FUNC_FLAG_EXPR_BODY;
                body = parse_assign(p, true);
            }
            return emit_node(p, AST_FUNC, OP_NONE, fflags, UINT32_MAX, params, body);
        }
        uint32_t inner = parse_expr(p, true);
        expect_tok(p, TOK_RPAREN, "Expected ')'");
        return inner;
    }
    if (k == TOK_LBRACK) {
        next_token(p);
        uint32_t head = 0, tail = 0;
        while (!p->has_err && p->cur.kind != TOK_RBRACK && p->cur.kind != TOK_EOF) {
            uint32_t elem = 0;
            if (p->cur.kind == TOK_COMMA) {
                elem = emit_node(p, AST_UNDEFINED, OP_NONE, 0, 0, 0, 0);
            } else if (match_tok(p, TOK_SPREAD)) {
                uint32_t sp = parse_assign(p, true);
                elem = emit_node(p, AST_SPREAD, OP_NONE, 0, sp, 0, 0);
            } else {
                elem = parse_assign(p, true);
            }
            if (!head) head = elem;
            else p->chunk->nodes[tail].next = elem;
            tail = elem;
            if (!match_tok(p, TOK_COMMA)) break;
        }
        expect_tok(p, TOK_RBRACK, "Expected ']'");
        return emit_node(p, AST_ARRAY, OP_NONE, 0, head, 0, 0);
    }
    if (k == TOK_LBRACE) {
        next_token(p);
        return parse_object_literal(p);
    }

    set_parse_err(p, "Unexpected token in expression");
    next_token(p);
    return 0;
}

static uint32_t parse_lhs_expr(Parser *p, bool allow_calls) {
    uint32_t expr = 0;
    if (match_tok(p, TOK_NEW)) {
        uint32_t callee = parse_lhs_expr(p, false);
        uint32_t args   = 0;
        if (match_tok(p, TOK_LPAREN)) {
            args = parse_arg_list(p);
        }
        expr = emit_node(p, AST_NEW, OP_NONE, 0, callee, args, 0);
    } else {
        expr = parse_primary(p);
    }

    while (!p->has_err) {
        if (match_tok(p, TOK_DOT)) {
            if (p->cur.kind >= TOK_IDENT && p->cur.kind <= TOK_UNDEFINED) {
                uint32_t pid = p->cur.str_id;
                next_token(p);
                expr = emit_node(p, AST_MEMBER, OP_NONE, 0, expr, pid, 0);
            } else {
                set_parse_err(p, "Expected property name after '.'");
                break;
            }
        } else if (match_tok(p, TOK_OPT_CHAIN)) {
            if (allow_calls && match_tok(p, TOK_LPAREN)) {
                uint32_t args = parse_arg_list(p);
                expr = emit_node(p, AST_CALL, OP_NONE, OPT_CHAIN_FLAG, expr, args, 0);
            } else if (match_tok(p, TOK_LBRACK)) {
                uint32_t idx = parse_expr(p, true);
                expect_tok(p, TOK_RBRACK, "Expected ']'");
                expr = emit_node(p, AST_INDEX, OP_NONE, OPT_CHAIN_FLAG, expr, idx, 0);
            } else if (p->cur.kind >= TOK_IDENT && p->cur.kind <= TOK_UNDEFINED) {
                uint32_t pid = p->cur.str_id;
                next_token(p);
                expr = emit_node(p, AST_MEMBER, OP_NONE, OPT_CHAIN_FLAG, expr, pid, 0);
            } else {
                set_parse_err(p, "Expected property after '?.'");
                break;
            }
        } else if (match_tok(p, TOK_LBRACK)) {
            uint32_t idx = parse_expr(p, true);
            expect_tok(p, TOK_RBRACK, "Expected ']'");
            expr = emit_node(p, AST_INDEX, OP_NONE, 0, expr, idx, 0);
        } else if (allow_calls && match_tok(p, TOK_LPAREN)) {
            uint32_t args = parse_arg_list(p);
            expr = emit_node(p, AST_CALL, OP_NONE, 0, expr, args, 0);
        } else {
            break;
        }
    }
    return expr;
}

static uint32_t parse_postfix(Parser *p) {
    uint32_t expr = parse_lhs_expr(p, true);
    if (!p->cur.had_newline && (p->cur.kind == TOK_INC || p->cur.kind == TOK_DEC)) {
        AstOp op = (p->cur.kind == TOK_INC) ? OP_INC : OP_DEC;
        next_token(p);
        expr = emit_node(p, AST_UPDATE, op, 0 /* postfix */, expr, 0, 0);
    }
    return expr;
}

static uint32_t parse_unary(Parser *p) {
    if (p->cur.kind == TOK_INC || p->cur.kind == TOK_DEC) {
        AstOp op = (p->cur.kind == TOK_INC) ? OP_INC : OP_DEC;
        next_token(p);
        uint32_t operand = parse_unary(p);
        return emit_node(p, AST_UPDATE, op, 1 /* prefix */, operand, 0, 0);
    }
    if (p->cur.kind == TOK_PLUS || p->cur.kind == TOK_MINUS ||
        p->cur.kind == TOK_BANG || p->cur.kind == TOK_TILDE ||
        p->cur.kind == TOK_TYPEOF || p->cur.kind == TOK_VOID || p->cur.kind == TOK_DELETE) {
        AstOp op = OP_NONE;
        switch (p->cur.kind) {
            case TOK_PLUS:   op = OP_ADD; break;
            case TOK_MINUS:  op = OP_SUB; break;
            case TOK_BANG:   op = OP_NOT; break;
            case TOK_TILDE:  op = OP_BIT_NOT; break;
            case TOK_TYPEOF: op = OP_TYPEOF; break;
            case TOK_VOID:   op = OP_VOID; break;
            case TOK_DELETE: op = OP_DELETE; break;
            default: break;
        }
        next_token(p);
        uint32_t operand = parse_unary(p);
        return emit_node(p, AST_UNARY, op, 0, operand, 0, 0);
    }
    return parse_postfix(p);
}

static uint32_t parse_pow(Parser *p) {
    uint32_t lhs = parse_unary(p);
    if (match_tok(p, TOK_POW)) {
        uint32_t rhs = parse_pow(p); /* right-associative */
        return emit_node(p, AST_BINARY, OP_POW, 0, lhs, rhs, 0);
    }
    return lhs;
}

static int binop_prec(TokKind k, bool allow_in, AstOp *out_op, bool *is_logical) {
    *is_logical = false;
    switch (k) {
        case TOK_OR:      *out_op = OP_OR; *is_logical = true; return 1;
        case TOK_NULLISH: *out_op = OP_NULLISH; *is_logical = true; return 1;
        case TOK_AND:     *out_op = OP_AND; *is_logical = true; return 2;
        case TOK_PIPE:    *out_op = OP_BIT_OR; return 3;
        case TOK_CARET:   *out_op = OP_BIT_XOR; return 4;
        case TOK_AMP:     *out_op = OP_BIT_AND; return 5;
        case TOK_EQ:        *out_op = OP_EQ; return 6;
        case TOK_NE:        *out_op = OP_NE; return 6;
        case TOK_STRICT_EQ: *out_op = OP_STRICT_EQ; return 6;
        case TOK_STRICT_NE: *out_op = OP_STRICT_NE; return 6;
        case TOK_LT:         *out_op = OP_LT; return 7;
        case TOK_LE:         *out_op = OP_LE; return 7;
        case TOK_GT:         *out_op = OP_GT; return 7;
        case TOK_GE:         *out_op = OP_GE; return 7;
        case TOK_INSTANCEOF: *out_op = OP_INSTANCEOF; return 7;
        case TOK_IN:
            if (!allow_in) return 0;
            *out_op = OP_IN;
            return 7;
        case TOK_SHL:  *out_op = OP_SHL; return 8;
        case TOK_SHR:  *out_op = OP_SHR; return 8;
        case TOK_USHR: *out_op = OP_USHR; return 8;
        case TOK_PLUS:  *out_op = OP_ADD; return 9;
        case TOK_MINUS: *out_op = OP_SUB; return 9;
        case TOK_STAR:    *out_op = OP_MUL; return 10;
        case TOK_SLASH:   *out_op = OP_DIV; return 10;
        case TOK_PERCENT: *out_op = OP_MOD; return 10;
        default: return 0;
    }
}

static uint32_t parse_binop_climb(Parser *p, int min_prec, bool allow_in) {
    uint32_t lhs = parse_pow(p);
    while (!p->has_err) {
        AstOp op = OP_NONE;
        bool is_log = false;
        int prec = binop_prec(p->cur.kind, allow_in, &op, &is_log);
        if (prec < min_prec || prec == 0) break;
        next_token(p);
        uint32_t rhs = parse_binop_climb(p, prec + 1, allow_in);
        lhs = emit_node(p, is_log ? AST_LOGICAL : AST_BINARY, op, 0, lhs, rhs, 0);
    }
    return lhs;
}

static uint32_t parse_ternary(Parser *p, bool allow_in) {
    uint32_t cond = parse_binop_climb(p, 1, allow_in);
    if (match_tok(p, TOK_QUESTION)) {
        uint32_t then_e = parse_assign(p, true);
        expect_tok(p, TOK_COLON, "Expected ':' in conditional expression");
        uint32_t else_e = parse_assign(p, allow_in);
        return emit_node(p, AST_TERNARY, OP_NONE, 0, cond, then_e, else_e);
    }
    return cond;
}

static uint32_t parse_assign(Parser *p, bool allow_in) {
    uint32_t lhs = parse_ternary(p, allow_in);
    AstOp op = OP_NONE;
    switch (p->cur.kind) {
        case TOK_ASSIGN:         op = OP_ASSIGN; break;
        case TOK_ADD_ASSIGN:     op = OP_ADD; break;
        case TOK_SUB_ASSIGN:     op = OP_SUB; break;
        case TOK_MUL_ASSIGN:     op = OP_MUL; break;
        case TOK_DIV_ASSIGN:     op = OP_DIV; break;
        case TOK_MOD_ASSIGN:     op = OP_MOD; break;
        case TOK_AND_ASSIGN:     op = OP_BIT_AND; break;
        case TOK_OR_ASSIGN:      op = OP_BIT_OR; break;
        case TOK_XOR_ASSIGN:     op = OP_BIT_XOR; break;
        case TOK_SHL_ASSIGN:     op = OP_SHL; break;
        case TOK_SHR_ASSIGN:     op = OP_SHR; break;
        case TOK_USHR_ASSIGN:    op = OP_USHR; break;
        case TOK_LAND_ASSIGN:    op = OP_AND; break;
        case TOK_LOR_ASSIGN:     op = OP_OR; break;
        case TOK_NULLISH_ASSIGN: op = OP_NULLISH; break;
        default: return lhs;
    }
    next_token(p);
    uint32_t rhs = parse_assign(p, allow_in);
    return emit_node(p, AST_ASSIGN, op, 0, lhs, rhs, 0);
}

static uint32_t parse_expr(Parser *p, bool allow_in) {
    uint32_t lhs = parse_assign(p, allow_in);
    while (match_tok(p, TOK_COMMA)) {
        uint32_t rhs = parse_assign(p, allow_in);
        lhs = emit_node(p, AST_SEQ, OP_NONE, 0, lhs, rhs, 0);
    }
    return lhs;
}

/* Destructuring pattern or identifier for var/let/const */
static uint32_t parse_binding_target(Parser *p) {
    if (p->cur.kind == TOK_IDENT) {
        uint32_t sid = p->cur.str_id;
        next_token(p);
        return emit_node(p, AST_IDENT, OP_NONE, 0, sid, 0, 0);
    }
    if (match_tok(p, TOK_LBRACK)) {
        uint32_t head = 0, tail = 0;
        while (!p->has_err && p->cur.kind != TOK_RBRACK && p->cur.kind != TOK_EOF) {
            uint32_t item = 0;
            if (p->cur.kind == TOK_COMMA) {
                item = emit_node(p, AST_EMPTY, OP_NONE, 0, 0, 0, 0);
            } else {
                uint32_t sid = p->cur.str_id;
                if (!expect_tok(p, TOK_IDENT, "Expected identifier in array destructuring")) break;
                uint32_t def = match_tok(p, TOK_ASSIGN) ? parse_assign(p, true) : 0;
                item = emit_node(p, AST_PARAM, OP_NONE, 0, sid, def, 0);
            }
            if (!head) head = item;
            else p->chunk->nodes[tail].next = item;
            tail = item;
            if (!match_tok(p, TOK_COMMA)) break;
        }
        expect_tok(p, TOK_RBRACK, "Expected ']'");
        return emit_node(p, AST_DESTRUCT_ARR, OP_NONE, 0, head, 0, 0);
    }
    if (match_tok(p, TOK_LBRACE)) {
        uint32_t head = 0, tail = 0;
        while (!p->has_err && p->cur.kind != TOK_RBRACE && p->cur.kind != TOK_EOF) {
            uint32_t key_sid = p->cur.str_id;
            if (!expect_tok(p, TOK_IDENT, "Expected property in object destructuring")) break;
            uint32_t target_sid = key_sid;
            if (match_tok(p, TOK_COLON)) {
                target_sid = p->cur.str_id;
                expect_tok(p, TOK_IDENT, "Expected target identifier");
            }
            uint32_t def = match_tok(p, TOK_ASSIGN) ? parse_assign(p, true) : 0;
            uint32_t item = emit_node(p, AST_PROP, OP_NONE, 0, key_sid, target_sid, def);
            if (!head) head = item;
            else p->chunk->nodes[tail].next = item;
            tail = item;
            if (!match_tok(p, TOK_COMMA)) break;
        }
        expect_tok(p, TOK_RBRACE, "Expected '}'");
        return emit_node(p, AST_DESTRUCT_OBJ, OP_NONE, 0, head, 0, 0);
    }
    set_parse_err(p, "Expected variable name");
    return 0;
}

static uint32_t parse_var_decl(Parser *p, uint16_t decl_kind, bool allow_in, bool consume_semi) {
    uint32_t head = 0, tail = 0;
    do {
        uint32_t target = parse_binding_target(p);
        uint32_t init   = 0;
        if (match_tok(p, TOK_ASSIGN)) {
            init = parse_assign(p, allow_in);
        }
        uint32_t d = emit_node(p, AST_DECLARATOR, OP_NONE, 0, target, init, 0);
        if (!head) head = d;
        else p->chunk->nodes[tail].next = d;
        tail = d;
    } while (!p->has_err && match_tok(p, TOK_COMMA));

    if (consume_semi) consume_asi(p);
    return emit_node(p, AST_VAR_DECL, OP_NONE, decl_kind, head, 0, 0);
}

static uint32_t parse_block(Parser *p) {
    if (!expect_tok(p, TOK_LBRACE, "Expected '{'")) return 0;
    uint32_t head = 0, tail = 0;
    while (!p->has_err && p->cur.kind != TOK_RBRACE && p->cur.kind != TOK_EOF) {
        uint32_t st = parse_stmt(p);
        if (st) {
            if (!head) head = st;
            else p->chunk->nodes[tail].next = st;
            tail = st;
        }
    }
    expect_tok(p, TOK_RBRACE, "Expected '}'");
    return emit_node(p, AST_BLOCK, OP_NONE, 0, head, 0, 0);
}

static uint32_t parse_stmt(Parser *p) {
    if (p->has_err) return 0;
    switch (p->cur.kind) {
        case TOK_SEMI:
            next_token(p);
            return emit_node(p, AST_EMPTY, OP_NONE, 0, 0, 0, 0);
        case TOK_LBRACE:
            return parse_block(p);
        case TOK_VAR:
            next_token(p);
            return parse_var_decl(p, DECL_VAR, true, true);
        case TOK_LET:
            next_token(p);
            return parse_var_decl(p, DECL_LET, true, true);
        case TOK_CONST:
            next_token(p);
            return parse_var_decl(p, DECL_CONST, true, true);
        case TOK_FUNCTION: {
            next_token(p);
            uint32_t fn = parse_function_common(p, true);
            return emit_node(p, AST_FUNC_DECL, OP_NONE, 0, fn, 0, 0);
        }
        case TOK_IF: {
            next_token(p);
            expect_tok(p, TOK_LPAREN, "Expected '(' after 'if'");
            uint32_t cond = parse_expr(p, true);
            expect_tok(p, TOK_RPAREN, "Expected ')' after 'if' condition");
            uint32_t then_s = parse_stmt(p);
            uint32_t else_s = match_tok(p, TOK_ELSE) ? parse_stmt(p) : 0;
            return emit_node(p, AST_IF, OP_NONE, 0, cond, then_s, else_s);
        }
        case TOK_WHILE: {
            next_token(p);
            expect_tok(p, TOK_LPAREN, "Expected '(' after 'while'");
            uint32_t cond = parse_expr(p, true);
            expect_tok(p, TOK_RPAREN, "Expected ')'");
            uint32_t body = parse_stmt(p);
            return emit_node(p, AST_WHILE, OP_NONE, 0, cond, body, 0);
        }
        case TOK_DO: {
            next_token(p);
            uint32_t body = parse_stmt(p);
            expect_tok(p, TOK_WHILE, "Expected 'while' after 'do' body");
            expect_tok(p, TOK_LPAREN, "Expected '('");
            uint32_t cond = parse_expr(p, true);
            expect_tok(p, TOK_RPAREN, "Expected ')'");
            match_tok(p, TOK_SEMI);
            return emit_node(p, AST_DO_WHILE, OP_NONE, 0, body, cond, 0);
        }
        case TOK_FOR: {
            next_token(p);
            expect_tok(p, TOK_LPAREN, "Expected '(' after 'for'");
            uint32_t init = 0;
            uint16_t decl_flag = 0xFF;
            if (p->cur.kind == TOK_VAR || p->cur.kind == TOK_LET || p->cur.kind == TOK_CONST) {
                decl_flag = (p->cur.kind == TOK_VAR) ? DECL_VAR
                          : (p->cur.kind == TOK_LET) ? DECL_LET : DECL_CONST;
                next_token(p);
                init = parse_var_decl(p, decl_flag, false, false);
            } else if (p->cur.kind != TOK_SEMI) {
                init = parse_expr(p, false);
            }

            /* Check for `for (x in obj)` or `for (x of arr)` */
            if (p->cur.kind == TOK_IN || p->cur.kind == TOK_OF) {
                AstKind fk = (p->cur.kind == TOK_IN) ? AST_FOR_IN : AST_FOR_OF;
                next_token(p);
                uint32_t target_ident = init;
                if (decl_flag != 0xFF && init) {
                    uint32_t decl = p->chunk->nodes[init].a;
                    uint32_t pat  = decl ? p->chunk->nodes[decl].a : 0;
                    target_ident  = pat;
                }
                uint32_t rhs = parse_expr(p, true);
                expect_tok(p, TOK_RPAREN, "Expected ')' in for-in/of");
                uint32_t body = parse_stmt(p);
                return emit_node(p, fk, OP_NONE, decl_flag, target_ident, rhs, body);
            }

            expect_tok(p, TOK_SEMI, "Expected ';' after for-loop init");
            uint32_t cond = (p->cur.kind != TOK_SEMI) ? parse_expr(p, true) : 0;
            expect_tok(p, TOK_SEMI, "Expected ';' after for-loop condition");
            uint32_t step = (p->cur.kind != TOK_RPAREN) ? parse_expr(p, true) : 0;
            expect_tok(p, TOK_RPAREN, "Expected ')' after for-loop header");
            uint32_t body = parse_stmt(p);
            uint32_t head = emit_node(p, AST_FOR_HEAD, OP_NONE, 0, init, cond, step);
            return emit_node(p, AST_FOR, OP_NONE, 0, head, body, 0);
        }
        case TOK_SWITCH: {
            next_token(p);
            expect_tok(p, TOK_LPAREN, "Expected '(' after 'switch'");
            uint32_t disc = parse_expr(p, true);
            expect_tok(p, TOK_RPAREN, "Expected ')'");
            expect_tok(p, TOK_LBRACE, "Expected '{' in switch");
            uint32_t chead = 0, ctail = 0;
            while (!p->has_err && p->cur.kind != TOK_RBRACE && p->cur.kind != TOK_EOF) {
                uint32_t test = 0;
                if (match_tok(p, TOK_CASE)) {
                    test = parse_expr(p, true);
                    expect_tok(p, TOK_COLON, "Expected ':' after case");
                } else if (match_tok(p, TOK_DEFAULT)) {
                    expect_tok(p, TOK_COLON, "Expected ':' after default");
                } else {
                    set_parse_err(p, "Expected 'case' or 'default' in switch");
                    break;
                }
                uint32_t shead = 0, stail = 0;
                while (!p->has_err && p->cur.kind != TOK_CASE &&
                       p->cur.kind != TOK_DEFAULT && p->cur.kind != TOK_RBRACE &&
                       p->cur.kind != TOK_EOF) {
                    uint32_t st = parse_stmt(p);
                    if (st) {
                        if (!shead) shead = st;
                        else p->chunk->nodes[stail].next = st;
                        stail = st;
                    }
                }
                uint32_t cn = emit_node(p, AST_CASE, OP_NONE, 0, test, shead, 0);
                if (!chead) chead = cn;
                else p->chunk->nodes[ctail].next = cn;
                ctail = cn;
            }
            expect_tok(p, TOK_RBRACE, "Expected '}' after switch");
            return emit_node(p, AST_SWITCH, OP_NONE, 0, disc, chead, 0);
        }
        case TOK_RETURN: {
            next_token(p);
            uint32_t val = 0;
            if (!p->cur.had_newline && p->cur.kind != TOK_SEMI &&
                p->cur.kind != TOK_RBRACE && p->cur.kind != TOK_EOF) {
                val = parse_expr(p, true);
            }
            consume_asi(p);
            return emit_node(p, AST_RETURN, OP_NONE, 0, val, 0, 0);
        }
        case TOK_BREAK:
            next_token(p);
            consume_asi(p);
            return emit_node(p, AST_BREAK, OP_NONE, 0, 0, 0, 0);
        case TOK_CONTINUE:
            next_token(p);
            consume_asi(p);
            return emit_node(p, AST_CONTINUE, OP_NONE, 0, 0, 0, 0);
        case TOK_THROW: {
            next_token(p);
            uint32_t val = parse_expr(p, true);
            consume_asi(p);
            return emit_node(p, AST_THROW, OP_NONE, 0, val, 0, 0);
        }
        case TOK_TRY: {
            next_token(p);
            uint32_t try_blk   = parse_block(p);
            uint32_t catch_nod = 0;
            uint32_t fin_blk   = 0;
            if (match_tok(p, TOK_CATCH)) {
                uint32_t param_id = UINT32_MAX;
                if (match_tok(p, TOK_LPAREN)) {
                    if (p->cur.kind == TOK_IDENT) {
                        param_id = p->cur.str_id;
                        next_token(p);
                    }
                    expect_tok(p, TOK_RPAREN, "Expected ')' after catch parameter");
                }
                uint32_t cblk = parse_block(p);
                catch_nod = emit_node(p, AST_CATCH, OP_NONE, 0, param_id, cblk, 0);
            }
            if (match_tok(p, TOK_FINALLY)) {
                fin_blk = parse_block(p);
            }
            if (!catch_nod && !fin_blk) {
                set_parse_err(p, "Missing catch or finally after try");
            }
            return emit_node(p, AST_TRY, OP_NONE, 0, try_blk, catch_nod, fin_blk);
        }
        default: {
            /* Handle labeled statement `label: stmt` gracefully by stripping label */
            if (p->cur.kind == TOK_IDENT) {
                Lexer saved_lx  = p->lx;
                Token saved_cur = p->cur;
                next_token(p);
                if (p->cur.kind == TOK_COLON) {
                    next_token(p);
                    return parse_stmt(p);
                }
                p->lx  = saved_lx;
                p->cur = saved_cur;
            }
            uint32_t e = parse_expr(p, true);
            consume_asi(p);
            return emit_node(p, AST_EXPR_STMT, OP_NONE, 0, e, 0, 0);
        }
    }
}

void js_chunk_free(JsVm *vm, JsChunk *chunk) {
    if (!chunk) return;
    for (uint32_t i = 0; i < chunk->str_count; i++) {
        size_t slen = chunk->str_lens[i];
        tb_free(chunk->strs[i]);
        if (vm && vm->gc_bytes >= slen + 1 + sizeof(char *) + sizeof(uint32_t))
            vm->gc_bytes -= slen + 1 + sizeof(char *) + sizeof(uint32_t);
    }
    tb_free(chunk->strs);
    tb_free(chunk->str_lens);
    if (vm) {
        size_t nbytes = chunk->node_cap * sizeof(AstNode) + chunk->num_cap * sizeof(double) + sizeof(JsChunk);
        if (vm->gc_bytes >= nbytes) vm->gc_bytes -= nbytes;
        else vm->gc_bytes = 0;
    }
    tb_free(chunk->nodes);
    tb_free(chunk->nums);
    tb_free(chunk);
}

JsChunk *js_parse(JsVm *vm, const char *src, size_t len, bool is_func_body,
                  char *err_buf, size_t err_cap) {
    (void)is_func_body;
    JsChunk *ch = (JsChunk *)tb_calloc(1, sizeof(JsChunk));
    if (!ch) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "Out of memory allocating JsChunk");
        return NULL;
    }
    vm->gc_bytes += sizeof(JsChunk);
    ch->pinned  = 1;
    ch->gc_next = vm->chunks;
    vm->chunks  = ch;

    Parser p;
    memset(&p, 0, sizeof(p));
    p.vm      = vm;
    p.chunk   = ch;
    p.lx.src  = src ? src : "";
    p.lx.len  = len;
    p.lx.line = 1;

    /* Reserve index 0 as AST_NONE */
    emit_node(&p, AST_NONE, OP_NONE, 0, 0, 0, 0);

    next_token(&p);
    uint32_t head = 0, tail = 0;
    while (!p.has_err && p.cur.kind != TOK_EOF) {
        uint32_t st = parse_stmt(&p);
        if (st) {
            if (!head) head = st;
            else ch->nodes[tail].next = st;
            tail = st;
        }
    }

    if (p.has_err) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "%s", p.err);
        ch->pinned = 0;
        return NULL;
    }

    ch->root_idx = emit_node(&p, AST_PROGRAM, OP_NONE, 0, head, 0, 0);
    ch->pinned   = 0;
    return ch;
}
