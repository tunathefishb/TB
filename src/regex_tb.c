#include "regex_tb.h"
#include "common.h"

#define RX_MAX_LOOPS      64
#define RX_MAX_STEPS      250000U
#define RX_MAX_BT_DEPTH   4096

typedef enum {
    OP_RX_CHAR = 0,
    OP_RX_ANY,
    OP_RX_SHORTHAND,
    OP_RX_CLASS,
    OP_RX_BOL,
    OP_RX_EOL,
    OP_RX_BOUND,
    OP_RX_SAVE,
    OP_RX_CLEAR_CAPS,
    OP_RX_BACKREF,
    OP_RX_JMP,
    OP_RX_SPLIT,
    OP_RX_LOOP_INIT,
    OP_RX_LOOP_STEP,
    OP_RX_LOOKAHEAD,
    OP_RX_LOOK_END,
    OP_RX_MATCH
} RxOpcode;

#define SH_DIGIT     (1U << 0)
#define SH_NOT_DIGIT (1U << 1)
#define SH_WORD      (1U << 2)
#define SH_NOT_WORD  (1U << 3)
#define SH_SPACE     (1U << 4)
#define SH_NOT_SPACE (1U << 5)

typedef struct {
    uint32_t lo;
    uint32_t hi;
} RxRange;

typedef struct {
    bool      negated;
    uint32_t  shorthands;
    RxRange  *ranges;
    uint32_t  count;
    uint32_t  cap;
} RxClass;

typedef struct {
    uint8_t  op;
    uint8_t  u8;
    uint16_t u16;
    uint32_t x;
    uint32_t y;
    uint32_t z;
} RxInst;

struct TbRegex {
    uint32_t flags;
    uint32_t group_count; /* Includes group 0 */
    uint32_t loop_count;
    RxInst  *code;
    uint32_t code_len;
    uint32_t code_cap;
    RxClass *classes;
    uint32_t class_len;
    uint32_t class_cap;
};

static inline uint32_t rx_fold(uint32_t cp, bool icase) {
    if (!icase) return cp;
    if (cp >= 'A' && cp <= 'Z') return cp + ('a' - 'A');
    return cp;
}

static inline bool rx_is_digit(uint32_t cp) {
    return cp >= '0' && cp <= '9';
}

static inline bool rx_is_word(uint32_t cp) {
    return (cp >= 'a' && cp <= 'z') ||
           (cp >= 'A' && cp <= 'Z') ||
           (cp >= '0' && cp <= '9') ||
           cp == '_';
}

static inline bool rx_is_space(uint32_t cp) {
    return cp == ' ' || cp == '\t' || cp == '\n' || cp == '\r' ||
           cp == '\f' || cp == '\v' || cp == 0x00A0U || cp == 0xFEFFU ||
           cp == 0x2028U || cp == 0x2029U;
}

static inline bool rx_is_newline(uint32_t cp) {
    return cp == '\n' || cp == '\r' || cp == 0x2028U || cp == 0x2029U;
}

static bool rx_match_shorthand(uint32_t cp, uint32_t sh) {
    if ((sh & SH_DIGIT) && rx_is_digit(cp)) return true;
    if ((sh & SH_NOT_DIGIT) && !rx_is_digit(cp)) return true;
    if ((sh & SH_WORD) && rx_is_word(cp)) return true;
    if ((sh & SH_NOT_WORD) && !rx_is_word(cp)) return true;
    if ((sh & SH_SPACE) && rx_is_space(cp)) return true;
    if ((sh & SH_NOT_SPACE) && !rx_is_space(cp)) return true;
    return false;
}

static bool rx_match_class(const RxClass *cls, uint32_t cp, bool icase) {
    bool hit = rx_match_shorthand(cp, cls->shorthands);
    if (!hit) {
        uint32_t fcp = rx_fold(cp, icase);
        for (uint32_t i = 0; i < cls->count; i++) {
            uint32_t lo = cls->ranges[i].lo;
            uint32_t hi = cls->ranges[i].hi;
            if (icase) {
                /* Check both original and folded range bounds for mixed-case ranges like [A-f] */
                for (uint32_t c = cp; ; ) {
                    if (c >= lo && c <= hi) { hit = true; break; }
                    uint32_t alt = (cp >= 'a' && cp <= 'z') ? (cp - 32U)
                                 : ((cp >= 'A' && cp <= 'Z') ? (cp + 32U) : cp);
                    if (c == alt) break;
                    c = alt;
                }
                if (!hit && fcp >= rx_fold(lo, true) && fcp <= rx_fold(hi, true) &&
                    ((lo >= 'a' && hi <= 'z') || (lo >= 'A' && hi <= 'Z'))) {
                    hit = true;
                }
            } else if (cp >= lo && cp <= hi) {
                hit = true;
            }
            if (hit) break;
        }
    }
    return cls->negated ? !hit : hit;
}

/* ── Regex Parser & Compiler ── */
typedef struct {
    TbRegex    *rx;
    const char *pat;
    size_t      len;
    size_t      pos;
    bool        err;
    char        err_msg[128];
} RxCompiler;

static void rxc_fail(RxCompiler *c, const char *msg) {
    if (!c->err) {
        c->err = true;
        snprintf(c->err_msg, sizeof(c->err_msg), "%s", msg);
    }
}

static uint32_t rxc_emit(RxCompiler *c, uint8_t op, uint8_t u8, uint16_t u16,
                         uint32_t x, uint32_t y, uint32_t z) {
    if (c->err) return 0;
    TbRegex *rx = c->rx;
    if (rx->code_len >= rx->code_cap) {
        uint32_t ncap = rx->code_cap ? rx->code_cap * 2U : 32U;
        RxInst *nc = (RxInst *)tb_realloc(rx->code, ncap * sizeof(RxInst));
        if (!nc) {
            rxc_fail(c, "Out of memory compiling RegExp");
            return 0;
        }
        rx->code     = nc;
        rx->code_cap = ncap;
    }
    uint32_t pc = rx->code_len++;
    rx->code[pc].op  = op;
    rx->code[pc].u8  = u8;
    rx->code[pc].u16 = u16;
    rx->code[pc].x   = x;
    rx->code[pc].y   = y;
    rx->code[pc].z   = z;
    return pc;
}

static bool rxc_insert_space(RxCompiler *c, uint32_t at_pc, uint32_t count) {
    if (c->err) return false;
    TbRegex *rx = c->rx;
    while (rx->code_len + count > rx->code_cap) {
        uint32_t ncap = rx->code_cap ? rx->code_cap * 2U : 32U;
        RxInst *nc = (RxInst *)tb_realloc(rx->code, ncap * sizeof(RxInst));
        if (!nc) {
            rxc_fail(c, "Out of memory compiling RegExp");
            return false;
        }
        rx->code     = nc;
        rx->code_cap = ncap;
    }
    uint32_t tail = rx->code_len - at_pc;
    if (tail > 0) {
        memmove(&rx->code[at_pc + count], &rx->code[at_pc], tail * sizeof(RxInst));
    }
    rx->code_len += count;

    /* Relocate internal jump targets >= at_pc in the shifted block */
    for (uint32_t i = at_pc + count; i < rx->code_len; i++) {
        RxInst *in = &rx->code[i];
        if (in->op == OP_RX_JMP) {
            if (in->x >= at_pc) in->x += count;
        } else if (in->op == OP_RX_SPLIT) {
            if (in->x >= at_pc) in->x += count;
            if (in->y >= at_pc) in->y += count;
        } else if (in->op == OP_RX_LOOP_STEP) {
            if (in->y >= at_pc) in->y += count;
            if (in->z >= at_pc) in->z += count;
        } else if (in->op == OP_RX_LOOKAHEAD) {
            if (in->x >= at_pc) in->x += count;
            if (in->y >= at_pc) in->y += count;
        }
    }
    return true;
}

static int hex_digit(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
    return -1;
}

static uint32_t rxc_next_cp(RxCompiler *c) {
    uint32_t cp = 0;
    size_t adv = tb_utf8_decode(c->pat + c->pos, c->len - c->pos, &cp);
    c->pos += (adv > 0 ? adv : 1);
    return cp;
}

/* Parse escape after '\'. Returns true if a single codepoint (*out_cp), false if shorthand (*out_sh) */
static bool rxc_parse_escape(RxCompiler *c, bool in_class, uint32_t *out_cp, uint32_t *out_sh) {
    *out_cp = 0;
    *out_sh = 0;
    if (c->pos >= c->len) {
        rxc_fail(c, "SyntaxError: Trailing backslash in RegExp");
        return true;
    }
    char ch = c->pat[c->pos++];
    switch (ch) {
        case 'd': *out_sh = SH_DIGIT;     return false;
        case 'D': *out_sh = SH_NOT_DIGIT; return false;
        case 'w': *out_sh = SH_WORD;      return false;
        case 'W': *out_sh = SH_NOT_WORD;  return false;
        case 's': *out_sh = SH_SPACE;     return false;
        case 'S': *out_sh = SH_NOT_SPACE; return false;
        case 'n': *out_cp = '\n'; return true;
        case 'r': *out_cp = '\r'; return true;
        case 't': *out_cp = '\t'; return true;
        case 'f': *out_cp = '\f'; return true;
        case 'v': *out_cp = '\v'; return true;
        case 'b':
            if (in_class) { *out_cp = '\b'; return true; }
            break;
        case '0': *out_cp = 0; return true;
        case 'c': {
            if (c->pos < c->len) {
                char ctrl = c->pat[c->pos++];
                *out_cp = (uint32_t)(ctrl & 0x1F);
            } else {
                *out_cp = 'c';
            }
            return true;
        }
        case 'x': {
            if (c->pos + 2 <= c->len &&
                hex_digit(c->pat[c->pos]) >= 0 && hex_digit(c->pat[c->pos + 1]) >= 0) {
                *out_cp = (uint32_t)((hex_digit(c->pat[c->pos]) << 4) |
                                     hex_digit(c->pat[c->pos + 1]));
                c->pos += 2;
            } else {
                *out_cp = 'x';
            }
            return true;
        }
        case 'u': {
            if (c->pos < c->len && c->pat[c->pos] == '{') {
                size_t k = c->pos + 1;
                uint32_t v = 0;
                int digits = 0;
                while (k < c->len && c->pat[k] != '}') {
                    int hd = hex_digit(c->pat[k]);
                    if (hd < 0) { digits = -1; break; }
                    v = (v << 4) | (uint32_t)hd;
                    digits++;
                    k++;
                }
                if (digits > 0 && k < c->len && c->pat[k] == '}' && v <= 0x10FFFFU) {
                    c->pos = k + 1;
                    *out_cp = v;
                    return true;
                }
            }
            if (c->pos + 4 <= c->len &&
                hex_digit(c->pat[c->pos]) >= 0 && hex_digit(c->pat[c->pos + 1]) >= 0 &&
                hex_digit(c->pat[c->pos + 2]) >= 0 && hex_digit(c->pat[c->pos + 3]) >= 0) {
                *out_cp = (uint32_t)((hex_digit(c->pat[c->pos]) << 12) |
                                     (hex_digit(c->pat[c->pos + 1]) << 8) |
                                     (hex_digit(c->pat[c->pos + 2]) << 4) |
                                     hex_digit(c->pat[c->pos + 3]));
                c->pos += 4;
            } else {
                *out_cp = 'u';
            }
            return true;
        }
        default:
            break;
    }
    c->pos--;
    *out_cp = rxc_next_cp(c);
    return true;
}

static bool cls_push_range(RxClass *cls, uint32_t lo, uint32_t hi) {
    if (lo > hi) return false;
    if (cls->count >= cls->cap) {
        uint32_t ncap = cls->cap ? cls->cap * 2U : 8U;
        RxRange *nr = (RxRange *)tb_realloc(cls->ranges, ncap * sizeof(RxRange));
        if (!nr) return false;
        cls->ranges = nr;
        cls->cap    = ncap;
    }
    cls->ranges[cls->count].lo = lo;
    cls->ranges[cls->count].hi = hi;
    cls->count++;
    return true;
}

static void rxc_parse_class(RxCompiler *c) {
    TbRegex *rx = c->rx;
    if (rx->class_len >= rx->class_cap) {
        uint32_t ncap = rx->class_cap ? rx->class_cap * 2U : 8U;
        RxClass *nc = (RxClass *)tb_realloc(rx->classes, ncap * sizeof(RxClass));
        if (!nc) { rxc_fail(c, "Out of memory compiling RegExp class"); return; }
        rx->classes   = nc;
        rx->class_cap = ncap;
    }
    uint32_t cls_id = rx->class_len++;
    RxClass *cls = &rx->classes[cls_id];
    memset(cls, 0, sizeof(*cls));

    if (c->pos < c->len && c->pat[c->pos] == '^') {
        cls->negated = true;
        c->pos++;
    }

    bool have_prev_cp = false;
    uint32_t prev_cp  = 0;
    bool closed       = false;

    while (c->pos < c->len && !c->err) {
        if (c->pat[c->pos] == ']') {
            c->pos++;
            closed = true;
            break;
        }
        if (have_prev_cp && c->pat[c->pos] == '-' &&
            c->pos + 1 < c->len && c->pat[c->pos + 1] != ']') {
            c->pos++; /* consume '-' */
            uint32_t hi_cp = 0, hi_sh = 0;
            bool is_cp = true;
            if (c->pat[c->pos] == '\\') {
                c->pos++;
                is_cp = rxc_parse_escape(c, true, &hi_cp, &hi_sh);
            } else {
                hi_cp = rxc_next_cp(c);
            }
            if (!is_cp) {
                /* e.g. [a-\d] in sloppy JS: treat prev_cp and '-' as literals, plus shorthand */
                cls_push_range(cls, prev_cp, prev_cp);
                cls_push_range(cls, '-', '-');
                cls->shorthands |= hi_sh;
            } else {
                if (prev_cp > hi_cp) {
                    rxc_fail(c, "SyntaxError: Range out of order in character class");
                    return;
                }
                cls_push_range(cls, prev_cp, hi_cp);
            }
            have_prev_cp = false;
            continue;
        }

        if (have_prev_cp) {
            cls_push_range(cls, prev_cp, prev_cp);
            have_prev_cp = false;
        }

        if (c->pat[c->pos] == '\\') {
            c->pos++;
            uint32_t cp = 0, sh = 0;
            if (rxc_parse_escape(c, true, &cp, &sh)) {
                prev_cp      = cp;
                have_prev_cp = true;
            } else {
                cls->shorthands |= sh;
            }
        } else {
            prev_cp      = rxc_next_cp(c);
            have_prev_cp = true;
        }
    }

    if (!closed) {
        rxc_fail(c, "SyntaxError: Unterminated character class in RegExp");
        return;
    }
    if (have_prev_cp) {
        cls_push_range(cls, prev_cp, prev_cp);
    }
    rxc_emit(c, OP_RX_CLASS, 0, 0, cls_id, 0, 0);
}

static void rxc_parse_alt(RxCompiler *c);

/* Parse a single atom; returns true if atom is quantifiable */
static bool rxc_parse_atom(RxCompiler *c, uint32_t *atom_start_pc,
                           uint32_t *first_inner_grp, uint32_t *last_inner_grp) {
    *atom_start_pc   = c->rx->code_len;
    *first_inner_grp = c->rx->group_count;
    *last_inner_grp  = c->rx->group_count;

    char ch = c->pat[c->pos];
    if (ch == '^') {
        c->pos++;
        rxc_emit(c, OP_RX_BOL, 0, 0, 0, 0, 0);
        return false;
    }
    if (ch == '$') {
        c->pos++;
        rxc_emit(c, OP_RX_EOL, 0, 0, 0, 0, 0);
        return false;
    }
    if (ch == '.') {
        c->pos++;
        rxc_emit(c, OP_RX_ANY, 0, 0, 0, 0, 0);
        return true;
    }
    if (ch == '[') {
        c->pos++;
        rxc_parse_class(c);
        return true;
    }
    if (ch == '(') {
        c->pos++;
        bool capturing = true;
        bool lookahead = false;
        bool look_neg  = false;
        uint32_t grp_id = 0;

        if (c->pos < c->len && c->pat[c->pos] == '?') {
            if (c->pos + 1 < c->len && c->pat[c->pos + 1] == ':') {
                capturing = false;
                c->pos += 2;
            } else if (c->pos + 1 < c->len &&
                       (c->pat[c->pos + 1] == '=' || c->pat[c->pos + 1] == '!')) {
                capturing = false;
                lookahead = true;
                look_neg  = (c->pat[c->pos + 1] == '!');
                c->pos += 2;
            } else {
                rxc_fail(c, "SyntaxError: Invalid group modifier in RegExp");
                return false;
            }
        }

        if (lookahead) {
            uint32_t la_pc = rxc_emit(c, OP_RX_LOOKAHEAD, look_neg ? 1 : 0, 0, 0, 0, 0);
            uint32_t sub_pc = c->rx->code_len;
            rxc_parse_alt(c);
            if (c->pos >= c->len || c->pat[c->pos] != ')') {
                rxc_fail(c, "SyntaxError: Unterminated lookahead group");
                return false;
            }
            c->pos++;
            rxc_emit(c, OP_RX_LOOK_END, 0, 0, 0, 0, 0);
            c->rx->code[la_pc].x = sub_pc;
            c->rx->code[la_pc].y = c->rx->code_len;
            *last_inner_grp = c->rx->group_count;
            return false;
        }

        if (capturing && c->rx->group_count < TB_REGEX_MAX_GROUPS) {
            grp_id = c->rx->group_count++;
            rxc_emit(c, OP_RX_SAVE, 0, 0, grp_id * 2U, 0, 0);
        }

        rxc_parse_alt(c);
        if (c->pos >= c->len || c->pat[c->pos] != ')') {
            rxc_fail(c, "SyntaxError: Unterminated '(' in RegExp");
            return false;
        }
        c->pos++;

        if (capturing && grp_id > 0) {
            rxc_emit(c, OP_RX_SAVE, 0, 0, grp_id * 2U + 1U, 0, 0);
        }
        *last_inner_grp = c->rx->group_count;
        return true;
    }
    if (ch == '\\') {
        c->pos++;
        if (c->pos >= c->len) {
            rxc_fail(c, "SyntaxError: Trailing backslash in RegExp");
            return false;
        }
        char nxt = c->pat[c->pos];
        if (nxt == 'b' || nxt == 'B') {
            c->pos++;
            rxc_emit(c, OP_RX_BOUND, (nxt == 'B') ? 1 : 0, 0, 0, 0, 0);
            return false;
        }
        if (nxt >= '1' && nxt <= '9') {
            uint32_t ref = (uint32_t)(nxt - '0');
            c->pos++;
            if (c->pos < c->len && c->pat[c->pos] >= '0' && c->pat[c->pos] <= '9') {
                uint32_t ref2 = ref * 10U + (uint32_t)(c->pat[c->pos] - '0');
                if (ref2 < TB_REGEX_MAX_GROUPS) {
                    ref = ref2;
                    c->pos++;
                }
            }
            rxc_emit(c, OP_RX_BACKREF, 0, 0, ref, 0, 0);
            return true;
        }
        uint32_t cp = 0, sh = 0;
        if (rxc_parse_escape(c, false, &cp, &sh)) {
            bool ic = (c->rx->flags & TB_RX_ICASE) != 0;
            rxc_emit(c, OP_RX_CHAR, 0, 0, rx_fold(cp, ic), 0, 0);
        } else {
            rxc_emit(c, OP_RX_SHORTHAND, 0, 0, sh, 0, 0);
        }
        return true;
    }
    if (ch == '*' || ch == '+' || ch == '?') {
        rxc_fail(c, "SyntaxError: Nothing to repeat in RegExp");
        return false;
    }

    uint32_t cp = rxc_next_cp(c);
    bool ic = (c->rx->flags & TB_RX_ICASE) != 0;
    rxc_emit(c, OP_RX_CHAR, 0, 0, rx_fold(cp, ic), 0, 0);
    return true;
}

static bool rxc_try_parse_brace_quant(RxCompiler *c, uint32_t *out_min, uint32_t *out_max) {
    size_t k = c->pos + 1;
    if (k >= c->len || c->pat[k] < '0' || c->pat[k] > '9') return false;
    uint32_t qmin = 0;
    while (k < c->len && c->pat[k] >= '0' && c->pat[k] <= '9') {
        qmin = qmin * 10U + (uint32_t)(c->pat[k] - '0');
        if (qmin > 65535U) qmin = 65535U;
        k++;
    }
    uint32_t qmax = qmin;
    if (k < c->len && c->pat[k] == ',') {
        k++;
        if (k < c->len && c->pat[k] == '}') {
            qmax = UINT32_MAX;
        } else {
            if (k >= c->len || c->pat[k] < '0' || c->pat[k] > '9') return false;
            qmax = 0;
            while (k < c->len && c->pat[k] >= '0' && c->pat[k] <= '9') {
                qmax = qmax * 10U + (uint32_t)(c->pat[k] - '0');
                if (qmax > 65535U) qmax = 65535U;
                k++;
            }
        }
    }
    if (k >= c->len || c->pat[k] != '}') return false;
    if (qmax < qmin) {
        rxc_fail(c, "SyntaxError: Numbers out of order in {} quantifier");
        return false;
    }
    c->pos   = k + 1;
    *out_min = qmin;
    *out_max = qmax;
    return true;
}

static void rxc_parse_seq(RxCompiler *c) {
    while (c->pos < c->len && !c->err) {
        char ch = c->pat[c->pos];
        if (ch == '|' || ch == ')') break;

        uint32_t atom_pc = 0, grp_lo = 0, grp_hi = 0;
        bool quantifiable = rxc_parse_atom(c, &atom_pc, &grp_lo, &grp_hi);
        if (c->err || c->pos >= c->len) break;

        char qch = c->pat[c->pos];
        bool has_q    = false;
        uint32_t qmin = 1, qmax = 1;

        if (qch == '*') { has_q = true; qmin = 0; qmax = UINT32_MAX; c->pos++; }
        else if (qch == '+') { has_q = true; qmin = 1; qmax = UINT32_MAX; c->pos++; }
        else if (qch == '?') { has_q = true; qmin = 0; qmax = 1; c->pos++; }
        else if (qch == '{') {
            has_q = rxc_try_parse_brace_quant(c, &qmin, &qmax);
            if (c->err) return;
        }

        if (!has_q) continue;
        if (!quantifiable) {
            rxc_fail(c, "SyntaxError: Invalid quantifier on assertion");
            return;
        }

        bool greedy = true;
        if (c->pos < c->len && c->pat[c->pos] == '?') {
            greedy = false;
            c->pos++;
        }

        if (qmin == 1 && qmax == 1) continue;
        if (qmin == 0 && qmax == 0) {
            c->rx->code_len = atom_pc;
            if (grp_hi > grp_lo) {
                rxc_emit(c, OP_RX_CLEAR_CAPS, (uint8_t)grp_lo, (uint16_t)grp_hi, 0, 0, 0);
            }
            continue;
        }

        /* Reset inner capture slots at start of each repeated group iteration per JS spec */
        if (grp_hi > grp_lo && !(qmin == 0 && qmax == 1)) {
            if (!rxc_insert_space(c, atom_pc, 1)) return;
            c->rx->code[atom_pc].op  = OP_RX_CLEAR_CAPS;
            c->rx->code[atom_pc].u8  = (uint8_t)grp_lo;
            c->rx->code[atom_pc].u16 = (uint16_t)grp_hi;
            c->rx->code[atom_pc].x   = 0;
            c->rx->code[atom_pc].y   = 0;
            c->rx->code[atom_pc].z   = 0;
        }

        if (qmin == 0 && qmax == 1) {
            /* E? / E?? */
            if (!rxc_insert_space(c, atom_pc, 1)) return;
            uint32_t body_pc = atom_pc + 1U;
            uint32_t end_pc  = c->rx->code_len;
            c->rx->code[atom_pc].op  = OP_RX_SPLIT;
            c->rx->code[atom_pc].u8  = 0;
            c->rx->code[atom_pc].u16 = 0;
            c->rx->code[atom_pc].x   = greedy ? body_pc : end_pc;
            c->rx->code[atom_pc].y   = greedy ? end_pc : body_pc;
            c->rx->code[atom_pc].z   = 0;
        } else if (c->rx->loop_count < RX_MAX_LOOPS) {
            /* Unified counted loop handles *, +, {n,m}, greedy & non-greedy, + empty-loop guard! */
            uint8_t lid = (uint8_t)(c->rx->loop_count++);
            uint16_t max16 = (qmax == UINT32_MAX) ? 0xFFFFU : (uint16_t)(qmax > 0xFFFEU ? 0xFFFEU : qmax);
            if (!rxc_insert_space(c, atom_pc, 2)) return;
            uint32_t step_pc = atom_pc + 1U;
            uint32_t body_pc = atom_pc + 2U;

            c->rx->code[atom_pc].op  = OP_RX_LOOP_INIT;
            c->rx->code[atom_pc].u8  = lid;
            c->rx->code[atom_pc].u16 = 0;
            c->rx->code[atom_pc].x   = 0;
            c->rx->code[atom_pc].y   = 0;
            c->rx->code[atom_pc].z   = 0;

            rxc_emit(c, OP_RX_JMP, 0, 0, step_pc, 0, 0);
            uint32_t exit_pc = c->rx->code_len;

            c->rx->code[step_pc].op  = OP_RX_LOOP_STEP;
            c->rx->code[step_pc].u8  = (uint8_t)(lid | (greedy ? 0x80U : 0U));
            c->rx->code[step_pc].u16 = max16;
            c->rx->code[step_pc].x   = qmin;
            c->rx->code[step_pc].y   = body_pc;
            c->rx->code[step_pc].z   = exit_pc;
        } else {
            rxc_fail(c, "SyntaxError: RegExp exceeds 64 quantifier loops");
            return;
        }
    }
}

static void rxc_parse_alt(RxCompiler *c) {
    uint32_t branch_start = c->rx->code_len;
    rxc_parse_seq(c);
    while (!c->err && c->pos < c->len && c->pat[c->pos] == '|') {
        c->pos++; /* consume '|' */
        if (!rxc_insert_space(c, branch_start, 1)) return;
        uint32_t left_pc = branch_start + 1U;
        uint32_t jmp_pc  = rxc_emit(c, OP_RX_JMP, 0, 0, 0, 0, 0);
        uint32_t right_pc = c->rx->code_len;

        rxc_parse_seq(c);
        uint32_t end_pc = c->rx->code_len;

        c->rx->code[branch_start].op  = OP_RX_SPLIT;
        c->rx->code[branch_start].u8  = 0;
        c->rx->code[branch_start].u16 = 0;
        c->rx->code[branch_start].x   = left_pc;
        c->rx->code[branch_start].y   = right_pc;
        c->rx->code[branch_start].z   = 0;
        c->rx->code[jmp_pc].x         = end_pc;
    }
}

TbRegex *tb_regex_compile(const char *pattern, const char *flags,
                          char *err_buf, size_t err_cap) {
    if (!pattern) pattern = "";
    if (!flags) flags = "";

    uint32_t fmask = 0;
    for (size_t i = 0; flags[i]; i++) {
        uint32_t bit = 0;
        switch (flags[i]) {
            case 'g': bit = TB_RX_GLOBAL; break;
            case 'i': bit = TB_RX_ICASE; break;
            case 'm': bit = TB_RX_MULTILINE; break;
            case 's': bit = TB_RX_DOTALL; break;
            case 'y': bit = TB_RX_STICKY; break;
            case 'u': bit = TB_RX_UNICODE; break;
            case 'd': bit = 0; break;
            default:
                if (err_buf && err_cap > 0)
                    snprintf(err_buf, err_cap, "SyntaxError: Invalid RegExp flag '%c'", flags[i]);
                return NULL;
        }
        if (bit && (fmask & bit)) {
            if (err_buf && err_cap > 0)
                snprintf(err_buf, err_cap, "SyntaxError: Duplicate RegExp flag '%c'", flags[i]);
            return NULL;
        }
        fmask |= bit;
    }

    TbRegex *rx = (TbRegex *)tb_calloc(1, sizeof(TbRegex));
    if (!rx) return NULL;
    rx->flags       = fmask;
    rx->group_count = 1; /* Group 0 = full match */

    RxCompiler c;
    memset(&c, 0, sizeof(c));
    c.rx  = rx;
    c.pat = pattern;
    c.len = strlen(pattern);

    rxc_emit(&c, OP_RX_SAVE, 0, 0, 0, 0, 0);
    rxc_parse_alt(&c);
    if (!c.err && c.pos < c.len) {
        rxc_fail(&c, "SyntaxError: Unmatched ')' in RegExp");
    }
    rxc_emit(&c, OP_RX_SAVE, 0, 0, 1, 0, 0);
    rxc_emit(&c, OP_RX_MATCH, 0, 0, 0, 0, 0);

    if (c.err) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "%s", c.err_msg);
        tb_regex_free(rx);
        return NULL;
    }
    return rx;
}

void tb_regex_free(TbRegex *rx) {
    if (!rx) return;
    if (rx->classes) {
        for (uint32_t i = 0; i < rx->class_len; i++) {
            tb_free(rx->classes[i].ranges);
        }
        tb_free(rx->classes);
    }
    tb_free(rx->code);
    tb_free(rx);
}

size_t tb_regex_mem_size(const TbRegex *rx) {
    if (!rx) return 0;
    size_t sz = sizeof(TbRegex) + rx->code_cap * sizeof(RxInst) + rx->class_cap * sizeof(RxClass);
    for (uint32_t i = 0; i < rx->class_len; i++) {
        sz += rx->classes[i].cap * sizeof(RxRange);
    }
    return sz;
}

uint32_t tb_regex_flags(const TbRegex *rx) {
    return rx ? rx->flags : 0;
}

uint32_t tb_regex_group_count(const TbRegex *rx) {
    return rx ? rx->group_count : 0;
}

/* ── Heap-Backed Backtracking Bytecode VM (Bounded Steps, Zero C Stack Blowup) ── */
typedef struct {
    uint32_t pc;
    size_t   sp;
    size_t   caps[TB_REGEX_MAX_GROUPS * 2];
    uint16_t loop_cnt[RX_MAX_LOOPS];
    size_t   loop_sp[RX_MAX_LOOPS];
} RxBtFrame;

typedef struct {
    const TbRegex *rx;
    const char    *subj;
    size_t         slen;
    uint32_t       steps;
    RxBtFrame     *bt;
    uint32_t       bt_cap;
} RxVmCtx;

static bool rx_push_bt(RxVmCtx *ctx, uint32_t *bt_sp, uint32_t base_sp,
                       uint32_t pc, size_t sp,
                       const size_t *caps, uint32_t ncap_slots,
                       const uint16_t *lcnt, const size_t *lsp, uint32_t nloops) {
    if (*bt_sp - base_sp >= RX_MAX_BT_DEPTH) return false;
    if (*bt_sp >= ctx->bt_cap) {
        uint32_t ncap = ctx->bt_cap ? ctx->bt_cap * 2U : 64U;
        if (ncap > RX_MAX_BT_DEPTH + 128U) ncap = RX_MAX_BT_DEPTH + 128U;
        if (*bt_sp >= ncap) return false;
        RxBtFrame *nb = (RxBtFrame *)tb_realloc(ctx->bt, ncap * sizeof(RxBtFrame));
        if (!nb) return false;
        ctx->bt     = nb;
        ctx->bt_cap = ncap;
    }
    RxBtFrame *f = &ctx->bt[(*bt_sp)++];
    f->pc = pc;
    f->sp = sp;
    memcpy(f->caps, caps, ncap_slots * sizeof(size_t));
    if (nloops > 0) {
        memcpy(f->loop_cnt, lcnt, nloops * sizeof(uint16_t));
        memcpy(f->loop_sp, lsp, nloops * sizeof(size_t));
    }
    return true;
}

static bool rx_run_sub(RxVmCtx *ctx, uint32_t start_pc, size_t start_sp,
                       size_t *io_caps, uint32_t *io_bt_sp, bool stop_on_look_end) {
    const TbRegex *rx = ctx->rx;
    const bool icase  = (rx->flags & TB_RX_ICASE) != 0;
    const bool multi  = (rx->flags & TB_RX_MULTILINE) != 0;
    const bool dotall = (rx->flags & TB_RX_DOTALL) != 0;
    const uint32_t ncap_slots = rx->group_count * 2U;
    const uint32_t nloops     = rx->loop_count;

    uint32_t pc = start_pc;
    size_t   sp = start_sp;
    uint16_t loop_cnt[RX_MAX_LOOPS] = {0};
    size_t   loop_sp[RX_MAX_LOOPS];
    for (uint32_t i = 0; i < nloops; i++) loop_sp[i] = SIZE_MAX;

    uint32_t base_bt = *io_bt_sp;

    for (;;) {
        for (;;) {
            if (++ctx->steps > RX_MAX_STEPS) {
                *io_bt_sp = base_bt;
                return false;
            }
            const RxInst *in = &rx->code[pc];
            switch ((RxOpcode)in->op) {
                case OP_RX_CHAR: {
                    if (sp >= ctx->slen) goto backtrack;
                    uint32_t cp = 0;
                    size_t adv = tb_utf8_decode(ctx->subj + sp, ctx->slen - sp, &cp);
                    if (adv == 0 || rx_fold(cp, icase) != in->x) goto backtrack;
                    sp += adv;
                    pc++;
                    break;
                }
                case OP_RX_ANY: {
                    if (sp >= ctx->slen) goto backtrack;
                    uint32_t cp = 0;
                    size_t adv = tb_utf8_decode(ctx->subj + sp, ctx->slen - sp, &cp);
                    if (adv == 0 || (!dotall && rx_is_newline(cp))) goto backtrack;
                    sp += adv;
                    pc++;
                    break;
                }
                case OP_RX_SHORTHAND: {
                    if (sp >= ctx->slen) goto backtrack;
                    uint32_t cp = 0;
                    size_t adv = tb_utf8_decode(ctx->subj + sp, ctx->slen - sp, &cp);
                    if (adv == 0 || !rx_match_shorthand(cp, in->x)) goto backtrack;
                    sp += adv;
                    pc++;
                    break;
                }
                case OP_RX_CLASS: {
                    if (sp >= ctx->slen) goto backtrack;
                    uint32_t cp = 0;
                    size_t adv = tb_utf8_decode(ctx->subj + sp, ctx->slen - sp, &cp);
                    if (adv == 0 || !rx_match_class(&rx->classes[in->x], cp, icase)) goto backtrack;
                    sp += adv;
                    pc++;
                    break;
                }
                case OP_RX_BOL: {
                    bool ok = (sp == 0) ||
                              (multi && sp > 0 &&
                               (ctx->subj[sp - 1] == '\n' ||
                                (ctx->subj[sp - 1] == '\r' && (sp >= ctx->slen || ctx->subj[sp] != '\n'))));
                    if (!ok) goto backtrack;
                    pc++;
                    break;
                }
                case OP_RX_EOL: {
                    bool ok = (sp == ctx->slen) ||
                              (multi && sp < ctx->slen &&
                               (ctx->subj[sp] == '\n' || ctx->subj[sp] == '\r'));
                    if (!ok) goto backtrack;
                    pc++;
                    break;
                }
                case OP_RX_BOUND: {
                    bool lw = (sp > 0) && rx_is_word((uint8_t)ctx->subj[sp - 1]);
                    bool rw = (sp < ctx->slen) && rx_is_word((uint8_t)ctx->subj[sp]);
                    bool is_b = (lw != rw);
                    if (in->u8 ? is_b : !is_b) goto backtrack;
                    pc++;
                    break;
                }
                case OP_RX_SAVE: {
                    if (in->x < ncap_slots) io_caps[in->x] = sp;
                    pc++;
                    break;
                }
                case OP_RX_CLEAR_CAPS: {
                    for (uint32_t g = in->u8; g < in->u16 && g < TB_REGEX_MAX_GROUPS; g++) {
                        io_caps[g * 2U]      = SIZE_MAX;
                        io_caps[g * 2U + 1U] = SIZE_MAX;
                    }
                    pc++;
                    break;
                }
                case OP_RX_BACKREF: {
                    uint32_t g = in->x;
                    if (g < rx->group_count &&
                        io_caps[g * 2U] != SIZE_MAX && io_caps[g * 2U + 1U] != SIZE_MAX) {
                        size_t cs   = io_caps[g * 2U];
                        size_t clen = io_caps[g * 2U + 1U] - cs;
                        if (sp + clen > ctx->slen) goto backtrack;
                        if (icase) {
                            if (tb_strncasecmp(ctx->subj + sp, ctx->subj + cs, clen) != 0)
                                goto backtrack;
                        } else {
                            if (memcmp(ctx->subj + sp, ctx->subj + cs, clen) != 0)
                                goto backtrack;
                        }
                        sp += clen;
                    }
                    pc++;
                    break;
                }
                case OP_RX_JMP:
                    pc = in->x;
                    break;
                case OP_RX_SPLIT: {
                    (void)rx_push_bt(ctx, io_bt_sp, base_bt, in->y, sp,
                                     io_caps, ncap_slots, loop_cnt, loop_sp, nloops);
                    pc = in->x;
                    break;
                }
                case OP_RX_LOOP_INIT: {
                    uint8_t lid = in->u8;
                    loop_cnt[lid] = 0;
                    loop_sp[lid]  = SIZE_MAX;
                    pc++;
                    break;
                }
                case OP_RX_LOOP_STEP: {
                    uint8_t  lid    = (uint8_t)(in->u8 & 0x7FU);
                    bool     greedy = (in->u8 & 0x80U) != 0;
                    uint32_t qmin   = in->x;
                    uint16_t qmax   = in->u16;
                    uint32_t body_pc = in->y;
                    uint32_t exit_pc = in->z;
                    uint16_t cnt    = loop_cnt[lid];

                    /* Zero-length repetition progress guard once qmin is satisfied */
                    if (cnt > 0 && cnt >= qmin && loop_sp[lid] == sp) {
                        pc = exit_pc;
                        break;
                    }
                    if (qmax != 0xFFFFU && cnt >= qmax) {
                        pc = exit_pc;
                        break;
                    }
                    if (cnt < qmin) {
                        loop_cnt[lid] = (uint16_t)(cnt + 1U);
                        loop_sp[lid]  = sp;
                        pc = body_pc;
                        break;
                    }
                    /* Optional repetition: cnt >= qmin && (unbounded || cnt < qmax) */
                    if (greedy) {
                        (void)rx_push_bt(ctx, io_bt_sp, base_bt, exit_pc, sp,
                                         io_caps, ncap_slots, loop_cnt, loop_sp, nloops);
                        loop_cnt[lid] = (uint16_t)(cnt + 1U);
                        loop_sp[lid]  = sp;
                        pc = body_pc;
                    } else {
                        uint16_t next_cnt = (uint16_t)(cnt + 1U);
                        size_t   prev_lsp = loop_sp[lid];
                        loop_cnt[lid] = next_cnt;
                        loop_sp[lid]  = sp;
                        (void)rx_push_bt(ctx, io_bt_sp, base_bt, body_pc, sp,
                                         io_caps, ncap_slots, loop_cnt, loop_sp, nloops);
                        loop_cnt[lid] = cnt;
                        loop_sp[lid]  = prev_lsp;
                        pc = exit_pc;
                    }
                    break;
                }
                case OP_RX_LOOKAHEAD: {
                    bool neg = (in->u8 != 0);
                    size_t sub_caps[TB_REGEX_MAX_GROUPS * 2];
                    memcpy(sub_caps, io_caps, ncap_slots * sizeof(size_t));
                    bool hit = rx_run_sub(ctx, in->x, sp, sub_caps, io_bt_sp, true);
                    if (neg ? hit : !hit) goto backtrack;
                    if (!neg) {
                        memcpy(io_caps, sub_caps, ncap_slots * sizeof(size_t));
                    }
                    pc = in->y;
                    break;
                }
                case OP_RX_LOOK_END:
                    if (stop_on_look_end) {
                        *io_bt_sp = base_bt;
                        return true;
                    }
                    pc++;
                    break;
                case OP_RX_MATCH:
                    *io_bt_sp = base_bt;
                    return true;
            }
        }

    backtrack:
        if (*io_bt_sp <= base_bt) {
            return false;
        }
        const RxBtFrame *f = &ctx->bt[--(*io_bt_sp)];
        pc = f->pc;
        sp = f->sp;
        memcpy(io_caps, f->caps, ncap_slots * sizeof(size_t));
        if (nloops > 0) {
            memcpy(loop_cnt, f->loop_cnt, nloops * sizeof(uint16_t));
            memcpy(loop_sp, f->loop_sp, nloops * sizeof(size_t));
        }
    }
}

bool tb_regex_exec(const TbRegex *rx, const char *subj, size_t subj_len,
                   size_t start_offset, TbRegexMatch *out_match) {
    if (!rx || !subj || start_offset > subj_len) return false;

    RxVmCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rx   = rx;
    ctx.subj = subj;
    ctx.slen = subj_len;

    size_t caps[TB_REGEX_MAX_GROUPS * 2];
    uint32_t nslots = rx->group_count * 2U;
    bool sticky = (rx->flags & TB_RX_STICKY) != 0;
    /* Optimization: un-multiline '^' at start of pattern anchors to offset 0 */
    bool anchored_zero = !(rx->flags & TB_RX_MULTILINE) &&
                         rx->code_len >= 2 &&
                         rx->code[0].op == OP_RX_SAVE &&
                         rx->code[1].op == OP_RX_BOL;

    for (size_t pos = start_offset; pos <= subj_len; ) {
        if (anchored_zero && pos > 0) break;
        for (uint32_t i = 0; i < nslots; i++) caps[i] = SIZE_MAX;
        uint32_t bt_sp = 0;
        ctx.steps = 0;

        if (rx_run_sub(&ctx, 0, pos, caps, &bt_sp, false)) {
            tb_free(ctx.bt);
            if (out_match) {
                out_match->group_count = rx->group_count;
                for (uint32_t g = 0; g < TB_REGEX_MAX_GROUPS; g++) {
                    if (g < rx->group_count) {
                        out_match->starts[g] = caps[g * 2U];
                        out_match->ends[g]   = caps[g * 2U + 1U];
                    } else {
                        out_match->starts[g] = SIZE_MAX;
                        out_match->ends[g]   = SIZE_MAX;
                    }
                }
            }
            return true;
        }
        if (sticky || pos == subj_len) break;
        if (rx->flags & TB_RX_UNICODE) {
            uint32_t dummy = 0;
            size_t adv = tb_utf8_decode(subj + pos, subj_len - pos, &dummy);
            pos += (adv > 0 ? adv : 1);
        } else {
            pos++;
        }
    }

    tb_free(ctx.bt);
    return false;
}
