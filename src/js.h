#ifndef TB_JS_H
#define TB_JS_H

#include "common.h"
#include "dom.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Hard JS GC heap cap: 2.5 MB (well inside the 7.5 MB total heap & <10 MB VmRSS target) */
#define JS_INITIAL_GC_THRESHOLD (256UL * 1024UL)
#define JS_MAX_HEAP_BYTES       (2560UL * 1024UL)
#define JS_DEFAULT_STEP_LIMIT   2000000U
#define JS_MAX_CALL_DEPTH       128
#define JS_MAX_TEMP_ROOTS       2048

typedef struct JsVm    JsVm;
typedef struct JsObj   JsObj;
typedef struct JsStr   JsStr;
typedef struct JsEnv   JsEnv;
typedef struct JsChunk JsChunk;

typedef enum {
    JS_UNDEFINED = 0,
    JS_NULL,
    JS_BOOL,
    JS_NUMBER,
    JS_OBJECT
} JsValType;

typedef struct {
    JsValType type;
    union {
        bool   boolean;
        double num;
        JsObj *obj;
    } u;
} JsVal;

typedef enum {
    OBJ_STRING = 1,
    OBJ_OBJECT,
    OBJ_ARRAY,
    OBJ_FUNC,
    OBJ_NATIVE_FN,
    OBJ_REGEX,
    OBJ_ENV
} JsObjType;

typedef enum {
    NATIVE_TAG_NONE = 0,
    NATIVE_TAG_WINDOW,
    NATIVE_TAG_DOCUMENT,
    NATIVE_TAG_DOM_NODE,
    NATIVE_TAG_STYLE,
    NATIVE_TAG_CLASSLIST,
    NATIVE_TAG_DATASET,
    NATIVE_TAG_PERF,
    NATIVE_TAG_LOCATION
} JsNativeTag;

struct JsObj {
    JsObj    *gc_next;
    uint32_t  alloc_size;
    uint8_t   obj_type;
    uint8_t   gc_mark;
    uint8_t   native_tag;
    uint8_t   pad;
};

struct JsStr {
    JsObj    hdr;
    uint32_t len;
    uint32_t hash;
    char     data[];
};

typedef struct {
    JsStr *key;
    JsVal  val;
} JsProp;

typedef struct {
    JsObj    hdr;
    JsObj   *proto;
    JsProp  *props;
    uint32_t count;
    uint32_t cap;
    void    *native_ptr;
} JsMapObj;

typedef struct {
    JsObj    hdr;
    JsObj   *proto;
    JsVal   *items;
    uint32_t len;
    uint32_t cap;
} JsArrObj;

typedef struct {
    JsObj    hdr;
    JsObj   *proto;
    JsObj   *func_prototype; /* .prototype object used by `new` */
    JsChunk *chunk;
    uint32_t ast_idx;
    JsEnv   *closure;
    JsVal    bound_this;
    bool     is_arrow;
    bool     has_bound_this;
} JsFuncObj;

typedef JsVal (*JsNativeFn)(JsVm *vm, JsVal this_val, int argc, const JsVal *argv, int magic);

typedef struct {
    JsObj      hdr;
    JsObj     *proto;
    JsObj     *props_obj;
    JsNativeFn fn;
    int        magic;
    char       name[32];
} JsNativeFnObj;

typedef struct {
    JsObj  hdr;
    JsObj *proto;
    char  *pattern;
    char  *flags;
} JsRegexObj;

typedef struct {
    JsStr *name;
    JsVal  val;
    bool   is_const;
} JsEnvVar;

struct JsEnv {
    JsObj     hdr;
    JsEnv    *parent;
    JsEnvVar *vars;
    JsVal     this_val;
    uint16_t  count;
    uint16_t  cap;
    bool      is_func_scope;
    bool      has_this;
};

/* Compact 24-byte flat-pool AST Node */
typedef enum {
    AST_NONE = 0,
    AST_UNDEFINED,
    AST_NULL,
    AST_BOOL,
    AST_NUM,
    AST_STR,
    AST_REGEX,
    AST_IDENT,
    AST_THIS,
    AST_ARRAY,
    AST_OBJECT,
    AST_PROP,
    AST_TEMPLATE,
    AST_FUNC,
    AST_PARAM,
    AST_SPREAD,
    AST_UNARY,
    AST_UPDATE,
    AST_BINARY,
    AST_LOGICAL,
    AST_TERNARY,
    AST_ASSIGN,
    AST_SEQ,
    AST_MEMBER,
    AST_INDEX,
    AST_CALL,
    AST_NEW,
    AST_PROGRAM,
    AST_BLOCK,
    AST_EMPTY,
    AST_EXPR_STMT,
    AST_VAR_DECL,
    AST_DECLARATOR,
    AST_DESTRUCT_ARR,
    AST_DESTRUCT_OBJ,
    AST_FUNC_DECL,
    AST_IF,
    AST_WHILE,
    AST_DO_WHILE,
    AST_FOR,
    AST_FOR_HEAD,
    AST_FOR_IN,
    AST_FOR_OF,
    AST_SWITCH,
    AST_CASE,
    AST_RETURN,
    AST_BREAK,
    AST_CONTINUE,
    AST_THROW,
    AST_TRY,
    AST_CATCH
} AstKind;

typedef enum {
    OP_NONE = 0,
    OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_POW,
    OP_BIT_AND, OP_BIT_OR, OP_BIT_XOR, OP_BIT_NOT,
    OP_SHL, OP_SHR, OP_USHR,
    OP_LT, OP_LE, OP_GT, OP_GE,
    OP_EQ, OP_NE, OP_STRICT_EQ, OP_STRICT_NE,
    OP_IN, OP_INSTANCEOF,
    OP_NOT, OP_TYPEOF, OP_VOID, OP_DELETE,
    OP_AND, OP_OR, OP_NULLISH,
    OP_INC, OP_DEC,
    OP_ASSIGN
} AstOp;

#define DECL_VAR   0
#define DECL_LET   1
#define DECL_CONST 2

#define FUNC_FLAG_ARROW      0x01
#define FUNC_FLAG_EXPR_BODY  0x02

#define PROP_FLAG_COMPUTED   0x01
#define PROP_FLAG_SPREAD     0x02

#define OPT_CHAIN_FLAG       0x01

typedef struct {
    uint8_t  kind;
    uint8_t  op;
    uint16_t flags;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t next;
} AstNode;

struct JsChunk {
    JsChunk  *gc_next;
    uint8_t   gc_mark;
    uint8_t   pinned;      /* Currently being parsed or actively executing on C stack */
    AstNode  *nodes;
    uint32_t  node_count;
    uint32_t  node_cap;
    double   *nums;
    uint32_t  num_count;
    uint32_t  num_cap;
    char    **strs;
    uint32_t *str_lens;
    uint32_t  str_count;
    uint32_t  str_cap;
    uint32_t  root_idx;
};

typedef enum {
    JS_LOG_INFO = 0,
    JS_LOG_WARN,
    JS_LOG_ERROR,
    JS_LOG_CLEAR
} JsLogLevel;

typedef void (*JsConsoleCb)(void *userdata, JsLogLevel level, const char *msg);
typedef void (*JsNavigateCb)(void *userdata, const char *url, bool reload);
typedef void (*JsAlertCb)(void *userdata, const char *msg);
typedef bool (*JsFetchCb)(void *userdata, const char *url, const char *method,
                          const char *body, int *out_status, char **out_text);

typedef struct {
    int      id;
    bool     active;
    bool     repeat;
    int64_t  interval_ms;
    int64_t  due_ms;
    JsObj   *fn_obj;
} JsTimer;

#define JS_MAX_TIMERS 64

struct JsVm {
    /* GC state */
    JsObj   *gc_objects;
    JsChunk *chunks;
    size_t   gc_bytes;
    size_t   gc_threshold;
    size_t   gc_max_bytes;
    uint32_t gc_obj_count;
    int      gc_pause;

    /* Rooted built-in objects & prototypes */
    JsObj   *global_obj;
    JsEnv   *global_env;
    JsObj   *object_proto;
    JsObj   *array_proto;
    JsObj   *string_proto;
    JsObj   *number_proto;
    JsObj   *bool_proto;
    JsObj   *func_proto;
    JsObj   *regex_proto;
    JsObj   *elem_proto;
    JsObj   *doc_obj;

    /* Active execution stacks (traced by GC) */
    JsEnv   *env_stack[JS_MAX_CALL_DEPTH * 4];
    int      env_sp;
    JsVal    temp_roots[JS_MAX_TEMP_ROOTS];
    int      temp_sp;
    int      call_depth;

    /* Step limit & exception state */
    uint32_t steps;
    uint32_t step_limit;
    bool     has_thrown;
    JsVal    thrown_val;
    char     last_error[256];

    /* Timers */
    JsTimer  timers[JS_MAX_TIMERS];
    int      next_timer_id;
    int64_t  boot_ms;

    /* Bound DOM & Browser callbacks */
    DomDocument *doc;
    const char  *current_url;
    int          viewport_w;
    int          viewport_h;
    int          scroll_y;
    int         *scroll_y_ptr;

    JsConsoleCb  on_console;
    JsNavigateCb on_navigate;
    JsAlertCb    on_alert;
    JsFetchCb    on_fetch;
    void        *host_userdata;
};

/* Value constructors */
static inline JsVal js_undefined(void) { JsVal v = { .type = JS_UNDEFINED }; return v; }
static inline JsVal js_null(void)      { JsVal v = { .type = JS_NULL }; return v; }
static inline JsVal js_bool(bool b)    { JsVal v = { .type = JS_BOOL, .u.boolean = b }; return v; }
static inline JsVal js_num(double n)   { JsVal v = { .type = JS_NUMBER, .u.num = n }; return v; }
static inline JsVal js_obj_val(JsObj *o) {
    if (!o) return js_null();
    JsVal v = { .type = JS_OBJECT, .u.obj = o };
    return v;
}

/* Lifecycle & Execution */
JsVm  *js_vm_new(void);
void   js_vm_free(JsVm *vm);
size_t js_gc_collect(JsVm *vm);
int64_t js_now_ms(void);

/* Parser (js_parse.c) */
JsChunk *js_parse(JsVm *vm, const char *src, size_t len, bool is_func_body,
                  char *err_buf, size_t err_cap);
void     js_chunk_free(JsVm *vm, JsChunk *chunk);

/* Evaluator & Object API (js_gc.c / js_stdlib.c / js_eval.c) */
bool   js_eval(JsVm *vm, const char *src, size_t len, JsVal *out_result);
JsVal  js_eval_chunk(JsVm *vm, JsChunk *chunk, JsEnv *env);
JsVal  js_call(JsVm *vm, JsVal callee, JsVal this_val, int argc, const JsVal *argv);

JsObj *js_gc_alloc(JsVm *vm, size_t size, JsObjType type);
JsStr *js_str_new(JsVm *vm, const char *s, size_t len);
JsStr *js_str_cstr(JsVm *vm, const char *s);
JsObj *js_map_new(JsVm *vm, JsObj *proto);
JsObj *js_arr_new(JsVm *vm, uint32_t cap);
JsObj *js_func_new(JsVm *vm, JsChunk *chunk, uint32_t ast_idx, JsEnv *closure, bool is_arrow);
JsObj *js_native_fn_new(JsVm *vm, const char *name, JsNativeFn fn, int magic);
JsObj *js_regex_new(JsVm *vm, const char *pattern, const char *flags);

JsEnv *js_env_new(JsVm *vm, JsEnv *parent, bool is_func_scope, bool has_this, JsVal this_val);
bool   js_env_define(JsVm *vm, JsEnv *env, JsStr *name, JsVal val, uint16_t decl_kind);
bool   js_env_lookup(JsVm *vm, JsEnv *env, JsStr *name, JsVal *out);
bool   js_env_assign(JsVm *vm, JsEnv *env, JsStr *name, JsVal val);
JsVal  js_env_resolve_this(JsVm *vm, JsEnv *env);

JsVal  js_get_prop(JsVm *vm, JsVal target, const char *key);
JsVal  js_get_prop_str(JsVm *vm, JsVal target, JsStr *key);
JsVal  js_get_index(JsVm *vm, JsVal target, uint32_t idx);
bool   js_set_prop(JsVm *vm, JsVal target, const char *key, JsVal val);
bool   js_set_prop_str(JsVm *vm, JsVal target, JsStr *key, JsVal val);
bool   js_set_index(JsVm *vm, JsVal target, uint32_t idx, JsVal val);
bool   js_del_prop_str(JsVm *vm, JsVal target, JsStr *key);
bool   js_has_prop_str(JsVm *vm, JsVal target, JsStr *key);
void   js_arr_push(JsVm *vm, JsObj *arr_obj, JsVal val);
void   js_define_native(JsVm *vm, JsObj *target, const char *name, JsNativeFn fn, int magic);

bool   js_strict_eq(JsVal a, JsVal b);
bool   js_loose_eq(JsVm *vm, JsVal a, JsVal b);
bool   js_to_bool(JsVal v);
double js_to_num(JsVm *vm, JsVal v);
JsStr *js_to_str(JsVm *vm, JsVal v);
void   js_val_format(JsVm *vm, JsVal v, TbBuf *out, int depth);
void   js_log(JsVm *vm, JsLogLevel level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
void   js_throw_str(JsVm *vm, const char *msg);

void   js_stdlib_init(JsVm *vm);
bool   js_regex_exec_posix(const char *pat, const char *flags, const char *subj,
                           size_t offset, size_t *match_start, size_t *match_end);

static inline bool js_temp_push(JsVm *vm, JsVal v) {
    if (vm->temp_sp >= JS_MAX_TEMP_ROOTS) return false;
    vm->temp_roots[vm->temp_sp++] = v;
    return true;
}

/* DOM Bindings & Events (js_dom.c) */
void  js_bind_document(JsVm *vm, DomDocument *doc, const char *url);
JsVal js_wrap_dom_node(JsVm *vm, DomNode *node);
bool  js_dom_get_virtual(JsVm *vm, JsMapObj *m, const char *key, JsVal *out);
bool  js_dom_set_virtual(JsVm *vm, JsMapObj *m, const char *key, JsVal val);
void  js_gc_mark_dom(JsVm *vm, void (*mark_obj)(JsVm *, JsObj *));
void  js_dom_on_wrapper_swept(JsMapObj *m);

/* Dispatch DOM event with bubbling; returns false if preventDefault() was called */
bool  js_dispatch_dom_event(JsVm *vm, DomNode *target, const char *type,
                            const char *key_name, bool bubbles);
/* Run any due setTimeout / setInterval callbacks; returns ms until next due timer (-1 if none) */
int   js_run_timers(JsVm *vm);

#endif /* TB_JS_H */
