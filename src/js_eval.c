#include "js.h"
#include "math_tb.h"

typedef enum {
    FLOW_NONE = 0,
    FLOW_RETURN,
    FLOW_BREAK,
    FLOW_CONTINUE,
    FLOW_THROW
} FlowKind;

typedef struct {
    FlowKind flow;
    JsVal    val;
} EvalRes;

static inline EvalRes res_ok(JsVal v)    { EvalRes r = { FLOW_NONE, v }; return r; }
static inline EvalRes res_throw(JsVal v) { EvalRes r = { FLOW_THROW, v }; return r; }

static inline EvalRes absorb_vm_throw(JsVm *vm) {
    vm->has_thrown = false;
    JsVal tv = vm->thrown_val;
    vm->thrown_val = js_undefined();
    return res_throw(tv);
}

static bool push_env(JsVm *vm, JsEnv *env) {
    if (vm->env_sp >= (int)(sizeof(vm->env_stack) / sizeof(vm->env_stack[0]))) {
        js_throw_str(vm, "RangeError: Maximum scope depth exceeded");
        return false;
    }
    vm->env_stack[vm->env_sp++] = env;
    return true;
}

static JsStr *chunk_js_str(JsVm *vm, const JsChunk *ch, uint32_t str_id) {
    if (str_id >= ch->str_count) return js_str_cstr(vm, "");
    return js_str_new(vm, ch->strs[str_id], ch->str_lens[str_id]);
}

/* Forward declarations */
static EvalRes eval_expr(JsVm *vm, JsChunk *ch, JsEnv *env, uint32_t idx);
static EvalRes eval_stmt(JsVm *vm, JsChunk *ch, JsEnv *env, uint32_t idx);

/* Pre-bind `var` declarations to `undefined` across nested control-flow blocks */
static void hoist_vars_rec(JsVm *vm, JsChunk *ch, JsEnv *func_env, uint32_t stmt_idx) {
    for (uint32_t cur = stmt_idx; cur != 0; cur = ch->nodes[cur].next) {
        const AstNode *n = &ch->nodes[cur];
        switch (n->kind) {
            case AST_VAR_DECL:
                if (n->flags == DECL_VAR) {
                    for (uint32_t d = n->a; d != 0; d = ch->nodes[d].next) {
                        uint32_t pat = ch->nodes[d].a;
                        if (pat && ch->nodes[pat].kind == AST_IDENT) {
                            JsStr *nm = chunk_js_str(vm, ch, ch->nodes[pat].a);
                            bool exists = false;
                            for (uint16_t i = 0; i < func_env->count; i++) {
                                if (func_env->vars[i].name->len == nm->len &&
                                    memcmp(func_env->vars[i].name->data, nm->data, nm->len) == 0) {
                                    exists = true;
                                    break;
                                }
                            }
                            if (!exists) js_env_define(vm, func_env, nm, js_undefined(), DECL_VAR);
                        }
                    }
                }
                break;
            case AST_BLOCK:
                hoist_vars_rec(vm, ch, func_env, n->a);
                break;
            case AST_IF:
                hoist_vars_rec(vm, ch, func_env, n->b);
                if (n->c) hoist_vars_rec(vm, ch, func_env, n->c);
                break;
            case AST_WHILE:
                hoist_vars_rec(vm, ch, func_env, n->b);
                break;
            case AST_DO_WHILE:
                hoist_vars_rec(vm, ch, func_env, n->a);
                break;
            case AST_FOR: {
                if (n->a) hoist_vars_rec(vm, ch, func_env, ch->nodes[n->a].a);
                hoist_vars_rec(vm, ch, func_env, n->b);
                break;
            }
            case AST_FOR_IN:
            case AST_FOR_OF:
                if (n->flags == DECL_VAR && n->a && ch->nodes[n->a].kind == AST_IDENT) {
                    JsStr *nm = chunk_js_str(vm, ch, ch->nodes[n->a].a);
                    js_env_define(vm, func_env, nm, js_undefined(), DECL_VAR);
                }
                hoist_vars_rec(vm, ch, func_env, n->c);
                break;
            case AST_SWITCH:
                for (uint32_t cs = n->b; cs != 0; cs = ch->nodes[cs].next) {
                    hoist_vars_rec(vm, ch, func_env, ch->nodes[cs].b);
                }
                break;
            case AST_TRY:
                hoist_vars_rec(vm, ch, func_env, n->a);
                if (n->b) hoist_vars_rec(vm, ch, func_env, ch->nodes[n->b].b);
                if (n->c) hoist_vars_rec(vm, ch, func_env, n->c);
                break;
            default:
                break;
        }
    }
}

static void hoist_functions(JsVm *vm, JsChunk *ch, JsEnv *env, uint32_t first_stmt, uint16_t decl_kind) {
    vm->gc_pause++;
    for (uint32_t cur = first_stmt; cur != 0; cur = ch->nodes[cur].next) {
        const AstNode *n = &ch->nodes[cur];
        if (n->kind == AST_FUNC_DECL && n->a) {
            const AstNode *fn_node = &ch->nodes[n->a];
            if (fn_node->a != UINT32_MAX) {
                JsStr *nm  = chunk_js_str(vm, ch, fn_node->a);
                JsObj *fno = js_func_new(vm, ch, n->a, env, false);
                if (nm && fno) {
                    js_env_define(vm, env, nm, js_obj_val(fno), decl_kind);
                }
            }
        }
    }
    vm->gc_pause--;
}

static JsVal apply_binop(JsVm *vm, AstOp op, JsVal lv, JsVal rv) {
    if (op == OP_ADD) {
        bool l_str = (lv.type == JS_OBJECT && lv.u.obj && lv.u.obj->obj_type == OBJ_STRING);
        bool r_str = (rv.type == JS_OBJECT && rv.u.obj && rv.u.obj->obj_type == OBJ_STRING);
        /* Also convert arrays/objects to string on + if either is non-numeric object */
        bool l_obj = (lv.type == JS_OBJECT && lv.u.obj && !l_str);
        bool r_obj = (rv.type == JS_OBJECT && rv.u.obj && !r_str);
        if (l_str || r_str || l_obj || r_obj) {
            int sp = vm->temp_sp;
            JsStr *ls = js_to_str(vm, lv);
            if (ls) js_temp_push(vm, js_obj_val((JsObj *)ls));
            JsStr *rs = js_to_str(vm, rv);
            if (!ls || !rs) { vm->temp_sp = sp; return js_undefined(); }
            TbBuf b;
            tb_buf_init(&b);
            tb_buf_append(&b, ls->data, ls->len);
            tb_buf_append(&b, rs->data, rs->len);
            JsStr *out = js_str_new(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            vm->temp_sp = sp;
            return out ? js_obj_val((JsObj *)out) : js_undefined();
        }
        return js_num(js_to_num(vm, lv) + js_to_num(vm, rv));
    }

    switch (op) {
        case OP_SUB: return js_num(js_to_num(vm, lv) - js_to_num(vm, rv));
        case OP_MUL: return js_num(js_to_num(vm, lv) * js_to_num(vm, rv));
        case OP_DIV: return js_num(js_to_num(vm, lv) / js_to_num(vm, rv));
        case OP_MOD: return js_num(tb_fmod(js_to_num(vm, lv), js_to_num(vm, rv)));
        case OP_POW: return js_num(tb_pow(js_to_num(vm, lv), js_to_num(vm, rv)));
        case OP_BIT_AND: return js_num((double)((int32_t)(int64_t)js_to_num(vm, lv) & (int32_t)(int64_t)js_to_num(vm, rv)));
        case OP_BIT_OR:  return js_num((double)((int32_t)(int64_t)js_to_num(vm, lv) | (int32_t)(int64_t)js_to_num(vm, rv)));
        case OP_BIT_XOR: return js_num((double)((int32_t)(int64_t)js_to_num(vm, lv) ^ (int32_t)(int64_t)js_to_num(vm, rv)));
        case OP_SHL:  return js_num((double)((int32_t)(int64_t)js_to_num(vm, lv) << ((uint32_t)(int64_t)js_to_num(vm, rv) & 31U)));
        case OP_SHR:  return js_num((double)((int32_t)(int64_t)js_to_num(vm, lv) >> ((uint32_t)(int64_t)js_to_num(vm, rv) & 31U)));
        case OP_USHR: return js_num((double)((uint32_t)(int64_t)js_to_num(vm, lv) >> ((uint32_t)(int64_t)js_to_num(vm, rv) & 31U)));
        case OP_EQ:        return js_bool(js_loose_eq(vm, lv, rv));
        case OP_NE:        return js_bool(!js_loose_eq(vm, lv, rv));
        case OP_STRICT_EQ: return js_bool(js_strict_eq(lv, rv));
        case OP_STRICT_NE: return js_bool(!js_strict_eq(lv, rv));
        case OP_LT: case OP_LE: case OP_GT: case OP_GE: {
            bool both_str = (lv.type == JS_OBJECT && lv.u.obj && lv.u.obj->obj_type == OBJ_STRING &&
                             rv.type == JS_OBJECT && rv.u.obj && rv.u.obj->obj_type == OBJ_STRING);
            if (both_str) {
                int c = strcmp(((JsStr *)lv.u.obj)->data, ((JsStr *)rv.u.obj)->data);
                if (op == OP_LT) return js_bool(c < 0);
                if (op == OP_LE) return js_bool(c <= 0);
                if (op == OP_GT) return js_bool(c > 0);
                return js_bool(c >= 0);
            }
            double ln = js_to_num(vm, lv);
            double rn = js_to_num(vm, rv);
            if (tb_isnan(ln) || tb_isnan(rn)) return js_bool(false);
            if (op == OP_LT) return js_bool(ln < rn);
            if (op == OP_LE) return js_bool(ln <= rn);
            if (op == OP_GT) return js_bool(ln > rn);
            return js_bool(ln >= rn);
        }
        case OP_IN: {
            if (rv.type != JS_OBJECT || !rv.u.obj) {
                js_throw_str(vm, "TypeError: Cannot use 'in' operator on non-object");
                return js_undefined();
            }
            JsStr *ks = js_to_str(vm, lv);
            return js_bool(ks && js_has_prop_str(vm, rv, ks));
        }
        case OP_INSTANCEOF: {
            if (lv.type != JS_OBJECT || !lv.u.obj || rv.type != JS_OBJECT || !rv.u.obj)
                return js_bool(false);
            JsVal target_p = js_get_prop(vm, rv, "prototype");
            if (target_p.type != JS_OBJECT || !target_p.u.obj) return js_bool(false);
            JsObj *cur = NULL;
            if (lv.u.obj->obj_type == OBJ_OBJECT) cur = ((JsMapObj *)lv.u.obj)->proto;
            else if (lv.u.obj->obj_type == OBJ_ARRAY) cur = ((JsArrObj *)lv.u.obj)->proto;
            else if (lv.u.obj->obj_type == OBJ_FUNC) cur = ((JsFuncObj *)lv.u.obj)->proto;
            else if (lv.u.obj->obj_type == OBJ_REGEX) cur = ((JsRegexObj *)lv.u.obj)->proto;
            int guard = 0;
            while (cur && guard++ < 16) {
                if (cur == target_p.u.obj) return js_bool(true);
                cur = (cur->obj_type == OBJ_OBJECT) ? ((JsMapObj *)cur)->proto : NULL;
            }
            return js_bool(false);
        }
        default:
            return js_undefined();
    }
}

static EvalRes bind_pattern(JsVm *vm, JsChunk *ch, JsEnv *env, uint32_t pat_idx,
                            JsVal val, uint16_t decl_kind, bool is_assign) {
    if (!pat_idx) return res_ok(val);
    const AstNode *pn = &ch->nodes[pat_idx];
    if (pn->kind == AST_IDENT) {
        JsStr *nm = chunk_js_str(vm, ch, pn->a);
        if (is_assign) {
            js_env_assign(vm, env, nm, val);
            if (vm->has_thrown) return absorb_vm_throw(vm);
        } else {
            js_env_define(vm, env, nm, val, decl_kind);
        }
        return res_ok(val);
    }
    int sp = vm->temp_sp;
    js_temp_push(vm, val);
    if (pn->kind == AST_DESTRUCT_ARR) {
        uint32_t idx = 0;
        for (uint32_t cur = pn->a; cur != 0; cur = ch->nodes[cur].next, idx++) {
            const AstNode *it = &ch->nodes[cur];
            if (it->kind == AST_EMPTY) continue;
            JsVal elem = js_get_index(vm, val, idx);
            if (vm->has_thrown) { vm->temp_sp = sp; return absorb_vm_throw(vm); }
            if (elem.type == JS_UNDEFINED && it->b) {
                EvalRes dr = eval_expr(vm, ch, env, it->b);
                if (dr.flow != FLOW_NONE) { vm->temp_sp = sp; return dr; }
                elem = dr.val;
            }
            JsStr *nm = chunk_js_str(vm, ch, it->a);
            if (is_assign) js_env_assign(vm, env, nm, elem);
            else js_env_define(vm, env, nm, elem, decl_kind);
            if (vm->has_thrown) { vm->temp_sp = sp; return absorb_vm_throw(vm); }
        }
    } else if (pn->kind == AST_DESTRUCT_OBJ) {
        for (uint32_t cur = pn->a; cur != 0; cur = ch->nodes[cur].next) {
            const AstNode *it = &ch->nodes[cur];
            JsStr *key_nm = chunk_js_str(vm, ch, it->a);
            JsVal prop    = js_get_prop_str(vm, val, key_nm);
            if (vm->has_thrown) { vm->temp_sp = sp; return absorb_vm_throw(vm); }
            if (prop.type == JS_UNDEFINED && it->c) {
                EvalRes dr = eval_expr(vm, ch, env, it->c);
                if (dr.flow != FLOW_NONE) { vm->temp_sp = sp; return dr; }
                prop = dr.val;
            }
            JsStr *dst_nm = chunk_js_str(vm, ch, it->b);
            if (is_assign) js_env_assign(vm, env, dst_nm, prop);
            else js_env_define(vm, env, dst_nm, prop, decl_kind);
            if (vm->has_thrown) { vm->temp_sp = sp; return absorb_vm_throw(vm); }
        }
    }
    vm->temp_sp = sp;
    return res_ok(val);
}

static EvalRes eval_arg_list_onto_roots(JsVm *vm, JsChunk *ch, JsEnv *env,
                                        uint32_t first_arg, int *out_argc) {
    int argc = 0;
    for (uint32_t a = first_arg; a != 0; a = ch->nodes[a].next) {
        const AstNode *an = &ch->nodes[a];
        if (an->kind == AST_SPREAD) {
            EvalRes sr = eval_expr(vm, ch, env, an->a);
            if (sr.flow != FLOW_NONE) return sr;
            if (sr.val.type == JS_OBJECT && sr.val.u.obj && sr.val.u.obj->obj_type == OBJ_ARRAY) {
                JsArrObj *arr = (JsArrObj *)sr.val.u.obj;
                for (uint32_t i = 0; i < arr->len; i++) {
                    if (!js_temp_push(vm, arr->items[i])) break;
                    argc++;
                }
            }
        } else {
            EvalRes ar = eval_expr(vm, ch, env, a);
            if (ar.flow != FLOW_NONE) return ar;
            if (!js_temp_push(vm, ar.val)) break;
            argc++;
        }
    }
    *out_argc = argc;
    return res_ok(js_undefined());
}

static EvalRes eval_expr(JsVm *vm, JsChunk *ch, JsEnv *env, uint32_t idx) {
    if (idx == 0) return res_ok(js_undefined());
    if (++vm->steps > vm->step_limit) {
        js_throw_str(vm, "RangeError: Execution step limit exceeded");
        return absorb_vm_throw(vm);
    }

    const AstNode *n = &ch->nodes[idx];
    switch (n->kind) {
        case AST_UNDEFINED: return res_ok(js_undefined());
        case AST_NULL:      return res_ok(js_null());
        case AST_BOOL:      return res_ok(js_bool(n->a != 0));
        case AST_NUM:       return res_ok(js_num(ch->nums[n->a]));
        case AST_STR: {
            JsStr *s = chunk_js_str(vm, ch, n->a);
            return res_ok(s ? js_obj_val((JsObj *)s) : js_undefined());
        }
        case AST_REGEX: {
            const char *pat = (n->a < ch->str_count) ? ch->strs[n->a] : "";
            const char *flg = (n->b < ch->str_count) ? ch->strs[n->b] : "";
            JsObj *rx = js_regex_new(vm, pat, flg);
            if (vm->has_thrown) return absorb_vm_throw(vm);
            return res_ok(js_obj_val(rx));
        }
        case AST_THIS:
            return res_ok(js_env_resolve_this(vm, env));
        case AST_IDENT: {
            JsStr *nm = chunk_js_str(vm, ch, n->a);
            JsVal out = js_undefined();
            if (!nm || !js_env_lookup(vm, env, nm, &out)) {
                char msg[128];
                snprintf(msg, sizeof(msg), "ReferenceError: %s is not defined",
                         nm ? nm->data : "<ident>");
                js_throw_str(vm, msg);
                return absorb_vm_throw(vm);
            }
            if (vm->has_thrown) return absorb_vm_throw(vm);
            return res_ok(out);
        }
        case AST_FUNC: {
            bool is_arrow = (n->flags & FUNC_FLAG_ARROW) != 0;
            JsObj *fn = js_func_new(vm, ch, idx, env, is_arrow);
            return res_ok(js_obj_val(fn));
        }
        case AST_TEMPLATE: {
            int sp = vm->temp_sp;
            TbBuf b;
            tb_buf_init(&b);
            for (uint32_t p = n->a; p != 0; p = ch->nodes[p].next) {
                EvalRes pr = eval_expr(vm, ch, env, p);
                if (pr.flow != FLOW_NONE) {
                    tb_buf_free(&b);
                    vm->temp_sp = sp;
                    return pr;
                }
                JsStr *ps = js_to_str(vm, pr.val);
                if (ps) tb_buf_append(&b, ps->data, ps->len);
            }
            JsStr *res = js_str_new(vm, b.data ? b.data : "", b.len);
            tb_buf_free(&b);
            vm->temp_sp = sp;
            return res_ok(res ? js_obj_val((JsObj *)res) : js_undefined());
        }
        case AST_ARRAY: {
            int sp = vm->temp_sp;
            JsObj *arr = js_arr_new(vm, 4);
            js_temp_push(vm, js_obj_val(arr));
            for (uint32_t e = n->a; e != 0; e = ch->nodes[e].next) {
                const AstNode *en = &ch->nodes[e];
                if (en->kind == AST_SPREAD) {
                    EvalRes sr = eval_expr(vm, ch, env, en->a);
                    if (sr.flow != FLOW_NONE) { vm->temp_sp = sp; return sr; }
                    if (sr.val.type == JS_OBJECT && sr.val.u.obj &&
                        sr.val.u.obj->obj_type == OBJ_ARRAY) {
                        JsArrObj *sa = (JsArrObj *)sr.val.u.obj;
                        for (uint32_t i = 0; i < sa->len; i++) js_arr_push(vm, arr, sa->items[i]);
                    }
                } else {
                    EvalRes er = eval_expr(vm, ch, env, e);
                    if (er.flow != FLOW_NONE) { vm->temp_sp = sp; return er; }
                    js_arr_push(vm, arr, er.val);
                }
            }
            vm->temp_sp = sp;
            return res_ok(js_obj_val(arr));
        }
        case AST_OBJECT: {
            int sp = vm->temp_sp;
            JsObj *obj = js_map_new(vm, vm->object_proto);
            js_temp_push(vm, js_obj_val(obj));
            for (uint32_t p = n->a; p != 0; p = ch->nodes[p].next) {
                const AstNode *pn = &ch->nodes[p];
                if (pn->flags & PROP_FLAG_SPREAD) {
                    EvalRes sr = eval_expr(vm, ch, env, pn->a);
                    if (sr.flow != FLOW_NONE) { vm->temp_sp = sp; return sr; }
                    if (sr.val.type == JS_OBJECT && sr.val.u.obj &&
                        sr.val.u.obj->obj_type == OBJ_OBJECT) {
                        JsMapObj *sm = (JsMapObj *)sr.val.u.obj;
                        for (uint32_t i = 0; i < sm->count; i++) {
                            js_set_prop_str(vm, js_obj_val(obj), sm->props[i].key, sm->props[i].val);
                        }
                    }
                    continue;
                }
                JsStr *ks = NULL;
                int psp = vm->temp_sp;
                if (pn->flags & PROP_FLAG_COMPUTED) {
                    EvalRes kr = eval_expr(vm, ch, env, pn->a);
                    if (kr.flow != FLOW_NONE) { vm->temp_sp = sp; return kr; }
                    ks = js_to_str(vm, kr.val);
                } else {
                    ks = chunk_js_str(vm, ch, pn->a);
                }
                if (ks) js_temp_push(vm, js_obj_val((JsObj *)ks));
                EvalRes vr = eval_expr(vm, ch, env, pn->b);
                if (vr.flow != FLOW_NONE) { vm->temp_sp = sp; return vr; }
                if (ks) js_set_prop_str(vm, js_obj_val(obj), ks, vr.val);
                vm->temp_sp = psp;
            }
            vm->temp_sp = sp;
            return res_ok(js_obj_val(obj));
        }
        case AST_UNARY: {
            if (n->op == OP_TYPEOF) {
                /* `typeof undeclared` returns "undefined" without throwing */
                const AstNode *opn = &ch->nodes[n->a];
                JsVal v = js_undefined();
                if (opn->kind == AST_IDENT) {
                    JsStr *nm = chunk_js_str(vm, ch, opn->a);
                    if (!nm || !js_env_lookup(vm, env, nm, &v)) {
                        return res_ok(js_obj_val((JsObj *)js_str_cstr(vm, "undefined")));
                    }
                } else {
                    EvalRes r = eval_expr(vm, ch, env, n->a);
                    if (r.flow != FLOW_NONE) return r;
                    v = r.val;
                }
                const char *ts = "undefined";
                switch (v.type) {
                    case JS_UNDEFINED: ts = "undefined"; break;
                    case JS_NULL:      ts = "object"; break;
                    case JS_BOOL:      ts = "boolean"; break;
                    case JS_NUMBER:    ts = "number"; break;
                    case JS_OBJECT:
                        if (!v.u.obj) ts = "object";
                        else if (v.u.obj->obj_type == OBJ_STRING) ts = "string";
                        else if (v.u.obj->obj_type == OBJ_FUNC || v.u.obj->obj_type == OBJ_NATIVE_FN) ts = "function";
                        else ts = "object";
                        break;
                }
                return res_ok(js_obj_val((JsObj *)js_str_cstr(vm, ts)));
            }
            if (n->op == OP_DELETE) {
                const AstNode *t = &ch->nodes[n->a];
                if (t->kind == AST_MEMBER) {
                    EvalRes or = eval_expr(vm, ch, env, t->a);
                    if (or.flow != FLOW_NONE) return or;
                    JsStr *ks = chunk_js_str(vm, ch, t->b);
                    return res_ok(js_bool(js_del_prop_str(vm, or.val, ks)));
                }
                if (t->kind == AST_INDEX) {
                    int sp = vm->temp_sp;
                    EvalRes or = eval_expr(vm, ch, env, t->a);
                    if (or.flow != FLOW_NONE) return or;
                    js_temp_push(vm, or.val);
                    EvalRes kr = eval_expr(vm, ch, env, t->b);
                    if (kr.flow != FLOW_NONE) { vm->temp_sp = sp; return kr; }
                    JsStr *ks = js_to_str(vm, kr.val);
                    bool ok   = js_del_prop_str(vm, or.val, ks);
                    vm->temp_sp = sp;
                    return res_ok(js_bool(ok));
                }
                return res_ok(js_bool(true));
            }
            EvalRes r = eval_expr(vm, ch, env, n->a);
            if (r.flow != FLOW_NONE) return r;
            switch (n->op) {
                case OP_ADD:     return res_ok(js_num(js_to_num(vm, r.val)));
                case OP_SUB:     return res_ok(js_num(-js_to_num(vm, r.val)));
                case OP_NOT:     return res_ok(js_bool(!js_to_bool(r.val)));
                case OP_BIT_NOT: return res_ok(js_num((double)(~(int32_t)(int64_t)js_to_num(vm, r.val))));
                case OP_VOID:    return res_ok(js_undefined());
                default:         return res_ok(js_undefined());
            }
        }
        case AST_UPDATE: {
            bool is_prefix = (n->flags != 0);
            double delta   = (n->op == OP_INC) ? 1.0 : -1.0;
            const AstNode *t = &ch->nodes[n->a];
            if (t->kind == AST_IDENT) {
                JsStr *nm = chunk_js_str(vm, ch, t->a);
                JsVal oldv = js_undefined();
                if (!js_env_lookup(vm, env, nm, &oldv)) {
                    js_throw_str(vm, "ReferenceError: Variable is not defined");
                    return absorb_vm_throw(vm);
                }
                double oldn = js_to_num(vm, oldv);
                JsVal newv  = js_num(oldn + delta);
                js_env_assign(vm, env, nm, newv);
                if (vm->has_thrown) return absorb_vm_throw(vm);
                return res_ok(is_prefix ? newv : js_num(oldn));
            }
            if (t->kind == AST_MEMBER) {
                int sp = vm->temp_sp;
                EvalRes or = eval_expr(vm, ch, env, t->a);
                if (or.flow != FLOW_NONE) return or;
                js_temp_push(vm, or.val);
                JsStr *ks  = chunk_js_str(vm, ch, t->b);
                JsVal oldv = js_get_prop_str(vm, or.val, ks);
                if (vm->has_thrown) { vm->temp_sp = sp; return absorb_vm_throw(vm); }
                double oldn = js_to_num(vm, oldv);
                JsVal newv  = js_num(oldn + delta);
                js_set_prop_str(vm, or.val, ks, newv);
                vm->temp_sp = sp;
                if (vm->has_thrown) return absorb_vm_throw(vm);
                return res_ok(is_prefix ? newv : js_num(oldn));
            }
            if (t->kind == AST_INDEX) {
                int sp = vm->temp_sp;
                EvalRes or = eval_expr(vm, ch, env, t->a);
                if (or.flow != FLOW_NONE) return or;
                js_temp_push(vm, or.val);
                EvalRes kr = eval_expr(vm, ch, env, t->b);
                if (kr.flow != FLOW_NONE) { vm->temp_sp = sp; return kr; }
                JsStr *ks = js_to_str(vm, kr.val);
                if (ks) js_temp_push(vm, js_obj_val((JsObj *)ks));
                JsVal oldv = js_get_prop_str(vm, or.val, ks);
                if (vm->has_thrown) { vm->temp_sp = sp; return absorb_vm_throw(vm); }
                double oldn = js_to_num(vm, oldv);
                JsVal newv  = js_num(oldn + delta);
                js_set_prop_str(vm, or.val, ks, newv);
                vm->temp_sp = sp;
                if (vm->has_thrown) return absorb_vm_throw(vm);
                return res_ok(is_prefix ? newv : js_num(oldn));
            }
            return res_ok(js_num(TB_NAN));
        }
        case AST_BINARY: {
            int sp = vm->temp_sp;
            EvalRes lr = eval_expr(vm, ch, env, n->a);
            if (lr.flow != FLOW_NONE) return lr;
            js_temp_push(vm, lr.val);
            EvalRes rr = eval_expr(vm, ch, env, n->b);
            if (rr.flow != FLOW_NONE) { vm->temp_sp = sp; return rr; }
            JsVal out = apply_binop(vm, (AstOp)n->op, lr.val, rr.val);
            vm->temp_sp = sp;
            if (vm->has_thrown) return absorb_vm_throw(vm);
            return res_ok(out);
        }
        case AST_LOGICAL: {
            EvalRes lr = eval_expr(vm, ch, env, n->a);
            if (lr.flow != FLOW_NONE) return lr;
            if (n->op == OP_AND) {
                return js_to_bool(lr.val) ? eval_expr(vm, ch, env, n->b) : lr;
            }
            if (n->op == OP_OR) {
                return js_to_bool(lr.val) ? lr : eval_expr(vm, ch, env, n->b);
            }
            /* OP_NULLISH (??) */
            return (lr.val.type != JS_NULL && lr.val.type != JS_UNDEFINED)
                       ? lr
                       : eval_expr(vm, ch, env, n->b);
        }
        case AST_TERNARY: {
            EvalRes cr = eval_expr(vm, ch, env, n->a);
            if (cr.flow != FLOW_NONE) return cr;
            return eval_expr(vm, ch, env, js_to_bool(cr.val) ? n->b : n->c);
        }
        case AST_SEQ: {
            EvalRes lr = eval_expr(vm, ch, env, n->a);
            if (lr.flow != FLOW_NONE) return lr;
            return eval_expr(vm, ch, env, n->b);
        }
        case AST_ASSIGN: {
            const AstNode *t = &ch->nodes[n->a];
            if (t->kind == AST_IDENT || t->kind == AST_DESTRUCT_ARR || t->kind == AST_DESTRUCT_OBJ) {
                if (n->op == OP_ASSIGN) {
                    EvalRes rr = eval_expr(vm, ch, env, n->b);
                    if (rr.flow != FLOW_NONE) return rr;
                    return bind_pattern(vm, ch, env, n->a, rr.val, DECL_VAR, true);
                }
                JsStr *nm  = chunk_js_str(vm, ch, t->a);
                JsVal oldv = js_undefined();
                if (!js_env_lookup(vm, env, nm, &oldv)) {
                    js_throw_str(vm, "ReferenceError: Variable is not defined");
                    return absorb_vm_throw(vm);
                }
                if (n->op == OP_AND && !js_to_bool(oldv)) return res_ok(oldv);
                if (n->op == OP_OR && js_to_bool(oldv)) return res_ok(oldv);
                if (n->op == OP_NULLISH && oldv.type != JS_NULL && oldv.type != JS_UNDEFINED) return res_ok(oldv);

                int sp = vm->temp_sp;
                js_temp_push(vm, oldv);
                EvalRes rr = eval_expr(vm, ch, env, n->b);
                if (rr.flow != FLOW_NONE) { vm->temp_sp = sp; return rr; }
                JsVal newv = (n->op == OP_AND || n->op == OP_OR || n->op == OP_NULLISH)
                                 ? rr.val
                                 : apply_binop(vm, (AstOp)n->op, oldv, rr.val);
                vm->temp_sp = sp;
                if (vm->has_thrown) return absorb_vm_throw(vm);
                js_env_assign(vm, env, nm, newv);
                if (vm->has_thrown) return absorb_vm_throw(vm);
                return res_ok(newv);
            }
            if (t->kind == AST_MEMBER || t->kind == AST_INDEX) {
                int sp = vm->temp_sp;
                EvalRes or = eval_expr(vm, ch, env, t->a);
                if (or.flow != FLOW_NONE) return or;
                js_temp_push(vm, or.val);
                JsStr *ks = NULL;
                if (t->kind == AST_MEMBER) {
                    ks = chunk_js_str(vm, ch, t->b);
                } else {
                    EvalRes kr = eval_expr(vm, ch, env, t->b);
                    if (kr.flow != FLOW_NONE) { vm->temp_sp = sp; return kr; }
                    ks = js_to_str(vm, kr.val);
                }
                if (ks) js_temp_push(vm, js_obj_val((JsObj *)ks));

                JsVal newv = js_undefined();
                if (n->op == OP_ASSIGN) {
                    EvalRes rr = eval_expr(vm, ch, env, n->b);
                    if (rr.flow != FLOW_NONE) { vm->temp_sp = sp; return rr; }
                    newv = rr.val;
                } else {
                    JsVal oldv = js_get_prop_str(vm, or.val, ks);
                    if (vm->has_thrown) { vm->temp_sp = sp; return absorb_vm_throw(vm); }
                    if ((n->op == OP_AND && !js_to_bool(oldv)) ||
                        (n->op == OP_OR && js_to_bool(oldv)) ||
                        (n->op == OP_NULLISH && oldv.type != JS_NULL && oldv.type != JS_UNDEFINED)) {
                        vm->temp_sp = sp;
                        return res_ok(oldv);
                    }
                    js_temp_push(vm, oldv);
                    EvalRes rr = eval_expr(vm, ch, env, n->b);
                    if (rr.flow != FLOW_NONE) { vm->temp_sp = sp; return rr; }
                    newv = (n->op == OP_AND || n->op == OP_OR || n->op == OP_NULLISH)
                               ? rr.val
                               : apply_binop(vm, (AstOp)n->op, oldv, rr.val);
                }
                js_set_prop_str(vm, or.val, ks, newv);
                vm->temp_sp = sp;
                if (vm->has_thrown) return absorb_vm_throw(vm);
                return res_ok(newv);
            }
            js_throw_str(vm, "SyntaxError: Invalid assignment target");
            return absorb_vm_throw(vm);
        }
        case AST_MEMBER: {
            int sp = vm->temp_sp;
            EvalRes or = eval_expr(vm, ch, env, n->a);
            if (or.flow != FLOW_NONE) return or;
            if ((n->flags & OPT_CHAIN_FLAG) &&
                (or.val.type == JS_NULL || or.val.type == JS_UNDEFINED)) {
                return res_ok(js_undefined());
            }
            js_temp_push(vm, or.val);
            JsStr *ks = chunk_js_str(vm, ch, n->b);
            JsVal out = js_get_prop_str(vm, or.val, ks);
            vm->temp_sp = sp;
            if (vm->has_thrown) return absorb_vm_throw(vm);
            return res_ok(out);
        }
        case AST_INDEX: {
            int sp = vm->temp_sp;
            EvalRes or = eval_expr(vm, ch, env, n->a);
            if (or.flow != FLOW_NONE) return or;
            if ((n->flags & OPT_CHAIN_FLAG) &&
                (or.val.type == JS_NULL || or.val.type == JS_UNDEFINED)) {
                return res_ok(js_undefined());
            }
            js_temp_push(vm, or.val);
            EvalRes kr = eval_expr(vm, ch, env, n->b);
            if (kr.flow != FLOW_NONE) { vm->temp_sp = sp; return kr; }
            JsVal out;
            if (kr.val.type == JS_NUMBER && kr.val.u.num >= 0 &&
                kr.val.u.num <= 0x7FFFFFFF && tb_floor(kr.val.u.num) == kr.val.u.num) {
                out = js_get_index(vm, or.val, (uint32_t)kr.val.u.num);
            } else {
                JsStr *ks = js_to_str(vm, kr.val);
                out = js_get_prop_str(vm, or.val, ks);
            }
            vm->temp_sp = sp;
            if (vm->has_thrown) return absorb_vm_throw(vm);
            return res_ok(out);
        }
        case AST_CALL: {
            int sp = vm->temp_sp;
            JsVal this_arg = js_undefined();
            JsVal callee   = js_undefined();
            const AstNode *cn = &ch->nodes[n->a];

            if (cn->kind == AST_MEMBER || cn->kind == AST_INDEX) {
                EvalRes or = eval_expr(vm, ch, env, cn->a);
                if (or.flow != FLOW_NONE) { vm->temp_sp = sp; return or; }
                if (((cn->flags | n->flags) & OPT_CHAIN_FLAG) &&
                    (or.val.type == JS_NULL || or.val.type == JS_UNDEFINED)) {
                    vm->temp_sp = sp;
                    return res_ok(js_undefined());
                }
                this_arg = or.val;
                js_temp_push(vm, this_arg);
                if (cn->kind == AST_MEMBER) {
                    JsStr *ks = chunk_js_str(vm, ch, cn->b);
                    callee    = js_get_prop_str(vm, this_arg, ks);
                } else {
                    EvalRes kr = eval_expr(vm, ch, env, cn->b);
                    if (kr.flow != FLOW_NONE) { vm->temp_sp = sp; return kr; }
                    JsStr *ks = js_to_str(vm, kr.val);
                    callee    = js_get_prop_str(vm, this_arg, ks);
                }
                if (vm->has_thrown) { vm->temp_sp = sp; return absorb_vm_throw(vm); }
            } else {
                EvalRes cr = eval_expr(vm, ch, env, n->a);
                if (cr.flow != FLOW_NONE) { vm->temp_sp = sp; return cr; }
                callee = cr.val;
                js_temp_push(vm, this_arg);
            }

            if ((n->flags & OPT_CHAIN_FLAG) &&
                (callee.type == JS_NULL || callee.type == JS_UNDEFINED)) {
                vm->temp_sp = sp;
                return res_ok(js_undefined());
            }

            js_temp_push(vm, callee);
            int arg_base = vm->temp_sp;
            int argc     = 0;
            EvalRes ar = eval_arg_list_onto_roots(vm, ch, env, n->b, &argc);
            if (ar.flow != FLOW_NONE) { vm->temp_sp = sp; return ar; }

            JsVal out = js_call(vm, callee, this_arg, argc, &vm->temp_roots[arg_base]);
            vm->temp_sp = sp;
            if (vm->has_thrown) return absorb_vm_throw(vm);
            return res_ok(out);
        }
        case AST_NEW: {
            int sp = vm->temp_sp;
            EvalRes cr = eval_expr(vm, ch, env, n->a);
            if (cr.flow != FLOW_NONE) return cr;
            JsVal callee = cr.val;
            js_temp_push(vm, callee);

            int arg_base = vm->temp_sp;
            int argc     = 0;
            EvalRes ar = eval_arg_list_onto_roots(vm, ch, env, n->b, &argc);
            if (ar.flow != FLOW_NONE) { vm->temp_sp = sp; return ar; }

            if (callee.type == JS_OBJECT && callee.u.obj && callee.u.obj->obj_type == OBJ_NATIVE_FN) {
                JsVal out = js_call(vm, callee, js_undefined(), argc, &vm->temp_roots[arg_base]);
                vm->temp_sp = sp;
                if (vm->has_thrown) return absorb_vm_throw(vm);
                return res_ok(out);
            }
            if (callee.type != JS_OBJECT || !callee.u.obj || callee.u.obj->obj_type != OBJ_FUNC) {
                vm->temp_sp = sp;
                js_throw_str(vm, "TypeError: Target is not a constructor");
                return absorb_vm_throw(vm);
            }

            JsVal proto_v = js_get_prop(vm, callee, "prototype");
            JsObj *proto  = (proto_v.type == JS_OBJECT && proto_v.u.obj) ? proto_v.u.obj : vm->object_proto;
            JsObj *inst   = js_map_new(vm, proto);
            JsVal inst_v  = js_obj_val(inst);
            js_temp_push(vm, inst_v);

            JsVal ret = js_call(vm, callee, inst_v, argc, &vm->temp_roots[arg_base]);
            vm->temp_sp = sp;
            if (vm->has_thrown) return absorb_vm_throw(vm);
            if (ret.type == JS_OBJECT && ret.u.obj && ret.u.obj->obj_type != OBJ_STRING) {
                return res_ok(ret);
            }
            return res_ok(inst_v);
        }
        default:
            return res_ok(js_undefined());
    }
}

static EvalRes eval_stmt_list(JsVm *vm, JsChunk *ch, JsEnv *env, uint32_t first_stmt) {
    JsVal last = js_undefined();
    for (uint32_t cur = first_stmt; cur != 0; cur = ch->nodes[cur].next) {
        EvalRes r = eval_stmt(vm, ch, env, cur);
        if (r.flow != FLOW_NONE) return r;
        last = r.val;
    }
    return res_ok(last);
}

static EvalRes eval_stmt(JsVm *vm, JsChunk *ch, JsEnv *env, uint32_t idx) {
    if (idx == 0) return res_ok(js_undefined());
    if (++vm->steps > vm->step_limit) {
        js_throw_str(vm, "RangeError: Execution step limit exceeded");
        return absorb_vm_throw(vm);
    }
    /* Safe statement-boundary Mark-and-Sweep GC */
    if (vm->gc_bytes > vm->gc_threshold && vm->gc_pause == 0) {
        js_gc_collect(vm);
    }

    const AstNode *n = &ch->nodes[idx];
    switch (n->kind) {
        case AST_EMPTY:
        case AST_FUNC_DECL: /* Already hoisted on scope entry */
            return res_ok(js_undefined());
        case AST_EXPR_STMT:
            return eval_expr(vm, ch, env, n->a);
        case AST_BLOCK: {
            int env_mark = vm->env_sp;
            JsEnv *benv  = js_env_new(vm, env, false, false, js_undefined());
            if (!benv || !push_env(vm, benv)) return absorb_vm_throw(vm);
            hoist_functions(vm, ch, benv, n->a, DECL_LET);
            EvalRes r = eval_stmt_list(vm, ch, benv, n->a);
            vm->env_sp = env_mark;
            return r;
        }
        case AST_VAR_DECL: {
            for (uint32_t d = n->a; d != 0; d = ch->nodes[d].next) {
                const AstNode *dn = &ch->nodes[d];
                JsVal val = js_undefined();
                if (dn->b) {
                    EvalRes ir = eval_expr(vm, ch, env, dn->b);
                    if (ir.flow != FLOW_NONE) return ir;
                    val = ir.val;
                }
                EvalRes br = bind_pattern(vm, ch, env, dn->a, val, n->flags, false);
                if (br.flow != FLOW_NONE) return br;
            }
            return res_ok(js_undefined());
        }
        case AST_IF: {
            EvalRes cr = eval_expr(vm, ch, env, n->a);
            if (cr.flow != FLOW_NONE) return cr;
            if (js_to_bool(cr.val)) return eval_stmt(vm, ch, env, n->b);
            if (n->c) return eval_stmt(vm, ch, env, n->c);
            return res_ok(js_undefined());
        }
        case AST_WHILE: {
            for (;;) {
                EvalRes cr = eval_expr(vm, ch, env, n->a);
                if (cr.flow != FLOW_NONE) return cr;
                if (!js_to_bool(cr.val)) break;
                EvalRes br = eval_stmt(vm, ch, env, n->b);
                if (br.flow == FLOW_BREAK) break;
                if (br.flow == FLOW_CONTINUE) continue;
                if (br.flow != FLOW_NONE) return br;
            }
            return res_ok(js_undefined());
        }
        case AST_DO_WHILE: {
            for (;;) {
                EvalRes br = eval_stmt(vm, ch, env, n->a);
                if (br.flow == FLOW_BREAK) break;
                if (br.flow != FLOW_NONE && br.flow != FLOW_CONTINUE) return br;
                EvalRes cr = eval_expr(vm, ch, env, n->b);
                if (cr.flow != FLOW_NONE) return cr;
                if (!js_to_bool(cr.val)) break;
            }
            return res_ok(js_undefined());
        }
        case AST_FOR: {
            int env_mark = vm->env_sp;
            JsEnv *fenv  = js_env_new(vm, env, false, false, js_undefined());
            if (!fenv || !push_env(vm, fenv)) return absorb_vm_throw(vm);
            const AstNode *hd = &ch->nodes[n->a];
            if (hd->a) {
                AstKind ik = (AstKind)ch->nodes[hd->a].kind;
                EvalRes ir = (ik == AST_VAR_DECL) ? eval_stmt(vm, ch, fenv, hd->a)
                                                  : eval_expr(vm, ch, fenv, hd->a);
                if (ir.flow != FLOW_NONE) { vm->env_sp = env_mark; return ir; }
            }
            for (;;) {
                if (hd->b) {
                    EvalRes cr = eval_expr(vm, ch, fenv, hd->b);
                    if (cr.flow != FLOW_NONE) { vm->env_sp = env_mark; return cr; }
                    if (!js_to_bool(cr.val)) break;
                }
                EvalRes br = eval_stmt(vm, ch, fenv, n->b);
                if (br.flow == FLOW_BREAK) break;
                if (br.flow != FLOW_NONE && br.flow != FLOW_CONTINUE) {
                    vm->env_sp = env_mark;
                    return br;
                }
                if (hd->c) {
                    EvalRes sr = eval_expr(vm, ch, fenv, hd->c);
                    if (sr.flow != FLOW_NONE) { vm->env_sp = env_mark; return sr; }
                }
            }
            vm->env_sp = env_mark;
            return res_ok(js_undefined());
        }
        case AST_FOR_IN:
        case AST_FOR_OF: {
            int sp = vm->temp_sp;
            EvalRes rr = eval_expr(vm, ch, env, n->b);
            if (rr.flow != FLOW_NONE) return rr;
            js_temp_push(vm, rr.val);

            /* Snapshot keys / items into a rooted temporary array */
            JsObj *items = js_arr_new(vm, 8);
            js_temp_push(vm, js_obj_val(items));
            if (n->kind == AST_FOR_IN) {
                if (rr.val.type == JS_OBJECT && rr.val.u.obj) {
                    if (rr.val.u.obj->obj_type == OBJ_OBJECT) {
                        JsMapObj *m = (JsMapObj *)rr.val.u.obj;
                        for (uint32_t i = 0; i < m->count; i++)
                            js_arr_push(vm, items, js_obj_val((JsObj *)m->props[i].key));
                    } else if (rr.val.u.obj->obj_type == OBJ_ARRAY) {
                        JsArrObj *a = (JsArrObj *)rr.val.u.obj;
                        for (uint32_t i = 0; i < a->len; i++) {
                            char kb[16];
                            snprintf(kb, sizeof(kb), "%u", i);
                            js_arr_push(vm, items, js_obj_val((JsObj *)js_str_cstr(vm, kb)));
                        }
                    }
                }
            } else { /* AST_FOR_OF */
                if (rr.val.type == JS_OBJECT && rr.val.u.obj) {
                    if (rr.val.u.obj->obj_type == OBJ_ARRAY) {
                        JsArrObj *a = (JsArrObj *)rr.val.u.obj;
                        for (uint32_t i = 0; i < a->len; i++) js_arr_push(vm, items, a->items[i]);
                    } else if (rr.val.u.obj->obj_type == OBJ_STRING) {
                        JsStr *s = (JsStr *)rr.val.u.obj;
                        for (uint32_t i = 0; i < s->len; i++)
                            js_arr_push(vm, items, js_obj_val((JsObj *)js_str_new(vm, s->data + i, 1)));
                    }
                }
            }

            JsArrObj *ia = (JsArrObj *)items;
            for (uint32_t i = 0; i < ia->len; i++) {
                int env_mark = vm->env_sp;
                JsEnv *ienv  = env;
                if (n->flags != 0xFF && n->flags != DECL_VAR) {
                    ienv = js_env_new(vm, env, false, false, js_undefined());
                    if (!ienv || !push_env(vm, ienv)) {
                        vm->temp_sp = sp;
                        return absorb_vm_throw(vm);
                    }
                }
                EvalRes bindr = bind_pattern(vm, ch, ienv, n->a, ia->items[i],
                                             n->flags == 0xFF ? DECL_VAR : n->flags,
                                             n->flags == 0xFF);
                if (bindr.flow != FLOW_NONE) {
                    vm->env_sp  = env_mark;
                    vm->temp_sp = sp;
                    return bindr;
                }
                EvalRes br = eval_stmt(vm, ch, ienv, n->c);
                vm->env_sp = env_mark;
                if (br.flow == FLOW_BREAK) break;
                if (br.flow != FLOW_NONE && br.flow != FLOW_CONTINUE) {
                    vm->temp_sp = sp;
                    return br;
                }
            }
            vm->temp_sp = sp;
            return res_ok(js_undefined());
        }
        case AST_SWITCH: {
            int sp = vm->temp_sp;
            EvalRes dr = eval_expr(vm, ch, env, n->a);
            if (dr.flow != FLOW_NONE) return dr;
            js_temp_push(vm, dr.val);

            uint32_t match_case = 0;
            uint32_t def_case   = 0;
            for (uint32_t cs = n->b; cs != 0; cs = ch->nodes[cs].next) {
                const AstNode *cn = &ch->nodes[cs];
                if (cn->a == 0) {
                    def_case = cs;
                } else {
                    EvalRes tr = eval_expr(vm, ch, env, cn->a);
                    if (tr.flow != FLOW_NONE) { vm->temp_sp = sp; return tr; }
                    if (js_strict_eq(dr.val, tr.val)) {
                        match_case = cs;
                        break;
                    }
                }
            }
            uint32_t start = match_case ? match_case : def_case;
            for (uint32_t cs = start; cs != 0; cs = ch->nodes[cs].next) {
                EvalRes sr = eval_stmt_list(vm, ch, env, ch->nodes[cs].b);
                if (sr.flow == FLOW_BREAK) break;
                if (sr.flow != FLOW_NONE) { vm->temp_sp = sp; return sr; }
            }
            vm->temp_sp = sp;
            return res_ok(js_undefined());
        }
        case AST_RETURN: {
            JsVal rv = js_undefined();
            if (n->a) {
                EvalRes er = eval_expr(vm, ch, env, n->a);
                if (er.flow != FLOW_NONE) return er;
                rv = er.val;
            }
            EvalRes r = { FLOW_RETURN, rv };
            return r;
        }
        case AST_BREAK:    { EvalRes r = { FLOW_BREAK, js_undefined() }; return r; }
        case AST_CONTINUE: { EvalRes r = { FLOW_CONTINUE, js_undefined() }; return r; }
        case AST_THROW: {
            EvalRes er = eval_expr(vm, ch, env, n->a);
            if (er.flow != FLOW_NONE) return er;
            return res_throw(er.val);
        }
        case AST_TRY: {
            int sp  = vm->temp_sp;
            EvalRes r = eval_stmt(vm, ch, env, n->a);
            if (r.flow == FLOW_THROW && n->b) {
                const AstNode *cn = &ch->nodes[n->b];
                int env_mark = vm->env_sp;
                JsEnv *cenv  = js_env_new(vm, env, false, false, js_undefined());
                if (cenv && push_env(vm, cenv)) {
                    if (cn->a != UINT32_MAX) {
                        JsStr *pnm = chunk_js_str(vm, ch, cn->a);
                        js_env_define(vm, cenv, pnm, r.val, DECL_LET);
                    }
                    r = eval_stmt(vm, ch, cenv, cn->b);
                }
                vm->env_sp = env_mark;
            }
            if (n->c) {
                js_temp_push(vm, r.val);
                EvalRes fr = eval_stmt(vm, ch, env, n->c);
                if (fr.flow != FLOW_NONE) r = fr;
            }
            vm->temp_sp = sp;
            return r;
        }
        default:
            return res_ok(js_undefined());
    }
}

JsVal js_call(JsVm *vm, JsVal callee, JsVal this_val, int argc, const JsVal *argv) {
    if (!vm || callee.type != JS_OBJECT || !callee.u.obj) {
        js_throw_str(vm, "TypeError: Value is not a function");
        return js_undefined();
    }
    if (vm->call_depth >= JS_MAX_CALL_DEPTH) {
        js_throw_str(vm, "RangeError: Maximum call stack size exceeded");
        return js_undefined();
    }

    JsObj *o = callee.u.obj;
    if (o->obj_type == OBJ_NATIVE_FN) {
        JsNativeFnObj *nf = (JsNativeFnObj *)o;
        vm->call_depth++;
        JsVal res = nf->fn(vm, this_val, argc, argv, nf->magic);
        vm->call_depth--;
        return res;
    }
    if (o->obj_type != OBJ_FUNC) {
        js_throw_str(vm, "TypeError: Object is not callable");
        return js_undefined();
    }

    JsFuncObj *fn = (JsFuncObj *)o;
    JsChunk   *ch = fn->chunk;
    if (!ch || fn->ast_idx == 0) return js_undefined();

    JsVal eff_this = fn->has_bound_this ? fn->bound_this : this_val;
    if (!fn->is_arrow && (eff_this.type == JS_UNDEFINED || eff_this.type == JS_NULL)) {
        eff_this = js_obj_val(vm->global_obj);
    }

    int env_mark = vm->env_sp;
    int sp_mark  = vm->temp_sp;
    js_temp_push(vm, callee);

    JsEnv *fenv = js_env_new(vm, fn->closure ? fn->closure : vm->global_env,
                             true, !fn->is_arrow, eff_this);
    if (!fenv || !push_env(vm, fenv)) {
        vm->temp_sp = sp_mark;
        return js_undefined();
    }

    ch->pinned++;
    vm->call_depth++;

    const AstNode *fnode = &ch->nodes[fn->ast_idx];
    /* Bind named function expression inside its own scope */
    if (fnode->a != UINT32_MAX) {
        JsStr *fnm = chunk_js_str(vm, ch, fnode->a);
        js_env_define(vm, fenv, fnm, callee, DECL_VAR);
    }
    /* Bind `arguments` array for non-arrow functions */
    if (!fn->is_arrow) {
        JsObj *args_arr = js_arr_new(vm, (uint32_t)(argc > 0 ? argc : 1));
        for (int i = 0; i < argc; i++) js_arr_push(vm, args_arr, argv[i]);
        JsStr *arg_nm = js_str_cstr(vm, "arguments");
        js_env_define(vm, fenv, arg_nm, js_obj_val(args_arr), DECL_VAR);
    }

    /* Bind parameters & defaults */
    int ai = 0;
    for (uint32_t p = fnode->b; p != 0; p = ch->nodes[p].next, ai++) {
        const AstNode *pn = &ch->nodes[p];
        if (pn->flags & 1) { /* ...rest */
            JsStr *pnm = chunk_js_str(vm, ch, pn->a);
            JsObj *rest = js_arr_new(vm, (uint32_t)(argc > ai ? argc - ai : 0));
            for (int r = ai; r < argc; r++) js_arr_push(vm, rest, argv[r]);
            js_env_define(vm, fenv, pnm, js_obj_val(rest), DECL_LET);
            break;
        }
        JsVal pv = (ai < argc) ? argv[ai] : js_undefined();
        if (pv.type == JS_UNDEFINED && pn->b) {
            EvalRes dr = eval_expr(vm, ch, fenv, pn->b);
            if (dr.flow == FLOW_THROW) {
                vm->has_thrown = true;
                vm->thrown_val = dr.val;
                vm->call_depth--;
                ch->pinned--;
                vm->env_sp  = env_mark;
                vm->temp_sp = sp_mark;
                return js_undefined();
            }
            pv = dr.val;
        }
        if (pn->flags & 2) {
            EvalRes br = bind_pattern(vm, ch, fenv, pn->c, pv, DECL_VAR, false);
            if (br.flow == FLOW_THROW) {
                vm->has_thrown = true;
                vm->thrown_val = br.val;
                vm->call_depth--;
                ch->pinned--;
                vm->env_sp  = env_mark;
                vm->temp_sp = sp_mark;
                return js_undefined();
            }
        } else {
            JsStr *pnm = chunk_js_str(vm, ch, pn->a);
            js_env_define(vm, fenv, pnm, pv, DECL_VAR);
        }
    }

    EvalRes res;
    if (fnode->flags & FUNC_FLAG_EXPR_BODY) {
        res = eval_expr(vm, ch, fenv, fnode->c);
        if (res.flow == FLOW_NONE) res.flow = FLOW_RETURN;
    } else {
        const AstNode *blk = &ch->nodes[fnode->c];
        hoist_vars_rec(vm, ch, fenv, blk->a);
        hoist_functions(vm, ch, fenv, blk->a, DECL_VAR);
        res = eval_stmt_list(vm, ch, fenv, blk->a);
    }

    vm->call_depth--;
    ch->pinned--;
    vm->env_sp  = env_mark;
    vm->temp_sp = sp_mark;

    if (res.flow == FLOW_THROW) {
        vm->has_thrown = true;
        vm->thrown_val = res.val;
        return js_undefined();
    }
    return (res.flow == FLOW_RETURN) ? res.val : js_undefined();
}

JsVal js_eval_chunk(JsVm *vm, JsChunk *ch, JsEnv *env) {
    if (!vm || !ch || ch->root_idx == 0) return js_undefined();
    int env_mark = vm->env_sp;
    if (!push_env(vm, env)) return js_undefined();

    ch->pinned++;
    uint32_t first_stmt = ch->nodes[ch->root_idx].a;
    JsEnv *func_env = env;
    while (func_env->parent && !func_env->is_func_scope) func_env = func_env->parent;
    hoist_vars_rec(vm, ch, func_env, first_stmt);
    hoist_functions(vm, ch, func_env, first_stmt, DECL_VAR);

    EvalRes res = eval_stmt_list(vm, ch, env, first_stmt);
    ch->pinned--;
    vm->env_sp = env_mark;

    if (res.flow == FLOW_THROW) {
        vm->has_thrown = true;
        vm->thrown_val = res.val;
        return js_undefined();
    }
    return res.val;
}

bool js_eval(JsVm *vm, const char *src, size_t len, JsVal *out_result) {
    if (out_result) *out_result = js_undefined();
    if (!vm || !src) return false;

    vm->steps      = 0;
    vm->has_thrown = false;
    vm->thrown_val = js_undefined();
    vm->last_error[0] = '\0';

    char err_buf[256] = "";
    JsChunk *ch = js_parse(vm, src, len, false, err_buf, sizeof(err_buf));
    if (!ch) {
        snprintf(vm->last_error, sizeof(vm->last_error), "%s", err_buf);
        js_log(vm, JS_LOG_ERROR, "%s", err_buf);
        return false;
    }

    JsVal res = js_eval_chunk(vm, ch, vm->global_env);
    if (ch->pinned > 0) ch->pinned--;
    if (vm->has_thrown) {
        TbBuf b;
        tb_buf_init(&b);
        tb_buf_append_cstr(&b, "Uncaught ");
        js_val_format(vm, vm->thrown_val, &b, 0);
        snprintf(vm->last_error, sizeof(vm->last_error), "%s", b.data ? b.data : "Uncaught Error");
        js_log(vm, JS_LOG_ERROR, "%s", vm->last_error);
        tb_buf_free(&b);
        vm->has_thrown = false;
        vm->thrown_val = js_undefined();
        return false;
    }

    if (out_result) *out_result = res;
    return true;
}
