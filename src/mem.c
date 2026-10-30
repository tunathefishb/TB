#define _GNU_SOURCE
#include "mem.h"

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t     g_heap_live   = 0;
static size_t     g_heap_peak   = 0;
static size_t     g_heap_limit  = TB_DEFAULT_HEAP_LIMIT;
static size_t     g_alloc_count = 0;
static size_t     g_oom_count   = 0;
static TbGcHookFn g_gc_hook     = NULL;
static void      *g_gc_userdata = NULL;
static bool       g_in_gc_hook  = false;

void tb_mem_init(size_t hard_limit_bytes) {
    /* Restrict glibc malloc to a single arena and return freed pages aggressively */
    mallopt(M_ARENA_MAX, 1);
    mallopt(M_TRIM_THRESHOLD, 32 * 1024);
    mallopt(M_MMAP_THRESHOLD, 64 * 1024);
    if (hard_limit_bytes > 0) {
        g_heap_limit = hard_limit_bytes;
    }
}

void tb_mem_set_limit(size_t hard_limit_bytes) {
    if (hard_limit_bytes > 0) {
        g_heap_limit = hard_limit_bytes;
    }
}

void tb_mem_set_gc_hook(TbGcHookFn fn, void *userdata) {
    g_gc_hook     = fn;
    g_gc_userdata = userdata;
}

void tb_mem_trim(void) {
    malloc_trim(0);
}

static bool check_budget_or_gc(size_t needed) {
    if (g_heap_live + needed <= g_heap_limit) {
        return true;
    }
    if (g_gc_hook && !g_in_gc_hook) {
        g_in_gc_hook = true;
        g_gc_hook(g_gc_userdata);
        malloc_trim(0);
        g_in_gc_hook = false;
        if (g_heap_live + needed <= g_heap_limit) {
            return true;
        }
    }
    g_oom_count++;
    return false;
}

static void record_alloc(void *p) {
    size_t u = malloc_usable_size(p);
    g_heap_live += u;
    if (g_heap_live > g_heap_peak) {
        g_heap_peak = g_heap_live;
    }
    g_alloc_count++;
}

void *tb_malloc(size_t size) {
    if (size == 0) size = 1;
    if (!check_budget_or_gc(size)) return NULL;
    void *p = malloc(size);
    if (!p) {
        g_oom_count++;
        return NULL;
    }
    record_alloc(p);
    return p;
}

void *tb_calloc(size_t count, size_t size) {
    if (count == 0 || size == 0) {
        count = 1;
        size  = 1;
    }
    if (count > SIZE_MAX / size) {
        g_oom_count++;
        return NULL;
    }
    size_t total = count * size;
    if (!check_budget_or_gc(total)) return NULL;
    void *p = calloc(count, size);
    if (!p) {
        g_oom_count++;
        return NULL;
    }
    record_alloc(p);
    return p;
}

void *tb_realloc(void *ptr, size_t size) {
    if (!ptr) return tb_malloc(size);
    if (size == 0) {
        tb_free(ptr);
        return NULL;
    }
    size_t old_u = malloc_usable_size(ptr);
    if (size > old_u) {
        size_t extra = size - old_u;
        if (!check_budget_or_gc(extra)) return NULL;
    }
    void *np = realloc(ptr, size);
    if (!np) {
        g_oom_count++;
        return NULL;
    }
    size_t new_u = malloc_usable_size(np);
    if (g_heap_live >= old_u) g_heap_live -= old_u;
    else g_heap_live = 0;
    g_heap_live += new_u;
    if (g_heap_live > g_heap_peak) {
        g_heap_peak = g_heap_live;
    }
    return np;
}

void tb_free(void *ptr) {
    if (!ptr) return;
    size_t u = malloc_usable_size(ptr);
    if (g_heap_live >= u) g_heap_live -= u;
    else g_heap_live = 0;
    if (g_alloc_count > 0) g_alloc_count--;
    free(ptr);
}

char *tb_strdup(const char *s) {
    if (!s) s = "";
    size_t n = strlen(s);
    char *p  = (char *)tb_malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

char *tb_strndup(const char *s, size_t n) {
    if (!s) s = "";
    size_t actual = strnlen(s, n);
    char *p       = (char *)tb_malloc(actual + 1);
    if (!p) return NULL;
    memcpy(p, s, actual);
    p[actual] = '\0';
    return p;
}

void tb_mem_stats(TbMemStats *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->heap_live   = g_heap_live;
    out->heap_peak   = g_heap_peak;
    out->heap_limit  = g_heap_limit;
    out->alloc_count = g_alloc_count;
    out->oom_count   = g_oom_count;

    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        unsigned long val = 0;
        if (strncmp(line, "VmRSS:", 6) == 0 && sscanf(line + 6, "%lu", &val) == 1) {
            out->vm_rss_kb = (size_t)val;
        } else if (strncmp(line, "RssAnon:", 8) == 0 && sscanf(line + 8, "%lu", &val) == 1) {
            out->rss_anon_kb = (size_t)val;
        } else if (strncmp(line, "RssFile:", 8) == 0 && sscanf(line + 8, "%lu", &val) == 1) {
            out->rss_file_kb = (size_t)val;
        } else if (strncmp(line, "VmHWM:", 6) == 0 && sscanf(line + 6, "%lu", &val) == 1) {
            out->vm_hwm_kb = (size_t)val;
        }
    }
    fclose(f);
}

/* Arena implementation */
void tb_arena_init(TbArena *a, size_t block_size) {
    memset(a, 0, sizeof(*a));
    a->block_size = block_size >= 1024 ? block_size : 16384;
}

void *tb_arena_alloc(TbArena *a, size_t size) {
    if (size == 0) size = 1;
    size = (size + 7U) & ~(size_t)7U;

    TbArenaBlock *b = a->curr;
    if (b && b->used + size <= b->cap) {
        void *p = b->data + b->used;
        b->used += size;
        return p;
    }

    /* Check remaining chain in case arena was reset */
    while (b && b->next) {
        b = b->next;
        if (b->used + size <= b->cap) {
            a->curr = b;
            void *p = b->data + b->used;
            b->used += size;
            return p;
        }
    }

    size_t cap = a->block_size;
    if (size > cap) cap = size;
    TbArenaBlock *nb = (TbArenaBlock *)tb_malloc(sizeof(TbArenaBlock) + cap);
    if (!nb) return NULL;
    nb->next = NULL;
    nb->used = size;
    nb->cap  = cap;
    a->total_bytes += sizeof(TbArenaBlock) + cap;

    if (!a->head) {
        a->head = nb;
    } else if (b) {
        b->next = nb;
    }
    a->curr = nb;
    return nb->data;
}

char *tb_arena_strdup(TbArena *a, const char *s) {
    if (!s) s = "";
    size_t n = strlen(s);
    char *p  = (char *)tb_arena_alloc(a, n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

char *tb_arena_strndup(TbArena *a, const char *s, size_t n) {
    if (!s) s = "";
    size_t actual = strnlen(s, n);
    char *p       = (char *)tb_arena_alloc(a, actual + 1);
    if (!p) return NULL;
    memcpy(p, s, actual);
    p[actual] = '\0';
    return p;
}

void tb_arena_reset(TbArena *a) {
    for (TbArenaBlock *b = a->head; b; b = b->next) {
        b->used = 0;
    }
    a->curr = a->head;
}

void tb_arena_destroy(TbArena *a) {
    TbArenaBlock *b = a->head;
    while (b) {
        TbArenaBlock *next = b->next;
        tb_free(b);
        b = next;
    }
    a->head        = NULL;
    a->curr        = NULL;
    a->total_bytes = 0;
}
