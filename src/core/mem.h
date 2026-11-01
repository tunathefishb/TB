#ifndef TB_MEM_H
#define TB_MEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Default hard heap budget: 7.5 MB (keeps total OS VmRSS strictly < 10 MB) */
#define TB_DEFAULT_HEAP_LIMIT (7680UL * 1024UL)

typedef void (*TbGcHookFn)(void *userdata);

typedef struct {
    size_t heap_live;    /* Currently allocated heap bytes tracked via malloc_usable_size */
    size_t heap_peak;    /* Peak heap bytes allocated */
    size_t heap_limit;   /* Hard heap cap in bytes */
    size_t alloc_count;  /* Number of live heap allocations */
    size_t oom_count;    /* Number of allocations rejected by hard cap */
    size_t vm_rss_kb;    /* Kernel VmRSS from /proc/self/status */
    size_t rss_anon_kb;  /* Kernel RssAnon (private memory) from /proc/self/status */
    size_t rss_file_kb;  /* Kernel RssFile (shared libs) from /proc/self/status */
    size_t vm_hwm_kb;    /* Kernel VmHWM (peak RSS) from /proc/self/status */
} TbMemStats;

void  tb_mem_init(size_t hard_limit_bytes);
void  tb_mem_set_limit(size_t hard_limit_bytes);
void  tb_mem_set_gc_hook(TbGcHookFn fn, void *userdata);
void  tb_mem_trim(void);
void  tb_mem_stats(TbMemStats *out);

void *tb_malloc(size_t size);
void *tb_calloc(size_t count, size_t size);
void *tb_realloc(void *ptr, size_t size);
char *tb_strdup(const char *s);
char *tb_strndup(const char *s, size_t n);
void  tb_free(void *ptr);

/* Fast bump-pointer Arena allocator for transient AST/CSS/Layout data */
typedef struct TbArenaBlock {
    struct TbArenaBlock *next;
    size_t used;
    size_t cap;
    uint8_t data[];
} TbArenaBlock;

typedef struct {
    TbArenaBlock *head;
    TbArenaBlock *curr;
    size_t block_size;
    size_t total_bytes;
} TbArena;

void  tb_arena_init(TbArena *a, size_t block_size);
void *tb_arena_alloc(TbArena *a, size_t size);
char *tb_arena_strdup(TbArena *a, const char *s);
char *tb_arena_strndup(TbArena *a, const char *s, size_t n);
void  tb_arena_reset(TbArena *a);
void  tb_arena_destroy(TbArena *a);

#endif /* TB_MEM_H */
