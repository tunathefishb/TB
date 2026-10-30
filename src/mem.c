#include "mem.h"
#include "sys.h"

#define PAGE_SZ       4096UL
#define SLAB_SZ       65536UL
#define LARGE_THRESH  32768UL
#define MIN_BLK_SZ    32UL
#define NUM_BINS      12

#define BLK_MAGIC       0x54420000U
#define BLK_MAGIC_MASK  0xFFFF0000U
#define BLK_IN_USE      0x00000001U
#define BLK_DIRECT_MMAP 0x00000002U
#define BLK_SENTINEL    0x00000004U

typedef struct RegionHdr {
    struct RegionHdr *prev;
    struct RegionHdr *next;
    size_t            map_size;
    size_t            live_blocks;
} RegionHdr; /* 32 bytes (16-byte aligned) */

typedef struct BlkHdr {
    uint32_t size;      /* Total bytes including 16-byte BlkHdr */
    uint32_t prev_phys; /* Size of physically preceding block in slab (0 if first) */
    uint32_t reg_off;   /* Byte offset from RegionHdr* to this BlkHdr* */
    uint32_t flags;     /* BLK_MAGIC | flags */
} BlkHdr; /* 16 bytes (16-byte aligned) */

typedef struct FreeNode {
    BlkHdr *prev;
    BlkHdr *next;
} FreeNode; /* Stored in 16-byte payload of free blocks */

static RegionHdr *g_regions         = NULL;
static BlkHdr    *g_bins[NUM_BINS]  = {0};

static size_t     g_heap_live   = 0;
static size_t     g_heap_peak   = 0;
static size_t     g_heap_limit  = TB_DEFAULT_HEAP_LIMIT;
static size_t     g_alloc_count = 0;
static size_t     g_oom_count   = 0;
static TbGcHookFn g_gc_hook     = NULL;
static void      *g_gc_userdata = NULL;
static bool       g_in_gc_hook  = false;

static inline size_t align16(size_t n) {
    return (n + 15UL) & ~15UL;
}

static inline size_t align_page(size_t n) {
    return (n + (PAGE_SZ - 1UL)) & ~(PAGE_SZ - 1UL);
}

static inline FreeNode *blk_freenode(BlkHdr *b) {
    return (FreeNode *)(b + 1);
}

static inline BlkHdr *blk_phys_next(BlkHdr *b) {
    return (BlkHdr *)((uint8_t *)b + b->size);
}

static inline BlkHdr *blk_phys_prev(BlkHdr *b) {
    return b->prev_phys ? (BlkHdr *)((uint8_t *)b - b->prev_phys) : NULL;
}

static inline RegionHdr *blk_region(BlkHdr *b) {
    return (RegionHdr *)((uint8_t *)b - b->reg_off);
}

static int bin_for_size(size_t sz) {
    if (sz <= 32)    return 0;
    if (sz <= 64)    return 1;
    if (sz <= 128)   return 2;
    if (sz <= 256)   return 3;
    if (sz <= 512)   return 4;
    if (sz <= 1024)  return 5;
    if (sz <= 2048)  return 6;
    if (sz <= 4096)  return 7;
    if (sz <= 8192)  return 8;
    if (sz <= 16384) return 9;
    if (sz <= 32768) return 10;
    return 11;
}

static void freelist_insert(BlkHdr *b) {
    int bi = bin_for_size(b->size);
    FreeNode *fn = blk_freenode(b);
    fn->prev = NULL;
    fn->next = g_bins[bi];
    if (g_bins[bi]) {
        blk_freenode(g_bins[bi])->prev = b;
    }
    g_bins[bi] = b;
}

static void freelist_remove(BlkHdr *b) {
    int bi = bin_for_size(b->size);
    FreeNode *fn = blk_freenode(b);
    if (fn->prev) {
        blk_freenode(fn->prev)->next = fn->next;
    } else if (g_bins[bi] == b) {
        g_bins[bi] = fn->next;
    }
    if (fn->next) {
        blk_freenode(fn->next)->prev = fn->prev;
    }
    fn->prev = NULL;
    fn->next = NULL;
}

static void region_unlink_and_unmap(RegionHdr *reg) {
    if (reg->prev) reg->prev->next = reg->next;
    else if (g_regions == reg) g_regions = reg->next;
    if (reg->next) reg->next->prev = reg->prev;
    munmap(reg, reg->map_size);
}

static BlkHdr *slab_grow(void) {
    void *mem = mmap(NULL, SLAB_SZ, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED || !mem) return NULL;

    RegionHdr *reg = (RegionHdr *)mem;
    reg->map_size    = SLAB_SZ;
    reg->live_blocks = 0;
    reg->prev        = NULL;
    reg->next        = g_regions;
    if (g_regions) g_regions->prev = reg;
    g_regions = reg;

    uint32_t main_off = (uint32_t)sizeof(RegionHdr);
    uint32_t sent_off = (uint32_t)(SLAB_SZ - sizeof(BlkHdr));
    uint32_t main_sz  = sent_off - main_off;

    BlkHdr *first = (BlkHdr *)((uint8_t *)mem + main_off);
    first->size      = main_sz;
    first->prev_phys = 0;
    first->reg_off   = main_off;
    first->flags     = BLK_MAGIC;

    BlkHdr *sent = (BlkHdr *)((uint8_t *)mem + sent_off);
    sent->size      = 0;
    sent->prev_phys = main_sz;
    sent->reg_off   = sent_off;
    sent->flags     = BLK_MAGIC | BLK_IN_USE | BLK_SENTINEL;

    freelist_insert(first);
    return first;
}

void tb_mem_init(size_t hard_limit_bytes) {
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
    RegionHdr *reg = g_regions;
    while (reg) {
        RegionHdr *next_reg = reg->next;
        if (reg->live_blocks == 0) {
            BlkHdr *first = (BlkHdr *)((uint8_t *)reg + sizeof(RegionHdr));
            freelist_remove(first);
            region_unlink_and_unmap(reg);
        } else {
            /* Reclaim full interior 4 KB physical pages inside large free blocks */
            BlkHdr *b = (BlkHdr *)((uint8_t *)reg + sizeof(RegionHdr));
            while (!(b->flags & BLK_SENTINEL)) {
                if (!(b->flags & BLK_IN_USE) && b->size >= PAGE_SZ + MIN_BLK_SZ) {
                    uintptr_t lo = ((uintptr_t)(b + 1) + sizeof(FreeNode) + PAGE_SZ - 1UL) &
                                   ~(PAGE_SZ - 1UL);
                    uintptr_t hi = ((uintptr_t)b + b->size) & ~(PAGE_SZ - 1UL);
                    if (hi > lo) {
                        (void)madvise((void *)lo, hi - lo, MADV_DONTNEED);
                    }
                }
                b = blk_phys_next(b);
            }
        }
        reg = next_reg;
    }
}

static bool check_budget_or_gc(size_t needed) {
    if (needed > g_heap_limit || g_heap_live + needed > g_heap_limit) {
        if (g_gc_hook && !g_in_gc_hook) {
            g_in_gc_hook = true;
            g_gc_hook(g_gc_userdata);
            tb_mem_trim();
            g_in_gc_hook = false;
            if (needed <= g_heap_limit && g_heap_live + needed <= g_heap_limit) {
                return true;
            }
        }
        g_oom_count++;
        return false;
    }
    return true;
}

static inline void add_live(size_t bytes) {
    g_heap_live += bytes;
    if (g_heap_live > g_heap_peak) g_heap_peak = g_heap_live;
}

static inline void sub_live(size_t bytes) {
    if (g_heap_live >= bytes) g_heap_live -= bytes;
    else g_heap_live = 0;
}

static void *raw_alloc(size_t size, bool *out_zeroed) {
    *out_zeroed = false;
    if (size == 0) size = 1;
    if (size > 0x7FFF0000UL) return NULL;

    if (size >= LARGE_THRESH) {
        size_t map_sz = align_page(sizeof(BlkHdr) + size);
        size_t usable = map_sz - sizeof(BlkHdr);
        if (!check_budget_or_gc(usable)) return NULL;

        void *mem = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED || !mem) {
            g_oom_count++;
            return NULL;
        }
        BlkHdr *b = (BlkHdr *)mem;
        b->size      = (uint32_t)map_sz;
        b->prev_phys = 0;
        b->reg_off   = 0;
        b->flags     = BLK_MAGIC | BLK_IN_USE | BLK_DIRECT_MMAP;

        add_live(usable);
        g_alloc_count++;
        *out_zeroed = true; /* Kernel anonymous mmap pages are guaranteed zero-filled */
        return (void *)(b + 1);
    }

    size_t blk_need = align16(sizeof(BlkHdr) + size);
    if (blk_need < MIN_BLK_SZ) blk_need = MIN_BLK_SZ;
    size_t usable = blk_need - sizeof(BlkHdr);
    if (!check_budget_or_gc(usable)) return NULL;

    BlkHdr *chosen = NULL;
    int start_bin = bin_for_size(blk_need);
    for (int bi = start_bin; bi < NUM_BINS && !chosen; bi++) {
        for (BlkHdr *cur = g_bins[bi]; cur; cur = blk_freenode(cur)->next) {
            if (cur->size >= blk_need) {
                chosen = cur;
                break;
            }
        }
    }
    if (!chosen) {
        chosen = slab_grow();
        if (!chosen || chosen->size < blk_need) {
            g_oom_count++;
            return NULL;
        }
    }

    freelist_remove(chosen);
    RegionHdr *reg = blk_region(chosen);

    if (chosen->size - blk_need >= MIN_BLK_SZ) {
        uint32_t rem_sz = (uint32_t)(chosen->size - blk_need);
        BlkHdr *rem = (BlkHdr *)((uint8_t *)chosen + blk_need);
        rem->size      = rem_sz;
        rem->prev_phys = (uint32_t)blk_need;
        rem->reg_off   = chosen->reg_off + (uint32_t)blk_need;
        rem->flags     = BLK_MAGIC;
        blk_phys_next(rem)->prev_phys = rem_sz;
        freelist_insert(rem);
        chosen->size = (uint32_t)blk_need;
    }

    chosen->flags = BLK_MAGIC | BLK_IN_USE;
    reg->live_blocks++;
    add_live(chosen->size - sizeof(BlkHdr));
    g_alloc_count++;
    return (void *)(chosen + 1);
}

void *tb_malloc(size_t size) {
    bool zeroed = false;
    return raw_alloc(size, &zeroed);
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
    bool zeroed = false;
    void *p = raw_alloc(total, &zeroed);
    if (p && !zeroed) {
        BlkHdr *b = ((BlkHdr *)p) - 1;
        memset(p, 0, b->size - sizeof(BlkHdr));
    }
    return p;
}

void tb_free(void *ptr) {
    if (!ptr) return;
    BlkHdr *b = ((BlkHdr *)ptr) - 1;
    if ((b->flags & BLK_MAGIC_MASK) != BLK_MAGIC || !(b->flags & BLK_IN_USE)) {
        return;
    }

    size_t usable = b->size - sizeof(BlkHdr);
    sub_live(usable);
    if (g_alloc_count > 0) g_alloc_count--;

    if (b->flags & BLK_DIRECT_MMAP) {
        b->flags = 0;
        munmap(b, b->size);
        return;
    }

    b->flags = BLK_MAGIC;
    RegionHdr *reg = blk_region(b);
    if (reg->live_blocks > 0) reg->live_blocks--;

    /* Coalesce with physical next block if free */
    BlkHdr *nxt = blk_phys_next(b);
    if (!(nxt->flags & BLK_IN_USE)) {
        freelist_remove(nxt);
        b->size += nxt->size;
        blk_phys_next(b)->prev_phys = b->size;
    }

    /* Coalesce with physical previous block if free */
    BlkHdr *prv = blk_phys_prev(b);
    if (prv && !(prv->flags & BLK_IN_USE)) {
        freelist_remove(prv);
        prv->size += b->size;
        blk_phys_next(prv)->prev_phys = prv->size;
        b = prv;
    }

    /* Keep at most 1 warm empty 64 KB slab; immediately unmap surplus empty slabs */
    if (reg->live_blocks == 0) {
        bool have_other_empty = false;
        for (RegionHdr *r = g_regions; r; r = r->next) {
            if (r != reg && r->live_blocks == 0) {
                have_other_empty = true;
                break;
            }
        }
        if (have_other_empty) {
            region_unlink_and_unmap(reg);
            return;
        }
    }

    freelist_insert(b);
}

void *tb_realloc(void *ptr, size_t size) {
    if (!ptr) return tb_malloc(size);
    if (size == 0) {
        tb_free(ptr);
        return NULL;
    }
    if (size > 0x7FFF0000UL) {
        g_oom_count++;
        return NULL;
    }

    BlkHdr *b = ((BlkHdr *)ptr) - 1;
    if ((b->flags & BLK_MAGIC_MASK) != BLK_MAGIC || !(b->flags & BLK_IN_USE)) {
        return NULL;
    }

    size_t old_usable = b->size - sizeof(BlkHdr);

    if (b->flags & BLK_DIRECT_MMAP) {
        if (size >= LARGE_THRESH / 2) {
            size_t old_map = b->size;
            size_t new_map = align_page(sizeof(BlkHdr) + size);
            if (new_map == old_map) return ptr;
            if (new_map > old_map) {
                if (!check_budget_or_gc(new_map - old_map)) return NULL;
            }
            void *nm = mremap(b, old_map, new_map, MREMAP_MAYMOVE);
            if (nm != MAP_FAILED && nm != NULL) {
                BlkHdr *nb = (BlkHdr *)nm;
                nb->size = (uint32_t)new_map;
                sub_live(old_usable);
                add_live(new_map - sizeof(BlkHdr));
                return (void *)(nb + 1);
            }
        }
    } else {
        size_t blk_need = align16(sizeof(BlkHdr) + size);
        if (blk_need < MIN_BLK_SZ) blk_need = MIN_BLK_SZ;

        if (blk_need <= b->size) {
            /* Shrink in place if remainder is worthwhile */
            if (b->size - blk_need >= 256UL) {
                uint32_t rem_sz = (uint32_t)(b->size - blk_need);
                b->size = (uint32_t)blk_need;
                BlkHdr *rem = (BlkHdr *)((uint8_t *)b + blk_need);
                rem->size      = rem_sz;
                rem->prev_phys = (uint32_t)blk_need;
                rem->reg_off   = b->reg_off + (uint32_t)blk_need;
                rem->flags     = BLK_MAGIC;
                BlkHdr *nxt = blk_phys_next(rem);
                if (!(nxt->flags & BLK_IN_USE)) {
                    freelist_remove(nxt);
                    rem->size += nxt->size;
                }
                blk_phys_next(rem)->prev_phys = rem->size;
                freelist_insert(rem);
                sub_live(rem_sz);
            }
            return ptr;
        }

        /* Try zero-copy in-place expansion into adjacent free block */
        if (size < LARGE_THRESH) {
            BlkHdr *nxt = blk_phys_next(b);
            if (!(nxt->flags & BLK_IN_USE) && (size_t)b->size + nxt->size >= blk_need) {
                size_t extra = blk_need - b->size;
                if (!check_budget_or_gc(extra)) return NULL;

                freelist_remove(nxt);
                uint32_t combined = b->size + nxt->size;
                if (combined - blk_need >= MIN_BLK_SZ) {
                    uint32_t rem_sz = (uint32_t)(combined - blk_need);
                    b->size = (uint32_t)blk_need;
                    BlkHdr *rem = (BlkHdr *)((uint8_t *)b + blk_need);
                    rem->size      = rem_sz;
                    rem->prev_phys = (uint32_t)blk_need;
                    rem->reg_off   = b->reg_off + (uint32_t)blk_need;
                    rem->flags     = BLK_MAGIC;
                    blk_phys_next(rem)->prev_phys = rem_sz;
                    freelist_insert(rem);
                } else {
                    b->size = combined;
                    blk_phys_next(b)->prev_phys = combined;
                }
                sub_live(old_usable);
                add_live(b->size - sizeof(BlkHdr));
                return ptr;
            }
        }
    }

    /* Fallback: allocate new block, copy payload, free old block.
     * Credit old_usable against budget check so net growth governs hard cap. */
    if (size > old_usable) {
        if (!check_budget_or_gc(size - old_usable)) return NULL;
    }
    sub_live(old_usable);
    void *np = tb_malloc(size);
    add_live(old_usable);
    if (!np) return NULL;

    size_t copy_len = old_usable < size ? old_usable : size;
    memcpy(np, ptr, copy_len);
    tb_free(ptr);
    return np;
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

    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return;
    char buf[3072];
    size_t total = 0;
    while (total + 1 < sizeof(buf)) {
        ssize_t n = read(fd, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    close(fd);
    buf[total] = '\0';

    const char *p = buf;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        if (llen > 6 && strncmp(p, "VmRSS:", 6) == 0) {
            out->vm_rss_kb = (size_t)strtoul(p + 6, NULL, 10);
        } else if (llen > 8 && strncmp(p, "RssAnon:", 8) == 0) {
            out->rss_anon_kb = (size_t)strtoul(p + 8, NULL, 10);
        } else if (llen > 8 && strncmp(p, "RssFile:", 8) == 0) {
            out->rss_file_kb = (size_t)strtoul(p + 8, NULL, 10);
        } else if (llen > 6 && strncmp(p, "VmHWM:", 6) == 0) {
            out->vm_hwm_kb = (size_t)strtoul(p + 6, NULL, 10);
        }
        if (!eol) break;
        p = eol + 1;
    }
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
