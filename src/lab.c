#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#ifdef __APPLE__
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#endif


#include "lab.h"

#define handle_error_and_die(msg) \
    do { perror(msg); raise(SIGKILL); } while(0)


static void *map_lower_half(size_t length)
{
#ifdef __APPLE__
    const uintptr_t START_HINT = 0x100000000ULL; 
    const uintptr_t END_HINT   = 0x800000000ULL; 
    for (uintptr_t addr = START_HINT; addr + length <= END_HINT; addr += length) {
        void *hint = (void*)addr;
        void *res = mmap(hint, length,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                         -1, 0);
        /* If mmap succeeds, it will return exactly the requested address */
        if (res != MAP_FAILED && res == hint) {
            return res; /* success */
        }
    }
    return MAP_FAILED;
#else
    const uintptr_t START_HINT = 0x100000000ULL; /* 4 GB */
    const uintptr_t END_HINT   = 0x800000000ULL; /* 32 GB */
    for (uintptr_t addr = START_HINT; addr + length <= END_HINT; addr += length) {
        void *hint = (void*)addr;
        void *res = mmap(hint, length,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                         -1, 0);
        if (res != MAP_FAILED) {
            return res; /* success */
        }
    }
    return MAP_FAILED;
#endif
}

/* map_aligned: If lower-half mapping fails, fall back to letting the OS pick an address.
 * Note: In that case pool->base may not be in the lower–half, which may cause tests
 * expecting a lower–half base address to fail.
 */
static void *map_aligned(size_t length)
{
    void *lh = map_lower_half(length);
    if (lh != MAP_FAILED) {
        return lh;
    }
    return mmap(NULL, length, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);
}


   

/**
 * Simple bitshift approach: find k with 2^k >= bytes.
 */
size_t btok(size_t bytes)
{
    if (bytes == 0) {
        return 0;
    }
    size_t k=0;
    size_t cap=1;
    while (cap < bytes) {
        k++;
        cap = (1ULL << k);
    }
    return k;
}

/**
 * buddy_init: clamp k in [MIN_K..(MAX_K-1)], map region,
 * init free-lists, insert one big free block.
 */
void buddy_init(struct buddy_pool *pool, size_t size)
{
    memset(pool, 0, sizeof(*pool));

    size_t k = btok(size);
    if (k < MIN_K) k = MIN_K;
    if (k > MAX_K) k = MAX_K - 1;
    pool->kval_m  = k;
    pool->numbytes = (1ULL << k);

    void *reg = map_aligned(pool->numbytes);
    if (reg == MAP_FAILED) {
        handle_error_and_die("buddy_init: could not map region");
    }
    pool->base = reg;

    for (size_t i=0; i<=k; i++){
        pool->avail[i].next = &pool->avail[i];
        pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].tag  = BLOCK_UNUSED;
        pool->avail[i].kval = i;
    }

    /* one big free block of size=k */
    struct avail *block = (struct avail*)reg;
    block->tag  = BLOCK_AVAIL;
    block->kval = k;
    block->next = block->prev = &pool->avail[k];
    pool->avail[k].next = block;
    pool->avail[k].prev = block;
}

/**
 * buddy_destroy: unmap & zero the pool struct.
 */
void buddy_destroy(struct buddy_pool *pool)
{
    if (pool->base) {
        munmap(pool->base, pool->numbytes);
    }
    memset(pool, 0, sizeof(*pool));
}

/**
 * buddy_calc: "Knuth" style. 
 *   offset_in_block = ( (uintptr_t)block - base ) mod 2^k
 *   buddy_offset_in_block = offset_in_block ^ (1 << (k-1))
 *   buddy = base + buddy_offset_in_block
 */
struct avail* buddy_calc(struct buddy_pool *pool, struct avail *block)
{
    uintptr_t base = (uintptr_t)pool->base;
    size_t k = block->kval;

    uintptr_t raw_offset = (uintptr_t)block - base;
    /* mask in lower k bits */
    uintptr_t region_mask = ( (1ULL << k) - 1ULL );
    uintptr_t offset_in_block = raw_offset & region_mask;

    uintptr_t buddy_off_in_block = offset_in_block ^ (1ULL << (k-1));
    uintptr_t buddy_addr = base + buddy_off_in_block;

    return (struct avail*)buddy_addr;
}

/**
 * buddy_malloc:
 *   overhead = sizeof(struct avail)
 *   total = user_size + overhead
 *   find j >= k w/ a free block
 *   remove from list
 *   split down
 *   mark reserved, return (block+1)
 */
void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    if (!pool || size==0) {
        return NULL;
    }

    /* overhead is real, so we do: */
    size_t total = size + sizeof(struct avail);

    size_t k = btok(total);
    if (k < SMALLEST_K) {
        k = SMALLEST_K;
    }

    /* search for j >= k with non-empty list */
    size_t j = k;
    while (j <= pool->kval_m) {
        if (pool->avail[j].next != &pool->avail[j]) {
            break; /* found a list w/ a block */
        }
        j++;
    }
    if (j > pool->kval_m) {
        errno = ENOMEM;
        return NULL;
    }

    /* remove first block from avail[j] */
    struct avail *block = pool->avail[j].next;
    block->prev->next = block->next;
    block->next->prev = block->prev;

    while (j > k) {
        j--;
        uintptr_t half = (1ULL << (j - 1));
        struct avail *buddy = (struct avail *)((uintptr_t)block + half);
    
        // init buddy
        buddy->tag  = BLOCK_AVAIL;
        buddy->kval = j;

        buddy->next = pool->avail[j].next;
        buddy->prev = &pool->avail[j];
        pool->avail[j].next->prev = buddy;
        pool->avail[j].next       = buddy;
    }

    /* mark final block reserved */
    block->tag  = BLOCK_RESERVED;
    block->kval = k;
    return (void*)(block + 1); /* user pointer */
}

/**
 * buddy_free:
 *   mark free
 *   coalesce w/ buddy if free & same k
 *   insert final block
 */
void buddy_free(struct buddy_pool *pool, void *ptr)
{
    if (!pool || !ptr) {
        return;
    }
    struct avail *block = (struct avail*)ptr - 1;
    if (block->tag != BLOCK_RESERVED) {
        return;
    }

    block->tag = BLOCK_AVAIL;
    size_t k = block->kval;

    while (k < pool->kval_m) {
        struct avail *buddy = buddy_calc(pool, block);

        /* check if buddy is in range, free, same k */
        uintptr_t baddr = (uintptr_t)buddy;
        uintptr_t start = (uintptr_t)pool->base;
        uintptr_t end   = start + pool->numbytes;
        if (baddr < start || baddr >= end) {
            break;
        }
        if (buddy->tag != BLOCK_AVAIL) {
            break;
        }
        if (buddy->kval != k) {
            break;
        }

        /* remove buddy from free list */
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        /* coalesce => bigger block labeled k+1 at lower address */
        if (buddy < block) {
            block = buddy;
        }
        block->kval = ++k;
    }

    /* insert final block */
    block->next = pool->avail[k].next;
    block->prev = &pool->avail[k];
    pool->avail[k].next->prev = block;
    pool->avail[k].next       = block;
}

/**
 * buddy_realloc:
 *   if ptr==NULL => malloc
 *   if size==0 => free
 *   else alloc new, copy, free old
 */
void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
{
    if (!ptr) {
        return buddy_malloc(pool, size);
    }
    if (size==0) {
        buddy_free(pool, ptr);
        return NULL;
    }

    struct avail *old = (struct avail*)ptr - 1;
    if (old->tag != BLOCK_RESERVED) {
        return NULL; /* invalid */
    }

    size_t old_bytes = (1ULL << old->kval);
    size_t old_user  = old_bytes - sizeof(struct avail);

    void *new_ptr = buddy_malloc(pool, size);
    if (!new_ptr) {
        return NULL;
    }
    size_t to_copy = (size < old_user) ? size : old_user;
    memcpy(new_ptr, ptr, to_copy);

    buddy_free(pool, ptr);
    return new_ptr;
}

/* optional main or debug routines */
int myMain(int argc, char** argv)
{
    (void)argc; (void)argv;
    return 0;
}
