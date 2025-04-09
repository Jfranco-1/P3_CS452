#include <assert.h>
#include <stdlib.h>
#include <string.h>  /* For memset */
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include "harness/unity.h"
#include "../src/lab.h"

/* Called before each test */
void setUp(void) {
  // No global setup required
}

/* Called after each test */
void tearDown(void) {
  // No global teardown required
}

/**
 * Check the pool to ensure it is full.
 */
void check_buddy_pool_full(struct buddy_pool *pool)
{
  /* A full pool should have all avail buckets for indices 0 to kval_m - 1 empty */
  for (size_t i = 0; i < pool->kval_m; i++) {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
  }

  /* For bucket at index kval_m, it should contain the single base free block */
  assert(pool->avail[pool->kval_m].next->tag == BLOCK_AVAIL);
  assert(pool->avail[pool->kval_m].next->next == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].prev->prev == &pool->avail[pool->kval_m]);

  /* The free block in the highest bucket should be exactly at the base address */
  assert(pool->avail[pool->kval_m].next == pool->base);
}

/**
 * Check the pool to ensure it is empty.
 */
void check_buddy_pool_empty(struct buddy_pool *pool)
{
  for (size_t i = 0; i <= pool->kval_m; i++) {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
  }
}

/**
 * Test allocating 1 byte ensuring splitting down to MIN_K, then freeing restores full pool.
 */
void test_buddy_malloc_one_byte(void)
{
  fprintf(stderr, "->Test allocating and freeing 1 byte\n");
  struct buddy_pool pool;
  int kval = MIN_K;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);

  void *mem = buddy_malloc(&pool, 1);
  TEST_ASSERT_NOT_NULL(mem);

  /* Free the allocated block and verify the pool is restored to full */
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test allocating one massive block that consumes the entire pool.
 */
void test_buddy_malloc_one_large(void)
{
  fprintf(stderr, "->Testing size that will consume entire memory pool\n");
  struct buddy_pool pool;
  size_t bytes = UINT64_C(1) << MIN_K;
  buddy_init(&pool, bytes);

  /* Ask for nearly the entire pool (accounting for the avail header) */
  size_t ask = bytes - sizeof(struct avail);
  void *mem = buddy_malloc(&pool, ask);
  TEST_ASSERT_NOT_NULL(mem);

  /* Verify that the allocated block has the expected kval and tag */
  struct avail *tmp = (struct avail *)mem - 1;
  TEST_ASSERT_EQUAL_UINT16(MIN_K, tmp->kval);
  TEST_ASSERT_EQUAL_UINT16(BLOCK_RESERVED, tmp->tag);
  check_buddy_pool_empty(&pool);

  /* Subsequent allocation should fail with ENOMEM */
  errno = 0;
  void *fail = buddy_malloc(&pool, 5);
  TEST_ASSERT_NULL(fail);
  TEST_ASSERT_EQUAL_INT(ENOMEM, errno);

  /* Free and check that the pool is full again */
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test buddy_init: for various sizes the pool should be correctly initialized.
 */
void test_buddy_init(void)
{
  fprintf(stderr, "->Testing buddy init\n");
  /* Loop for sizes from MIN_K up through DEFAULT_K */
  for (size_t i = MIN_K; i <= DEFAULT_K; i++) {
      size_t size = UINT64_C(1) << i;
      struct buddy_pool pool;
      buddy_init(&pool, size);
      check_buddy_pool_full(&pool);
      buddy_destroy(&pool);
  }
}

/**
 * Test the btok function.
 */
void test_btok(void)
{
  fprintf(stderr, "->Testing btok function\n");
  TEST_ASSERT_EQUAL_size_t(0, btok(1));     // 1 => 2^0
  TEST_ASSERT_EQUAL_size_t(1, btok(2));     // 2 => 2^1
  TEST_ASSERT_EQUAL_size_t(2, btok(3));     // 3 => rounds to 4 => k=2
  TEST_ASSERT_EQUAL_size_t(10, btok(1024)); // 1024 => 2^10
}

/**
 * Test buddy_calc function.
 */
void test_buddy_calc(void)
{
  fprintf(stderr, "->Testing buddy_calc function\n");
  struct buddy_pool pool;
  size_t kval = MIN_K;
  buddy_init(&pool, (UINT64_C(1) << kval));

  /* Base block is at pool->base */
  struct avail *base_block = (struct avail *)pool.base;
  struct avail *buddy = buddy_calc(&pool, base_block);

  /* Expected buddy offset = 2^(kval - 1) relative to pool->base */
  uintptr_t expected = (UINT64_C(1) << (kval - 1));
  uintptr_t actual   = (uintptr_t)buddy - (uintptr_t)pool.base;
  TEST_ASSERT_EQUAL_UINT64(expected, actual);

  /* Buddy of buddy should be the original block */
  struct avail *buddy_of_buddy = buddy_calc(&pool, buddy);
  TEST_ASSERT_EQUAL_PTR(base_block, buddy_of_buddy);

  buddy_destroy(&pool);
}

/**
 * Test multiple allocations/frees.
 */
void test_buddy_multiple_allocs(void)
{
  fprintf(stderr, "->Testing multiple allocations/frees\n");
  struct buddy_pool pool;
  size_t pool_size = UINT64_C(1) << 22; // 4 MiB
  buddy_init(&pool, pool_size);

  void *a = buddy_malloc(&pool, 128);
  TEST_ASSERT_NOT_NULL(a);
  void *b = buddy_malloc(&pool, 1000);
  TEST_ASSERT_NOT_NULL(b);
  void *c = buddy_malloc(&pool, 50000);
  TEST_ASSERT_NOT_NULL(c);

  /* Free in a different order */
  buddy_free(&pool, b);
  buddy_free(&pool, a);
  buddy_free(&pool, c);

  /* Pool should now be full (all blocks coalesced) */
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test out-of-memory scenario by allocating many small blocks.
 */
void test_buddy_out_of_memory(void) {
  struct buddy_pool pool;
  size_t kval = 20; // 1MB pool
  buddy_init(&pool, UINT64_C(1) << kval);

  size_t chunk_size = 1024;
  size_t block_size = chunk_size + sizeof(struct avail);
  
  /* Calculate how many blocks might fit */
  size_t total_chunks = (UINT64_C(1) << kval) / block_size;
  
  void **blocks = malloc(total_chunks * sizeof(void *));
  TEST_ASSERT_NOT_NULL(blocks);

  size_t allocated = 0;
  for (size_t i = 0; i < total_chunks + 10; i++) {
      void *ptr = buddy_malloc(&pool, chunk_size);
      if (!ptr) break;
      blocks[allocated++] = ptr;
  }

  /* Expect exactly total_chunks blocks allocated due to buddy splitting constraints */
  TEST_ASSERT_EQUAL_size_t(total_chunks, allocated);

  /* Next allocation should fail */
  errno = 0;
  void *fail = buddy_malloc(&pool, chunk_size);
  TEST_ASSERT_NULL(fail);
  TEST_ASSERT_EQUAL_INT(ENOMEM, errno);

  /* Free all allocated blocks */
  for (size_t i = 0; i < allocated; i++) {
      buddy_free(&pool, blocks[i]);
  }
  free(blocks);

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test buddy_malloc edge cases.
 */
void test_buddy_malloc_edge_cases(void)
{
  fprintf(stderr, "->Testing malloc edge cases\n");
  struct buddy_pool pool;
  buddy_init(&pool, (1ULL << MIN_K));

  /* Null pool should return NULL */
  void *r1 = buddy_malloc(NULL, 100);
  TEST_ASSERT_NULL(r1);

  /* Zero size should return NULL */
  void *r2 = buddy_malloc(&pool, 0);
  TEST_ASSERT_NULL(r2);

  buddy_destroy(&pool);
}

/**
 * Test buddy_free edge cases.
 */
void test_buddy_free_edge_cases(void)
{
  fprintf(stderr, "->Testing free edge cases\n");
  struct buddy_pool pool;
  buddy_init(&pool, (1ULL << MIN_K));

  /* Passing a NULL pool does nothing */
  buddy_free(NULL, (void*)0x1234);

  /* Passing a NULL pointer does nothing */
  buddy_free(&pool, NULL);

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test buddy_realloc.
 */
void test_buddy_realloc(void)
{
  fprintf(stderr, "->Testing realloc\n");
  struct buddy_pool pool;
  buddy_init(&pool, (1ULL << 22)); // 4 MiB

  /* realloc(NULL, size) should work like malloc */
  void *ptr1 = buddy_realloc(&pool, NULL, 100);
  TEST_ASSERT_NOT_NULL(ptr1);
  memset(ptr1, 0x5A, 100);

  /* Expand allocation */
  void *ptr2 = buddy_realloc(&pool, ptr1, 1000);
  TEST_ASSERT_NOT_NULL(ptr2);
  for (int i = 0; i < 100; i++) {
    TEST_ASSERT_EQUAL_UINT8(0x5A, ((unsigned char*)ptr2)[i]);
  }

  /* Shrink allocation */
  void *ptr3 = buddy_realloc(&pool, ptr2, 50);
  TEST_ASSERT_NOT_NULL(ptr3);
  for (int i = 0; i < 50; i++) {
    TEST_ASSERT_EQUAL_UINT8(0x5A, ((unsigned char*)ptr3)[i]);
  }

  /* realloc to 0 should free the block and return NULL */
  void *ptr4 = buddy_realloc(&pool, ptr3, 0);
  TEST_ASSERT_NULL(ptr4);

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test buddy coalescing.
 */
void test_buddy_coalescing(void)
{
  fprintf(stderr, "->Testing buddy coalescing\n");
  struct buddy_pool pool;
  size_t kval = 21; // 2 MiB
  buddy_init(&pool, (1ULL << kval));

  /* Allocate half of the pool */
  size_t half_size = (1ULL << (kval - 1));
  void *blockA = buddy_malloc(&pool, half_size - sizeof(struct avail));
  TEST_ASSERT_NOT_NULL(blockA);

  /* Allocate a small block from the other half */
  void *blockB = buddy_malloc(&pool, 1024);
  TEST_ASSERT_NOT_NULL(blockB);

  /* Free both blocks and expect them to coalesce into one block */
  buddy_free(&pool, blockA);
  buddy_free(&pool, blockB);

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/* -------------------------------------------------------------------
   main() - run all tests
   ------------------------------------------------------------------- */
int main(void) {
  time_t t;
  unsigned seed = (unsigned)time(&t);
  fprintf(stderr, "Random seed:%u\n", seed);
  srand(seed);
  printf("Running memory tests.\n");

  UNITY_BEGIN();

  /* -- Original tests -- */
  RUN_TEST(test_buddy_init);
  RUN_TEST(test_buddy_malloc_one_byte);
  RUN_TEST(test_buddy_malloc_one_large);

  /* -- Additional / custom tests -- */
  RUN_TEST(test_btok);
  RUN_TEST(test_buddy_calc);
  RUN_TEST(test_buddy_multiple_allocs);
  RUN_TEST(test_buddy_out_of_memory);
  RUN_TEST(test_buddy_malloc_edge_cases);
  RUN_TEST(test_buddy_free_edge_cases);
  RUN_TEST(test_buddy_realloc);
  RUN_TEST(test_buddy_coalescing);

  return UNITY_END();
}
