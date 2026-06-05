#include "fv_witness.h"

/* ============================================================
** 1. Bounded abstract heap for one concrete verification witness.
**
** We never store real bytes. For a small fixed set of allocation ids we
** remember only allocation size and liveness. A Pointer is a fat pointer
** carrying {id, offset, length}. Access checks consult both the pointer's
** carried bound and the heap metadata, so a Pointer that over-claims its
** length can still be rejected.
**
** This is not a general-purpose heap model. The heap is intentionally small,
** pre-seeded for the witness in fv_setup(), and only supports a few dynamic
** allocations for the output buffer.
** ============================================================ */

/* Keep concatFuncCore's loop structure intact, but only model the allocation
** extents and read/write bounds needed by this witness. */
static int span_fits(i64 offset, i64 count, i64 limit){
  return count>=0 && offset>=0 && offset<=limit && count<=limit-offset;
}

/* ============================================================
** 2. The sqlite value/context/argv layer, modeled with small shadow state.
**
** The heap tracks only extents and liveness. The semantic fields of the
** witness objects live in a few explicit globals: three argv slots, three
** values, and one result context. Accessors first bounds-check the relevant
** object, then read or update this shadow state.
**
** This keeps the accessor layer close to the original API shape without
** reintroducing a fully symbolic object model.
** ============================================================ */
i64 heap_len[HEAP_MAX];
int heap_live[HEAP_MAX];
int heap_next = 8;

/* Small shadow state for this witness: exactly three argv slots, three values,
** and one result context. */
struct Pointer argv_slot0 = {0, 0, 0};
struct Pointer argv_slot1 = {0, 0, 0};
struct Pointer argv_slot2 = {0, 0, 0};
i64 val_nbyte0 = 0;
i64 val_nbyte1 = 0;
i64 val_nbyte2 = 0;
struct Pointer val_text0 = {0, 0, 0};
struct Pointer val_text1 = {0, 0, 0};
struct Pointer val_text2 = {0, 0, 0};
int ctx_err0 = 0;
struct Pointer ctx_result0 = {0, 0, 0};
i64 ctx_result_len0 = 0;

/* ---- mocked API entry points (same names as the real ones) ---- */
static i64 heap_extent(struct Pointer p){
  if( p.id<=0 || p.id>=HEAP_MAX ) return -1;
  if( !heap_live[p.id] ) return -1;
  return heap_len[p.id];
}

static void check_access(struct Pointer p, i64 count){
  i64 extent = heap_extent(p);
  CVT_assert(
    !MOCK_IS_NULL(p) &&
    span_fits(p.offset, count, p.length) &&
    extent>=0 &&
    span_fits(p.offset, count, extent)
  );
}

void mock_memcpy(struct Pointer dst, struct Pointer src, i64 count){
  check_access(dst, count);
  check_access(src, count);
}

void mock_store_byte(struct Pointer buf, i64 idx, char value){
  (void)value;
  check_access(mock_add(buf, idx), 1);
}

struct Pointer sqlite3_malloc64(i64 n){
  if( n<=0 ) return PTR(0, 0, 0);
  if( heap_next>=HEAP_MAX ) return PTR(0, 0, 0);
  heap_len[heap_next] = n;
  heap_live[heap_next] = 1;
  return PTR(heap_next++, 0, n);
}

void sqlite3_free(struct Pointer p){
  if( p.id>=8 && p.id<HEAP_MAX ) heap_live[p.id] = 0;
}

i64 sqlite3_value_bytes(struct Pointer v){
  check_access(v, VAL_REC_SZ);
  if( v.id==5 ) return val_nbyte0;
  if( v.id==6 ) return val_nbyte1;
  return val_nbyte2;
}

struct Pointer sqlite3_value_text(struct Pointer v){
  if( MOCK_IS_NULL(v) ) return v;
  check_access(v, VAL_REC_SZ);
  if( v.id==5 ) return val_text0;
  if( v.id==6 ) return val_text1;
  return val_text2;
}

struct Pointer sqlite3_argv_get(struct Pointer argv, int i){
  CVT_assert( i>=0 );
  check_access(mock_add(argv, (i64)i * ARG_SLOT_SZ), ARG_SLOT_SZ);
  if( i==0 ) return argv_slot0;
  if( i==1 ) return argv_slot1;
  return argv_slot2;
}

void sqlite3_result_error_nomem(struct Pointer ctx){
  check_access(ctx, CTX_REC_SZ);
  ctx_err0 = SQLITE_NOMEM;
  ctx_result0 = PTR(0, 0, 0);
  ctx_result_len0 = 0;
}

void sqlite3_result_text64(
  struct Pointer ctx, struct Pointer z, i64 n,
  void (*xDel)(struct Pointer), int enc
){
  (void)z;
  (void)xDel;
  (void)enc;
  check_access(ctx, CTX_REC_SZ);
  ctx_err0 = 0;
  ctx_result0 = z;
  ctx_result_len0 = n;
}
