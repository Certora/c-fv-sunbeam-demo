typedef long long i64;

void CVT_assert(int rc) {
  if(!rc) {
	__builtin_trap();
  }
}

/* ============================================================
** 1. Bounded mock of heap for one concrete verification witness.
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
struct Pointer { int id; i64 offset; i64 length; };
#define MOCK_IS_NULL(p) ((p).id == 0)
#define PTR(id, offset, length) ((struct Pointer){(id), (offset), (length)})
#define mock_add(base, delta) PTR((base).id, (base).offset + (delta), (base).length)
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
#define PTR_SZ      8                       /* bytes a Pointer occupies      */
#define INT_SZ      4
#define VAL_REC_SZ  (INT_SZ + PTR_SZ)       /* { nByte, text }               */
#define CTX_REC_SZ  (INT_SZ + PTR_SZ + INT_SZ) /* { err, result, resultLen } */
#define ARG_SLOT_SZ PTR_SZ                   /* one Pointer per argv slot     */
#define MAX_ARGS    3
#define SQLITE_UTF8 1
#define SQLITE_NOMEM 7
/* 2 * 2,147,483,647 = 2^32 - 2, so removing the (i64) cast from the
** separator-size contribution turns it into -2 after i32 wraparound. */
#define CVE_ARGC     3
#define CVE_ARG_NBYTE 1
#define CVE_NSEP     2147483647

#define P_CTX  PTR(1, 0, CTX_REC_SZ)
#define P_ARGV PTR(2, 0, (i64)CVE_ARGC * ARG_SLOT_SZ)
#define P_SEP  PTR(3, 0, CVE_NSEP)
#define P_TEXT PTR(4, 0, CVE_ARG_NBYTE)
#define P_VAL0 PTR(5, 0, VAL_REC_SZ)
#define P_VAL1 PTR(6, 0, VAL_REC_SZ)
#define P_VAL2 PTR(7, 0, VAL_REC_SZ)

#define HEAP_MAX 10
static i64 heap_len[HEAP_MAX];
static int heap_live[HEAP_MAX];
static int heap_next = 8;

/* Small shadow state for this witness: exactly three argv slots, three values,
** and one result context. */
static struct Pointer argv_slot0 = {0, 0, 0};
static struct Pointer argv_slot1 = {0, 0, 0};
static struct Pointer argv_slot2 = {0, 0, 0};
static i64 val_nbyte0 = 0;
static i64 val_nbyte1 = 0;
static i64 val_nbyte2 = 0;
static struct Pointer val_text0 = {0, 0, 0};
static struct Pointer val_text1 = {0, 0, 0};
static struct Pointer val_text2 = {0, 0, 0};
static int ctx_err0 = 0;
static struct Pointer ctx_result0 = {0, 0, 0};
static i64 ctx_result_len0 = 0;

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

static void mock_memcpy(struct Pointer dst, struct Pointer src, i64 count){
  check_access(dst, count);
  check_access(src, count);
}

static void mock_store_byte(struct Pointer buf, i64 idx, char value){
  (void)value;
  check_access(mock_add(buf, idx), 1);
}

static struct Pointer sqlite3_malloc64(i64 n){
  if( n<=0 ) return PTR(0, 0, 0);
  if( heap_next>=HEAP_MAX ) return PTR(0, 0, 0);
  heap_len[heap_next] = n;
  heap_live[heap_next] = 1;
  return PTR(heap_next++, 0, n);
}
static void sqlite3_free(struct Pointer p){
  if( p.id>=8 && p.id<HEAP_MAX ) heap_live[p.id] = 0;
}

static i64 sqlite3_value_bytes(struct Pointer v){
  check_access(v, VAL_REC_SZ);
  if( v.id==5 ) return val_nbyte0;
  if( v.id==6 ) return val_nbyte1;
  return val_nbyte2;
}

static struct Pointer sqlite3_value_text(struct Pointer v){
  if( MOCK_IS_NULL(v) ) return v;
  check_access(v, VAL_REC_SZ);
  if( v.id==5 ) return val_text0;
  if( v.id==6 ) return val_text1;
  return val_text2;
}

static struct Pointer sqlite3_argv_get(struct Pointer argv, int i){
  CVT_assert( i>=0 );
  check_access(mock_add(argv, (i64)i * ARG_SLOT_SZ), ARG_SLOT_SZ);
  if( i==0 ) return argv_slot0;
  if( i==1 ) return argv_slot1;
  return argv_slot2;
}

static void sqlite3_result_error_nomem(struct Pointer ctx){
  check_access(ctx, CTX_REC_SZ);
  ctx_err0 = SQLITE_NOMEM;
  ctx_result0 = PTR(0, 0, 0);
  ctx_result_len0 = 0;
}

static void sqlite3_result_text64(
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

/* Seed the bounded heap and the shadow SQLite state for the single witness
** used by run_case(). This is verifier scaffolding, not modeled program logic. */
/* Initialize the bounded heap metadata and shadow SQLite state
** for the single concrete witness used by run_case(). */
static void fv_setup(void){
  heap_len[0] = 0;
  heap_len[1] = CTX_REC_SZ;
  heap_len[2] = (i64)CVE_ARGC * ARG_SLOT_SZ;
  heap_len[3] = CVE_NSEP;
  heap_len[4] = CVE_ARG_NBYTE;
  heap_len[5] = VAL_REC_SZ;
  heap_len[6] = VAL_REC_SZ;
  heap_len[7] = VAL_REC_SZ;
  heap_len[8] = 0;
  heap_len[9] = 0;
  heap_live[0] = 0;
  heap_live[1] = 1;
  heap_live[2] = 1;
  heap_live[3] = 1;
  heap_live[4] = 1;
  heap_live[5] = 1;
  heap_live[6] = 1;
  heap_live[7] = 1;
  heap_live[8] = 0;
  heap_live[9] = 0;
  heap_next = 8;
  argv_slot0 = P_VAL0;
  argv_slot1 = P_VAL1;
  argv_slot2 = P_VAL2;
  val_nbyte0 = CVE_ARG_NBYTE;
  val_nbyte1 = CVE_ARG_NBYTE;
  val_nbyte2 = CVE_ARG_NBYTE;
  val_text0 = P_TEXT;
  val_text1 = P_TEXT;
  val_text2 = P_TEXT;
  ctx_err0 = 0;
  ctx_result0 = PTR(0, 0, 0);
  ctx_result_len0 = 0;
}

/* ============================================================
** 3. The function -- now purely Pointer + ints. No opaque types.
** ============================================================ */
static void concatFuncCore(
  struct Pointer context,        /* was: sqlite3_context *context */
  int argc,
  struct Pointer argv,           /* was: sqlite3_value **argv     */
  int nSep,
  struct Pointer zSep            /* was: const char *zSep         */
){
  i64 j, k, n = 0;
  int i;
  struct Pointer z;
  for(i=0; i<argc; i++){
    n += sqlite3_value_bytes( sqlite3_argv_get(argv, i) );
  }
  n += (argc-1)*nSep; // buggy version
  // n += (argc-1)*(i64)nSep; // fixed version
  z = sqlite3_malloc64(n+1);
  if( MOCK_IS_NULL(z) ){
    sqlite3_result_error_nomem(context);
    return;
  }
  j = 0;
  for(i=0; i<argc; i++){
    struct Pointer ai = sqlite3_argv_get(argv, i);     /* argv[i] */
    k = sqlite3_value_bytes(ai);
    if( k>0 ){
      struct Pointer v = sqlite3_value_text(ai);
      if( !MOCK_IS_NULL(v) ){
        if( j>0 && nSep>0 ){
          mock_memcpy(mock_add(z, j), zSep, nSep);
          j += nSep;
        }
        mock_memcpy(mock_add(z, j), v, k);
        j += k;
      }
    }
  }
  mock_store_byte(z, j, 0);
  CVT_assert( j<=n );
  sqlite3_result_text64(context, z, j, sqlite3_free, SQLITE_UTF8);
}

/* Exported verification entrypoint for the concrete witness used in this repo. */
__attribute__((export_name("run_case")))
void run_case(void){
  fv_setup();
  concatFuncCore(P_CTX, CVE_ARGC, P_ARGV, CVE_NSEP, P_SEP);
}
