#include "mocksql.h"

/* ============================================================
The core function used in concat_ws.
** ============================================================ */
void concatFuncCore(
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
