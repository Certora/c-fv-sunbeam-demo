#ifndef MOCKSQL_H
#define MOCKSQL_H

typedef long long i64;

struct Pointer { int id; i64 offset; i64 length; };

#define MOCK_IS_NULL(p) ((p).id == 0)
#define PTR(id, offset, length) ((struct Pointer){(id), (offset), (length)})
#define mock_add(base, delta) PTR((base).id, (base).offset + (delta), (base).length)

#define SQLITE_UTF8 1

void CVT_assert(int rc);

struct Pointer sqlite3_malloc64(i64 n);
void sqlite3_free(struct Pointer p);
void mock_memcpy(struct Pointer dst, struct Pointer src, i64 count);
void mock_store_byte(struct Pointer buf, i64 idx, char value);
i64 sqlite3_value_bytes(struct Pointer v);
struct Pointer sqlite3_value_text(struct Pointer v);
struct Pointer sqlite3_argv_get(struct Pointer argv, int i);
void sqlite3_result_error_nomem(struct Pointer ctx);
void sqlite3_result_text64(
  struct Pointer ctx, struct Pointer z, i64 n,
  void (*xDel)(struct Pointer), int enc
);

void concatFuncCore(
  struct Pointer context,
  int argc,
  struct Pointer argv,
  int nSep,
  struct Pointer zSep
);

#endif
