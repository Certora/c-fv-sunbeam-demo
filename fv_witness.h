#ifndef FV_WITNESS_H
#define FV_WITNESS_H

#include "mocksql.h"

#define PTR_SZ      8
#define INT_SZ      4
#define VAL_REC_SZ  (INT_SZ + PTR_SZ)
#define CTX_REC_SZ  (INT_SZ + PTR_SZ + INT_SZ)
#define ARG_SLOT_SZ PTR_SZ
#define SQLITE_NOMEM 7

/* 2 * 2,147,483,647 = 2^32 - 2, so removing the (i64) cast from the
** separator-size contribution turns it into -2 after i32 wraparound. */
#define CVE_ARGC      3
#define CVE_ARG_NBYTE 1
#define CVE_NSEP      2147483647

#define P_CTX  PTR(1, 0, CTX_REC_SZ)
#define P_ARGV PTR(2, 0, (i64)CVE_ARGC * ARG_SLOT_SZ)
#define P_SEP  PTR(3, 0, CVE_NSEP)
#define P_TEXT PTR(4, 0, CVE_ARG_NBYTE)
#define P_VAL0 PTR(5, 0, VAL_REC_SZ)
#define P_VAL1 PTR(6, 0, VAL_REC_SZ)
#define P_VAL2 PTR(7, 0, VAL_REC_SZ)

#define HEAP_MAX 10

extern i64 heap_len[HEAP_MAX];
extern int heap_live[HEAP_MAX];
extern int heap_next;

extern struct Pointer argv_slot0;
extern struct Pointer argv_slot1;
extern struct Pointer argv_slot2;
extern i64 val_nbyte0;
extern i64 val_nbyte1;
extern i64 val_nbyte2;
extern struct Pointer val_text0;
extern struct Pointer val_text1;
extern struct Pointer val_text2;
extern int ctx_err0;
extern struct Pointer ctx_result0;
extern i64 ctx_result_len0;

void fv_setup(void);

#endif
