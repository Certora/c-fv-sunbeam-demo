#include "fv_witness.h"

void CVT_assert(int rc) {
  if(!rc) {
    __builtin_trap();
  }
}

/* Initialize the bounded heap metadata and shadow SQLite state
** for the single concrete witness used by run_case(). */
void fv_setup(void){
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

/* Exported verification entrypoint for the concrete witness used in this repo. */
__attribute__((export_name("run_case")))
void run_case(void){
  fv_setup();
  concatFuncCore(P_CTX, CVE_ARGC, P_ARGV, CVE_NSEP, P_SEP);
}
