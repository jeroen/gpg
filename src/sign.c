#include "common.h"

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

SEXP R_gpgme_verify(SEXP sig, SEXP msg) {
  gpgme_data_t SIG, MSG;
  bail(gpgme_data_new_from_mem(&SIG, (const char*) RAW(sig), LENGTH(sig), 0), "creating sig buffer");
  if(Rf_length(msg)){
    bail(gpgme_data_new_from_mem(&MSG, (const char*) RAW(msg), LENGTH(msg), 0), "creating msg buffer");
    bail(gpgme_op_verify(ctx, SIG, MSG, NULL), "detached verification");
  } else {
    bail(gpgme_op_verify(ctx, SIG, NULL, NULL), "clear verification");
  }
  gpgme_verify_result_t result = gpgme_op_verify_result(ctx);
  gpgme_signature_t cur1 = result->signatures;
  int n = 0;
  while(cur1) {
    cur1 = cur1->next;
    n++;
  }
  if(n == 0)
    Rf_errorcall(R_NilValue, "Failed to find signature for this file");
  gpgme_signature_t cur2 = result->signatures;
  SEXP out = PROTECT(allocVector(VECSXP, n));
  for(int i = 0; i < n; i++) {
    SEXP el = PROTECT(allocVector(VECSXP, 5));
    SET_VECTOR_ELT(el, 0, make_string(cur2->fpr));
    SET_VECTOR_ELT(el, 1, ScalarInteger(cur2->timestamp));
    SET_VECTOR_ELT(el, 2, make_string(gpgme_hash_algo_name(cur2->hash_algo)));
    SET_VECTOR_ELT(el, 3, make_string(gpgme_pubkey_algo_name(cur2->pubkey_algo)));
    SET_VECTOR_ELT(el, 4, ScalarLogical(cur2->status == GPG_ERR_NO_ERROR));
    cur2 = cur2->next;
    SET_VECTOR_ELT(out, i, el);
    UNPROTECT(1);
  }
  UNPROTECT(1);
  return out;
}

SEXP R_gpg_sign(SEXP msg, SEXP id, SEXP mode){
  gpgme_data_t SIG, MSG;
  gpgme_signers_clear(ctx);

  // GPG uses default or first key if no id's are given
  for(int i = 0; i < Rf_length(id); i++){
    gpgme_key_t key = NULL;
    bail(gpgme_get_key(ctx, CHAR(STRING_ELT(id, i)), &key, 1), "load key from keyring");
    bail(gpgme_signers_add(ctx, key), "add signer");
  }

  gpgme_sig_mode_t sigmode = GPGME_SIG_MODE_NORMAL;
  if(!strcmp(CHAR(STRING_ELT(mode, 0)), "detach")){
    sigmode = GPGME_SIG_MODE_DETACH;
  } else if(!strcmp(CHAR(STRING_ELT(mode, 0)), "clear")){
    sigmode = GPGME_SIG_MODE_CLEAR;
  }

  //create signature
  bail(gpgme_data_new_from_mem(&MSG, (const char*) RAW(msg), LENGTH(msg), 0), "creating msg buffer");
  bail(gpgme_data_new(&SIG), "memory to hold signature");
  bail(gpgme_op_sign(ctx, MSG, SIG, sigmode), "signing");
  gpgme_signers_clear(ctx);

  //do something with result
  //gpgme_sign_result_t result = gpgme_op_sign_result(ctx);
  //gpgme_new_signature_t res = result->signatures;
  return data_to_string(SIG);
}
