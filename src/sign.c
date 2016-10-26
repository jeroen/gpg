#include "common.h"

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


SEXP make_signatures(gpgme_signature_t sig){
  gpgme_signature_t cur1 = sig;
  gpgme_signature_t cur2 = sig;
  int n = 0;
  while(cur1) {
    cur1 = cur1->next;
    n++;
  }

  SEXP rowname = PROTECT(allocVector(INTSXP, n));
  SEXP fpr = PROTECT(allocVector(STRSXP, n));
  SEXP timestamp = PROTECT(allocVector(INTSXP, n));
  SEXP hash = PROTECT(allocVector(STRSXP, n));
  SEXP algo = PROTECT(allocVector(STRSXP, n));
  SEXP status = PROTECT(allocVector(LGLSXP, n));

  for(int i = 0; i < n; i++) {
    INTEGER(rowname)[i] = i+1;
    SET_STRING_ELT(fpr, i, make_char(cur2->fpr));
    INTEGER(timestamp)[i] = cur2->timestamp;
    SET_STRING_ELT(hash, i, make_char(gpgme_hash_algo_name(cur2->hash_algo)));
    SET_STRING_ELT(algo, i, make_char(gpgme_pubkey_algo_name(cur2->pubkey_algo)));
    LOGICAL(status)[i] = cur2->status == GPG_ERR_NO_ERROR;
    cur2 = cur2->next;
  }
  SEXP df = PROTECT(allocVector(VECSXP, 5));
  SET_VECTOR_ELT(df, 0, fpr);
  SET_VECTOR_ELT(df, 1, timestamp);
  SET_VECTOR_ELT(df, 2, hash);
  SET_VECTOR_ELT(df, 3, algo);
  SET_VECTOR_ELT(df, 4, status);

  SEXP names = PROTECT(allocVector(STRSXP, 5));
  SET_STRING_ELT(names, 0, mkChar("fingerprint"));
  SET_STRING_ELT(names, 1, mkChar("timestamp"));
  SET_STRING_ELT(names, 2, mkChar("hash"));
  SET_STRING_ELT(names, 3, mkChar("pubkey"));
  SET_STRING_ELT(names, 4, mkChar("success"));
  setAttrib(df, R_NamesSymbol, names);
  setAttrib(df, R_ClassSymbol, mkString("data.frame"));
  setAttrib(df, R_RowNamesSymbol, rowname);
  UNPROTECT(8);
  return df;
}

SEXP R_gpgme_verify(SEXP sig, SEXP msg) {
  gpgme_data_t SIG, MSG;
  bail(gpgme_data_new_from_mem(&SIG, (const char*) RAW(sig), LENGTH(sig), 0), "creating sig buffer");
  if(Rf_length(msg)){
    bail(gpgme_data_new_from_mem(&MSG, (const char*) RAW(msg), LENGTH(msg), 0), "creating msg buffer");
    bail(gpgme_op_verify(ctx, SIG, MSG, NULL), "detached verification");
  } else {
    bail(gpgme_data_new(&MSG), "creating output buffer");
    bail(gpgme_op_verify(ctx, SIG, NULL, MSG), "clear verification");
    //do something with MSG here?
  }
  gpgme_verify_result_t result = gpgme_op_verify_result(ctx);
  return make_signatures(result->signatures);
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
