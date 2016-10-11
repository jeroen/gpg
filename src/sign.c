#include "common.h"

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

SEXP R_gpgme_verify(SEXP sig, SEXP msg) {
  gpgme_data_t SIG, MSG;
  bail(gpgme_data_new_from_mem(&SIG, (const char*) RAW(sig), LENGTH(sig), 0), "creating sig buffer");
  bail(gpgme_data_new_from_mem(&MSG, (const char*) RAW(msg), LENGTH(msg), 0), "creating msg buffer");
  bail(gpgme_op_verify(ctx, SIG, MSG, NULL), "verification");
  gpgme_verify_result_t result = gpgme_op_verify_result(ctx);
  gpgme_signature_t cur1 = result->signatures;
  int n = 0;
  while(cur1) {
    cur1 = cur1->next;
    n++;
  }
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

SEXP R_gpg_sign(SEXP msg, SEXP id){
  gpgme_data_t SIG, MSG;
  gpgme_key_t key = NULL;
  bail(gpgme_get_key(ctx, CHAR(STRING_ELT(id, 0)), &key, 1), "load key from keyring");
  bail(gpgme_data_new_from_mem(&MSG, (const char*) RAW(msg), LENGTH(msg), 0), "creating msg buffer");

  // TODO: vectorize to sign with multiple keys
  gpgme_signers_clear(ctx);
  bail(gpgme_signers_add(ctx, key), "add signer");
  bail(gpgme_data_new(&SIG), "memory to hold signature");
  bail(gpgme_op_sign(ctx, MSG, SIG, GPGME_SIG_MODE_DETACH), "signing");
  gpgme_signers_clear(ctx);

  //do something with result
  //gpgme_sign_result_t result = gpgme_op_sign_result(ctx);
  //gpgme_new_signature_t res = result->signatures;
  return data_to_string(SIG);
}
