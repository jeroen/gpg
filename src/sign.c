#include "common.h"

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* password prompt only supported in gpg1, not in gpg2 which uses the 'pinentry' program */
gpgme_error_t pwprompt(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd){

  /* hardcoded password */
  SEXP cb = (SEXP) hook;
  if(isString(cb)){
    gpgme_io_write(fd, CHAR(STRING_ELT(cb, 0)), LENGTH(STRING_ELT(cb, 0)));
    gpgme_io_write(fd, "\n", 1);
    return 0;
  }

  /* expression to call */
  if(TYPEOF(cb) == LANGSXP){
    //Rprintf("Enter password for %s (attempt %d)\n", uid_hint, prev_was_bad+1);

    int err;
    SEXP res = PROTECT(R_tryEval(cb, R_GlobalEnv, &err));

    if(err || !isString(res)){
      UNPROTECT(1);
      Rf_errorcall(R_NilValue, "Password expression must return a string.");
    }

    gpgme_io_write(fd, CHAR(STRING_ELT(res, 0)), LENGTH(STRING_ELT(res, 0)));
    gpgme_io_write(fd, "\n", 1);
    UNPROTECT(1);
    return 0;
  }

  Rf_errorcall(R_NilValue, "Invalid ");
  return 1;
}

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

SEXP R_gpg_sign(SEXP msg, SEXP name, SEXP fun){
  gpgme_data_t SIG, MSG;
  gpgme_key_t key = NULL;
  bail(gpgme_data_new_from_mem(&MSG, (const char*) RAW(msg), LENGTH(msg), 0), "creating msg buffer");

  // get the key of the signer
  gpgme_signers_clear(ctx);
  bail(gpgme_op_keylist_start(ctx, CHAR(STRING_ELT(name, 0)), 1), "searching keys");

  gpgme_error_t err = gpgme_op_keylist_next(ctx, &key);
  if(gpg_err_code (err) == GPG_ERR_EOF)
    Rf_errorcall(R_NilValue, "No secret key found for '%s'", CHAR(STRING_ELT(name, 0)));
  bail(err, "selecting first matched key");
  bail(gpgme_op_keylist_end(ctx), "done listing keys");

  // debug
  Rprintf("Using key: %s (%s)\n", key->subkeys->_keyid, key->uids->name);

  // set passwd callback
  gpgme_set_passphrase_cb(ctx, pwprompt, fun);

  gpgme_signers_add(ctx, key);
  bail(gpgme_data_new(&SIG), "memory to hold signature");
  bail(gpgme_op_sign(ctx, MSG, SIG, GPGME_SIG_MODE_DETACH), "signing");

  //do something with result
  //gpgme_sign_result_t result = gpgme_op_sign_result(ctx);
  //gpgme_new_signature_t res = result->signatures;

  size_t len;
  char *sig = gpgme_data_release_and_get_mem(SIG, &len);
  SEXP out = PROTECT(allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, mkCharLen(sig, len));
  UNPROTECT(1);
  gpgme_free(sig);
  return out;
}
