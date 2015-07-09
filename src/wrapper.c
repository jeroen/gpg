#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <gpgme.h>
#include <locale.h>
#include <stdlib.h>

#define GPG4WIN "C:\\Program Files (x86)\\GNU\\GnuPG\\gpg2.exe"

gpgme_ctx_t ctx;

struct keylist {
  gpgme_key_t key;
  struct keylist *next;
};

void assert(gpgme_error_t err, const char * msg){
  if(err)
    Rf_error("GPG %s error: %s", msg, gpgme_strerror(err));
}

void R_init_gpg(DllInfo *info) {
#ifdef DEBUG
  gpgme_set_global_flag("debug", "9");
#endif
  gpgme_check_version (NULL);
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef _WIN32
  assert(gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, GPG4WIN, NULL), "setting engine");
#endif
  assert(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP), "engine init");
  assert(gpgme_new(&ctx), "context creation");
  gpgme_set_armor(ctx, 1);
}

SEXP R_gpgme_verify(SEXP sig, SEXP msg) {
  gpgme_data_t SIG, MSG;
  assert(gpgme_data_new_from_mem(&SIG, (const char*) RAW(sig), LENGTH(sig), 0), "creating sig buffer");
  assert(gpgme_data_new_from_mem(&MSG, (const char*) RAW(msg), LENGTH(msg), 0), "creating msg buffer");
  assert(gpgme_op_verify(ctx, SIG, MSG, NULL), "verification");
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
    SET_VECTOR_ELT(el, 0, mkString(cur2->fpr));
    SET_VECTOR_ELT(el, 1, ScalarInteger(cur2->timestamp));
    SET_VECTOR_ELT(el, 2, mkString(gpgme_hash_algo_name(cur2->hash_algo)));
    SET_VECTOR_ELT(el, 3, mkString(gpgme_pubkey_algo_name(cur2->pubkey_algo)));
    SET_VECTOR_ELT(el, 4, ScalarLogical(cur2->status == GPG_ERR_NO_ERROR));
    cur2 = cur2->next;
    SET_VECTOR_ELT(out, i, el);
    UNPROTECT(1);
  }
  UNPROTECT(1);
  return out;
}

SEXP R_gpg_import(SEXP pubkey) {
  gpgme_data_t KEY;
  assert(gpgme_data_new_from_mem(&KEY, (const char*) RAW(pubkey), LENGTH(pubkey), 0), "creating key buffer");
  assert(gpgme_op_import(ctx, KEY), "importing pubkey");
  gpgme_import_result_t result = gpgme_op_import_result(ctx);
  SEXP out = PROTECT(allocVector(INTSXP, 3));
  INTEGER(out)[0] = result->considered;
  INTEGER(out)[1] = result->imported;
  INTEGER(out)[2] = result->unchanged;
  UNPROTECT(1);
  return out;
}

SEXP R_gpg_keylist(SEXP filter) {
  assert(gpgme_op_keylist_start (ctx, CHAR(STRING_ELT(filter, 0)), 0), "starting keylist");
  struct keylist *keys = (struct keylist *)  malloc(sizeof(struct keylist));
  struct keylist *head = keys;

  gpgme_error_t err;
  int count = 0;
  while(1){
    err = gpgme_op_keylist_next (ctx, &(keys->key));
    if(gpg_err_code (err) == GPG_ERR_EOF)
      break;
    assert(err, "getting next key");
    keys->next = (struct keylist *)  malloc(sizeof(struct keylist));
    keys = keys->next;
    count++;
  }

  /* convert the linked list into vectors */
  SEXP keyid = PROTECT(allocVector(STRSXP, count));
  SEXP fpr = PROTECT(allocVector(STRSXP, count));
  SEXP name = PROTECT(allocVector(STRSXP, count));
  SEXP email = PROTECT(allocVector(STRSXP, count));
  SEXP algo = PROTECT(allocVector(STRSXP, count));
  SEXP timestamp = PROTECT(allocVector(INTSXP, count));
  SEXP expires = PROTECT(allocVector(INTSXP, count));

  gpgme_key_t key;
  for(int i = 0; i < count; i++){
    key = head->key;
    SET_STRING_ELT(keyid, i, mkChar(key->subkeys->keyid));
    SET_STRING_ELT(fpr, i, mkChar(key->subkeys->fpr));
    SET_STRING_ELT(algo, i, mkChar(gpgme_pubkey_algo_name(key->subkeys->pubkey_algo)));

    if(key->issuer_name)
      SET_STRING_ELT(fpr, i, mkChar(key->issuer_name));
    if(key->uids && key->uids->name)
      SET_STRING_ELT(name, i, mkChar(key->uids->name));
    if(key->uids && key->uids->email)
      SET_STRING_ELT(email, i, mkChar(key->uids->email));

    INTEGER(timestamp)[i] = (key->subkeys->timestamp > 0) ? key->subkeys->timestamp : NA_INTEGER;
    INTEGER(expires)[i] = (key->subkeys->expires > 0) ? key->subkeys->expires : NA_INTEGER;

    keys = head;
    head = head->next;
    free(keys);
  }


  SEXP result = PROTECT(allocVector(VECSXP, 7));
  SET_VECTOR_ELT(result, 0, keyid);
  SET_VECTOR_ELT(result, 1, fpr);
  SET_VECTOR_ELT(result, 2, name);
  SET_VECTOR_ELT(result, 3, email);
  SET_VECTOR_ELT(result, 4, algo);
  SET_VECTOR_ELT(result, 5, timestamp);
  SET_VECTOR_ELT(result, 6, expires);
  UNPROTECT(8);
  return result;
}

SEXP R_gpg_dirinfo(SEXP what){
  return mkString(gpgme_get_dirinfo(CHAR(STRING_ELT(what, 0))));
}
