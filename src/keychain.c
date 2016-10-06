#include "common.h"

SEXP R_gpg_keygen(SEXP params){
  const char * par = Rf_length(params) ? CHAR(STRING_ELT(params, 0)) : NULL;
  bail(gpgme_op_genkey(ctx, par, NULL, NULL), "generate key");
  return R_NilValue;
}

SEXP R_gpg_import(SEXP pubkey) {
  gpgme_data_t KEY;
  bail(gpgme_data_new_from_mem(&KEY, (const char*) RAW(pubkey), LENGTH(pubkey), 0), "creating key buffer");
  bail(gpgme_op_import(ctx, KEY), "importing pubkey");
  gpgme_import_result_t result = gpgme_op_import_result(ctx);
  SEXP out = PROTECT(allocVector(INTSXP, 3));
  INTEGER(out)[0] = result->considered;
  INTEGER(out)[1] = result->imported;
  INTEGER(out)[2] = result->unchanged;
  UNPROTECT(1);
  return out;
}

SEXP R_gpg_keylist(SEXP filter, SEXP secret_only, SEXP local) {
  gpgme_keylist_mode_t mode = 0;
  if(asLogical(local)){
    mode |= GPGME_KEYLIST_MODE_LOCAL;
  } else {
    mode |= GPGME_KEYLIST_MODE_EXTERN;
  }
  mode |= GPGME_KEYLIST_MODE_SIGS;
  mode |= GPGME_KEYLIST_MODE_SIG_NOTATIONS;
  gpgme_set_keylist_mode (ctx, mode);
  gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);

  //gpgme_set_global_flag("auto-key-locate", "hkp://pgp.mit.edu");

  bail(gpgme_op_keylist_start (ctx, CHAR(STRING_ELT(filter, 0)), asLogical(secret_only)), "starting keylist");
  struct keylist *keys = (struct keylist *)  malloc(sizeof(struct keylist));
  struct keylist *head = keys;

  gpgme_error_t err;
  int count = 0;
  while(1){
    err = gpgme_op_keylist_next (ctx, &(keys->key));
    if(gpg_err_code (err) == GPG_ERR_EOF)
      break;
    bail(err, "getting next key");
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
    SET_STRING_ELT(keyid, i, make_char(key->subkeys->keyid));
    SET_STRING_ELT(fpr, i, make_char(key->subkeys->fpr));
    SET_STRING_ELT(algo, i, make_char(gpgme_pubkey_algo_name(key->subkeys->pubkey_algo)));

    if(key->issuer_name)
      SET_STRING_ELT(fpr, i, make_char(key->issuer_name));
    if(key->uids && key->uids->name)
      SET_STRING_ELT(name, i, make_char(key->uids->name));
    if(key->uids && key->uids->email)
      SET_STRING_ELT(email, i, make_char(key->uids->email));

    INTEGER(timestamp)[i] = (key->subkeys->timestamp > 0) ? key->subkeys->timestamp : NA_INTEGER;
    INTEGER(expires)[i] = (key->subkeys->expires > 0) ? key->subkeys->expires : NA_INTEGER;

    keys = head;
    head = head->next;
    gpgme_key_unref (key);
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
