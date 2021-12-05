#include "common.h"

//note: passphrase callback seems broken for keygen
SEXP R_gpg_keygen(SEXP params){
  void * cb = NULL;
  gpgme_get_passphrase_cb(ctx, NULL, &cb);
  gpgme_set_passphrase_cb(ctx, NULL, NULL);
  const char * par = Rf_length(params) ? CHAR(STRING_ELT(params, 0)) : NULL;
  bail(gpgme_op_genkey(ctx, par, NULL, NULL), "generate key");
  gpgme_genkey_result_t res = gpgme_op_genkey_result(ctx);
  gpgme_key_t key;
  bail(gpgme_get_key(ctx, res->fpr, &key, 0), "get new key");
  gpgme_set_passphrase_cb(ctx, pwprompt, cb);
  return mkString(key->subkeys->keyid);
}

// NEW method, requires GPGME 1.7 and GnuPG 2.1
SEXP R_gpg_keygen_new(SEXP userid){
#if GPGME_VERSION_NUMBER >= 0x010700
  unsigned int flags = GPGME_CREATE_NOPASSWD | GPGME_CREATE_FORCE;
  bail(gpgme_op_createkey(ctx, CHAR(STRING_ELT(userid, 0)), "default", 0, 0, NULL, flags), "create key");
  gpgme_genkey_result_t res = gpgme_op_genkey_result(ctx);
  gpgme_key_t key;
  bail(gpgme_get_key(ctx, res->fpr, &key, 0), "get new key");
  return mkString(key->subkeys->keyid);
#else
  Rf_error("GPGME too old for gpgme_op_createkey");
#endif
}

SEXP R_gpg_delete(SEXP id, SEXP secret){
  gpgme_key_t key;
  const char * idstr = CHAR(STRING_ELT(id, 0));
  bail(gpgme_get_key(ctx, idstr, &key, 0), "find key");
#if GPGME_VERSION_NUMBER >= 0x010901
  //Force is needed with gpg2 to prevent asking for confirmation
  int flags = (Rf_asLogical(secret) * GPGME_DELETE_ALLOW_SECRET) | GPGME_DELETE_FORCE;
  gpgme_error_t err = gpgme_op_delete_ext(ctx, key, flags);
#else
  gpgme_error_t err = gpgme_op_delete(ctx, key, Rf_asLogical(secret));
#endif
  if(gpg_err_code (err) == GPG_ERR_CONFLICT){
    Rf_warningcall(R_NilValue, "Did not delete %s. Set secret = TRUE to delete private keys", idstr);
    return mkString("");
  }
  bail(err, "delete key");
  return mkString(key->subkeys->keyid);
}

SEXP R_gpg_import(SEXP pubkey) {
  gpgme_data_t KEY;
  bail(gpgme_data_new_from_mem(&KEY, (const char*) RAW(pubkey), LENGTH(pubkey), 0), "creating key buffer");
  bail(gpgme_op_import(ctx, KEY), "importing pubkey");
  gpgme_import_result_t result = gpgme_op_import_result(ctx);
  SEXP out = PROTECT(allocVector(INTSXP, 5));
  INTEGER(out)[0] = result->considered;
  INTEGER(out)[1] = result->imported;
  INTEGER(out)[2] = result->secret_imported;
  INTEGER(out)[3] = result->new_signatures;
  INTEGER(out)[4] = result->new_revocations;
  UNPROTECT(1);
  return out;
}

SEXP R_gpg_export(SEXP id, SEXP secret){
  gpgme_data_t keydata = NULL;
  bail(gpgme_data_new(&keydata), "initiatie keydata");
#ifdef GPGME_EXPORT_MODE_SECRET
  gpgme_export_mode_t mode = asLogical(secret) * GPGME_EXPORT_MODE_SECRET;
#else
  int mode = 0;
#ifndef CHECK_OLD_GPGME
  if(asLogical(secret)) Rf_error("gpgme is too old, GPGME_EXPORT_MODE_SECRET not supported");
#endif
#endif
  bail(gpgme_op_export(ctx, CHAR(STRING_ELT(id, 0)), mode, keydata), "export key");
  return data_to_string(keydata);
}

SEXP R_gpg_keylist(SEXP filter, SEXP secret_only, SEXP local) {
  gpgme_keylist_mode_t mode = gpgme_get_keylist_mode(ctx);
  mode |= asLogical(local) ? GPGME_KEYLIST_MODE_LOCAL : GPGME_KEYLIST_MODE_EXTERN;
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
