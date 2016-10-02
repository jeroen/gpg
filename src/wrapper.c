#include <Rinternals.h>
#include <gpgme.h>

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define make_string(x) x ? Rf_mkString(x) : ScalarString(NA_STRING)
#define make_char(x) x ? Rf_mkChar(x) : NA_STRING
#define ALT(x,y) (x != NULL ? x : y)

gpgme_ctx_t ctx;

struct keylist {
  gpgme_key_t key;
  struct keylist *next;
};

void assert(gpgme_error_t err, const char * msg){
  if(err)
    Rf_errorcall(R_NilValue, "GPG %s error: %s", msg, gpgme_strerror(err));
}

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

void R_init_gpg(void *info) {
#ifdef DEBUG
  gpgme_set_global_flag("debug", "9");
#endif

/* Hardcode some paths of common GPG installations */
#ifdef _WIN32
  if (!access("C://Program Files (x86)//GnuPG/bin", F_OK)){
    gpgme_set_global_flag("w32-inst-dir", "C://Program Files (x86)//GnuPG/bin");
  } else if(!access("C://Program Files (x86)//GNU/GnuPG", F_OK)){
    gpgme_set_global_flag("w32-inst-dir", "C://Program Files (x86)//GnuPG/bin");
  } else {
    Rf_warningcall(R_NilValue, "GPG not found! Please install GPG4Win or similar.");
  }
#elif __APPLE__
  //assert(gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, "/usr/local/bin/gpg", "~/.gnupg/"), "setting engine");
#endif
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  const char * version = gpgme_check_version (NULL);
  Rprintf("GPGME version %s\n", version);
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

  assert(gpgme_op_keylist_start (ctx, CHAR(STRING_ELT(filter, 0)), asLogical(secret_only)), "starting keylist");
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

SEXP R_gpg_sign(SEXP msg, SEXP name, SEXP fun){
  gpgme_data_t SIG, MSG;
  gpgme_key_t key = NULL;
  assert(gpgme_data_new_from_mem(&MSG, (const char*) RAW(msg), LENGTH(msg), 0), "creating msg buffer");

  // get the key of the signer
  gpgme_signers_clear(ctx);
  assert(gpgme_op_keylist_start(ctx, CHAR(STRING_ELT(name, 0)), 1), "searching keys");

  gpgme_error_t err = gpgme_op_keylist_next(ctx, &key);
  if(gpg_err_code (err) == GPG_ERR_EOF)
    Rf_errorcall(R_NilValue, "No secret key found for '%s'", CHAR(STRING_ELT(name, 0)));
  assert(err, "selecting first matched key");
  assert(gpgme_op_keylist_end(ctx), "done listing keys");

  // debug
  Rprintf("Using key: %s (%s)\n", key->subkeys->_keyid, key->uids->name);

  // set passwd callback
  gpgme_set_passphrase_cb(ctx, pwprompt, fun);

  gpgme_signers_add(ctx, key);
  assert(gpgme_data_new(&SIG), "memory to hold signature");
  assert(gpgme_op_sign(ctx, MSG, SIG, GPGME_SIG_MODE_DETACH), "signing");

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

SEXP R_gpg_list_options(){
  gpgme_conf_comp_t conf;
  gpgme_op_conf_load (ctx, &conf);
  gpgme_conf_comp_t comp = conf;

  //search for the 'gpg' component
  while(comp && strcmp(comp->name, "gpg"))
    comp = comp->next;

  //component was not found
  if(!comp)
    return R_NilValue;

  //first option
  gpgme_conf_opt_t opt = comp->options;

  //count
  int count = 0;
  do {
    //this is a group name, not a real option
    if(opt->flags & GPGME_CONF_GROUP)
      continue;
    count++;
  } while((opt = opt->next));

  //reset iterator
  opt = comp->options;
  SEXP res = PROTECT(allocVector(VECSXP, count));
  SEXP names = PROTECT(allocVector(STRSXP, count));
  int i = 0;
  do {
    if(opt->flags & GPGME_CONF_GROUP)
      continue;
    SET_STRING_ELT(names, i, make_char(opt->name));
    //Rprintf("Option '%s' with type %d\n", opt->name, opt->type);
    if(ALT(opt->value, opt->default_value) == NULL){
      SET_VECTOR_ELT(res, i, R_NilValue);
    } else {
      switch (opt->type){
        case GPGME_CONF_STRING:
        case GPGME_CONF_PATHNAME:
        case GPGME_CONF_LDAP_SERVER:
        case GPGME_CONF_KEY_FPR:
        case GPGME_CONF_PUB_KEY:
        case GPGME_CONF_SEC_KEY:
        case GPGME_CONF_ALIAS_LIST:
          SET_VECTOR_ELT(res, i, make_string(ALT(opt->value, opt->default_value)->value.string));
          break;

        case GPGME_CONF_UINT32:
          SET_VECTOR_ELT(res, i, ScalarInteger((int) ALT(opt->value, opt->default_value)->value.uint32));
          break;

        case GPGME_CONF_INT32:
          SET_VECTOR_ELT(res, i, ScalarInteger(ALT(opt->value, opt->default_value)->value.int32));
          break;

        case GPGME_CONF_NONE:
          SET_VECTOR_ELT(res, i, ScalarInteger(ALT(opt->value, opt->default_value)->value.count));
          break;

        default:
          SET_VECTOR_ELT(res, i, R_NilValue);
          warning("Unknown option type: %s", opt->name);
          break;
      }
    }
    i++;
  } while((opt = opt->next));
  setAttrib(res, R_NamesSymbol, names);
  UNPROTECT(2);
  return res;
}

SEXP R_gpg_options(SEXP input){
  gpgme_conf_comp_t conf;
  gpgme_op_conf_load (ctx, &conf);
  gpgme_conf_comp_t comp = conf;

  //search for the 'gpg' component
  while(comp && strcmp(comp->name, "gpg"))
    comp = comp->next;

  //component was not found
  if(!comp)
    return R_NilValue;

  //first option
  gpgme_conf_opt_t opt = comp->options;
  SEXP names = getAttrib(input, R_NamesSymbol);
  SEXP res = duplicate(input);

  //iteratate over input list
  for(int i = 0; i < LENGTH(names); i++){
    const char *argname = CHAR(STRING_ELT(names, i));

    //search for the 'gpg' component
    gpgme_conf_opt_t cur = opt;
    while(cur && strcmp(cur->name, argname))
      cur = cur->next;

    if(!cur){
      Rf_error("Unsupported option: %s", argname);
    } else {
      gpgme_conf_arg_t arg;
      assert(gpgme_conf_arg_new (&arg, cur->type, CHAR(STRING_ELT(VECTOR_ELT(input, i), 0))), "new arg");
      assert(gpgme_conf_opt_change (cur, 0, arg), "change opt");
    }
  }

  //save config
  assert(gpgme_op_conf_save (ctx, comp), "conf save");
  return res;
}


SEXP R_gpg_download(SEXP filter) {
  gpgme_keylist_mode_t mode = 0;
  mode |= GPGME_KEYLIST_MODE_EXTERN;
  mode |= GPGME_KEYLIST_MODE_SIGS;
  mode |= GPGME_KEYLIST_MODE_SIG_NOTATIONS;
  gpgme_set_keylist_mode (ctx, mode);
  gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);

  //init search
  assert(gpgme_op_keylist_start (ctx, CHAR(STRING_ELT(filter, 0)), 0), "starting keylist");

  //load key
  gpgme_key_t key;
  gpgme_error_t err = gpgme_op_keylist_next (ctx, &key);
  if(gpg_err_code (err) == GPG_ERR_EOF){
    Rf_error("Key not found.");
  }
  assert(err, "getting key");
  if(gpg_err_code(gpgme_op_keylist_next (ctx, NULL)) == GPG_ERR_EOF){
    gpgme_op_keylist_end(ctx);
    Rf_error("Multiple keys found! Please be more specific.");
  }

  //output block
  SEXP result = PROTECT(allocVector(STRSXP, 1));
  setAttrib(result, install("keyid"), make_string(key->subkeys->keyid));
  setAttrib(result, install("fingerprint"), make_string(key->subkeys->keyid));

  /* export the public key */
  gpgme_data_t dh = NULL;
  assert(gpgme_data_new (&dh), "initiating data buffer");
  gpgme_export_mode_t emode = 0;
  gpgme_key_t keyarray[2] = {key, NULL};
  gpgme_set_armor (ctx, 1);
  gpgme_op_export_keys(ctx, keyarray, emode, dh);

  char buf[100000];
  assert(gpgme_data_seek (dh, 0, SEEK_SET), "data seek");
  size_t size = gpgme_data_read (dh, buf, 99999);
  assert(size > -1, "data read");
  SET_STRING_ELT(result, 0, mkCharLen(buf, size));
  UNPROTECT(1);
  return result;
}
