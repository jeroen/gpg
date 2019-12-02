#include "common.h"
#include <locale.h>
#include <unistd.h>

gpgme_ctx_t ctx;

void bail(gpgme_error_t err, const char * msg){
  // Override error messages because GPGME errors are pretty poor
  if(err){
    const char * errmsg = NULL;
    switch(gpg_err_code (err)) {
    case GPG_ERR_EOF:
      errmsg = "Not found"; break;
    default:
      errmsg = gpgme_strerror(err);
    };

    // Throw the error
    Rf_errorcall(R_NilValue, "%s %s error: %s", gpgme_strsource(err), msg, errmsg);
  }
}

/* password prompt only supported in gpg1, not in gpg2 which uses the 'pinentry' program */
gpgme_error_t pwprompt(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd){

  SEXP cb = (SEXP) hook;
  if(!isFunction(cb)){
    Rprintf("Invalid passphrase callback");
    return 1;
  }

  int err;
  SEXP call = PROTECT(LCONS(cb, LCONS(mkString("Please enter private key passphrase: "), R_NilValue)));
  SEXP res = PROTECT(R_tryEval(call, R_GlobalEnv, &err));
  if(err || !isString(res)){
    UNPROTECT(2);
    error("Password callback did not return a string value");
  }

  if(!Rf_isString(res) || !Rf_length(res))
    Rf_error("Failed to prompt for GPG passphrase");

#ifdef HAVE_GPGME_IO_READWRITE
  gpgme_io_write(fd, CHAR(STRING_ELT(res, 0)), LENGTH(STRING_ELT(res, 0)));
  gpgme_io_write(fd, "\n", 1);
#else
  if(write(fd, CHAR(STRING_ELT(res, 0)), LENGTH(STRING_ELT(res, 0))) < 1)
    Rf_error("Failed to write password to buffer");
  if(write(fd, "\n", 1) < 1)
    Rf_error("Failed to write EOL to buffer");
#endif

  UNPROTECT(2);
  return 0;
}

SEXP R_engine_info(){
  gpgme_engine_info_t info = gpgme_ctx_get_engine_info (ctx);
  SEXP out = PROTECT(Rf_allocVector(VECSXP, 4));
  SET_VECTOR_ELT(out, 0, make_string(info->file_name));
  SET_VECTOR_ELT(out, 1, make_string(info->version));
  SET_VECTOR_ELT(out, 2, make_string(info->home_dir));
  SET_VECTOR_ELT(out, 3, make_string(gpgme_check_version (NULL)));
  UNPROTECT(1);
  return out;
}

SEXP R_gpg_restart(SEXP home, SEXP path, SEXP pwfun, SEXP debug) {
  // Clean up old engine
  if(ctx != NULL){
    gpgme_release(ctx);
    ctx = NULL;
  }

  // Set GPG path and config dir
  const char * pathdir = Rf_length(path) ? CHAR(STRING_ELT(path, 0)) : NULL;
  const char * homedir = Rf_length(home) ? CHAR(STRING_ELT(home, 0)) : NULL;

  // Set or reset debugging flag
#if GPGME_VERSION_NUMBER >= 0x010400
  gpgme_set_global_flag("debug", CHAR(STRING_ELT(debug, 0)));
#endif

  // Windows needs path to gpgme-w32spawn.exe
#ifdef WIN32
  bail(gpgme_set_global_flag("w32-inst-dir", pathdir), "setting w32-inst-dir");
  bail(gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, NULL, homedir), "setting OpenPGP home");
#else
  bail(gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, pathdir, homedir), "setting OpenPGP path/home");
#endif

  // Initialize system
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  gpgme_check_version (NULL);
  bail(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP), "initate OpenPGP engine");
  bail(gpgme_new(&ctx), "context creation");
  gpgme_set_armor(ctx, 1);


#if GPGME_VERSION_NUMBER >= 0x010700
  // Required for GPG 2.1
  bail(gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK), "set pinentry to loopback");
#endif
  gpgme_set_passphrase_cb(ctx, pwprompt, pwfun);

  // Get engine info
  return R_engine_info();
}

//gpgme_get_dirinfo was introduced in GPGME 1.5.0
SEXP R_dir_info(){
  SEXP out = PROTECT(allocVector(VECSXP, 4));
#if GPGME_VERSION_NUMBER >= 0x010500
  SET_VECTOR_ELT(out, 0, make_string(gpgme_get_dirinfo("homedir")));
  SET_VECTOR_ELT(out, 1, make_string(gpgme_get_dirinfo("sysconfdir")));
  SET_VECTOR_ELT(out, 2, make_string(gpgme_get_dirinfo("gpgconf-name")));
  SET_VECTOR_ELT(out, 3, make_string(gpgme_get_dirinfo("gpg-name")));
#endif
  UNPROTECT(1);
  return out;
}
