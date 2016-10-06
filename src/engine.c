#include "common.h"
#include <locale.h>

void bail(gpgme_error_t err, const char * msg){
  if(err)
    Rf_errorcall(R_NilValue, "GPG %s error: %s", msg, gpgme_strerror(err));
}

SEXP R_engine_info(){
  gpgme_engine_info_t info = gpgme_ctx_get_engine_info (ctx);
  return Rf_list4(
    make_string(info->file_name),
    make_string(info->version),
    make_string(info->home_dir),
    make_string(gpgme_check_version (NULL))
  );
}

SEXP R_gpg_restart(SEXP path, SEXP home, SEXP debug) {
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
