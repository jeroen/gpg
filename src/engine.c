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

SEXP R_gpg_restart(SEXP path, SEXP home, SEXP wininst, SEXP debug) {
  // Clean up old engine
  if(ctx != NULL){
    gpgme_release(ctx);
    ctx = NULL;
  }

  // Set or reset debugging flag
  gpgme_set_global_flag("debug", CHAR(STRING_ELT(debug, 0)));

  // Windows needs path to gpgme-w32spawn.exe
  #ifdef WIN32
    bail(gpgme_set_global_flag("w32-inst-dir", CHAR(STRING_ELT(wininst, 0))), "setting w32-inst-dir");
  #endif

  //temporary
  #ifdef BUILD_AUTOBREW
    gpgme_set_global_flag("gpg-name", "gpg1");
  #endif

  // Set GPG path and config dir
  const char * pathdir = Rf_length(path) ? CHAR(STRING_ELT(path, 0)) : NULL;
  const char * homedir = Rf_length(home) ? CHAR(STRING_ELT(home, 0)) : NULL;
  bail(gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, pathdir, homedir), "setting OpenPGP options");

  // Initialize system
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  gpgme_check_version (NULL);
  bail(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP), "initate OpenPGP engine");
  bail(gpgme_new(&ctx), "context creation");
  gpgme_set_armor(ctx, 1);

  // Get engine info
  return R_engine_info();
}

SEXP R_dir_info(){
  SEXP out = PROTECT(allocVector(VECSXP, 4));
  SET_VECTOR_ELT(out, 0, make_string(gpgme_get_dirinfo("homedir")));
  SET_VECTOR_ELT(out, 1, make_string(gpgme_get_dirinfo("sysconfdir")));
  SET_VECTOR_ELT(out, 2, make_string(gpgme_get_dirinfo("gpgconf-name")));
  SET_VECTOR_ELT(out, 3, make_string(gpgme_get_dirinfo("gpg-name")));
  UNPROTECT(1);
  return out;
}
