#include "common.h"
#include <locale.h>

void bail(gpgme_error_t err, const char * msg){
  if(err)
    Rf_errorcall(R_NilValue, "GPG %s error: %s", msg, gpgme_strerror(err));
}

SEXP R_gpg_restart(SEXP path, SEXP home, SEXP wininst, SEXP debug) {
  if(ctx != NULL){
    gpgme_release(ctx);
    ctx = NULL;
  }

  if(Rf_length(debug))
    gpgme_set_global_flag("debug", CHAR(STRING_ELT(debug, 0)));

  // Windows needs path to gpgme-w32spawn.exe
  #ifdef WIN32
    bail(gpgme_set_global_flag("w32-inst-dir", CHAR(STRING_ELT(wininst, 0))));
  #endif

  // Set GPG path and config dir
  const char * pathdir = Rf_length(path) ? CHAR(STRING_ELT(path, 0)) : NULL;
  const char * homedir = Rf_length(home) ? CHAR(STRING_ELT(home, 0)) : NULL;
  if(pathdir || homedir)
    bail(gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, pathdir, homedir), "setting engine");

  // Initialize system
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  const char * version = gpgme_check_version (NULL);
  bail(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP), "engine init");
  bail(gpgme_new(&ctx), "context creation");
  gpgme_set_armor(ctx, 1);
  return mkString(version);
}

SEXP R_gpg_info(){
  return Rf_list5(
    mkString(gpgme_get_dirinfo("homedir")),
    mkString(gpgme_get_dirinfo("sysconfdir")),
    mkString(gpgme_get_dirinfo("gpgconf-name")),
    mkString(gpgme_get_dirinfo("gpg-name")),
    mkString(gpgme_get_dirinfo("gpgsm-name"))
  );
}
