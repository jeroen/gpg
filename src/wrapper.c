#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <gpgme.h>
#include <locale.h>

gpgme_ctx_t ctx;

void assert(gpgme_error_t err, const char * msg){
  if(err)
    Rf_error("GPG %s error: %s", msg, gpgme_strerror(err));
}

void R_init_gpg(DllInfo *info) {
  gpgme_check_version (NULL);
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  assert(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP), "engine init");
  assert(gpgme_new(&ctx), "context creation");
  gpgme_set_armor(ctx, 1);
}

SEXP R_gpgme_verify(SEXP sig, SEXP msg) {
  gpgme_data_t SIG, MSG;
  assert(gpgme_data_new_from_mem(&SIG, (const char*) RAW(sig), LENGTH(sig), 0), "creating buffer");
  assert(gpgme_data_new_from_mem(&MSG, (const char*) RAW(msg), LENGTH(msg), 0), "creating buffer");
  assert(gpgme_op_verify(ctx, SIG, MSG, NULL), "verification");
  gpgme_verify_result_t result = gpgme_op_verify_result(ctx);
  gpgme_signature_t out = result->signatures;
  return ScalarLogical(out->status == GPG_ERR_NO_ERROR);
}
