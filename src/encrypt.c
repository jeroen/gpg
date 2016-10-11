#include "common.h"

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

SEXP R_gpgme_encrypt(SEXP data, SEXP id) {
  gpgme_data_t output, input;
  gpgme_key_t keys[2] = {NULL, NULL};
  bail(gpgme_get_key(ctx, CHAR(STRING_ELT(id, 0)), &keys[0], 0), "load pubkey from keyring");
  bail(gpgme_data_new_from_mem(&input, (const char*) RAW(data), LENGTH(data), 0), "creating input buffer");
  bail(gpgme_data_new(&output), "creating output buffer");
  bail(gpgme_op_encrypt(ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, input, output), "encrypt message");
  return data_to_string(output);
}

SEXP R_gpgme_decrypt(SEXP data) {
  gpgme_data_t output, input;
  bail(gpgme_data_new_from_mem(&input, (const char*) RAW(data), LENGTH(data), 0), "creating input buffer");
  bail(gpgme_data_new(&output), "creating output buffer");
  bail(gpgme_op_decrypt(ctx, input, output), "decrypt message");
  return data_to_string(output);
}

SEXP R_gpgme_signed_encrypt(SEXP data, SEXP receiver, SEXP sender) {
  gpgme_data_t output, input;

  //receiver key
  gpgme_key_t keys[2] = {NULL, NULL};
  bail(gpgme_get_key(ctx, CHAR(STRING_ELT(receiver, 0)), &keys[0], 0), "load pubkey from keyring");

  //signer key
  gpgme_key_t sender_key;
  bail(gpgme_get_key(ctx, CHAR(STRING_ELT(sender, 0)), &sender_key, 0), "load pubkey from keyring");
  gpgme_signers_clear(ctx);
  bail(gpgme_signers_add(ctx, sender_key), "add signer");

  //sign and encrypt
  bail(gpgme_data_new_from_mem(&input, (const char*) RAW(data), LENGTH(data), 0), "creating input buffer");
  bail(gpgme_data_new(&output), "creating output buffer");
  bail(gpgme_op_encrypt_sign(ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, input, output), "encrypt message");
  gpgme_signers_clear(ctx);
  return data_to_string(output);
}

SEXP R_gpgme_signed_decrypt(SEXP data) {
  gpgme_data_t output, input;
  bail(gpgme_data_new_from_mem(&input, (const char*) RAW(data), LENGTH(data), 0), "creating input buffer");
  bail(gpgme_data_new(&output), "creating output buffer");
  bail(gpgme_op_decrypt_verify(ctx, input, output), "verify signatures and decrypt message");
  SEXP out = PROTECT(data_to_string(output));

  //check signatures
  gpgme_verify_result_t result = gpgme_op_verify_result(ctx);
  gpgme_signature_t signer = result->signatures;
  if(signer != NULL){
    if(signer->status)
      Rf_errorcall(R_NilValue, "Failed to verify signature for key %s: %s\n",
                   signer->fpr, gpgme_strerror(signer->status));
    setAttrib(out, install("signer"), mkString(signer->fpr));
  }
  UNPROTECT(1);
  return out;
}

SEXP data_to_string(gpgme_data_t buf){
  size_t len;
  char * sig = gpgme_data_release_and_get_mem(buf, &len);
  SEXP out = PROTECT(allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, mkCharLenCE(sig, len, CE_UTF8));
  UNPROTECT(1);
  gpgme_free(sig);
  return out;
}

