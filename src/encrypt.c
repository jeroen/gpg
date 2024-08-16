#include "common.h"

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

SEXP R_gpgme_encrypt(SEXP data, SEXP id) {
  size_t len = Rf_length(id);
  gpgme_key_t keys[len + 1];
  for(size_t i = 0; i < len; i++)
    bail(gpgme_get_key(ctx, CHAR(STRING_ELT(id, i)), &keys[i], 0), "load pubkey from keyring");
  keys[len] = NULL;
  gpgme_data_t output, input;
  bail(gpgme_data_new_from_mem(&input, (const char*) RAW(data), LENGTH(data), 0), "creating input buffer");
  bail(gpgme_data_new(&output), "creating output buffer");
  bail(gpgme_op_encrypt(ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, input, output), "encrypt message");
  return data_to_string(output);
}

SEXP R_gpgme_decrypt(SEXP data, SEXP as_text) {
  gpgme_data_t output, input;
  bail(gpgme_data_new_from_mem(&input, (const char*) RAW(data), LENGTH(data), 0), "creating input buffer");
  bail(gpgme_data_new(&output), "creating output buffer");
  bail(gpgme_op_decrypt(ctx, input, output), "decrypt message");
  return Rf_asLogical(as_text) ? data_to_string(output) : data_to_raw(output);
}

SEXP R_gpgme_signed_encrypt(SEXP data, SEXP receiver, SEXP sender) {
  //receiver keys
  size_t len = Rf_length(receiver);
  gpgme_key_t keys[len + 1];
  for(size_t i = 0; i < len; i++)
    bail(gpgme_get_key(ctx, CHAR(STRING_ELT(receiver, i)), &keys[i], 0), "load pubkey from keyring");
  keys[len] = NULL;

  // signer keys; GPG uses default or first key if no id's are given
  gpgme_signers_clear(ctx);
  for(int i = 0; i < Rf_length(sender); i++){
    gpgme_key_t key = NULL;
    bail(gpgme_get_key(ctx, CHAR(STRING_ELT(sender, i)), &key, 1), "load key from keyring");
    bail(gpgme_signers_add(ctx, key), "add signer");
  }

  //sign and encrypt
  gpgme_data_t output, input;
  bail(gpgme_data_new_from_mem(&input, (const char*) RAW(data), LENGTH(data), 0), "creating input buffer");
  bail(gpgme_data_new(&output), "creating output buffer");
  bail(gpgme_op_encrypt_sign(ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, input, output), "encrypt message");
  gpgme_signers_clear(ctx);
  return data_to_string(output);
}

SEXP R_gpgme_signed_decrypt(SEXP data, SEXP as_text) {
  gpgme_data_t output, input;
  bail(gpgme_data_new_from_mem(&input, (const char*) RAW(data), LENGTH(data), 0), "creating input buffer");
  bail(gpgme_data_new(&output), "creating output buffer");
  bail(gpgme_op_decrypt_verify(ctx, input, output), "verify signatures and decrypt message");
  SEXP out = Rf_asLogical(as_text) ? data_to_string(output) : data_to_raw(output);
  PROTECT(out);

  //check signatures
  gpgme_verify_result_t result = gpgme_op_verify_result(ctx);
  gpgme_signature_t signer = result->signatures;
  if(signer != NULL){
    if(signer->status)
      Rf_errorcall(R_NilValue, "Failed to verify signature for key %s: %s\n",
                   signer->fpr, gpgme_strerror(signer->status));
    SEXP symbol = PROTECT(install("signer"));
    setAttrib(out, symbol, mkString(signer->fpr));
    UNPROTECT(1);
  }
  UNPROTECT(1);
  return out;
}

SEXP data_to_string(gpgme_data_t buf){
  size_t len;
  char * sig = gpgme_data_release_and_get_mem(buf, &len);
  SEXP out = PROTECT(allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, mkCharLenCE(sig, (int) len, CE_UTF8));
  UNPROTECT(1);
  gpgme_free(sig);
  return out;
}

SEXP data_to_raw(gpgme_data_t buf){
  size_t len;
  char * sig = gpgme_data_release_and_get_mem(buf, &len);
  SEXP out = allocVector(RAWSXP, len);
  memcpy(RAW(out), sig, len);
  gpgme_free(sig);
  return out;
}
