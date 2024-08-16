#include "common.h"

SEXP make_keysig(gpgme_key_sig_t sig){
  gpgme_key_sig_t cur1 = sig;
  gpgme_key_sig_t cur2 = sig;
  int n = 0;
  while(cur1) {
    cur1 = cur1->next;
    n++;
  }

  SEXP timestamp = PROTECT(allocVector(INTSXP, n));
  SEXP tsclass = PROTECT(allocVector(STRSXP, 2));
  SET_STRING_ELT(tsclass, 0, make_char("POSIXct"));
  SET_STRING_ELT(tsclass, 1, make_char("POSIXt"));
  setAttrib(timestamp, R_ClassSymbol, tsclass);
  UNPROTECT(1);

  SEXP rowname = PROTECT(allocVector(INTSXP, n));
  SEXP id = PROTECT(allocVector(STRSXP, n));
  SEXP name = PROTECT(allocVector(STRSXP, n));
  SEXP email = PROTECT(allocVector(STRSXP, n));
  SEXP status = PROTECT(allocVector(LGLSXP, n));

  for(int i = 0; i < n; i++) {
    INTEGER(rowname)[i] = i+1;
    SET_STRING_ELT(id, i, make_char(cur2->_keyid));
    INTEGER(timestamp)[i] = (int) cur2->timestamp;
    SET_STRING_ELT(name, i, make_char(cur2->name));
    SET_STRING_ELT(email, i, make_char(cur2->email));
    LOGICAL(status)[i] = cur2->status == GPG_ERR_NO_ERROR;
    cur2 = cur2->next;
  }
  SEXP df = PROTECT(allocVector(VECSXP, 5));
  SET_VECTOR_ELT(df, 0, id);
  SET_VECTOR_ELT(df, 1, timestamp);
  SET_VECTOR_ELT(df, 2, name);
  SET_VECTOR_ELT(df, 3, email);
  SET_VECTOR_ELT(df, 4, status);

  SEXP names = PROTECT(allocVector(STRSXP, 5));
  SET_STRING_ELT(names, 0, mkChar("id"));
  SET_STRING_ELT(names, 1, mkChar("timestamp"));
  SET_STRING_ELT(names, 2, mkChar("name"));
  SET_STRING_ELT(names, 3, mkChar("email"));
  SET_STRING_ELT(names, 4, mkChar("success"));
  setAttrib(df, R_NamesSymbol, names);
  setAttrib(df, R_ClassSymbol, mkString("data.frame"));
  setAttrib(df, R_RowNamesSymbol, rowname);
  UNPROTECT(8);
  return df;
}

SEXP R_gpg_keysig(SEXP id){
  gpgme_key_t key;
  bail(gpgme_get_key(ctx, CHAR(STRING_ELT(id, 0)), &key, 0), "find key");
  return make_keysig(key->uids->signatures);
}
