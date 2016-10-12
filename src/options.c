#include "common.h"

SEXP R_gpg_list_options(){
  gpgme_conf_comp_t conf;
  bail(gpgme_op_conf_load (ctx, &conf), "load gpg config");
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

/* Comment out, doens't work well and causes problems on old GPG

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
      bail(gpgme_conf_arg_new (&arg, cur->type, CHAR(STRING_ELT(VECTOR_ELT(input, i), 0))), "new arg");
      bail(gpgme_conf_opt_change (cur, 0, arg), "change opt");
    }
  }

  //save config
  bail(gpgme_op_conf_save (ctx, comp), "conf save");
  return res;
}

*/

