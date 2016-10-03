#include <Rinternals.h>
#include <string.h> //strlen
#include <stdlib.h> //malloc
#include <gpgme.h>

#define make_string(x) ScalarString(make_char(x))
#define make_char(x) x ? Rf_mkChar(x) : NA_STRING
#define ALT(x,y) (x != NULL ? x : y)

gpgme_ctx_t ctx;

struct keylist {
  gpgme_key_t key;
  struct keylist *next;
};

void bail(gpgme_error_t err, const char * msg);
