#' @useDynLib gpg R_gpg_import
#' @export
#' @rdname gpg
gpg_import <- function(pubkey){
  stopifnot(file.exists(pubkey))
  key <- readBin(pubkey, raw(), file.info(pubkey)$size)
  out <- .Call(R_gpg_import, key)
  structure(as.list(out), names = c("considered", "imported", "unchanged"))
}

#' @export
#' @rdname gpg
gpg_list <- function(secret_only = FALSE){
  gpg_keylist_internal("", secret_only, local = TRUE)
}

#' @useDynLib gpg R_gpg_keylist
gpg_keylist_internal <- function(name = "", secret_only = FALSE, local = FALSE){
  stopifnot(is.character(name))
  stopifnot(is.logical(secret_only))
  out <- .Call(R_gpg_keylist, name, secret_only, local)
  names(out) <- c("keyid", "fingerprint", "name", "email", "algo", "timestamp", "expires")
  out$timestamp <- structure(out$timestamp, class=c("POSIXct", "POSIXt"))
  out$expires <- structure(out$expires, class=c("POSIXct", "POSIXt"))
  data.frame(out, stringsAsFactors = FALSE)
}