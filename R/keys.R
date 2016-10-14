#' GPG keyring management
#'
#' Signing or encrypting with GPG require that the keys are stored in your
#' personal keyring. Use \link{gpg_version} to see which keyring (home dir)
#' you are using. Also see \link{gpg_keygen} for generating a new key.
#'
#' @useDynLib gpg R_gpg_import
#' @param file path to the key file or raw vector with key data
#' @export
#' @rdname gpg_keys
gpg_import <- function(file){
  if(is.character(file)){
    stopifnot(file.exists(file))
    file <- readBin(file, raw(), file.info(file)$size)
  }
  out <- .Call(R_gpg_import, file)
  stats::setNames(out, c("considered", "imported", "unchanged"))
}

#' @export
#' @rdname gpg_keys
#' @param keyserver address of http keyserver
#' @param id unique ID of the pubkey (starts with `0x`)
gpg_recv <- function(id, keyserver = "https://keyserver.ubuntu.com"){
  keyserver <- sub("hkp://", "http://", keyserver, fixed = TRUE)
  keyserver <- sub("/$", "", keyserver)
  if(!identical(substring(id, 1, 2), "0x")){
    id <- paste0("0x", id);
  }
  tmp <- tempfile()
  req <- curl::curl_fetch_memory(paste0(keyserver, '/pks/lookup?op=get&search=', id))
  if(req$status > 200)
    stop("Failed to receive key! HTTP", req$status)
  gpg_import(req$content)
}

#' @useDynLib gpg R_gpg_delete
#' @export
#' @rdname gpg_keys
gpg_delete <- function(id, secret = TRUE){
  .Call(R_gpg_delete, id, secret)
}

#' @export
#' @rdname gpg_keys
#' @useDynLib gpg R_gpg_export
gpg_export <- function(id, secret = FALSE){
  .Call(R_gpg_export, id, secret)
}

#' @export
#' @rdname gpg_keys
#' @param secret set to `TRUE` to list/export/delete private (secret) keys
gpg_list_keys <- function(secret = FALSE){
  gpg_keylist_internal(secret_only = secret, local = TRUE)
}

#' @useDynLib gpg R_gpg_keylist
gpg_keylist_internal <- function(name = "", secret_only = FALSE, local = FALSE){
  stopifnot(is.character(name))
  stopifnot(is.logical(secret_only))
  out <- .Call(R_gpg_keylist, name, secret_only, local)
  names(out) <- c("id", "fingerprint", "name", "email", "algo", "timestamp", "expires")
  out$timestamp <- structure(out$timestamp, class=c("POSIXct", "POSIXt"))
  out$expires <- structure(out$expires, class=c("POSIXct", "POSIXt"))
  data.frame(out, stringsAsFactors = FALSE)
}
