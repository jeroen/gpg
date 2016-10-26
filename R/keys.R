#' GPG keyring management
#'
#' Signing or encrypting with GPG require that the keys are stored in your
#' personal keyring. Use \link{gpg_version} to see which keyring (home dir)
#' you are using. Also see \link{gpg_keygen} for generating a new key.
#'
#' @useDynLib gpg R_gpg_import
#' @param file path to the key file or raw vector with key data
#' @export
#' @family gpg
#' @name gpg_keys
#' @rdname gpg_keys
gpg_import <- function(file){
  if(is.character(file)){
    stopifnot(file.exists(file))
    file <- readBin(file, raw(), file.info(file)$size)
  }
  out <- .Call(R_gpg_import, file)
  stats::setNames(out, c("found", "imported", "secrets", "signatures", "revoked"))
}

#' @export
#' @rdname gpg_keys
#' @param keyserver address of http keyserver. Default searches several common
#' servers (MIT, Ubuntu, GnuPG)
#' @param id unique ID of the pubkey to import (starts with `0x`). Alternatively you
#' can specify a `search` string.
#' @param search string with name or email address to match the key info.
gpg_recv <- function(id, search = NULL, keyserver = NULL){
  if(is.null(keyserver))
    keyserver <- c("https://pgp.mit.edu", "https://keyserver.ubuntu.com",
                   "http://keys.gnupg.net", "http://pgp.surfnet.nl")
  keyserver <- sub("hkp://", "http://", keyserver, fixed = TRUE)
  keyserver <- sub("/$", "", keyserver)
  search <- if(!length(search) && length(id)){
    id <- paste0("0x", sub("^0x", "", id));
    if(!grepl("^0x[0-9a-fA-F]+$", id))
      stop("ID is not valid hexadecimal string. Use 'search' to find keys by name.", call. = FALSE)
    id
  } else {
    gsub(' ', '+', search)
  }
  data <- download_key(search, keyserver)
  gpg_import(data)
}

#' @useDynLib gpg R_gpg_delete
#' @export
#' @rdname gpg_keys
gpg_delete <- function(id, secret = FALSE){
  vapply(id, function(x){
    .Call(R_gpg_delete, x, secret)
  }, character(1), USE.NAMES = FALSE)
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
gpg_list_keys <- function(search = "", secret = FALSE){
  gpg_keylist_internal(name = search, secret_only = secret, local = TRUE)
}

#' @export
#' @rdname gpg_keys
#' @useDynLib gpg R_gpg_keysig
gpg_list_signatures <- function(id){
  .Call(R_gpg_keysig, id)
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

download_key <- function(id, servers){
  for(keyserver in servers){
    message("Searching: ", keyserver)
    try({
      req <- curl::curl_fetch_memory(paste0(keyserver, '/pks/lookup?op=get&search=', id))
      if(req$status == 200) return(req$content)
    })
  }
  stop("Failed to find/download public key: ", id, call. = FALSE)
}

