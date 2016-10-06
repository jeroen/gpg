#' @useDynLib gpg R_gpg_import
#' @export
#' @rdname gpg
gpg_import <- function(pubkey){
  if(is.character(pubkey)){
    stopifnot(file.exists(pubkey))
    pubkey <- readBin(pubkey, raw(), file.info(pubkey)$size)
  }
  out <- .Call(R_gpg_import, pubkey)
  stats::setNames(out, c("considered", "imported", "unchanged"))
}

#' @export
#' @rdname gpg
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

#' @export
#' @rdname gpg
gpg_list_keys <- function(){
  gpg_keylist_internal(secret_only = FALSE, local = TRUE)
}

#' @export
#' @rdname gpg
gpg_list_secret_keys <- function(){
  gpg_keylist_internal(secret_only = TRUE, local = TRUE)
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

