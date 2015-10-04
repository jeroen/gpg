#' GPG keyserver
#'
#' Search, download or publish keys on the GPG keyserver network via the HKP
#' (OpenPGP HTTP Keyserver Protocol). Requires a valid keyserver is configured
#' in your gpg.conf file. Might not work behind a firewall.
#'
#' @export
#' @rdname gpg_keyserver
#' @family gpg
gpg_search <- function(name = ""){
  gpg_keylist_internal(name, secret_only = FALSE, local = FALSE)
}

#' @export
#' @useDynLib gpg R_gpg_download
#' @rdname gpg_keyserver
gpg_download <- function(id = ""){
  if(!identical(substring(id, 1, 2), "0x")){
    id <- paste0("0x", id);
  }
  .Call(R_gpg_download, id)
}
