#' GPG keyserver
#'
#' Search, download or publish keys on the GPG keyserver network via the HKP
#' (OpenPGP HTTP Keyserver Protocol). Requires a valid keyserver is configured
#' in your gpg.conf file. Might not work behind a firewall.
#'
#' @export
#' @rdname gpg_keyserver
#' @param name filter keys by name
#' @family gpg
gpg_search <- function(name = ""){
  gpg_keylist_internal(name, secret_only = FALSE, local = FALSE)
}
