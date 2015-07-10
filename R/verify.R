#' PGP tools
#'
#' Utilities to create and verify PGP signatures.
#'
#' @export
#' @name gpg utilities
#' @rdname gpg
#' @aliases gpg
#' @useDynLib gpg R_gpgme_verify
#' @param sigfile path to the gpg file containing the \code{PGP SIGNATURE} block.
#' @param datafile path to the file containing the message to be verified.
#' @param pubkey path to a file with a trusted public key
#' @param name find a key that matches a particular name
#' @param secret_only only list keys for which we have the secret (private key)
#' @param password a string or expression callback to read a passphrase when needed
#' @examples # This requires you have the Debian master key in your keyring
#' # See https://lists.debian.org/debian-devel-announce/2014/11/msg00017.html
#' # gpg --keyserver pgp.mit.edu --recv 0x7638d0442b90d010
#' msg <- tempfile()
#' sig <- tempfile()
#' download.file("http://http.us.debian.org/debian/dists/jessie/Release", msg)
#' download.file("http://http.us.debian.org/debian/dists/jessie/Release.gpg", sig)
#' gpg_verify(sig, msg)
gpg_verify <- function(sigfile, datafile){
  stopifnot(file.exists(sigfile))
  stopifnot(file.exists(datafile))
  sig <- readBin(sigfile, raw(), file.info(sigfile)$size)
  msg <- readBin(datafile, raw(), file.info(datafile)$size)
  out <- .Call(R_gpgme_verify, sig, msg)
  out <- data.frame(lapply(1:5, function(i){sapply(out, `[[`, i)}), stringsAsFactors=FALSE)
  names(out) <- c("fingerprint", "timestamp", "hash", "pubkey", "success");
  out$timestamp <- structure(out$timestamp, class=c("POSIXct", "POSIXt"))
  out
}

#' @useDynLib gpg R_gpg_sign
#' @export
#' @rdname gpg
gpg_sign <- function(datafile, name = "", password = readline("ENTER PASSWORD: ")){
  stopifnot(file.exists(datafile))
  password = substitute(password)
  stopifnot(is.character(password) || is.call(password))
  msg <- readBin(datafile, raw(), file.info(datafile)$size)
  .Call(R_gpg_sign, msg, name, password)
}

#' @useDynLib gpg R_gpg_import
#' @export
#' @rdname gpg
gpg_import <- function(pubkey){
  stopifnot(file.exists(pubkey))
  key <- readBin(pubkey, raw(), file.info(pubkey)$size)
  out <- .Call(R_gpg_import, key)
  structure(as.list(out), names = c("considered", "imported", "unchanged"))
}

#' @useDynLib gpg R_gpg_keylist
#' @export
#' @rdname gpg
gpg_keylist <- function(name = "", secret_only = FALSE){
  stopifnot(is.character(name))
  stopifnot(is.logical(secret_only))
  out <- .Call(R_gpg_keylist, name, secret_only)
  names(out) <- c("keyid", "fingerprint", "name", "email", "algo", "timestamp", "expires")
  out$timestamp <- structure(out$timestamp, class=c("POSIXct", "POSIXt"))
  out$expires <- structure(out$expires, class=c("POSIXct", "POSIXt"))
  data.frame(out, stringsAsFactors = FALSE)
}
