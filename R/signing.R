#' PGP Signatures
#'
#' Utilities to create and verify PGP signatures.
#'
#' @export
#' @name gpg utilities
#' @rdname gpg
#' @family gpg
#' @aliases gpg
#' @useDynLib gpg R_gpgme_verify
#' @param sigfile path to the gpg file containing the \code{PGP SIGNATURE} block.
#' @param datafile path to the file containing the message to be verified.
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
#' @param file file-path or raw vector with data to sign
#' @param id which private key to use for signing
#' @param password a string or expression callback to read a passphrase when needed
#' @rdname gpg
gpg_sign <- function(file, id, password = readline){
  pinentry_warning()
  if(is.character(file)){
    stopifnot(file.exists(file))
    file <- readBin(file, raw(), file.info(file)$size)
  }
  stopifnot(is.raw(file))
  .Call(R_gpg_sign, file, id, password)
}
