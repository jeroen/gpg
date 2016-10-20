#' PGP Signatures
#'
#' Utilities to create and verify PGP signatures.
#'
#' @export
#' @rdname gpg_sign
#' @family gpg
#' @aliases gpg
#' @useDynLib gpg R_gpgme_verify
#' @param signature path or raw vector for the gpg signature file (contains the \code{PGP SIGNATURE} block)
#' @param error raise an error if verification fails because you do not have the
#' signer public key in your keyring.
#' @examples # This requires you have the Debian master key in your keyring
#' # See https://lists.debian.org/debian-devel-announce/2014/11/msg00017.html
#' msg <- tempfile()
#' sig <- tempfile()
#' download.file("http://http.us.debian.org/debian/dists/jessie/Release", msg)
#' download.file("http://http.us.debian.org/debian/dists/jessie/Release.gpg", sig)
#' gpg_verify(sig, msg, error = FALSE)
gpg_verify <- function(signature, file = NULL, error = TRUE){
  sig <- file_or_raw(signature)
  msg <- if(is.null(file)){
    NULL
  } else {
    file_or_raw(file)
  }
  out <- .Call(R_gpgme_verify, sig, msg)
  if(!length(out)){
    out <- as.data.frame(matrix(ncol = 5, nrow = 0))
  } else {
    out <- data.frame(lapply(1:5, function(i){sapply(out, `[[`, i)}), stringsAsFactors=FALSE)
  }
  names(out) <- c("fingerprint", "timestamp", "hash", "pubkey", "success");
  out$timestamp <- structure(out$timestamp, class=c("POSIXct", "POSIXt"))
  if(isTRUE(error) && !any(out$success)){
    fp_failed <- out$fingerprint[!(out$success)]
    stop("Verification failed. None of the pubkeys not found in keyring: ", paste(fp_failed, collapse = ", "), call. = FALSE)
  } else {
    out
  }
}

#' @useDynLib gpg R_gpg_sign
#' @export
#' @param file file-path or raw vector with data to sign or verify. In `gpg_verify` this
#' should be `NULL` if `signature` is not detached (i.e. `clear` or `normal` signature)
#' @param id (optional) vector with key ID's to use for signing. If `NULL`, GPG tries
#' the user default private key.
#' @param mode use `normal` to create a full OpenPGP message containing both data and
#' signature or `clear` append the signature to the clear-text data (for email messages).
#' Default `detach` only returns the signature itself.
#' @rdname gpg_sign
gpg_sign <- function(file, id = NULL, mode = c("detach", "normal", "clear")){
  pinentry_warning()
  mode <- match.arg(mode)
  if(is.character(file)){
    stopifnot(file.exists(file))
    file <- readBin(file, raw(), file.info(file)$size)
  }
  stopifnot(is.raw(file))
  .Call(R_gpg_sign, file, id, mode)
}
