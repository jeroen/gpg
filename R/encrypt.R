#' Encryption
#'
#' Encrypt or decrypt a message using the public key from the `receiver`.
#' Optionally the message can be signed using the private key of the sender.
#'
#' @export
#' @rdname gpg_encrypt
#' @useDynLib gpg R_gpgme_encrypt R_gpgme_signed_encrypt
#' @param file path to file or raw vector with data to encrypt / decrypt
#' @param receiver key id or fingerprint for recepient
#' @param signer (optional) key id or fingerprint for the sender to sign the message
gpg_encrypt <- function(file, receiver, signer = NULL){
  data <- file_or_raw(file)
  stopifnot(is.character(receiver))
  if(length(signer)){
    stopifnot(is.character(signer))
    .Call(R_gpgme_signed_encrypt, data, receiver, signer)
  } else {
    .Call(R_gpgme_encrypt, data, receiver)
  }
}

#' @export
#' @rdname gpg_encrypt
#' @useDynLib gpg R_gpgme_decrypt
gpg_decrypt <- function(file){
  data <- file_or_raw(file)
  .Call(R_gpgme_decrypt, data)
}

file_or_raw <- function(file){
  if(is.raw(file))
    return(file)
  if(is.character(file)){
    stopifnot(file.exists(file))
    return(readBin(file, raw(), file.info(file)$size))
  }
  stop("Argument 'file' must be existing filepath or raw vector")
}