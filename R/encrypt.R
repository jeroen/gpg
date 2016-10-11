#' Encryption
#'
#' Encrypt or decrypt a message.
#'
#'
#' @export
#' @rdname gpg_encrypt
#' @useDynLib gpg R_gpgme_encrypt
#' @param file path to file or raw vector with data to encrypt / decrypt
#' @param id key id or fingerprint
gpg_encrypt <- function(file, id){
  data <- file_or_raw(file)
  stopifnot(is.character(id))
  .Call(R_gpgme_encrypt, data, id)
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