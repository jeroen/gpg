#' GPG key generation
#'
#' Use `gpg_keygen` to generate a new private-public keypair. Supported options
#' and parameters depend on the version of GPG. See the GPG manual section on
#' [Unattended key generation](https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html).
#'
#' @export
#' @rdname gpg_keygen
#' @useDynLib gpg R_gpg_keygen R_gpg_keygen_new
#' @param name value for the `Name-Real` field
#' @param email value for the `Name-Email` field
#' @param passphrase (optional) protect with a passphrase
gpg_keygen <- function(name, email, passphrase = NULL){
  info <- gpg_info()
  # Use the 'new' API, required for GnuPG 2.1
  if(!length(passphrase) && info$gpgme >= "1.7.0" && info$version >= "2.1"){
    userstring <- paste0(name, " <", email, ">")
    .Call(R_gpg_keygen_new, userstring)
  } else {
    params <- list("Key-Type" = "RSA", "Name-Real" = name, "Name-Email" = email)
    cat(make_args_str(params))
    params["Passphrase"] = passphrase # Can be NULL
    .Call(R_gpg_keygen, make_args_str(params))
  }
}

make_args_str <- function(params){
  str <- paste(names(params), unname(params), sep = ": ", collapse = "\n")
  paste('<GnupgKeyParms format="internal">', str, '</GnupgKeyParms>\n', sep = "\n")
}
