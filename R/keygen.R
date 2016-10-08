#' GPG key generation
#'
#' Use `gpg_keygen` to generate a new private-public keypair. Supported options
#' and parameters depend on the version of GPG. See the GPG manual section on
#' [Unattended key generation](https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html).
#'
#' @export
#' @useDynLib gpg R_gpg_keygen
#' @param name value for the `Name-Real` field
#' @param email value for the `Name-Email` field
#' @param passphrase (optional) protect with a passphrase
#' @param key_type required field, defaults to RSA
#' @param ... other fields, see [GPG manual](https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html)
gpg_keygen <- function(name, email, passphrase = NULL, key_type = "RSA", ...){
  params <- list("Key-Type" = key_type, "Name-Real" = name,
                 "Name-Email" = email, ...)
  cat(make_args_str(params))
  params["Passphrase"] = passphrase # Can be NULL
  .Call(R_gpg_keygen, make_args_str(params))
}

make_args_str <- function(params){
  str <- paste(names(params), unname(params), sep = ": ", collapse = "\n")
  paste('<GnupgKeyParms format="internal">', str, '</GnupgKeyParms>\n', sep = "\n")
}
