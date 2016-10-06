#' GPG keygen
#'
#' Generates a new private-public keypair. Note that some options are
#' only supported if you have GPG2. The [GPG manual](https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html)
#' explains which fields are suppor
#'
#' @export
#' @useDynLib gpg R_gpg_keygen
#' @param name value for the `Name-Real` field
#' @param email value for the `Name-Email` field
#' @param passphrase (optional) protect with a passphrase
#' @param ... other fields, see [GPG manual](https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html)
gpg_keygen <- function(name, email, passphrase = NULL, ...){
  params <- list("Key-Type" = "default", "Subkey-Type" = "default",
                 "Name-Real" = name, "Name-Email" = email, ...)
  params["Passphrase"] = passphrase
  str <- paste(names(params), unname(params), sep = ": ", collapse = "\n")
  str <- paste('<GnupgKeyParms format="internal">', str, '</GnupgKeyParms>\n', sep = "\n")
  .Call(R_gpg_keygen, str)
  invisible(cat(str))
}
