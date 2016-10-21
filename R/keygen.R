#' GPG key generation
#'
#' Generates a new standard private-public keypair. This function is mostly
#' for testing purposes. Use the `gpg --gen-key` command line utility to generate an
#' official GPG key with custom fields and options.
#'
#' @references GPG manual section on
#' [Unattended key generation](https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html).
#' @export
#' @rdname gpg_keygen
#' @family gpg
#' @useDynLib gpg R_gpg_keygen R_gpg_keygen_new
#' @param name value for the `Name-Real` field
#' @param email value for the `Name-Email` field
#' @param passphrase (optional) protect with a passphrase
gpg_keygen <- function(name, email, passphrase = NULL){
  info <- gpg_info()
  check_entropy()
  # Use the 'new' API, required for GnuPG 2.1
  if(!length(passphrase) && info$gpgme >= "1.7.0" && info$version >= "2.1"){
    userstring <- paste0(name, " <", email, ">")
    .Call(R_gpg_keygen_new, userstring)
  } else {
    params <- list("Key-Type" = "RSA", "Name-Real" = name, "Name-Email" = email)
    controls <- "%no-ask-passphrase"
    if(length(passphrase)){
       params["Passphrase"] <- passphrase
    } else {
      controls <- c(controls, "%no-protection")
    }
    .Call(R_gpg_keygen, make_args_str(params, controls))
  }
}

check_entropy <- function(){
  try({
    if(is_unix()){
      if(file.exists("/proc/sys/kernel/random/entropy_avail")){
        val <- as.numeric(readLines("/proc/sys/kernel/random/entropy_avail"))
        if(val < 1000)
          warning("Available entropy is low. Consider installing the 'haveged' program.", call. = FALSE)
        return(val)
      }
    }
  })
  invisible()
}

make_args_str <- function(params, controls = c()){
  str <- paste(names(params), unname(params), sep = ": ", collapse = "\n")
  str <- paste(c(str, controls), collapse = "\n")
  paste('<GnupgKeyParms format="internal">', str, '</GnupgKeyParms>\n', sep = "\n")
}
