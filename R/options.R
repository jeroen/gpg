#' GPG options
#'
#' Get and set options GnuPG configuration options.
#'
#' This function reads and edits options in the GnuPG configuration file, which
#' is stored by default in \code{~/.gnupg/gpg.conf}. Note that changing options
#' can affect other software using this installation of GnuPG.
#'
#' @export
#' @useDynLib gpg R_gpg_options R_gpg_list_options
#' @rdname gpg_info
gpg_options <- function(){
  # only works with GPG2 ?
  .Call(R_gpg_list_options)
}

#' @useDynLib gpg R_dir_info
#' @useDynLib gpg R_engine_info
#' @export
#' @rdname gpg_info
#' @examples gpg_info()
gpg_info <- function(){
  dirs <- structure(lapply(.Call(R_dir_info), trimws),
    names = c("home", "sysconf", "gpgconf", "gpg"))
  engine <- structure(lapply(.Call(R_engine_info), trimws),
    names = c("gpg", "version", "home", "gpgme"))
  if(is.na(engine$home))
    engine$home <- dirs$home
  engine$version <- as.numeric_version(engine$version)
  engine$gpgme <- as.numeric_version(engine$gpgme)
  c(list(gpgconf = dirs$gpgconf), engine)
}


#' @export
#' @rdname gpg_info
#' @examples gpg_version()
#' @param silent suppress output of `gpg --version`
gpg_version <- function(silent = FALSE){
  info <- gpg_info()
  out <- system2(info$gpg, "--version", stdout = TRUE)
  if(!isTRUE(silent))
    cat(out, sep = "\n")
  invisible(out)
}
