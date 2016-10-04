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
#' @family gpg
#' @examples # Read options:
#' gpg_options()
#' gpg_options("keyserver")
#'
#' # Write options
#' gpg_options("debug-level" = "9")
#' gpg_options("debug-level" = "none")
gpg_options <- function(...){
  opts <- list(...)
  if(length(names(opts))){
    opts <- lapply(opts, as.character)
    .Call(R_gpg_options, opts)
  } else {
    out <- .Call(R_gpg_list_options)
    args <- c(...);
    if(is.character(args) && length(args) == 1L){
      out <- out[[args]]
    }
    out
  }
}


#' @useDynLib gpg R_dir_info
#' @useDynLib gpg R_engine_info
#' @export
gpg_info <- function(){
  dirs <- structure(lapply(.Call(R_dir_info), trimws),
    names = c("home", "sysconf", "gpgconf", "gpg"))
  engine <- structure(lapply(.Call(R_engine_info), trimws),
    names = c("gpg", "version", "home", "gpgme"))
  if(is.na(engine$home))
    engine$home <- dirs$home
  c(list(gpgconf = dirs$gpgconf), engine)
}
