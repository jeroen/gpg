#' Start GPG engine
#'
#' Finds the `gpg` program and loads a context.
#'
#' @export
#' @useDynLib gpg R_gpg_restart
#' @param path location of `gpg` or `gpg2` or `gpgconf` or (on windows) `gpgme-w32spawn.exe`
#' @param home path to your GPG configuration directory
#' @param debug debugging level, integer between 1 and 9
#' @rdname gpg
gpg_restart <- function(path = NULL, home = NULL, debug = "none", silent = FALSE){
  if(!length(path) && is_windows())
    path <- find_wininst()
  path <- normalizePath(as.character(path), mustWork = FALSE)
  home <- normalizePath(as.character(home), mustWork = FALSE)
  if(length(home) && !file.exists(home)){
    dir.create(home, showWarnings = FALSE)
    stopifnot(isTRUE(file.info(home)$isdir))
  }
  debug <- normalizePath(as.character(debug), mustWork = FALSE)
  engine <- .Call(R_gpg_restart, path, home, debug)
  gpg_version(silent = silent)
}

find_wininst <- function(){
  libs <- c("C://Program Files/GnuPG/bin", "C://Program Files/GNU/GnuPG",
    "C://Program Files (x86)//GnuPG/bin", "C://Program Files (x86)/GNU/GnuPG",
    system.file("bin", package = "gpg"))
  for(x in libs){
    exec <- normalizePath(file.path(x, "gpgme-w32spawn.exe"), mustWork = FALSE)
    if(file.exists(exec))
      return(normalizePath(x))
  }
  stop("No GPG installation found", call. = FALSE)
}

is_windows <- function(){
  identical(.Platform$OS.type, "windows")
}
