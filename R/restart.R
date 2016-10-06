#' Start GPG engine
#'
#' Finds the `gpg` program and loads a context.
#'
#' @export
#' @useDynLib gpg R_gpg_restart
#' @param path location of `gpg` or `gpg2` or `gpgconf`
#' @param home path to your GPG configuration directory
#' @param wininst path to `gpgme-w32spawn.exe` executable on Windows
#' @param debug debugging level, integer between 1 and 9
gpg_restart <- function(path = NULL, home = NULL, debug = "none"){
  if(!length(path) && is_windows())
    path <- find_wininst()
  path <- normalizePath(as.character(path), mustWork = FALSE)
  home <- normalizePath(as.character(home), mustWork = FALSE)
  debug <- normalizePath(as.character(debug), mustWork = FALSE)
  engine <- .Call(R_gpg_restart, path, home, debug)
  gpg_info()
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
