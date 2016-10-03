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
gpg_restart <- function(path = NULL, home = NULL, wininst = NULL, debug = "none"){
  path <- as.character(path)
  home <- as.character(home)
  debug <- as.character(debug)
  wininst <- find_wininst()
  .Call(R_gpg_restart, path, home, wininst, debug)
}

find_wininst <- function(){
  if(!identical(.Platform$OS.type, "windows"))
    return(NULL)
  libs <- c("C://Program Files/GnuPG/bin", "C://Program Files/GNU/GnuPG",
    "C://Program Files (x86)//GnuPG/bin", "C://Program Files (x86)/GNU/GnuPG")
  for(x in libs){
    x <- normalizePath(file.path(x, "gpgme-w32spawn.exe"), mustWork = FALSE)
    if(file.exists(x))
      return(normalizePath(x))
  }
  warning("No GPG installation found. Please install GPG4Win or similar", call. = FALSE)
  return(NULL)
}
