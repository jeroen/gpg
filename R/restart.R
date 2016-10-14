#' Manage the GPG engine
#'
#' Use `gpg_restart()` to find the `gpg` program and home directory (which contains
#' configuration and keychains). Usually the default should be fine and you
#' do not need to run this function manually.
#'
#' Use `gpg_info()` to get your current engine settings. The `gpg_version()` function
#' simply calls `gpg --version` to see some verbose output about the `gpg` executable.
#'
#' `gpg_options` reads options in the GnuPG configuration file, which is stored by
#' default in \code{~/.gnupg/gpg.conf}. Note that changing options might affect
#' other software using GnuPG.
#'
#' @export
#' @useDynLib gpg R_gpg_restart
#' @param path location of `gpg` or `gpg2` or `gpgconf` or (on windows) `gpgme-w32spawn.exe`
#' @param home path to your GPG configuration directory (including keyrings)
#' @param debug debugging level, integer between 1 and 9
#' @rdname gpg_info
gpg_restart <- function(home = NULL, path = NULL, debug = "none", silent = FALSE){
  if(!length(path) && is_windows())
    path <- find_wininst()
  path <- normalizePath(as.character(path), mustWork = FALSE)
  home <- normalizePath(as.character(home), mustWork = FALSE)
  if(length(home) && !file.exists(home)){
    dir.create(home, showWarnings = FALSE)
    stopifnot(isTRUE(file.info(home)$isdir))
  }
  debug <- normalizePath(as.character(debug), mustWork = FALSE)
  engine <- .Call(R_gpg_restart, home, path, readline, debug)
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

pinentry_warning <- function(){
  if(gpg_info()$version >= 2 && !is_windows()){
    try({
      if(system2("tty", stdout = NULL) > 0){
        message("Note that in GPG2, passphrases can only be entered if R runs in a terminal session")
      }
    }, silent = TRUE)
  }
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

#' @useDynLib gpg R_dir_info R_engine_info
#' @export
#' @rdname gpg_info
#' @examples gpg_info()
gpg_info <- function(){
  dirs <- structure(lapply(.Call(R_dir_info), mytrimws),
                    names = c("home", "sysconf", "gpgconf", "gpg"))
  engine <- structure(lapply(.Call(R_engine_info), mytrimws),
                      names = c("gpg", "version", "home", "gpgme"))
  if(is.na(engine$home))
    engine$home <- dirs$home
  engine$version <- as.numeric_version(engine$version)
  engine$gpgme <- as.numeric_version(engine$gpgme)
  c(list(gpgconf = dirs$gpgconf), engine)
}

#' @export
#' @useDynLib gpg R_gpg_list_options
#' @rdname gpg_info
gpg_options <- function(){
  # only works with GPG2 ?
  .Call(R_gpg_list_options)
}

# Fallback for base::trimws for R < 3.2
mytrimws <- function(x){
  mysub <- function(re, x) sub(re, "", x, perl = TRUE)
  mysub("[ \t\r\n]+$", mysub("^[ \t\r\n]+", x))
}

