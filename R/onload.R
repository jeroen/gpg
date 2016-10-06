.onLoad <- function(lib, pkg){
  if(grepl("darwin", R.Version()$platform)){
    path <- Sys.getenv("PATH")
    gpgbin <- file.path(lib, pkg, "bin")
    if(file.exists(gpgbin) && !grepl(gpgbin, path, fixed = TRUE)){
      Sys.setenv(PATH = paste(path, normalizePath(gpgbin), sep = ":"))
    }
  }
  gpg_restart(silent = TRUE)
}

.onAttach <- function(lib, pkg){
  engine <- gpg_info()
  packageStartupMessage("Found GPG ", engine$version, ". Using keyring: ", engine$home)
}