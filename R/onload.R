.onLoad <- function(pkg, lib){
  if(grepl("darwin", R.Version()$platform)){
    path <- Sys.getenv("PATH")
    gpgbin <- system.file('bin', package = 'gpg')
    if(file.exists(gpgbin) && !grepl(gpgbin, path, fixed = TRUE)){
      sep <- ifelse(identical(.Platform$OS.type, "windows"), ";", ":")
      Sys.setenv(PATH = paste(path, normalizePath(gpgbin), sep = sep))
    }
  }
  engine <- gpg_restart()
  packageStartupMessage("Found GPG ", engine$version, " with keyring: ", engine$home)
}
