.onLoad <- function(pkg, lib){
  path <- Sys.getenv("PATH")
  gpgbin <- system.file('bin', package = 'gpg')
  if(file.exists(gpgbin) && !grepl(gpgbin, path, fixed = TRUE)){
    Sys.setenv(PATH = paste(path, gpgbin, sep = ":"))
  }
  try({
    engine <- gpg_restart()
    packageStartupMessage("Found GPG version ", engine$version, " in: ", engine$gpg)
    packageStartupMessage("Using keyring in: ", engine$home)
  })
}
