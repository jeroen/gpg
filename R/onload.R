.onLoad <- function(pkg, lib){
  out <- gpg_restart()
  packageStartupMessage("Found GPG version ", out$engine$version, " in ", out$engine$path)
  #if(!length(gpg_options()$keyserver))
  #  try(gpg_options(keyserver="hkp://keyserver.ubuntu.com:80"))
}
