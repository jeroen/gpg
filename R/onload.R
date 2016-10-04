.onLoad <- function(pkg, lib){
  try({
    engine <- gpg_restart()
    packageStartupMessage("Found GPG version ", engine$version, " in: ", engine$gpg)
    packageStartupMessage("Using keyring in: ", engine$home)
  })
}
