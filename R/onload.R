.onLoad <- function(pkg, lib){
  gpg_restart()
  #if(!length(gpg_options()$keyserver))
  #  try(gpg_options(keyserver="hkp://keyserver.ubuntu.com:80"))
}
