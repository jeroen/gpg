configdir <- function(){
  home <- Sys.getenv("HOME", unset="~")
  sys <- Sys.info()[['sysname']]
  if (identical(sys, "Windows"))
    Sys.getenv("APPDATA")
  else if (identical(sys, "Darwin"))
    file.path(homeDir, "Library/Application Support")
  else
    Sys.getenv("XDG_CONFIG_HOME", file.path(home, ".config"))
}
