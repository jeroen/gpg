#' Password Entry
#'
#' Function to prompt the user for a password to read a protected private key.
#' IDE can provide a custom password entry widget by setting the \code{askpass}
#' option. If no such option is specified we default to \code{\link{readline}}.
#'
#' @export
#' @param prompt the string printed when prompting the user for input.
askpass <- function(prompt = "Enter your GPG passphrase:"){
  if(is_unix() && (is_cmd_build() || is_tty()) && has_pinentry()){
    pinentry(prompt)
  } else {
    FUN <- getOption("askpass", readline)
    FUN(prompt)
  }
}

is_cmd_build <- function(){
  grepl("^Rbuild", basename(getwd()))
}

is_unix <- function(){
  identical(.Platform$OS.type, "unix")
}

is_tty <- function(){
  return(system2("tty", "<&2") == 0)
}

has_pinentry <- function(){
  return(system2("pinentry", "--version", stdout = FALSE, stderr = FALSE) == 0)
}

# in POSIX, "/dev/tty" means current CTTY
pinentry <- function(str){
  input <- c(paste("SETPROMPT", str), "GETPIN")
  res <- system2("pinentry", paste("-T", '/dev/tty'), input = input, stdout = TRUE)
  pwline <- res[grepl("D ", res, fixed = TRUE)]
  sub("D ", "", pwline, fixed = TRUE)
}
