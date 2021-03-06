#' Password Entry
#'
#' Function to prompt the user for a password to read a protected private key.
#'
#' If available, this function calls the GnuPG `pinentry` program. However this
#' only works in a terminal. Therefore the IDE can provide a custom password entry
#' widget by setting the \code{askpass} option. If no such option is specified
#' we default to \code{\link{readline}}.
#'
#' @export
#' @param prompt the string printed when prompting the user for input.
pinentry <- function(prompt = "Enter your GPG passphrase:"){
  if(is_unix() && isatty(stdin()) && has_pinentry()){
    try({
      return(pinentry_exec(prompt))
    })
  }
  askpass::askpass(prompt = prompt)
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
pinentry_exec <- function(str){
  input <- c(paste("SETPROMPT", str), "GETPIN")
  tty <- system2("tty", stdout = TRUE)
  res <- system2("pinentry", paste("-T", tty, '-C', 'UTF-8'), input = input, stdout = TRUE)
  errors <- res[grepl("^ERR ", res)]
  if(length(errors))
    stop(sub("^ERR", "Pinentry error", errors[1]), call. = FALSE)
  pwline <- res[grepl("^D ", res)]
  if(!length(pwline))
    return(NULL) #no password entered
  sub("D ", "", pwline, fixed = TRUE)
}
