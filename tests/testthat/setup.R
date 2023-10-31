# Generate random string.
#
rnd_string <- function(n = 24) {
  rawToChar(as.raw(sample(c(48:57, 65:90, 97:122), n, replace=T)))
}

# Generate random email address.
#
rnd_email <- function(n = 24, domain = "gmail.com") {
  paste(rnd_string(n), domain, sep = "@")
}

EMAIL_ALICE <- rnd_email()
EMAIL_BOB <- rnd_email()

PASSPHRASE_ALICE <- rnd_string()
PASSPHRASE_BOB <- rnd_string()

DESCRIPTION_PATH <- system.file("DESCRIPTION", package = "gpg")

BEGIN_PGP_MESSAGE <- "-----BEGIN PGP MESSAGE-----"
END_PGP_MESSAGE <- "-----END PGP MESSAGE-----"
