test_that("encrypt file", {
  # Receiver specified by email address.
  #
  encrypted <- gpg_encrypt(DESCRIPTION_PATH, receiver = EMAIL_ALICE)

  expect_match(encrypted, BEGIN_PGP_MESSAGE)

  # Receiver specified by fingerprint.
  #
  encrypted <- gpg_encrypt(DESCRIPTION_PATH, receiver = FINGERPRINT_ALICE)

  expect_match(encrypted, BEGIN_PGP_MESSAGE)
})