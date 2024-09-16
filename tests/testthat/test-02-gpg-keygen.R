test_that("generate key (without passphrase)", {
  expect_error(gpg_keygen("Alice"))
  expect_error(gpg_keygen(email = EMAIL_ALICE))

  FINGERPRINT_ALICE <<- gpg_keygen("Alice", EMAIL_ALICE)
  expect_match(FINGERPRINT_ALICE, "[A-Z0-9]{16}")
})

test_that("generate key (with passphrase)", {
  FINGERPRINT_BOB <<- gpg_keygen("Bob", EMAIL_BOB, PASSPHRASE_BOB)

  expect_match(FINGERPRINT_BOB, "[A-Z0-9]{16}")
})