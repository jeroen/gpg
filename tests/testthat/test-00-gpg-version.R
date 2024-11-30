test_that("get version", {
  expect_error(gpg_version(silent = TRUE), NA)
})