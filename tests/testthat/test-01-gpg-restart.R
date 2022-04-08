test_that("set configuration directory", {
  expect_error(gpg_restart(home = tempdir(), silent = TRUE), NA)
})