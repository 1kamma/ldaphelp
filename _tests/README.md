# Test layout

The real test files live in this directory.

Root-level `*_test.go` symlinks point here so `go test ./...` can still compile tests in the same `package main` directory. This is required because several tests intentionally cover unexported helpers.

Go ignores underscore-prefixed directories during `./...` package discovery, so `_tests/` is not compiled as a separate package.
