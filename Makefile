# testing.go is //go:build testhelpers-gated so the production
# binary's dependency closure excludes miniredis/gopher-lua (a full embedded
# Lua VM pulled in by miniredis's EVAL support) and, more subtly, the App
# struct's own test-only fields are typed `any` (not *miniredis.Miniredis) in
# app.go for the same reason — see testing.go's and app.go's doc comments.
# Consequence: ANY invocation that touches _test.go files (test, vet) must
# carry the tag, or compilation fails with "undefined: TestApp" etc. — the
# gated symbols (TestApp, SeedTestTrust, ...) are only visible with the tag.
# ALWAYS use these targets; never bare `go test`/`go vet`.
GOFLAGS_TEST := -tags testhelpers

.PHONY: build test test-fast vet lint

build: ## prod build — no tag; matches the Dockerfile build stage and the shipped binary exactly
	go build ./...

test: ## full suite with the race detector (CI: cgo available)
	go test $(GOFLAGS_TEST) -race ./...

test-fast: ## local convenience: no -race (this workspace's local DoD runs without cgo — docs/conventions.md)
	go test $(GOFLAGS_TEST) ./...

vet: ## vet must ALSO carry the tag — it type-checks _test.go files, which reference gated symbols
	go vet $(GOFLAGS_TEST) ./...

lint:
	golangci-lint run --build-tags testhelpers
