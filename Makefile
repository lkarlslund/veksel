.PHONY: build test fast unit-test quality loadtest release-matrix release-ci-matrix release-test

build:
	go build ./...

test:
	go test ./...

fast:
	go test -short ./...

unit-test:
	./scripts/test-unit

quality:
	./scripts/check-gofmt
	go vet ./cmd/... ./pkg/...
	staticcheck -checks 'SA*' ./cmd/... ./pkg/...
	go test ./cmd/... ./pkg/...

loadtest:
	go test -v -timeout 120s ./pkg/loadtest/...

release-matrix:
	go run ./cmd/veksel-release matrix --profile release

release-ci-matrix:
	go run ./cmd/veksel-release matrix --profile ci

release-test:
	go test ./pkg/releasebuild ./cmd/veksel-release
