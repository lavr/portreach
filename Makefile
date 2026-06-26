VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE_NAME ?= lavr/portreach

# Escape single quotes for safe shell embedding in single-quoted strings
sq = $(subst ','\'',$(1))

.PHONY: build test lint fmt race vet docker-build version run

build:
	mkdir -p dist/
	go build -ldflags='-s -w -X main.version=$(call sq,$(VERSION))' -o dist/portreach .

test:
	go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	find . -name '*.go' -not -path './.ralphex/*' -exec $(shell go env GOPATH)/bin/goimports -w {} +

race:
	go test -race -timeout=60s ./...

docker-build:
	docker build --target alpine --build-arg VERSION='$(call sq,$(VERSION))' -t '$(call sq,$(IMAGE_NAME)):$(call sq,$(VERSION))' .

version:
	@echo '$(call sq,$(VERSION))'

# Run the UI against a local agent by default so the target works from a clean
# checkout (ui requires --agents/--agents-dns). When PORTREACH_AGENTS or
# PORTREACH_AGENTS_DNS is set, default to no flags and let the binary read its
# env config — passing --agents on top of a DNS env var would trip the
# "set only one of --agents or --agents-dns" check. Override with ARGS, e.g.
# `make run ARGS="--agents-dns=portreach-agents"`.
ARGS ?= $(if $(or $(PORTREACH_AGENTS),$(PORTREACH_AGENTS_DNS)),,--agents=127.0.0.1:8732)
run:
	go run . ui $(ARGS)
