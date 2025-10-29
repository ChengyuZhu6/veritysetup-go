GO ?= go
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
BINDIR ?= bin
BIN_NAME ?= veritysetup-go
CMD_PATH ?= ./cmd/veritysetup-go
PREFIX ?= $(CURDIR)/$(BINDIR)/
CMD_BINARY=$(addprefix $(PREFIX),$(BIN_NAME))

.PHONY: all build clean test fmt vet tidy install build-linux-amd64 build-linux-arm64 build-darwin-arm64 build-darwin-amd64 build-all

all: build

build:
	@mkdir -p $(BINDIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 $(GO) build -o $(BINDIR)/$(BIN_NAME) $(CMD_PATH)

install:
	@install $(CMD_BINARY) /usr/local/bin

clean:
	rm -rf $(BINDIR)

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy


