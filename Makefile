#   Copyright The containerd Authors.

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at

#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

GO ?= go
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
BINDIR ?= bin
BIN_NAME ?= go-dmverity
CMD_PATH ?= ./cmd/go-dmverity
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


