.PHONY: all build install proto clean install-dependencies install-opengrep install-codeql ci help

DESTDIR = /usr/local/bin
BINARY = mcpxray

OS ?= $(shell uname -s)

# Build everything (proto + binary)
all: proto build

# Build the binary
build:
	go build -o $(BINARY) ./cmd/xray

# install tools (buf; macOS: brew, Linux: go install)
install-dependencies:
ifeq ($(OS),Darwin)
	brew install bufbuild/buf/buf
else ifeq ($(OS),Linux)
	go install github.com/bufbuild/buf/cmd/buf@latest
	@echo "buf installed to $$(go env GOPATH)/bin — ensure that directory is on your PATH"
else
	$(error Unsupported OS: $(OS). Install buf manually: https://buf.build/docs/installation)
endif

# Install the OpenGrep engine used by the repo-scan taint SAST (pinned + SHA-verified)
install-opengrep:
	bash scripts/install_opengrep.sh

# Install the CodeQL bundle for cross-file Go/TS/Python taint (pinned + SHA-verified)
install-codeql:
	bash scripts/install_codeql.sh

# Generate protobuf Go code
proto:
	buf generate proto

# Install the binary
install: build
	install -m 0755 $(BINARY) $(DESTDIR)

# Run the same checks CI runs. Tests that reach the public internet are behind the
# integration build tag: vet still compiles them, go test -tags integration runs them.
ci:
	go build ./...
	go vet -tags integration ./...
	go test ./...

# Clean generated files
clean:
	rm -f proto/*.pb.go
	rm -f $(BINARY)

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Generate protobuf code and build the binary"
	@echo "  build         - Build the mcpxray binary"
	@echo "  install       - Install the mcpxray binary"
	@echo "  ci            - Run build, vet, and deterministic tests (same as CI)"
	@echo "  proto         - Generate Go code from protobuf"
	@echo "  clean         - Clean generated protobuf files and binary"
	@echo "  install-dependencies - Install required dependencies (buf); supports macOS (brew) and Linux (go install)"
	@echo "  install-opengrep     - Download the pinned OpenGrep engine for the repo-scan taint SAST"
	@echo "  install-codeql       - Download the pinned CodeQL bundle for cross-file Go/TS/Python taint"
	@echo "  help          - Show this help message"
