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

# Run the same checks CI runs. Excludes only the configscan package, whose tests make
# live network calls to third-party servers (not a deterministic gate).
ci:
	go build ./...
	go vet ./...
	@pkgs=$$(go list ./...) || exit 1; \
		pkgs=$$(printf '%s\n' "$$pkgs" | grep -v '/internal/configscan$$'); \
		[ -n "$$pkgs" ] || { echo "no packages to test" >&2; exit 1; }; \
		go test $$pkgs

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
