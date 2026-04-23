.PHONY: all build install proto clean install-dependencies help

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

# Generate protobuf Go code
proto:
	buf generate proto

# Install the binary
install: build
	install -m 0755 $(BINARY) $(DESTDIR)

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
	@echo "  proto         - Generate Go code from protobuf"
	@echo "  clean         - Clean generated protobuf files and binary"
	@echo "  install-dependencies - Install required dependencies (buf); supports macOS (brew) and Linux (go install)"
	@echo "  help          - Show this help message"
