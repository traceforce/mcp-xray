.PHONY: proto clean install-tools help

# install tools
install-tools:
	brew install bufbuild/buf/buf

# Generate protobuf Go code
proto:
	buf generate proto

# Clean generated files
clean:
	rm -f proto/*.pb.go

# Help target
help:
	@echo "Available targets:"
	@echo "  proto         - Generate Go code from protobuf"
	@echo "  clean         - Clean generated protobuf files"
	@echo "  install-tools - Install required tools (protobuf, protoc-gen-go)"
	@echo "  help          - Show this help message"
