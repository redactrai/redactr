.PHONY: build test dev clean

BINARY=bin/redactr
MCP_BINARY=bin/redactr-mcp-wrap
SERVER_BINARY=bin/redactr-server

build:
	go build -o $(BINARY) ./cmd/redactr
	go build -o $(MCP_BINARY) ./cmd/redactr-mcp-wrap
	go build -o $(SERVER_BINARY) ./cmd/redactr-server

test:
	go test ./... -v

dev:
	go run ./cmd/redactr

clean:
	rm -rf bin/

benchmark:
	go test ./benchmarks/... -bench=. -v

.PHONY: sandbox-image
sandbox-image:
	docker build -t redactr-base:local -f build/sandbox/Dockerfile.base build/sandbox
