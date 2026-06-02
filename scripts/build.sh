#!/bin/bash
set -euo pipefail

echo "Building Go binaries..."
go build -o bin/redactr ./cmd/redactr
go build -o bin/redactr-mcp-wrap ./cmd/redactr-mcp-wrap

echo "Build complete!"
echo "  bin/redactr"
echo "  bin/redactr-mcp-wrap"
