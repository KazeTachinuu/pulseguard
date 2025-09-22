.PHONY: build test run clean

# Build the application
build:
	go build -o bin/pulseguard ./cmd/pulseguard

# Run tests
test:
	go test ./...

# Run the application
run:
	go run ./cmd/pulseguard

# Clean build artifacts
clean:
	rm -rf bin/

# Install dependencies
deps:
	go mod tidy
	go mod download
