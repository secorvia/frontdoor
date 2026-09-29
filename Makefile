BINARY := frontdoor
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test vet fmt check clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/frontdoor

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

check: fmt vet test

clean:
	rm -f $(BINARY) $(BINARY).exe
