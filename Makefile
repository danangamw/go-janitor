BINARY    := go-janitor
CMD       := ./cmd/janitor
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE      := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

.PHONY: build build-all test lint vet install docker clean release

## build: compile binary for host OS/arch
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY) $(CMD)

## build-all: cross-compile for linux/amd64 and linux/arm64
build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64 $(CMD)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64 $(CMD)

## test: run all tests with race detector and coverage
test:
	go test -race -cover ./...

## vet: run go vet
vet:
	go vet ./...

## lint: run golangci-lint (must be installed: https://golangci-lint.run)
lint:
	golangci-lint run ./...

## install: copy binary to /usr/local/bin
install: build
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

## docker: build multi-stage Docker image
docker:
	docker build -t $(BINARY):$(VERSION) .

## clean: remove build artifacts
clean:
	rm -rf bin/

## release: run goreleaser (requires GITHUB_TOKEN)
release:
	goreleaser release --clean
