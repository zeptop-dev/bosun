BIN := bin/bosun
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build web test vet tidy clean linux

# The web panel is embedded; build it first (needs pnpm) or fetch a release.
web:
	cd web/ui && pnpm install --frozen-lockfile && pnpm build

build: web
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/bosun

linux:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/bosun-linux-amd64 ./cmd/bosun
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/bosun-linux-arm64 ./cmd/bosun

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin
