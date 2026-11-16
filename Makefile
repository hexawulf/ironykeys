# IronyKeys build helpers. Recipe lines start with a tab.
VERSION ?= 0.1.0-dev+$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION)
PREFIX  ?= /usr/local

.PHONY: build test interop install dist clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ironykeys ./cmd/ironykeys

test:
	go vet ./...
	go test ./...

# Needs root, loop devices, dm-crypt, cryptsetup and the veracrypt CLI.
interop:
	go vet -tags interop ./...
	go test -c -tags interop -o interop.test ./internal/interop
	sudo ./interop.test -test.v

install: build
	sudo install -o root -g root -m 0755 ironykeys $(PREFIX)/bin/ironykeys

dist:
	mkdir -p dist
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ironykeys-linux-arm64 ./cmd/ironykeys
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ironykeys-linux-amd64 ./cmd/ironykeys
	cd dist && sha256sum ironykeys-linux-* > SHA256SUMS

clean:
	go clean
	$(RM) ironykeys interop.test
	$(RM) -r dist
