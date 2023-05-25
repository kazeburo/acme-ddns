VERSION=0.0.8
LDFLAGS=-ldflags "-w -s -X main.version=${VERSION}"
all: acme-ddns

.PHONY: acme-ddns

acme-ddns: cmd/acme-ddns/main.go
	go build $(LDFLAGS) -o acme-ddns cmd/acme-ddns/main.go

linux: cmd/acme-ddns/main.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o acme-ddns cmd/acme-ddns/main.go

fmt:
	go fmt ./...

check:
	go test ./...

clean:
	rm -rf acme-ddns

tag:
	git tag v${VERSION}
	git push origin v${VERSION}
	git push origin main