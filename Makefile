.PHONY: test build serve dist clean

test:
	go vet ./...
	go test ./...

build:
	go build -o sentinel .

serve: build
	./sentinel -serve

# Cross-compile static binaries for a server (Go does this with two env vars).
dist:
	mkdir -p dist
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/sentinel-linux-amd64 .
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/sentinel-linux-arm64 .
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/sentinel-darwin-arm64 .

clean:
	rm -rf dist sentinel
