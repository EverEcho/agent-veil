.PHONY: test verify build

test:
	go test ./...

verify:
	go vet ./...
	go test -race ./...

build:
	go build -trimpath -o veil ./cmd/veil
