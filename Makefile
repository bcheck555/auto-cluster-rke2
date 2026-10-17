.PHONY: build test vet fmt-check

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/host-agent ./cmd/host-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/bootstrap-authority ./cmd/bootstrap-authority

test:
	go test ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$$(gofmt -l cmd internal)"
