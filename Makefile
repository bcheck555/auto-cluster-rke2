.PHONY: test vet fmt-check

test:
	go test ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$$(gofmt -l internal)"
