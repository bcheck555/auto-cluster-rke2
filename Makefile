.PHONY: test vet fmt-check

test:
	go test ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$$(gofmt -l $$(find cmd internal -name '*.go' -type f 2>/dev/null))"
