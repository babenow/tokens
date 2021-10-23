.PHONY: test

test:
	go test -v -timeout 30s ./...

.DEFAULT_GOAL := test