.PHONY: install build compile clean test ci check fmt fix fix-check vet

BINARY      := fenced
INSTALL_DIR := $(HOME)/.local/bin
SRC         := ./cmd/fenced

install:
	go build -o $(INSTALL_DIR)/$(BINARY) $(SRC)

build:
	go build -o ./bin/$(BINARY) $(SRC)

clean:
	rm -f ./bin/$(BINARY) $(INSTALL_DIR)/$(BINARY)

compile:
	go build ./...

fmt:
	@out=$$(go tool gofumpt -l .); \
	if [ -n "$$out" ]; then \
		echo "gofumpt needs to be run on:"; \
		echo "$$out"; \
		exit 1; \
	fi

fix:
	go fix ./...

fix-check: fix
	@if ! git diff --exit-code; then \
		echo "go fix produced changes; commit them."; \
		exit 1; \
	fi

vet:
	go vet ./...

test:
	go test -race ./...

check: fmt fix-check vet test

ci: compile check
