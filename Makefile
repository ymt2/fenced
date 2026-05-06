.PHONY: install build clean test

BINARY      := fenced
INSTALL_DIR := $(HOME)/.local/bin
SRC         := ./cmd/fenced

install:
	go build -o $(INSTALL_DIR)/$(BINARY) $(SRC)

build:
	go build -o ./bin/$(BINARY) $(SRC)

test:
	go test ./...

clean:
	rm -f ./bin/$(BINARY) $(INSTALL_DIR)/$(BINARY)
