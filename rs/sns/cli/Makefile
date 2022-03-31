.PHONY: all
all: build

.PHONY: build
.SILENT: build
build:
	dfx canister create --all
	dfx build
	cargo build

.PHONY: clean
.SILENT: clean
clean:
	rm -rf .dfx
