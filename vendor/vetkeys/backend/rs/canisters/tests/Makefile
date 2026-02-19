.PHONY: build
.SILENT: build
build:
	cargo build --release --target wasm32-unknown-unknown

.PHONY: test
.SILENT: test
test: build
	cargo test
