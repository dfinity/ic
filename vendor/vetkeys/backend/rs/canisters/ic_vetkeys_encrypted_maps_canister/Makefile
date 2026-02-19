ROOT_DIR := $(shell git rev-parse --show-toplevel)

.PHONY: compile-wasm
.SILENT: compile-wasm
compile-wasm:
	cargo build --release --target wasm32-unknown-unknown

.PHONY: extract-candid
.SILENT: extract-candid
extract-candid: compile-wasm
	candid-extractor $(ROOT_DIR)/target/wasm32-unknown-unknown/release/ic_vetkeys_encrypted_maps_canister.wasm > ic_vetkeys_encrypted_maps_canister.did

.PHONY: clean
.SILENT: clean
clean:
	cargo clean
	rm -rf .dfx