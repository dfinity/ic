PWD:=$(shell pwd)

.PHONY: compile-wasm
.SILENT: compile-wasm
compile-wasm:
	dfx build --check

# Test the APIs of this canister using the respective Rust canister tests.
# This has the advantage that the tests are consistent (less room for bugs by having only one implementation of the tests) and the checked expected behavior is consistent across Rust and Motoko.
.PHONY: test
.SILENT: test
test: compile-wasm
	CUSTOM_WASM_PATH=$(PWD)/.dfx/local/canisters/ic_vetkeys_manager_canister/ic_vetkeys_manager_canister.wasm cargo test -p ic-vetkeys-manager-canister
