.PHONY: all
all: build

.PHONY: build
.SILENT: build
build:
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --bin sns-governance-canister --release
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/release/sns-governance-canister.wasm -o ../../target/wasm32-unknown-unknown/release/sns-governance-canister-opt.wasm
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --release --bin ledger-canister
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/release/ledger-canister.wasm -o ../../target/wasm32-unknown-unknown/release/ledger-canister-opt.wasm
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --release --bin sns-root-canister
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/release/sns-root-canister.wasm -o ../../target/wasm32-unknown-unknown/release/sns-root-canister-opt.wasm
	cargo build

.PHONY: clean
.SILENT: clean
clean:
	rm -rf .dfx
