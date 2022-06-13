.PHONY: all
all: build

.PHONY: build
.SILENT: build
build:
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --profile canister-release --bin sns-governance-canister
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/canister-release/sns-governance-canister.wasm -o ../../target/wasm32-unknown-unknown/canister-release/sns-governance-canister-opt.wasm
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --profile canister-release --bin ledger-canister
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/canister-release/ledger-canister.wasm -o ../../target/wasm32-unknown-unknown/canister-release/ledger-canister-opt.wasm
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --profile canister-release --bin sns-root-canister
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/canister-release/sns-root-canister.wasm -o ../../target/wasm32-unknown-unknown/canister-release/sns-root-canister-opt.wasm
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --profile canister-release --bin sns-sale-canister
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/canister-release/sns-sale-canister.wasm -o ../../target/wasm32-unknown-unknown/canister-release/sns-sale-canister-opt.wasm
	cargo build

.PHONY: clean
.SILENT: clean
clean:
	rm -rf .dfx
