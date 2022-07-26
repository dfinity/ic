.PHONY: all
all: build

.PHONY: build
.SILENT: build
build:
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --profile canister-release --bin sns-governance-canister
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/canister-release/sns-governance-canister.wasm -o ../../target/wasm32-unknown-unknown/canister-release/sns-governance-canister-opt.wasm
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --profile canister-release --bin ic-icrc1-archive
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/canister-release/ic-icrc1-archive.wasm -o ../../target/wasm32-unknown-unknown/canister-release/ic-icrc1-archive-opt.wasm
	IC_ICRC1_ARCHIVE_WASM_PATH=../../../../target/wasm32-unknown-unknown/canister-release/ic-icrc1-archive-opt.wasm cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --profile canister-release --bin ic-icrc1-ledger
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/canister-release/ic-icrc1-ledger.wasm -o ../../target/wasm32-unknown-unknown/canister-release/ic-icrc1-ledger-opt.wasm
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --profile canister-release --bin sns-root-canister
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/canister-release/sns-root-canister.wasm -o ../../target/wasm32-unknown-unknown/canister-release/sns-root-canister-opt.wasm
	cargo build --manifest-path ../../Cargo.toml --target wasm32-unknown-unknown --profile canister-release --bin sns-swap-canister
	ic-cdk-optimizer ../../target/wasm32-unknown-unknown/canister-release/sns-swap-canister.wasm -o ../../target/wasm32-unknown-unknown/canister-release/sns-swap-canister-opt.wasm
	cargo build

.PHONY: clean
.SILENT: clean
clean:
	rm -rf .dfx
