use std::fs::File;
use std::path::PathBuf;

fn main() {
    // The environment variable `<canister-name>_CANISTER_WASM_PATH` pointing to a file (storing the corresponding canister) is needed
    // for the PocketIC server to compile. There are two flows to support:
    // - code validation using `cargo`: we create a dummy file and point `<canister-name>_CANISTER_WASM_PATH` to that file for code validation to succeed;
    // - building the PocketIC server using `bazel`: `bazel` always sets `<canister-name>_CANISTER_WASM_PATH` to an actual file storing the corresponding canister
    //   (built separately) and thus we don't override `<canister>_CANISTER_WASM_PATH` if already set.
    for canister_name in [
        "REGISTRY",
        "CYCLES_MINTING",
        "ICP_LEDGER",
        "ICP_INDEX",
        "CYCLES_LEDGER",
        "CYCLES_LEDGER_INDEX",
        "GOVERNANCE_TEST",
        "ROOT",
        "SNS_WASM",
        "SNS_ROOT",
        "SNS_GOVERNANCE",
        "SNS_SWAP",
        "SNS_LEDGER",
        "SNS_LEDGER_ARCHIVE",
        "SNS_LEDGER_INDEX",
        "SNS_AGGREGATOR_TEST",
        "INTERNET_IDENTITY_TEST",
        "NNS_DAPP_TEST",
        "BITCOIN_TESTNET",
        "DOGECOIN",
        "MIGRATION",
    ] {
        let env_var_name = format!("{canister_name}_CANISTER_WASM_PATH");
        if std::env::var(&env_var_name).is_err() {
            let canister_wasm_name = format!("{}.wasm.gz", env_var_name.to_lowercase());
            let canister_wasm_path =
                PathBuf::from(std::env::var("OUT_DIR").unwrap()).join(canister_wasm_name);
            File::create(&canister_wasm_path).unwrap();
            println!(
                "cargo:rustc-env={}={}",
                env_var_name,
                canister_wasm_path.display()
            );
        }
    }
}
