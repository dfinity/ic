use std::env::{self};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    if env::var_os("IN_BAZEL").is_none() {
        let cargo_manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
        let compile_time_env_variables = [
            "LEDGER_CANISTER_WASM_PATH",
            "INDEX_CANISTER_WASM_PATH",
            "LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH",
        ];
        for env_var in compile_time_env_variables {
            let archive_path = match env::var_os(env_var) {
                Some(wasm_path) => PathBuf::from(wasm_path),
                None => cargo_manifest_dir
                    // This is a hack.
                    // Cargo is called on CI via ci/src/rust_lint/lint.sh.
                    // The included WASMS binary for ledger, index and archive canisters are built by BAZEL tasks
                    // which would need here to be somehow spawned by Cargo. To avoid this, we just use a wasm binary that
                    // happens to be already checked-in in the repo.
                    .join("../../ledger_suite/icrc1/wasm/ic-icrc1-archive.wasm.gz")
                    .canonicalize()
                    .expect("failed to canonicalize a path"),
            };

            println!("cargo:rerun-if-changed={}", archive_path.display());
            println!("cargo:rerun-if-env-changed={env_var}");
            println!("cargo:rustc-env={}={}", env_var, archive_path.display());
        }
    }

    // Build reproducibility. askama adds a include_bytes! call when it's generating
    // a template impl so that rustc will recompile the module when the file changes
    // on disk. See https://github.com/djc/askama/blob/180696053833147a61b3348646a953e7d92ae582/askama_shared/src/generator.rs#L141
    // The stringified output of every proc-macro is added to the metadata hash for
    // a crate. That output includes the full filepath to include_bytes!. It may be
    // different on two machines, if they use different tempdir paths for the build.
    // The metadata hash is an input to generated symbol names.
    // So using the askama proc-macro could result in slightly different symbols.
    // However, if we include the html source directly in the output, no
    // inconsistency is introduced.
    //
    // This should really be fixed in askama. See:
    // https://github.com/askama-rs/askama/issues/461
    println!("cargo:rerun-if-changed=templates/dashboard.html");
    let mut f = File::create(
        PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("dashboard_template.rs"),
    )
    .unwrap();
    f.write_all(
        format!(
            r#"
#[derive(Template)]
#[template(escape = "html", source = {:?}, ext = "html")]
pub struct DashboardTemplate {{
    managed_canisters: BTreeMap<Erc20Token, CanistersDashboardData>,
    other_canisters: BTreeMap<String, Vec<CanisterDashboardData>>,
    wasm_store: Vec<DashboardStoredWasm>,
}}
    "#,
            std::fs::read_to_string("templates/dashboard.html").unwrap()
        )
        .as_bytes(),
    )
    .unwrap();
}
