use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use candid::Principal;
use cargo_metadata::MetadataCommand;
use pocket_ic::common::rest::RawEffectivePrincipal;
use pocket_ic::{call_candid, PocketIc, PocketIcBuilder, RejectResponse};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Once;

/// Builds a canister with the specified name from the current
/// package and returns the WebAssembly module.
pub fn cargo_build_canister(bin_name: &str) -> Vec<u8> {
    static LOG_INIT: Once = Once::new();
    LOG_INIT.call_once(env_logger::init);
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    let cargo_toml_path = dir.join("Cargo.toml");

    let target_dir = MetadataCommand::new()
        .manifest_path(&cargo_toml_path)
        .no_deps()
        .exec()
        .expect("failed to run cargo metadata")
        .target_directory;

    // We use a different target path to stop the native cargo build
    // cache being invalidated every time we run this function
    let wasm_target_dir = target_dir.join("canister-build");

    let mut cmd = Command::new("cargo");
    let target = match std::env::var("WASM64") {
        Ok(_) => {
            cmd.args([
                "+nightly-2025-05-09", // 1.88.0
                "build",
                "-Z",
                "build-std=std,panic_abort",
                "--target",
                "wasm64-unknown-unknown",
            ]);
            "wasm64-unknown-unknown"
        }
        Err(_) => {
            cmd.args(["build", "--target", "wasm32-unknown-unknown"]);
            "wasm32-unknown-unknown"
        }
    };

    let cmd = cmd
        .args([
            "--bin",
            bin_name,
            "--profile",
            "canister-release",
            "--manifest-path",
            &cargo_toml_path.to_string_lossy(),
            "--target-dir",
            wasm_target_dir.as_ref(),
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let output = cmd.output().expect("failed to locate cargo");
    assert!(output.status.success(), "failed to compile the wasm binary");

    let wasm_path = wasm_target_dir
        .join(target)
        .join("canister-release")
        .join(bin_name)
        .with_extension("wasm");

    std::fs::read(&wasm_path).unwrap_or_else(|e| {
        panic!(
            "failed to read compiled Wasm file from {:?}: {}",
            &wasm_path, e
        )
    })
}

// The linter complains "function `update` is never used"
// because not EVERY test uses this function.
pub fn update<Input, Output>(
    env: &PocketIc,
    canister_id: Principal,
    method: &str,
    input: Input,
) -> Result<Output, RejectResponse>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    call_candid(env, canister_id, RawEffectivePrincipal::None, method, input)
}

/// Creates a PocketIcBuilder with the base configuration for e2e tests.
///
/// The PocketIc server binary is cached for reuse.
pub fn pic_base() -> PocketIcBuilder {
    let pocket_ic_server = check_pocket_ic_server();
    PocketIcBuilder::new()
        .with_server_binary(pocket_ic_server)
        .with_application_subnet()
}

fn check_pocket_ic_server() -> PathBuf {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let cargo_toml_path = dir.join("Cargo.toml");
    let metadata = MetadataCommand::new()
        .manifest_path(&cargo_toml_path)
        .exec()
        .expect("failed to run cargo metadata");
    let e2e_tests_package = metadata
        .packages
        .iter()
        .find(|m| m.name.as_ref() == "ic-cdk-e2e-tests")
        .expect("ic-cdk-e2e-tests not found in Cargo.toml");
    let pocket_ic_tag = e2e_tests_package
        .dependencies
        .iter()
        .find(|d| d.name == "pocket-ic")
        .expect("pocket-ic not found in Cargo.toml")
        .source
        .as_ref()
        .expect("pocket-ic source not found in Cargo.toml")
        .repr
        .split_once("tag=")
        .expect("`tag=` not found in pocket-ic source")
        .1;
    let target_dir = metadata.target_directory;
    let artifact_dir = target_dir.join("e2e-tests-artifacts");
    let tag_path = artifact_dir.join("pocket-ic-tag");
    let server_binary_path = artifact_dir.join("pocket-ic");
    if let Ok(tag) = std::fs::read_to_string(&tag_path) {
        if tag == pocket_ic_tag && server_binary_path.exists() {
            return server_binary_path.into();
        }
    }
    panic!("pocket-ic server not found or tag mismatch, please run `scripts/download_pocket_ic_server.sh` in the project root");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pocket_ic() {
        let _pic = pic_base();
    }

    #[test]
    fn test_update() {
        let pic = pic_base().build();
        let canister_id = pic.create_canister();
        pic.add_cycles(canister_id, 2_000_000_000_000);
        pic.install_canister(
            canister_id,
            b"\x00asm\x01\x00\x00\x00".to_vec(),
            vec![],
            None,
        );
        assert!(update::<(), ()>(&pic, canister_id, "insert", ()).is_err());
    }
}
