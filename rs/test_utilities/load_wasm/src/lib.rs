use cargo_metadata::MetadataCommand;
use escargot::CargoBuild;
use std::env;
use std::path::Path;

fn env_var_name(bin_name: &str, features: &[&str]) -> String {
    let features_part = if features.is_empty() {
        "".into()
    } else {
        format!("_{}", features.join("_"))
    };
    format!("{bin_name}{features_part}_WASM_PATH")
        .replace('-', "_")
        .to_uppercase()
}

/// Obtains a WebAssembly module by either loading a pre-build binary (on CI) or
/// building it from scratch (for local development).
///
/// # Arguments
///   * `manifest_dir` is a path to the cargo package containing the source code of
///     the canister to build.
///   * `binary_name` is the name of target to build.
///   * `features` is the list of enabled features.
///
/// # CI and Bazel Integration
///
/// If there is an environment variable called `<binary_name>_WASM_PATH`, the
/// function will load the file indicated by the environment variable instead of
/// building it from source.
///
/// Note: this function is useful only before full migration to Bazel build.
pub fn load_wasm(manifest_dir: impl AsRef<Path>, binary_name: &str, features: &[&str]) -> Vec<u8> {
    let var_name = env_var_name(binary_name, features);
    // First, check whether there is a matching environment variable specifying
    // the location of the Wasm file.
    match env::var_os(&var_name) {
        Some(path) => {
            let bytes = std::fs::read(&path).unwrap_or_else(|e| {
                panic!("failed to load Wasm file from path {path:?} (env var {var_name}): {e}")
            });
            eprintln!(
                "Using pre-built binary for {} (size = {} bytes)",
                binary_name,
                bytes.len()
            );
            return bytes;
        }
        None => {
            if env::var("CI").is_ok() {
                eprintln!("Environment variables with name containing \"WASM_PATH\":");
                for (k, v) in env::vars() {
                    if k.contains("WASM_PATH") {
                        eprintln!("  {k}: {v}");
                    }
                }

                panic!(
                    "Running on CI and expected canister env var {var_name}\n\
                         Please add {binary_name} as a data dependency in the test's BUILD.bazel target:\n"
                )
            }
        }
    }

    // The environment variable is not defined, let's build the WebAssembly file
    // from source.
    let cargo_toml_path = manifest_dir.as_ref().join("Cargo.toml");
    let target_dir = MetadataCommand::new()
        .manifest_path(&cargo_toml_path)
        .no_deps()
        .exec()
        .unwrap_or_else(|e| {
            panic!(
                "Failed to run cargo metadata on {}: {}",
                cargo_toml_path.display(),
                e
            )
        })
        .target_directory;

    // We use a different target path to stop the native cargo build
    // cache being invalidated every time we run this function
    let wasm_target_dir = Path::new(&target_dir).join("wasm-cargo-bin");

    let mut cargo_build = CargoBuild::new()
        .target("wasm32-unknown-unknown")
        .bin(binary_name)
        .arg("--profile")
        .arg("canister-release")
        .manifest_path(&cargo_toml_path)
        .target_dir(wasm_target_dir);

    if !features.is_empty() {
        cargo_build = cargo_build.features(features.join(" "));
    }

    let binary = cargo_build
        .run()
        .expect("Cargo failed to compile a Wasm binary");

    std::fs::read(binary.path()).unwrap_or_else(|e| {
        panic!(
            "failed to load Wasm from {}: {}",
            binary.path().display(),
            e
        )
    })
}
