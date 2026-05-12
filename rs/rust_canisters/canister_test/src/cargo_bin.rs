use crate::canister::Wasm;
use cargo_metadata::MetadataCommand;
use escargot::CargoBuild;
use std::collections::BTreeMap;
use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

/// This allows you to write multi canister tests by building multiple wasm
/// binaries then loading them into the runtime
///```ignore
/// use canister_test::*;
/// canister_test(|r|{
///     let project = Project::new();
///     let canister_1 =
///         project
///         .cargo_bin("canister_1", &[])
///         .install(&r)
///         .bytes(vec![]);
///
///     let canister_2 =
///         project
///         .cargo_bin("canister_2", &[])
///         .install(&r)
///         .bytes(vec![]);
///
///     canister_1
///         .query("inter_canister_method")
///         .bytes(canister_2.canister_id().get().into_vec());
/// });
/// ```
pub struct Project {
    pub cargo_manifest_dir: PathBuf,
}

impl Default for Project {
    fn default() -> Self {
        Self::new()
    }
}

fn is_cargo_workspace_root(p: impl AsRef<Path>) -> bool {
    let cargo_toml = p.as_ref().join("Cargo.toml");
    if !cargo_toml.exists() {
        return false;
    }
    let contents = std::fs::read(&cargo_toml)
        .unwrap_or_else(|e| panic!("failed to read file {}: {}", cargo_toml.display(), e));
    String::from_utf8_lossy(&contents).contains("[workspace]")
}

impl Project {
    pub fn new() -> Self {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        let mut h = Path::new(&manifest_dir);
        while !is_cargo_workspace_root(h) {
            match h.parent() {
                Some(p) => {
                    h = p;
                }
                None => {
                    // We reached the root but didn't find the workspace file.
                    // We're probably running under Bazel, so we don't need the manifest directory
                    // in the first place.
                    break;
                }
            }
        }
        Project {
            cargo_manifest_dir: h.to_path_buf(),
        }
    }

    /// On CI, returns the pre-compiled binary, found thanks to an env var. For
    /// local development, compiles the canister with Cargo into a Wasm module and
    /// returns it.
    ///
    /// If installing the resulting Wasm module fails with "Module imports function
    /// '__wbindgen_describe'", consider using `cargo_bin_with_package()` instead.
    pub fn cargo_bin_maybe_from_env(bin_name: &str, features: &[&str]) -> Wasm {
        Wasm::from_location_specified_by_env_var(bin_name, features)
            .unwrap_or_else(|| Self::new().compile_cargo_bin(None, bin_name, features))
    }

    /// On CI, returns the pre-compiled binary, found thanks to an env var. For
    /// local development, compiles the canister with Cargo into a Wasm module and
    /// returns it.
    ///
    /// If installing the resulting Wasm module fails with "Module imports function
    /// '__wbindgen_describe'", consider using `cargo_bin_with_package()` instead.
    pub fn cargo_bin(&self, bin_name: &str, features: &[&str]) -> Wasm {
        Wasm::from_location_specified_by_env_var(bin_name, features)
            .unwrap_or_else(|| self.compile_cargo_bin(None, bin_name, features))
    }

    /// On CI, returns the pre-compiled binary, found thanks to an env var. For
    /// local development, compiles the given canister binary from the given Cargo
    /// package into a Wasm module and returns it.
    ///
    /// Specifiying the cargo package name may help if installing the resulting Wasm
    /// module fails with "Module imports function '__wbindgen_describe'". Without
    /// limiting the build to the canister's package, `cargo` will build all
    /// dependencies with a superset of all features used anywhere in the workspace,
    /// which likely includes bindings not available to canisters.
    pub fn cargo_bin_with_package(
        &self,
        package: Option<&str>,
        bin_name: &str,
        features: &[&str],
    ) -> Wasm {
        Wasm::from_location_specified_by_env_var(bin_name, features)
            .unwrap_or_else(|| self.compile_cargo_bin(package, bin_name, features))
    }

    /// Compiles the given canister binary from the (optionally) given Cargo package
    /// into a Wasm module and returns it.
    ///
    /// This is largely equivalent to running
    /// ```bash
    /// cargo build --target wasm32-unknown-unknown \
    ///   --target-dir <repo_root>/target/wasm-cargo-bin \
    ///   --profile canister-release \
    ///   --manifest-path <cargo_manifest_dir>/Cargo.toml \
    ///   [--package <package_name>] \
    ///   --bin <bin_name> \
    ///   [--features <features>]
    /// ```
    /// then finding the wasm file output by cargo and running
    /// ```ignore
    /// # use canister_test::*;
    /// # use std::path::PathBuf;
    /// # let wasm_file = PathBuf::from("test");
    /// Wasm::from_file(wasm_file);
    /// ```
    /// We also ignore linker arguments during this compilation because they
    /// generally don't play well with the WASM linker.
    fn compile_cargo_bin(&self, package: Option<&str>, bin_name: &str, features: &[&str]) -> Wasm {
        // Cache compiled canisters to avoid running `cargo build` repeatedly.
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
        struct WasmKey {
            package: Option<String>,
            bin_name: String,
            features: Vec<String>,
        }
        static COMPILED_CANISTERS: Mutex<BTreeMap<WasmKey, PathBuf>> = Mutex::new(BTreeMap::new());

        let key = WasmKey {
            package: package.map(|s| s.to_string()),
            bin_name: bin_name.to_string(),
            features: features.iter().map(|s| s.to_string()).collect(),
        };
        // There is a race condition here, but we don't really care.
        let path = if let Some(path) = COMPILED_CANISTERS.lock().unwrap().get(&key) {
            path.clone()
        } else {
            let path = self.compile_cargo_bin_impl(package, bin_name, features);
            COMPILED_CANISTERS.lock().unwrap().insert(key, path.clone());
            path
        };

        // Strip debug info to reduce Wasm binary size. We want to avoid unnecessary
        // test failures due to oversized canister binaries.
        Wasm::from_file(path).strip_debug_info()
    }

    fn compile_cargo_bin_impl(
        &self,
        package: Option<&str>,
        bin_name: &str,
        features: &[&str],
    ) -> PathBuf {
        let since_start_secs = {
            let s = SystemTime::now();
            move || (SystemTime::now().duration_since(s).unwrap()).as_secs_f32()
        };
        eprintln!("Compiling {bin_name}...");

        let cargo_toml_path = self.cargo_manifest_dir.join("Cargo.toml");
        let target_dir = MetadataCommand::new()
            .manifest_path(&cargo_toml_path)
            .no_deps()
            .exec()
            .expect("Failed to run cargo metadata")
            .target_directory;

        // We use a different target path to stop the native cargo build
        // cache being invalidated every time we run this function
        let wasm_target_dir = Path::new(&target_dir).join("wasm-cargo-bin");

        // We change the linker flags, because there is not a consistent set of
        // linker flags that will compile both lucet with the ability to
        // re-enter the replica and wasm
        let build_rust_flags = "-C link-args=";

        let mut cargo_build = CargoBuild::new()
            .target("wasm32-unknown-unknown")
            .env("CARGO_BUILD_RUSTFLAGS", build_rust_flags)
            .bin(bin_name)
            .arg("--profile")
            .arg("canister-release")
            .manifest_path(cargo_toml_path)
            .target_dir(wasm_target_dir);
        if let Some(pkg) = package {
            cargo_build = cargo_build.package(pkg);
        }

        if !features.is_empty() {
            cargo_build = cargo_build.features(features.join(" "));
        }

        let binary = cargo_build
            .run()
            .expect("Cargo failed to compile the wasm binary");

        eprintln!("Compiling {} took {:.1} s", bin_name, since_start_secs());
        binary.path().to_path_buf()
    }
}
