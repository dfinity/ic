use crate::canister::Wasm;
use cargo_metadata::MetadataCommand;
use escargot::CargoBuild;
use std::env;
use std::path::Path;
use std::path::PathBuf;
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

impl Project {
    pub fn new() -> Self {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        let mut h = Path::new(&manifest_dir);
        while !h.ends_with("rs") {
            h = h
                .parent()
                .expect("unable to find `rs` directory while traversing to root");
        }
        Project {
            cargo_manifest_dir: h.to_path_buf(),
        }
    }

    /// On CI, returns the pre-compiled binary, found thanks to an env var.
    ///
    /// For local development, compile the canister with cargo using the given `bin_name`.
    pub fn cargo_bin_maybe_from_env(bin_name: &str, features: &[&str]) -> Wasm {
        Wasm::from_location_specified_by_env_var(bin_name, features)
            .unwrap_or_else(|| Self::new().cargo_bin(bin_name, features))
    }

    /// this is largely equivalent to running
    /// ```bash
    /// cargo build --target wasm32-unknown-unknown --release \
    ///   --manifest-path <cargo_manifest_dir>/Cargo.toml
    ///   --target-dir <repo_root>/rs/target/wasm-cargo-bin
    /// ```
    /// then finding the wasm file outputted by cargo and running
    /// ```ignore
    /// # use canister_test::*;
    /// # use std::path::PathBuf;
    /// # let wasm_file = PathBuf::from("test");
    /// WASM::from_file(wasm_file);
    /// ```
    /// We also ignore linker arguments during this compilation
    /// because they generally don't play well with the WASM
    /// linker
    pub fn cargo_bin(&self, bin_name: &str, features: &[&str]) -> Wasm {
        if let Some(wasm) = Wasm::from_location_specified_by_env_var(bin_name, features) {
            return wasm;
        }
        let since_start_secs = {
            let s = SystemTime::now();
            move || (SystemTime::now().duration_since(s).unwrap()).as_secs_f32()
        };
        eprintln!("Compiling {}...", bin_name);

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

        if !features.is_empty() {
            cargo_build = cargo_build.features(features.join(" "));
        }

        let binary = cargo_build
            .run()
            .expect("Cargo failed to compile the wasm binary");

        let wasm = Wasm::from_file(binary.path()).strip_debug_info();
        eprintln!("Compiling {} took {:.1} s", bin_name, since_start_secs());
        wasm
    }
}
