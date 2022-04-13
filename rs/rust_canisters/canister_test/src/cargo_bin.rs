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
///     let project = Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());
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

impl Project {
    /// Generally the right way to call this function is
    /// ```ignore
    /// # use canister_test::*;
    /// Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    /// ```
    /// `cargo_manifest_dir` is the directory where the Cargo.toml of the
    /// project with the binaries you want to test are
    pub fn new<P: AsRef<Path>>(cargo_manifest_dir: P) -> Self {
        Project {
            cargo_manifest_dir: PathBuf::from(cargo_manifest_dir.as_ref()),
        }
    }

    /// Wrapper around `new`, where the path to the Cargo.toml of the canister
    /// to build is given relative to `rs/`.
    ///
    /// This can be more convenient than using `new` directly, because the path
    /// given is independent of the location of the Cargo.toml of the
    /// test/binary that uses it.
    fn new_from_path_relative_to_rs(relative_path_from_rs: impl AsRef<Path>) -> Self {
        // This fn should remain private, because it will panic on CI.
        let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let canonical = dir.canonicalize().unwrap();
        let rs = {
            let mut d = canonical.as_path();
            // TODO(VER-190) Robustify -- there could be more than one dir called 'rs'
            while !d.ends_with("rs") {
                d = d.parent().unwrap_or_else(||
                    panic!(
                        "Could not find the rs/ directory while going up from the CARGO_MANIFEST_DIR, \
                        which is {}, and got canonicalized to {}. \
                        Are you seeing this on CI? If so, then probably you're missing some \
                        entries in the canistersForTests map in rs/check.nix.",
                           dir.as_os_str().to_string_lossy(),
                           canonical.as_os_str().to_string_lossy()));
            }
            d
        };
        let crate_dir = rs.join(relative_path_from_rs);
        Self::new(crate_dir)
    }

    /// On CI, returns the pre-compiled binary, found thanks to an env var. The
    /// `relative_path_from_rs` argument is unused in this case.
    ///
    /// For local development, compile the canister with cargo, searching for
    /// the Cargo.toml of the canister to build thanks to its relative path
    /// from rs/.
    pub fn cargo_bin_maybe_use_path_relative_to_rs(
        relative_path_from_rs: impl AsRef<Path>,
        bin_name: &str,
        features: &[&str],
    ) -> Wasm {
        Wasm::from_location_specified_by_env_var(bin_name, features).unwrap_or_else(|| {
          if env::var("CARGO_MANIFEST_DIR").is_ok() {
            Self::new_from_path_relative_to_rs(relative_path_from_rs).cargo_bin(bin_name, features)
          } else {
              panic!(
                  "No CARGO_MANIFEST_DIR set, but also no _CANISTER env var, while searching for {}",
                  bin_name
              )
          }
        })
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

        let cargo_toml_path = &self.cargo_manifest_dir.clone().join("Cargo.toml");
        let target_dir = MetadataCommand::new()
            .manifest_path(cargo_toml_path)
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
            .bin(bin_name.to_string())
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

        let wasm = Wasm::from_file(binary.path());
        eprintln!("Compiling {} took {:.1} s", bin_name, since_start_secs());
        wasm
    }
}
