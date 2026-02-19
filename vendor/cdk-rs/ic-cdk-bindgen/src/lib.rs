#![allow(clippy::needless_doctest_main)]
#![doc = include_str!("../README.md")]

use candid::Principal;
use candid_parser::bindings::rust::{
    Config as BindgenConfig, ExternalConfig, emit_bindgen, output_handlebar,
};
use candid_parser::configs::Configs;
use candid_parser::pretty_check_file;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

/// Config for Candid to Rust bindings generation.
///
/// # Choose Bindgen Modes
///
/// The bindgen has following modes:
/// - Types only: Only the types definition will be generated. This is the default behavior with [`Self::new`].
/// - Static callee: The canister ID is known at compile time. Call [`Self::static_callee`] to set it.
/// - Dynamic callee: The canister ID is determined at runtime via ICP environment variable. Call [`Self::dynamic_callee`] to set it.
///
/// # Generate Bindings
///
/// After configuring your bindgen settings through the methods above, you must call
/// [`Self::generate`] to actually produce the Rust bindings.
#[derive(Debug)]
pub struct Config {
    canister_name: String,
    candid_path: PathBuf,
    mode: Mode,
    type_selector_config_path: Option<PathBuf>, // TODO: Implement type selector config
}

/// Bindgen mode.
#[derive(Debug)]
enum Mode {
    TypesOnly,
    StaticCallee { canister_id: Principal },
    DynamicCallee { env_var_name: String },
}

impl Config {
    /// Create a new `Config` instance.
    ///
    /// # Arguments
    /// - `canister_name` - The name of the canister. This will be used as the generated file name.
    ///   It is important to ensure that this name is valid for use in a file system (no
    ///   spaces, special characters, or other characters that could cause issues with file paths).
    /// - `candid_path` - The path to the Candid file.
    pub fn new<N, P>(canister_name: N, candid_path: P) -> Self
    where
        N: Into<String>,
        P: Into<PathBuf>,
    {
        Self {
            canister_name: canister_name.into(),
            candid_path: candid_path.into(),
            mode: Mode::TypesOnly,
            type_selector_config_path: None,
        }
    }

    /// Changes the bindgen mode to "Static callee", where the canister ID is known at compile time.
    ///
    /// This mode hardcodes the target canister ID in the generated code, making it suitable
    /// for deployments where the canister ID is fixed and known at compile time.
    ///
    /// # Arguments
    ///
    /// - `canister_id` - The Principal ID of the target canister
    pub fn static_callee<S>(&mut self, canister_id: S) -> &mut Self
    where
        S: Into<Principal>,
    {
        if !matches!(self.mode, Mode::TypesOnly) {
            panic!("The bindgen mode has already been set.");
        }
        self.mode = Mode::StaticCallee {
            canister_id: canister_id.into(),
        };
        self
    }

    /// Changes the bindgen mode to "Dynamic callee", where the canister ID is determined at runtime.
    ///
    /// This mode allows the canister ID to be resolved dynamically from an Internet Computer (ICP)
    /// environment variable, making it suitable for deployments where the target canister ID
    /// may change across environments.
    ///
    /// # Arguments
    ///
    /// - `env_var_name` - The name of the ICP environment variable containing the canister ID.
    pub fn dynamic_callee<S>(&mut self, env_var_name: S) -> &mut Self
    where
        S: Into<String>,
    {
        if !matches!(self.mode, Mode::TypesOnly) {
            panic!("The bindgen mode has already been set.");
        }
        self.mode = Mode::DynamicCallee {
            env_var_name: env_var_name.into(),
        };
        self
    }

    /// Sets the path to the type selector configuration file.
    ///
    /// The "type selector config" is a TOML file that specifies how certain Candid types
    /// should be mapped to Rust types (attributes, visibility, etc.). Please refer to the
    /// [specification](https://github.com/dfinity/candid/blob/master/spec/Type-selector.md#rust-binding-configuration)
    /// for more details.
    pub fn set_type_selector_config<P>(&mut self, path: P) -> &mut Self
    where
        P: Into<PathBuf>,
    {
        self.type_selector_config_path = Some(path.into());
        self
    }

    /// Generate the bindings.
    ///
    /// The generated bindings will be written to the output directory specified by the
    /// `OUT_DIR` environment variable. The file will be named after the canister name.
    /// For example, if the canister name is "my_canister", the generated file will be
    /// located at `$OUT_DIR/my_canister.rs`.
    pub fn generate(&self) {
        // 0. Load type selector config if provided
        let type_selector_configs_str = match &self.type_selector_config_path {
            Some(p) => {
                println!("cargo:rerun-if-changed={}", p.display());
                fs::read_to_string(p).unwrap_or_else(|e| {
                    panic!(
                        "failed to read the type selector config file ({}): {}",
                        p.display(),
                        e
                    )
                })
            }
            None => "".to_string(),
        };
        let type_selector_configs = Configs::from_str(&type_selector_configs_str)
            .unwrap_or_else(|e| panic!("failed to parse the type selector config: {}", e));
        let rust_bindgen_config = BindgenConfig::new(type_selector_configs);

        // 1. Parse the candid file and generate the Output (the struct for bindings)
        // This tells Cargo to re-run the build-script if the Candid file changes.
        println!("cargo:rerun-if-changed={}", self.candid_path.display());
        let (env, actor, prog) = pretty_check_file(&self.candid_path).unwrap_or_else(|e| {
            panic!(
                "failed to parse candid file ({}): {}",
                self.candid_path.display(),
                e
            )
        });
        // unused are not handled
        let (output, _unused) = emit_bindgen(&rust_bindgen_config, &env, &actor, &prog);

        // 2. Generate the Rust bindings using the Handlebars template
        let mut external = ExternalConfig::default();
        let content = match &self.mode {
            Mode::StaticCallee { canister_id } => {
                let template = include_str!("templates/static_callee.hbs");
                external
                    .0
                    .insert("canister_id".to_string(), canister_id.to_string());
                output_handlebar(output, external, template)
            }
            Mode::DynamicCallee { env_var_name } => {
                let template = include_str!("templates/dynamic_callee.hbs");
                external
                    .0
                    .insert("env_var_name".to_string(), env_var_name.to_string());
                output_handlebar(output, external, template)
            }
            Mode::TypesOnly => {
                let template = include_str!("templates/types_only.hbs");
                output_handlebar(output, external, template)
            }
        };

        // 3. Write the generated Rust bindings to the output directory
        let out_dir_str = std::env::var("OUT_DIR")
            .expect("OUT_DIR should always be set when execute the build.rs script");
        let out_dir = PathBuf::from(out_dir_str);
        let generated_path = out_dir.join(format!("{}.rs", self.canister_name));
        let mut file = fs::File::create(&generated_path).unwrap_or_else(|e| {
            panic!(
                "failed to create the output file ({}): {}",
                generated_path.display(),
                e
            )
        });
        writeln!(file, "{content}").unwrap_or_else(|e| {
            panic!(
                "failed to write to the output file ({}): {}",
                generated_path.display(),
                e
            )
        });
    }
}
