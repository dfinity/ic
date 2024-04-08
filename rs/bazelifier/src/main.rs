use std::{
    borrow::Cow,
    collections::{btree_map, BTreeMap, BTreeSet},
    fmt::Display,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use self::deps::*;
use self::overrides::NameOverride;
use askama::Template;
use clap::Parser;
use serde::Deserialize;
use toml::Value;

mod deps;
mod overrides;

#[derive(Parser, Debug)]
struct Options {
    /// Overwrite any existing BUILD file
    #[clap(short, long)]
    force: bool,
    /// Show the generated file instead of writing it
    #[clap(short = 'n', long)]
    dry_run: bool,
    /// Generate rust_test invocations
    #[clap(short = 't', long = "tests")]
    gen_tests: bool,
    /// Cargo.toml file to convert
    cargo_file: String,
    /// Workspace root file
    #[clap(short = 'w', long = "workspace")]
    workspace: Option<String>,
}

type Deps = BTreeSet<String>;

enum BuildType {
    Lib,
    ProcMacro,
}

impl Display for BuildType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lib => write!(f, "rust_library"),
            Self::ProcMacro => write!(f, "rust_proc_macro"),
        }
    }
}

impl Default for BuildType {
    fn default() -> Self {
        Self::Lib
    }
}

#[derive(Deserialize, Debug)]
struct Crate {
    package: Package,
    #[serde(default)]
    lib: Option<LibSection>,
    #[serde(default)]
    dependencies: BTreeMap<String, Dep>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, Dep>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: BTreeMap<String, Dep>,
    #[serde(default)]
    target: toml::map::Map<String, toml::Value>,
    #[serde(default)]
    bin: Vec<BinSection>,
}

#[derive(Deserialize, Debug)]
struct LibSection {
    #[serde(rename = "proc-macro", default)]
    proc_macro: bool,
    #[serde(rename = "name", default)]
    name_override: Option<String>,
}

#[derive(Deserialize, Debug)]
struct BinSection {
    name: String,
    path: String,
}

#[derive(Debug)]
struct BinSectionOut {
    name: String,
    path: String,
    canister: bool,
}

#[derive(Deserialize, Debug)]
struct Package {
    name: String,
    version: PackageProperty,
    edition: PackageProperty,
}

#[derive(Debug)]
enum PackageProperty {
    Simple(String),
    Complex(Value),
}

impl<'de> Deserialize<'de> for PackageProperty {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match Value::deserialize(deserializer)? {
            Value::String(s) => Self::Simple(s),
            v => Self::Complex(v),
        })
    }
}

#[derive(Template, Default)]
#[template(path = "buildfile.template", escape = "none")]
struct BuildFile<'a> {
    build_type: BuildType,
    deps: Deps,
    dev_deps: Deps,
    macro_deps: Deps,
    macro_dev_deps: Deps,
    build_deps: Deps,
    aliases: BTreeMap<String, String>,
    target_name: Cow<'a, str>,
    edition: &'a str,
    crate_name: String,
    crate_version: &'a str,
    bins: Vec<BinSectionOut>,
    gen_tests: bool,
    has_testsuite: bool,
    has_canister: bool,
    build_script: bool,
    protobufs: Option<ProtogenConfig>,
}

struct ProtogenConfig {
    manifest_dir: String,
    generator_name: &'static str,
}

#[derive(Template)]
#[template(path = "protogen.template", escape = "none")]
struct ProtogenFile<'a> {
    crate_name: String,
    generator_name: &'a str,
    manifest_dir: std::path::Display<'a>,
}

static MACRO_CRATES: &[&str] = &[
    "async-trait",
    "derive_more",
    "dfn_macro",
    "fe-derive",
    "hex-literal",
    "ic-nervous-system-common-build-metadata",
    "paste",
    "proptest-derive",
    "strum_macros",
];

struct Bazelifier {
    opts: Options,
    rs_dir: PathBuf,
    manifest_dir_abs: PathBuf,
    manifest_dir: PathBuf,
    pkg: Crate,
    workspace_manifest: toml::Value,
}

impl Bazelifier {
    fn new() -> eyre::Result<Self> {
        let opts = Options::parse();
        let abs = std::fs::canonicalize(&opts.cargo_file)?;
        let manifest_dir = abs.parent().unwrap();

        let git_dir = String::from_utf8_lossy(
            &Command::new("git")
                .args(["rev-parse", "--show-toplevel"])
                .output()?
                .stdout,
        )
        .trim()
        .to_string();

        let rs_dir = Path::new(&git_dir).join("rs");
        let contents = std::fs::read_to_string(&abs)?;
        let pkg = toml::from_str::<Crate>(&contents)?;
        let manifest_dir_relative = pathdiff::diff_paths(manifest_dir, &rs_dir).unwrap();
        let workspace_manifest = match opts.workspace.clone() {
            Some(val) => Path::new(&val).canonicalize()?,
            None => Path::new(&git_dir).join("Cargo.toml"),
        };

        let mut toml_string = String::new();
        File::open(workspace_manifest)?.read_to_string(&mut toml_string)?;
        let workspace_manifest = toml::de::from_str(&toml_string)?;

        Ok(Self {
            opts,
            manifest_dir_abs: manifest_dir.into(),
            manifest_dir: manifest_dir_relative,
            rs_dir,
            pkg,
            workspace_manifest,
        })
    }

    fn process_deps(
        &self,
        deps_iter: btree_map::Iter<String, Dep>,
        deps: &mut Deps,
        mut macro_deps: Option<&mut Deps>,
        aliases: &mut BTreeMap<String, String>,
    ) -> eyre::Result<()> {
        for (dep_name_, dep) in deps_iter {
            let over = overrides::dep_name_override(dep_name_, dep).unwrap_or(NameOverride {
                name: dep_name_.into(),
                repo: None,
            });
            let dep_name = over.name;
            let repo = over.repo.unwrap_or("crate_index");

            let dep_text = match dep {
                Dep::VersionExtra(NormalDep {
                    package: Some(alias),
                    ..
                }) => {
                    aliases.insert(format!("@{repo}//:{alias}"), dep_name.to_string());
                    format!("@{repo}//:{alias}")
                }
                Dep::Version { .. } | Dep::VersionExtra { .. } | Dep::Git { .. } => {
                    let colon = if dep_name.contains(':') { "" } else { ":" };
                    format!("@{repo}//{colon}{dep_name}")
                }
                Dep::Local(LocalDep { path }) => format!(
                    "//rs/{}",
                    pathdiff::diff_paths(
                        self.manifest_dir_abs.join(path).canonicalize()?,
                        &self.rs_dir
                    )
                    .unwrap()
                    .display()
                ),
                Dep::Workspace(val) => {
                    if !val.workspace {
                        eprintln!("Only workspace = true is supported");
                        std::process::exit(1)
                    }

                    format!("@{repo}//:{dep_name}")
                }
            };
            if let Some(ref mut mdeps) = macro_deps {
                if MACRO_CRATES.contains(&&*dep_name) {
                    mdeps.insert(dep_text);
                    continue;
                }
            }
            deps.insert(dep_text);
        }
        Ok(())
    }

    fn generate_tests(&self, bf: &mut BuildFile) -> eyre::Result<()> {
        bf.has_testsuite = self.manifest_dir_abs.join("tests").is_dir();

        self.process_deps(
            self.pkg.dev_dependencies.iter(),
            &mut bf.dev_deps,
            Some(&mut bf.macro_dev_deps),
            &mut bf.aliases,
        )?;

        bf.dev_deps = bf.dev_deps.difference(&bf.deps).cloned().collect();
        bf.macro_dev_deps = bf
            .macro_dev_deps
            .difference(&bf.macro_deps)
            .cloned()
            .collect();

        Ok(())
    }

    fn gen_proto_gen(&mut self, generator_name: &str) -> eyre::Result<()> {
        let dir = self.manifest_dir_abs.join(generator_name);

        let protogen_pkg_contents = std::fs::read_to_string(dir.join("Cargo.toml"))?;
        let protogen_pkg = toml::from_str::<Crate>(&protogen_pkg_contents)?;

        let crate_name = protogen_pkg.package.name.replace('-', "_");
        let manifest_dir = self.manifest_dir.join(generator_name);

        let protogen_build_file = ProtogenFile {
            crate_name,
            generator_name,
            manifest_dir: manifest_dir.display(),
        };

        let protogen_build_path = dir.join("BUILD.bazel");

        if self.opts.dry_run {
            println!("Additional BUILD.bazel generated for {}:", dir.display());
            std::io::stdout().write_all(protogen_build_file.render()?.as_bytes())?;
            println!();
        } else {
            std::fs::File::create(&protogen_build_path)?
                .write_all(protogen_build_file.render()?.as_bytes())?;
            println!("Created {}", protogen_build_path.display());
        }

        Ok(())
    }

    fn run(mut self) -> eyre::Result<()> {
        let buildfile_path = self.manifest_dir_abs.join("BUILD.bazel");
        if !self.opts.dry_run && !self.opts.force && buildfile_path.exists() {
            eprintln!(
                "{} already exists, refusing to overwrite it",
                buildfile_path.display()
            );
            std::process::exit(1);
        }

        if !self.pkg.target.is_empty() {
            eprintln!("WARNING: Cargo.toml has a target-specific dependencies section. Please add those dependencies manually to BUILD.bazel.");
        }

        let mut protobufs = None;

        for protogen in ["proto_generator", "protobuf_generator"] {
            let pdir = self.manifest_dir_abs.join(protogen);
            if pdir.is_dir() {
                protobufs = Some(ProtogenConfig {
                    manifest_dir: self.manifest_dir.display().to_string(),
                    generator_name: protogen,
                });
                self.gen_proto_gen(protogen)?;
                break;
            }
        }

        let lib_build_type = if self.pkg.lib.as_ref().map_or(false, |x| x.proc_macro) {
            BuildType::ProcMacro
        } else {
            BuildType::Lib
        };
        let mut bins = vec![];
        let mut has_canister = false;
        for b in self.pkg.bin.drain(..) {
            let bout = BinSectionOut {
                canister: b.name.ends_with("canister"),
                name: b.name,
                path: b.path,
            };
            has_canister = has_canister || bout.canister;
            bins.push(bout);
        }
        let mut bf = BuildFile {
            edition: match &self.pkg.package.edition {
                PackageProperty::Simple(s) => s,
                PackageProperty::Complex(v) => {
                    match v.get("workspace").unwrap_or(&Value::Boolean(false)) {
                        Value::Boolean(true) => self.workspace_manifest["workspace"]["package"]
                            ["edition"]
                            .as_str()
                            .unwrap(),
                        _ => {
                            eprintln!("Only edition.workspace = true and edition = \"<edition>\" are supported");
                            std::process::exit(1)
                        }
                    }
                }
            },
            crate_version: match &self.pkg.package.version {
                PackageProperty::Simple(s) => s,
                PackageProperty::Complex(v) => {
                    match v.get("workspace").unwrap_or(&Value::Boolean(false)) {
                        Value::Boolean(true) => self.workspace_manifest["workspace"]["package"]
                            ["version"]
                            .as_str()
                            .unwrap(),
                        _ => {
                            eprintln!("Only package.workspace = true and package = \"<package>\" are supported");
                            std::process::exit(1)
                        }
                    }
                }
            },
            build_type: lib_build_type,
            target_name: self.manifest_dir_abs.file_name().unwrap().to_string_lossy(),
            crate_name: self
                .pkg
                .lib
                .as_ref()
                .and_then(|x| x.name_override.as_ref())
                .map_or_else(|| self.pkg.package.name.replace('-', "_"), |x| x.clone()),
            gen_tests: self.opts.gen_tests,
            bins,
            has_canister,
            protobufs,
            ..Default::default()
        };

        self.process_deps(
            self.pkg.dependencies.iter(),
            &mut bf.deps,
            Some(&mut bf.macro_deps),
            &mut bf.aliases,
        )?;

        self.process_deps(
            self.pkg.build_dependencies.iter(),
            &mut bf.build_deps,
            None,
            &mut bf.aliases,
        )?;

        if self.opts.gen_tests {
            self.generate_tests(&mut bf)?;
        }

        bf.build_script = self.manifest_dir_abs.join("build.rs").is_file();

        if self.opts.dry_run {
            std::io::stdout().write_all(bf.render()?.as_bytes())?;
        } else {
            std::fs::File::create(&buildfile_path)?.write_all(bf.render()?.as_bytes())?;

            println!("Created {}", buildfile_path.display());
        }

        Ok(())
    }
}

fn main() -> eyre::Result<()> {
    if let Some(wd) = std::env::var_os("BUILD_WORKING_DIRECTORY") {
        std::env::set_current_dir(wd)?;
    }

    let bzl = Bazelifier::new()?;
    bzl.run()
}
