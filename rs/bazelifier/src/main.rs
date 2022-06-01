use std::{
    borrow::Cow,
    collections::{btree_map, BTreeMap, BTreeSet},
    fmt::Display,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use askama::Template;
use clap::Parser;
use serde::Deserialize;

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
    #[serde(default)]
    target: toml::map::Map<String, toml::Value>,
}

#[derive(Deserialize, Debug)]
struct LibSection {
    #[serde(rename = "proc-macro")]
    proc_macro: bool,
}

#[derive(Deserialize, Debug)]
struct Package {
    name: String,
    edition: String,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum Dep {
    Version(String),
    VersionExtra(NormalDep),
    Local(LocalDep),
    Git(GitDep),
}

#[derive(Deserialize, Debug)]
struct NormalDep {
    #[serde(rename = "version")]
    _version: String,
    #[serde(default)]
    package: Option<String>,
}

#[derive(Deserialize, Debug)]
struct LocalDep {
    path: String,
}

#[derive(Deserialize, Debug)]
struct GitDep {
    #[serde(rename = "git")]
    _git: String,
}

#[derive(Template, Default)]
#[template(path = "buildfile.template", escape = "none")]
struct BuildFile<'a> {
    build_type: BuildType,
    deps: Deps,
    dev_deps: Deps,
    macro_deps: Deps,
    macro_dev_deps: Deps,
    aliases: BTreeMap<String, String>,
    target_name: Cow<'a, str>,
    edition: &'a str,
    crate_name: String,
    gen_tests: bool,
    integration_tests: Vec<BuildTest>,
}

struct BuildTest {
    name: String,
    filepath: String,
}

static MACRO_CRATES: &[&str] = &[
    "async-trait",
    "debug_stub_derive",
    "derive_more",
    "fe-derive",
    "hex-literal",
    "paste",
    "proptest-derive",
    "slog_derive",
    "strum_macros",
];

struct Bazelifier {
    opts: Options,
    rs_dir: PathBuf,
    manifest_dir: PathBuf,
    pkg: Crate,
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

        Ok(Self {
            opts,
            manifest_dir: manifest_dir.into(),
            rs_dir,
            pkg,
        })
    }

    fn process_deps(
        &self,
        deps_iter: btree_map::Iter<String, Dep>,
        deps: &mut Deps,
        macro_deps: &mut Deps,
        aliases: &mut BTreeMap<String, String>,
    ) -> eyre::Result<()> {
        for (dep_name, dep) in deps_iter {
            let dep_text = match dep {
                Dep::VersionExtra(NormalDep {
                    package: Some(alias),
                    ..
                }) => {
                    aliases.insert(format!("@crate_index//:{}", alias), dep_name.clone());
                    format!("@crate_index//:{}", alias)
                }
                Dep::Version { .. } | Dep::VersionExtra { .. } | Dep::Git { .. } => {
                    format!("@crate_index//:{}", dep_name)
                }
                Dep::Local(LocalDep { path }) => format!(
                    "//rs/{}",
                    pathdiff::diff_paths(
                        self.manifest_dir.join(path).canonicalize()?,
                        &self.rs_dir
                    )
                    .unwrap()
                    .display()
                ),
            };
            if MACRO_CRATES.contains(&&**dep_name) {
                macro_deps.insert(dep_text);
            } else {
                deps.insert(dep_text);
            }
        }
        Ok(())
    }

    fn generate_tests(&self, bf: &mut BuildFile) -> eyre::Result<()> {
        self.process_deps(
            self.pkg.dev_dependencies.iter(),
            &mut bf.dev_deps,
            &mut bf.macro_dev_deps,
            &mut bf.aliases,
        )?;

        bf.dev_deps = bf.dev_deps.difference(&bf.deps).cloned().collect();
        bf.macro_dev_deps = bf
            .macro_dev_deps
            .difference(&bf.macro_deps)
            .cloned()
            .collect();

        if let Ok(tests_dir) = std::fs::read_dir(self.manifest_dir.join("tests")) {
            for file in tests_dir {
                let file = file?;
                if !file.path().extension().map_or(false, |x| x == "rs") {
                    continue;
                }
                if let Some(stem) = file.path().file_stem() {
                    let stem = stem.to_string_lossy();
                    bf.integration_tests.push(BuildTest {
                        name: stem.to_string(),
                        filepath: format!("tests/{}.rs", stem),
                    });
                }
            }
        }
        Ok(())
    }

    fn run(self) -> eyre::Result<()> {
        let buildfile_path = self.manifest_dir.join("BUILD.bazel");
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

        let lib_build_type = if self.pkg.lib.as_ref().map_or(false, |x| x.proc_macro) {
            BuildType::ProcMacro
        } else {
            BuildType::Lib
        };
        let mut bf = BuildFile {
            edition: &self.pkg.package.edition,
            build_type: lib_build_type,
            target_name: self.manifest_dir.file_name().unwrap().to_string_lossy(),
            crate_name: self.pkg.package.name.replace('-', "_"),
            gen_tests: self.opts.gen_tests,
            ..Default::default()
        };

        self.process_deps(
            self.pkg.dependencies.iter(),
            &mut bf.deps,
            &mut bf.macro_deps,
            &mut bf.aliases,
        )?;

        if self.opts.gen_tests {
            self.generate_tests(&mut bf)?;
        }

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
