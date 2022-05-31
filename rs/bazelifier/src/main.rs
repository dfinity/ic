// unused struct fields are needed for serde to get the names right
#![allow(dead_code)]

use std::{collections::BTreeMap, fmt::Display, io::Write, path::Path, process::Command};

use askama::Template;
use clap::Parser;
use serde::Deserialize;

#[derive(Parser, Debug)]
struct Options {
    /// Overwrite any existing BUILD file
    #[clap(short, long)]
    force: bool,
    /// Cargo.toml file to convert
    cargo_file: String,
}

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

#[derive(Deserialize, Debug)]
struct Crate {
    package: Package,
    #[serde(default)]
    lib: Option<LibSection>,
    #[serde(default)]
    dependencies: BTreeMap<String, Dep>,
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
    version: String,
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
    version: String,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    package: Option<String>,
}

#[derive(Deserialize, Debug)]
struct LocalDep {
    path: String,
}

#[derive(Deserialize, Debug)]
struct GitDep {
    git: String,
    branch: Option<String>,
    rev: Option<String>,
    tag: Option<String>,
}

#[derive(Template)]
#[template(path = "buildfile.template", escape = "none")]
struct Buildfile<'a> {
    build_type: BuildType,
    target_name: &'a str,
    crate_name: &'a str,
    edition: &'a str,
    deps: Vec<String>,
    macro_deps: Vec<String>,
    aliases: BTreeMap<String, String>,
}

static MACRO_CRATES: &[&str] = &[
    "async-trait",
    "derive_more",
    "fe-derive",
    "paste",
    "proptest-derive",
    "slog_derive",
    "strum_macros",
];

fn main() -> eyre::Result<()> {
    let Options {
        force,
        cargo_file: tomlfile,
    } = Options::parse();

    // if running with bazel run, move to the requested cwd
    if let Some(wd) = std::env::var_os("BUILD_WORKING_DIRECTORY") {
        std::env::set_current_dir(wd)?;
    }

    let abs = std::fs::canonicalize(&tomlfile)?;
    let manifest_dir = abs.parent().unwrap();
    let buildfile_path = manifest_dir.join("BUILD.bazel");
    if !force && buildfile_path.exists() {
        eprintln!(
            "{} already exists, refusing to overwrite it",
            buildfile_path.display()
        );
        std::process::exit(1);
    }
    let contents = std::fs::read_to_string(&abs)?;
    let pkg = toml::from_str::<Crate>(&contents)?;

    if !pkg.target.is_empty() {
        eprintln!("WARNING: Cargo.toml has a target-specific dependencies section. Please double check the generated BUILD.bazel file before committing");
    }

    let git_dir = String::from_utf8_lossy(
        &Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()?
            .stdout,
    )
    .trim()
    .to_string();

    let rs_dir = Path::new(&git_dir).join("rs");

    let target_name = manifest_dir.file_name().unwrap().to_string_lossy();
    let crate_name = pkg.package.name.replace('-', "_");

    let mut deps = vec![];
    let mut macro_deps = vec![];
    let mut aliases = BTreeMap::new();
    let build_type = if pkg.lib.map_or(false, |x| x.proc_macro) {
        BuildType::ProcMacro
    } else {
        BuildType::Lib
    };

    for (dep_name, dep) in pkg.dependencies {
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
                pathdiff::diff_paths(manifest_dir.join(path).canonicalize()?, &rs_dir)
                    .unwrap()
                    .display()
            ),
        };
        if MACRO_CRATES.contains(&&*dep_name) {
            macro_deps.push(dep_text);
        } else {
            deps.push(dep_text);
        }
    }

    let buildfile = Buildfile {
        build_type,
        target_name: &*target_name,
        crate_name: &crate_name,
        edition: &pkg.package.edition,
        deps,
        macro_deps,
        aliases,
    };

    std::fs::File::create(&buildfile_path)?.write_all(buildfile.render()?.as_bytes())?;

    println!("Created {}", buildfile_path.display());

    Ok(())
}
