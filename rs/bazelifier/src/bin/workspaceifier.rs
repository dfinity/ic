use std::{
    collections::{btree_map, BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    process::Command,
    sync::Mutex,
};

use askama::Template;
use clap::Parser;
use eyre::{bail, ensure, Context, Result};
use lazy_static::lazy_static;
use semver::VersionReq;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct BigFile {
    workspace: Workspace,
}

#[derive(Deserialize, Debug)]
struct Workspace {
    members: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct Crate {
    #[serde(default)]
    dependencies: BTreeMap<String, TomlDep>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, TomlDep>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: BTreeMap<String, TomlDep>,
    #[serde(default)]
    target: BTreeMap<String, Crate>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum TomlDep {
    Version(VersionReq),
    VersionExtra(NormalDep),
    Local(LocalDep),
    Git(GitDep),
}

impl TomlDep {
    fn as_dep(&self) -> Option<&NormalDep> {
        match self {
            Self::VersionExtra(n) => Some(n),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug)]
struct NormalDep {
    version: VersionReq,
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default = "t", rename = "default-features")]
    default_features: bool,
}

fn t() -> bool {
    true
}

#[derive(Deserialize, Debug)]
struct LocalDep {
    #[serde(rename = "path")]
    _path: String,
}

#[derive(Deserialize, Debug, Hash, PartialEq, Eq, Clone)]
struct GitDep {
    git: String,
    #[serde(default)]
    rev: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    branch: String,
}

#[derive(Debug)]
struct CrateSpec {
    name: String,
    features: BTreeSet<String>,
    default_features: bool,
    version: SpecVers,
}

#[derive(Debug, PartialEq, Eq)]
enum SpecVers {
    Version(SpecVersion),
    Git(SpecGit),
}

#[derive(Debug, PartialEq, Eq)]
struct SpecVersion {
    version: VersionReq,
}

#[derive(Debug, PartialEq, Eq)]
struct SpecGit {
    git: String,
    rev: String,
}

#[derive(Parser, Debug)]
struct Opts {
    cargo_file: PathBuf,
}

#[derive(Template)]
#[template(path = "workspace.template", escape = "none")]
struct WorkspaceBzl {
    crates: BTreeMap<String, CrateSpec>,
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    let cargo_file = opts.cargo_file.canonicalize()?;
    let manifest_dir = cargo_file.parent().unwrap();
    let contents = std::fs::read_to_string(&cargo_file)?;
    let pkg = toml::from_str::<BigFile>(&contents)?;

    let mut all_deps: BTreeMap<String, CrateSpec> = BTreeMap::new();

    for crt in pkg.workspace.members {
        let crtfile = std::fs::read_to_string(manifest_dir.join(&crt).join("Cargo.toml"))?;
        let crt_desc = toml::from_str::<Crate>(&crtfile).with_context(|| crtfile)?;
        process_deps(crt_desc.dependencies.iter(), &mut all_deps)?;
        process_deps(crt_desc.dev_dependencies.iter(), &mut all_deps)?;
        process_deps(crt_desc.build_dependencies.iter(), &mut all_deps)?;
        for target_spec in crt_desc.target.values() {
            process_deps(target_spec.dependencies.iter(), &mut all_deps)?;
            process_deps(target_spec.dev_dependencies.iter(), &mut all_deps)?;
            process_deps(target_spec.build_dependencies.iter(), &mut all_deps)?;
        }
    }

    println!("{}", WorkspaceBzl { crates: all_deps }.render()?);

    Ok(())
}

fn process_deps(
    deps: btree_map::Iter<String, TomlDep>,
    all_deps: &mut BTreeMap<String, CrateSpec>,
) -> Result<()> {
    for (kname, kval) in deps {
        let vers = match kval {
            TomlDep::Local { .. } => continue,
            TomlDep::Git(g) => SpecVers::Git(SpecGit {
                git: g.git.clone(),
                rev: find_ref(g)?,
            }),
            TomlDep::Version(s) => SpecVers::Version(SpecVersion { version: s.clone() }),
            TomlDep::VersionExtra(v) => SpecVers::Version(SpecVersion {
                version: v.version.clone(),
            }),
        };

        let mut csp = CrateSpec {
            name: kval
                .as_dep()
                .and_then(|x| x.package.clone())
                .unwrap_or_else(|| kname.clone()),
            features: kval
                .as_dep()
                .map_or_else(BTreeSet::new, |d| d.features.iter().cloned().collect()),
            default_features: kval.as_dep().map_or(true, |x| x.default_features),
            version: vers,
        };
        if let Some(mut spec) = all_deps.remove(&csp.name) {
            csp.features.append(&mut spec.features);
            csp.default_features = csp.default_features || spec.default_features;
            use self::SpecVers::*;
            match (&csp.version, &spec.version) {
                // ideally, we would warn if there are two conflicting requirements listed in the cargo file,
                // like rand ^0.7.1 and rand ^0.8.3. unfortunately, there's no easy way to figure out if one requirement
                // is a superset of another, and if we try to combine them into one big intersected requirement
                // using semver's comma operator, it will complain "excessive number of version comparators".
                // for now, just use the first one. the generated file will require manual review anyway so
                // it's not the end of the world
                (Version(..), Version(..)) => {
                    // do nothing
                }
                (Git(s1), Git(s2)) => ensure!(
                    s1 == s2,
                    "mismatched git dependencies for {}: {}#{} != {}#{}",
                    csp.name,
                    s1.git,
                    s1.rev,
                    s2.git,
                    s2.rev
                ),
                (_, _) => bail!("{} has one git source and one crates.io source", csp.name),
            };
        }
        all_deps.insert(csp.name.clone(), csp);
    }

    Ok(())
}

fn find_ref(g: &GitDep) -> Result<String> {
    lazy_static! {
        static ref REF_CACHE: Mutex<HashMap<GitDep, String>> = Mutex::new(HashMap::new());
    }

    fn find_ref_impl(g: &GitDep) -> Result<String> {
        if g.rev.len() == 40 && g.rev.chars().all(|x| x.is_ascii_hexdigit()) {
            Ok(g.rev.clone())
        } else {
            let search_for = if !g.rev.is_empty() {
                &g.rev
            } else if !g.tag.is_empty() {
                &g.tag
            } else if !g.branch.is_empty() {
                &g.branch
            } else {
                bail!("git dependency with no information: {:?}", g)
            };
            Ok(String::from_utf8_lossy(
                &Command::new("git")
                    .args(["ls-remote", &g.git, search_for])
                    .output()?
                    .stdout,
            )
            .split_once('\t')
            .ok_or_else(|| eyre::eyre!("malformed output from git ls-remote"))?
            .0
            .to_string())
        }
    }

    let mut cache = REF_CACHE.lock().unwrap();
    if let Some(r) = cache.get(g) {
        Ok(r.clone())
    } else {
        let r = find_ref_impl(g)?;
        cache.insert(g.clone(), r.clone());
        Ok(r)
    }
}

#[test]
fn test_find_ref() {
    assert_eq!(
        find_ref(&GitDep {
            git: "https://github.com/dfinity-lab/wabt-rs".into(),
            rev: "".into(),
            tag: "0.10.0-dfinity".into(),
            branch: "".into(),
        })
        .unwrap(),
        "7ab9062ddc63067843b62af8ae2cb83bf4bf601e"
    )
}
