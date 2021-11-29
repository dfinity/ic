use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cargo::core::{dependency::Kind as DependencyKind, Package, PackageId, SourceId};
use serde::Serialize;

use crate::manifest::TomlProfile;
use crate::{platform, BoolExpr, Feature as FeatureStr, Optionality, ResolvedPackage, Result};

#[derive(Debug, Serialize)]
pub struct BuildPlan {
    pub cargo2nix_version: String,
    pub root_features: Vec<String>,
    pub profiles: BTreeMap<String, String>,
    pub workspace_members: Vec<Member>,
    pub crates: Vec<Crate>,
}

impl BuildPlan {
    pub fn from_items(
        root_pkgs: Vec<&'_ Package>,
        profiles: TomlProfile,
        rpkgs_by_id: BTreeMap<PackageId, ResolvedPackage<'_>>,
        cwd: &Path,
    ) -> Result<Self> {
        let root_features = root_pkgs
            .iter()
            .map(|pkg| format!("{}/default", pkg.name()))
            .collect();

        let profiles = profiles
            .into_iter()
            .map(|(name, profile)| (name, toml::to_string(&profile).unwrap()))
            .map(|(name, toml)| (name, toml.replace("${", "\\${").escape_debug().to_string()))
            .collect();

        let workspace_members = root_pkgs
            .into_iter()
            .map(|pkg| Member {
                name: pkg.name().to_string(),
                version: pkg.version().to_string(),
            })
            .collect();

        let crates = rpkgs_by_id
            .into_iter()
            .map(|(pkg_id, resolved_pkg)| {
                let (deps, dev_deps, build_deps) = to_dependencies(&resolved_pkg);
                Ok(Crate {
                    name: pkg_id.name().to_string(),
                    version: pkg_id.version().to_string(),
                    registry: to_registry_string(pkg_id.source_id()),
                    source: to_source(&resolved_pkg, cwd)?,
                    features: to_features(&resolved_pkg.features),
                    dependencies: deps,
                    dev_dependencies: dev_deps,
                    build_dependencies: build_deps,
                })
            })
            .collect::<Result<_>>()?;

        Ok(BuildPlan {
            cargo2nix_version: env!("CARGO_PKG_VERSION").to_string(),
            root_features,
            profiles,
            workspace_members,
            crates,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Member {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct Crate {
    pub name: String,
    pub version: String,
    pub registry: String,
    pub source: Source,
    pub features: Vec<Feature>,
    pub dependencies: Vec<Dependency>,
    pub dev_dependencies: Vec<Dependency>,
    pub build_dependencies: Vec<Dependency>,
}

#[derive(Debug, Serialize)]
pub enum Source {
    CratesIo { sha256: String },
    Git { url: String, rev: String },
    Local { path: PathBuf },
    Registry { index: String, sha256: String },
}

#[derive(Debug, Serialize)]
pub struct Feature {
    pub name: String,
    pub activated_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Dependency {
    pub name: String,
    pub extern_name: String,
    pub version: String,
    pub registry: String,
    pub cfg_condition: Option<String>,
    pub is_proc_macro: bool,
}

fn to_registry_string(src_id: SourceId) -> String {
    if src_id.is_path() {
        "file://local-registry".to_string()
    } else if src_id.is_git() {
        format!("git+{}", src_id.url())
    } else {
        src_id.into_url().to_string()
    }
}

fn to_source(pkg: &ResolvedPackage<'_>, cwd: &Path) -> Result<Source> {
    let id = pkg.pkg.package_id();

    let source = if id.source_id().is_default_registry() {
        Source::CratesIo {
            sha256: pkg
                .checksum
                .as_ref()
                .map(|c| c.to_string())
                .ok_or_else(|| {
                    failure::format_err!("checksum is required for crates.io package {}", id)
                })?,
        }
    } else if id.source_id().is_git() {
        Source::Git {
            url: id.source_id().url().to_string(),
            rev: id
                .source_id()
                .precise()
                .map(|p| p.to_string())
                .ok_or_else(|| {
                    failure::format_err!("precise ref not found for git package {}", id)
                })?,
        }
    } else if id.source_id().is_path() {
        Source::Local {
            path: pathdiff::diff_paths(Path::new(id.source_id().url().path()), cwd)
                .map(|p| p.join("."))
                .ok_or_else(|| {
                    failure::format_err!("path is not absolute for local package {}", id)
                })?,
        }
    } else if id.source_id().is_registry() {
        Source::Registry {
            index: id.source_id().url().to_string(),
            sha256: pkg
                .checksum
                .as_ref()
                .map(|c| c.to_string())
                .ok_or_else(|| {
                    failure::format_err!(
                        "checksum is required for alternate registry package {}",
                        id
                    )
                })?,
        }
    } else {
        return Err(failure::format_err!("unsupported source for {}", id));
    };

    Ok(source)
}

fn to_features(features: &BTreeMap<FeatureStr<'_>, Optionality<'_>>) -> Vec<Feature> {
    features
        .iter()
        .map(
            |(name, optionality)| match optionality.to_expr("rootFeatures'").simplify() {
                BoolExpr::True => Feature {
                    name: name.to_string(),
                    activated_by: None,
                },
                expr => Feature {
                    name: name.to_string(),
                    activated_by: Some(expr.to_nix().to_string()),
                },
            },
        )
        .collect()
}

fn to_dependencies(
    pkg: &ResolvedPackage<'_>,
) -> (Vec<Dependency>, Vec<Dependency>, Vec<Dependency>) {
    let mut dependencies = Vec::new();
    let mut dev_dependencies = Vec::new();
    let mut build_dependencies = Vec::new();

    for ((pkg_id, kind), dep) in &pkg.deps {
        let platforms = match dep.platforms {
            None => BoolExpr::True,
            Some(ref platforms) => BoolExpr::ors(
                platforms
                    .iter()
                    .map(|p| platform::to_expr(p, "hostPlatform")),
            ),
        };

        let cfg_condition = match dep
            .optionality
            .to_expr("rootFeatures'")
            .and(platforms)
            .simplify()
        {
            BoolExpr::True => None,
            expr => Some(expr.to_nix().to_string()),
        };

        let dep = Dependency {
            name: pkg_id.name().to_string(),
            extern_name: dep.extern_name.to_string(),
            version: pkg_id.version().to_string(),
            registry: to_registry_string(pkg_id.source_id()),
            cfg_condition,
            is_proc_macro: crate::is_proc_macro(&dep.pkg),
        };

        match kind {
            DependencyKind::Normal => dependencies.push(dep),
            DependencyKind::Development => dev_dependencies.push(dep),
            DependencyKind::Build => build_dependencies.push(dep),
        }
    }

    (dependencies, dev_dependencies, build_dependencies)
}
