use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::components_parser::{get_icos_manifest, IcosManifest, COMPONENTS_PATH};

pub fn check_unused_components(repo_root: &Path) -> Result<()> {
    let icos_manifest = get_icos_manifest(repo_root)?;

    let components_path: PathBuf = repo_root.join(COMPONENTS_PATH);

    let repo_files = collect_repo_files(&components_path)?;
    let manifest_files = collect_manifest_files(&icos_manifest);

    let unused_files: Vec<&PathBuf> = repo_files.difference(&manifest_files).collect();

    if !unused_files.is_empty() {
        println!("Unused files:");
        for component in unused_files {
            println!("{}", component.display());
        }
    } else {
        println!("No unused file found.");
    }

    Ok(())
}

fn collect_repo_files(dir: &Path) -> Result<HashSet<PathBuf>, std::io::Error> {
    let mut files = HashSet::new();

    for entry in WalkDir::new(dir) {
        let entry = entry?;
        let path = entry.path().to_path_buf();

        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                if file_name.ends_with(".bzl")
                    || file_name.ends_with(".bazel")
                    || file_name.to_lowercase().starts_with("readme.")
                {
                    continue;
                }
            }
            files.insert(path);
        }
    }

    Ok(files)
}

fn collect_manifest_files(icos_manifest: &IcosManifest) -> HashSet<PathBuf> {
    let mut manifest_files: HashSet<PathBuf> = HashSet::new();

    for entry in &icos_manifest.guestos.manifest {
        manifest_files.insert(entry.source.clone());
    }
    for entry in &icos_manifest.hostos.manifest {
        manifest_files.insert(entry.source.clone());
    }
    for entry in &icos_manifest.setupos.manifest {
        manifest_files.insert(entry.source.clone());
    }
    for entry in &icos_manifest.boundary_guestos.manifest {
        manifest_files.insert(entry.source.clone());
    }

    manifest_files
}
