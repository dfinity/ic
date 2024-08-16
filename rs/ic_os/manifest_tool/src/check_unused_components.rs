use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::components_parser::{get_icos_manifest, IcosManifest, COMPONENTS_PATH};

pub fn check_unused_components(repo_root: &Path) -> Result<()> {
    let icos_manifest = get_icos_manifest(repo_root)?;

    let components_path: PathBuf = repo_root.join(COMPONENTS_PATH);

    let repo_files: HashSet<PathBuf> = collect_repo_files(&components_path)?;
    let manifest_files: HashSet<PathBuf> = collect_manifest_files(&icos_manifest);

    let unused_files: Vec<&PathBuf> = repo_files.difference(&manifest_files).collect();

    if unused_files.is_empty() {
        println!("No unused files found.");
        return Ok(())
    } else {
        return Err(anyhow::anyhow!(
            "Unused files found:\n{}",
            unused_files
                .iter()
                .map(|unused_file| unused_file.display().to_string())
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
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

    let manifests = [
        &icos_manifest.guestos.manifest,
        &icos_manifest.hostos.manifest,
        &icos_manifest.setupos.manifest,
        &icos_manifest.boundary_guestos.manifest,
    ];

    for manifest in &manifests {
        for entry in *manifest {
            manifest_files.insert(entry.source.clone());
        }
    }

    manifest_files
}
