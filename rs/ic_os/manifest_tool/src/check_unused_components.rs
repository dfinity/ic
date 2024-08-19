use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::components_parser::{get_icos_manifest, IcosManifest, COMPONENTS_PATH};

const IGNORED_COMPONENT_FILES: &[&str] = &[
    "components/networking/dev-certs/root_cert_gen.sh",
    "components/networking/dev-certs/canister_http_test_ca.key",
];

pub fn check_unused_components(repo_root: &Path) -> Result<()> {
    let icos_manifest = get_icos_manifest(repo_root)?;

    let components_path: PathBuf = repo_root.join(COMPONENTS_PATH);

    let repo_files: HashSet<PathBuf> = collect_repo_files(&components_path)?;
    let filtered_repo_files = filter_ignored_files(repo_files);
    let manifest_files: HashSet<PathBuf> = collect_manifest_files(&icos_manifest);

    let unused_files: Vec<&PathBuf> = filtered_repo_files.difference(&manifest_files).collect();

    if unused_files.is_empty() {
        println!("No unused files found.");
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Unused files found:\n{}",
            unused_files
                .iter()
                .map(|unused_file| unused_file.display().to_string())
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}

fn collect_repo_files(dir: &Path) -> Result<HashSet<PathBuf>, std::io::Error> {
    let mut files = HashSet::new();

    for entry in WalkDir::new(dir) {
        let entry = entry?;
        let path = entry.path().to_path_buf();

        if path.is_file() {
            files.insert(path);
        }
    }

    Ok(files)
}

fn filter_ignored_files(files: HashSet<PathBuf>) -> HashSet<PathBuf> {
    files
        .into_iter()
        .filter(|path| {
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();

            if file_name.ends_with(".bzl") || file_name.ends_with(".bazel") {
                return false;
            }
            if file_name.to_lowercase().starts_with("readme.") {
                return false;
            }
            if IGNORED_COMPONENT_FILES
                .iter()
                .any(|&ignored_file_path| path.to_string_lossy().ends_with(ignored_file_path))
            {
                return false;
            }

            true
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components_parser::{Manifest, ManifestEntry};
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_collect_repo_files_and_filter() {
        let dir = tempdir().unwrap();
        let file1 = dir.path().join("file1.txt");
        let file2 = dir.path().join("file2.bzl");
        let file3 = dir.path().join("README.md");

        File::create(&file1).unwrap();
        File::create(&file2).unwrap();
        File::create(&file3).unwrap();

        let repo_files = collect_repo_files(dir.path()).unwrap();
        let filtered_repo_files = filter_ignored_files(repo_files);

        assert!(filtered_repo_files.contains(&file1));
        assert!(!filtered_repo_files.contains(&file2));
        assert!(!filtered_repo_files.contains(&file3));
    }

    #[test]
    fn test_collect_manifest_files() {
        let mut manifest = Manifest::new();
        manifest.add_entry(ManifestEntry::new(
            PathBuf::from("src/lib.rs"),
            PathBuf::from("lib.rs"),
        ));

        let icos_manifest = IcosManifest {
            guestos: manifest.clone(),
            hostos: manifest.clone(),
            setupos: manifest.clone(),
            boundary_guestos: manifest.clone(),
        };

        let manifest_files = collect_manifest_files(&icos_manifest);

        assert!(manifest_files.contains(&PathBuf::from("src/lib.rs")));
    }

    #[test]
    fn test_check_unused_components() {
        let repo_root: tempfile::TempDir = tempdir().unwrap();
        let components_dir = repo_root.path().join("ic-os/components");
        std::fs::create_dir_all(&components_dir).unwrap();

        let used_file = components_dir.join("used_file.rs");
        let unused_file = components_dir.join("unused_file.rs");
        File::create(&used_file).unwrap();
        File::create(&unused_file).unwrap();

        let guestos_manifest_path = components_dir.join("guestos.bzl");
        let mut guestos_manifest_file = File::create(&guestos_manifest_path).unwrap();
        writeln!(
            guestos_manifest_file,
            r#"Label("used_file.rs"): "used_file.rs""#
        )
        .unwrap();

        // must create other manifest files to avoid read error
        let hostos_manifest_path = components_dir.join("hostos.bzl");
        File::create(&hostos_manifest_path).unwrap();
        let setupos_manifest_path = components_dir.join("setupos.bzl");
        File::create(&setupos_manifest_path).unwrap();
        let boundary_guestos_manifest_path = components_dir.join("boundary-guestos.bzl");
        File::create(&boundary_guestos_manifest_path).unwrap();

        let result = check_unused_components(repo_root.path());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unused_file.rs"));
    }
}
