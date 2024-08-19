use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

pub const COMPONENTS_PATH: &str = "ic-os/components";

#[derive(Debug)]
pub struct IcosManifest {
    pub setupos: Manifest,
    pub hostos: Manifest,
    pub guestos: Manifest,
    pub boundary_guestos: Manifest,
}

impl IcosManifest {
    pub fn new(
        guestos_components: Manifest,
        hostos_components: Manifest,
        setupos_components: Manifest,
        boundary_guestos_components: Manifest,
    ) -> Self {
        IcosManifest {
            guestos: guestos_components,
            hostos: hostos_components,
            setupos: setupos_components,
            boundary_guestos: boundary_guestos_components,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub manifest: Vec<ManifestEntry>,
}

impl Manifest {
    pub fn new() -> Self {
        Manifest {
            manifest: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, component: ManifestEntry) {
        self.manifest.push(component);
    }
}

#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub source: PathBuf,
    #[allow(dead_code)]
    pub destination: PathBuf,
}

impl ManifestEntry {
    pub fn new(source: PathBuf, destination: PathBuf) -> Self {
        ManifestEntry {
            source,
            destination,
        }
    }
}

fn parse_manifest(manifest_contents: &str, components_path: &Path) -> Result<Manifest> {
    let re = Regex::new(r#"Label\("(.+?)"\): "(.+?)""#)?;
    let mut manifest = Manifest::new();

    for cap in re.captures_iter(manifest_contents) {
        let source = components_path.join(&cap[1]);
        let destination = PathBuf::from(&cap[2]);
        manifest.add_entry(ManifestEntry::new(source, destination));
    }

    Ok(manifest)
}

fn get_manifest(manifest_path: &Path, components_path: &Path) -> Result<Manifest> {
    let manifest_contents = fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read file: {:?}", manifest_path))?;

    parse_manifest(&manifest_contents, components_path)
}

pub fn get_icos_manifest(repo_root: &Path) -> Result<IcosManifest> {
    let components_path = repo_root.join(COMPONENTS_PATH);
    let guestos_manifest_path = components_path.join("guestos.bzl");
    let hostos_manifest_path = components_path.join("hostos.bzl");
    let setupos_manifest_path = components_path.join("setupos.bzl");
    let boundary_guestos_manifest_path = components_path.join("boundary-guestos.bzl");

    let guestos_manifest = get_manifest(&guestos_manifest_path, &components_path)?;
    let hostos_manifest = get_manifest(&hostos_manifest_path, &components_path)?;
    let setupos_manifest = get_manifest(&setupos_manifest_path, &components_path)?;
    let boundary_guestos_manifest =
        get_manifest(&boundary_guestos_manifest_path, &components_path)?;

    Ok(IcosManifest::new(
        guestos_manifest,
        hostos_manifest,
        setupos_manifest,
        boundary_guestos_manifest,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_get_manifest() {
        let dir = tempdir().unwrap();
        let manifest_path = dir.path().join("test.bzl");
        let components_path = dir.path().join("components");

        fs::create_dir(&components_path).unwrap();

        let mut file = File::create(&manifest_path).unwrap();
        writeln!(file, r#"Label("src/lib.rs"): "lib.rs""#).unwrap();

        let manifest = get_manifest(&manifest_path, &components_path).unwrap();
        let entry = &manifest.manifest[0];

        assert_eq!(entry.source, components_path.join("src/lib.rs"));
        assert_eq!(entry.destination, PathBuf::from("lib.rs"));
    }
}
