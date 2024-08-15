use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

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

#[derive(Debug)]
pub struct Manifest {
    pub manifest: Vec<Entry>,
}

impl Manifest {
    pub fn new() -> Self {
        Manifest {
            manifest: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, component: Entry) {
        self.manifest.push(component);
    }
}

#[derive(Debug)]
pub struct Entry {
    pub source: PathBuf,
    pub destination: PathBuf,
}

impl Entry {
    pub fn new(source: PathBuf, destination: PathBuf) -> Self {
        Entry {
            source,
            destination,
        }
    }
}

fn get_manifest(manifest_path: &Path, components_path: &Path) -> Result<Manifest> {
    let manifest_contents = fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read file: {:?}", manifest_path))?;

    let re = Regex::new(r#"Label\("(.+?)"\): "(.+?)""#)?;

    let mut manifest = Manifest::new();

    for cap in re.captures_iter(&manifest_contents) {
        let source = components_path.join(&cap[1]);
        let destination = PathBuf::from(&cap[2]);
        manifest.add_entry(Entry::new(source, destination));
    }

    Ok(manifest)
}

pub fn get_icos_manifest(repo_root: &PathBuf) -> Result<IcosManifest> {
    let components_path = repo_root.join("ic-os/components/");
    let guestos_manifest_path = components_path.join("guestos.bzl");
    let hostos_manifest_path = components_path.join("hostos.bzl");
    let setupos_manifest_path = components_path.join("setupos.bzl");
    let boundary_guestos_manifest_path = components_path.join("boundary-guestos.bzl");

    let guestos_manifest = get_manifest(&guestos_manifest_path, &components_path)?;
    let hostos_manifest = get_manifest(&hostos_manifest_path, &components_path)?;
    let setupos_manifest = get_manifest(&setupos_manifest_path, &components_path)?;
    let boundary_guestos_manifest = get_manifest(&boundary_guestos_manifest_path, &components_path)?;

    Ok(IcosManifest::new(
        guestos_manifest,
        hostos_manifest,
        setupos_manifest,
        boundary_guestos_manifest,
    ))
}
