use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct IcosComponents {
    pub setupos: IcosVariant,
    pub hostos: IcosVariant,
    pub guestos: IcosVariant,
    pub boundary_guestos: IcosVariant,
}

impl IcosComponents {
    pub fn new(
        guestos_components: IcosVariant,
        hostos_components: IcosVariant,
        setupos_components: IcosVariant,
        boundary_guestos_components: IcosVariant,
    ) -> Self {
        IcosComponents {
            guestos: guestos_components,
            hostos: hostos_components,
            setupos: setupos_components,
            boundary_guestos: boundary_guestos_components,
        }
    }
}

#[derive(Debug)]
pub struct IcosVariant {
    pub components: Vec<Component>,
}

impl IcosVariant {
    pub fn new() -> Self {
        IcosVariant {
            components: Vec::new(),
        }
    }

    pub fn add_component(&mut self, component: Component) {
        self.components.push(component);
    }
}

#[derive(Debug)]
pub struct Component {
    pub source: PathBuf,
    pub destination: PathBuf,
}

impl Component {
    pub fn new(source: PathBuf, destination: PathBuf) -> Self {
        Component {
            source,
            destination,
        }
    }
}

pub fn get_components(file_path: &Path) -> Result<IcosVariant> {
    let content = fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read file: {:?}", file_path))?;

    let re = Regex::new(r#"Label\("(.+?)"\): "(.+?)""#)?;

    let mut components = IcosVariant::new();

    for cap in re.captures_iter(&content) {
        let source = PathBuf::from(&cap[1]);
        let destination = PathBuf::from(&cap[2]);
        components.add_component(Component::new(source, destination));
    }

    Ok(components)
}

pub fn get_icos_components(repo_root: &PathBuf) -> Result<IcosComponents> {
    let guestos_path = repo_root.join("ic-os/components/guestos.bzl");
    let hostos_path = repo_root.join("ic-os/components/hostos.bzl");
    let setupos_path = repo_root.join("ic-os/components/setupos.bzl");
    let boundary_guestos_path = repo_root.join("ic-os/components/boundary-guestos.bzl");

    let guestos_components = get_components(&guestos_path)?;
    let hostos_components = get_components(&hostos_path)?;
    let setupos_components = get_components(&setupos_path)?;
    let boundary_guestos_components = get_components(&boundary_guestos_path)?;

    Ok(IcosComponents::new(
        guestos_components,
        hostos_components,
        setupos_components,
        boundary_guestos_components,
    ))
}
