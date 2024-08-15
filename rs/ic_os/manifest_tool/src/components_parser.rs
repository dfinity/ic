use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct IcosComponents {
    pub setupos: Components,
    pub hostos: Components,
    pub guestos: Components,
    pub boundary_guestos: Components,
}

impl IcosComponents {
    pub fn new(
        guestos_components: Components,
        hostos_components: Components,
        setupos_components: Components,
        boundary_guestos_components: Components,
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
pub struct Components {
    pub components: Vec<Component>,
}

impl Components {
    pub fn new() -> Self {
        Components {
            components: Vec::new(),
        }
    }

    pub fn add_component(&mut self, component: Component) {
        self.components.push(component);
    }
}

#[derive(Debug)]
pub struct Component {
    pub source: String,
    pub destination: String,
}

impl Component {
    pub fn new(source: &str, destination: &str) -> Self {
        Component {
            source: source.to_string(),
            destination: destination.to_string(),
        }
    }
}

pub fn get_components_from_bzl(file_path: &Path) -> Result<Components> {
    let content = fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read file: {:?}", file_path))?;

    // Regular expression to capture the key and value in the component_files dictionary
    let re = Regex::new(r#"Label\("(.+?)"\): "(.+?)""#)?;

    let mut components = Components::new();

    for cap in re.captures_iter(&content) {
        let source = &cap[1];
        let destination = &cap[2];
        components.add_component(Component::new(source, destination));
    }

    Ok(components)
}

pub fn get_all_components() -> Result<IcosComponents> {
    //TODO: help: fix file paths
    let guestos_path = Path::new("../../../ic-os/components/guestos.bzl");
    let hostos_path = Path::new("../../../ic-os/components/hostos.bzl");
    let setupos_path = Path::new("../../../ic-os/components/setupos.bzl");
    let boundary_guestos_path = Path::new("../../../ic-os/components/boundary-guestos.bzl");

    let guestos_components = get_components_from_bzl(guestos_path)?;
    let hostos_components = get_components_from_bzl(hostos_path)?;
    let setupos_components = get_components_from_bzl(setupos_path)?;
    let boundary_guestos_components = get_components_from_bzl(boundary_guestos_path)?;

    Ok(IcosComponents::new(
        guestos_components,
        hostos_components,
        setupos_components,
        boundary_guestos_components,
    ))
}
