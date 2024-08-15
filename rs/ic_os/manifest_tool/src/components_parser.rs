use anyhow::{Context, Result};
use regex::Regex;
use std::fs;

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
    pub _source: String,
    pub _destination: String,
}

impl Component {
    pub fn new(name: String, path: String) -> Self {
        Component {
            _source: name,
            _destination: path,
        }
    }
}

pub fn get_components_from_bzl(file_path: &str) -> Result<Components> {
    let content = fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read file: {}", file_path))?;

    // Regular expression to capture the key and value in the component_files dictionary
    let re = Regex::new(r#"Label\("(.+?)"\): "(.+?)""#)?;

    let mut components = Components::new();

    for cap in re.captures_iter(&content) {
        let name = cap[1].to_string();
        let path = cap[2].to_string();
        components.add_component(Component::new(name, path));
    }

    Ok(components)
}

pub fn get_all_components() -> Result<IcosComponents> {
    //TODO: help: fix file paths
    let guestos_components = get_components_from_bzl("../../../ic-os/components/guestos.bzl")?;
    let hostos_components = get_components_from_bzl("../../../ic-os/components/hostos.bzl")?;
    let setupos_components = get_components_from_bzl("../../../ic-os/components/setupos.bzl")?;
    let boundary_guestos_components =
        get_components_from_bzl("../../../ic-os/components/boundary-guestos.bzl")?;

    Ok(IcosComponents::new(
        guestos_components,
        hostos_components,
        setupos_components,
        boundary_guestos_components,
    ))
}
