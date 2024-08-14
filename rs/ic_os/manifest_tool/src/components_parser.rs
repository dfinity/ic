use anyhow::{Context, Result};
use std::fs;
use regex::Regex;

#[derive(Debug)]
pub struct Components {
    pub source: String,
    pub destination: String,
}

impl Components {
    pub fn new(name: String, path: String) -> Self {
        Components { source: name, destination: path }
    }
}

pub fn get_components_from_bzl(file_path: &str) -> Result<Vec<Components>> {
    let content = fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read file: {}", file_path))?;

    // Regular expression to capture the key and value in the component_files dictionary
    let re = Regex::new(r#"Label\("(.+?)"\): "(.+?)""#)?;

    let mut components = Vec::new();

    for cap in re.captures_iter(&content) {
        let name = cap[1].to_string();
        let path = cap[2].to_string();
        components.push(Components::new(name, path));
    }

    Ok(components)
}

pub fn get_all_components() -> Result<Vec<Components>> {
    //TODO: help: fix file paths
    let guestos_components = get_components_from_bzl("../../../ic-os/components/guestos.bzl")?;
    let hostos_components = get_components_from_bzl("../../../ic-os/components/hostos.bzl")?;
    let setupos_components = get_components_from_bzl("../../../ic-os/components/setupos.bzl")?;
    let boundary_guestos_components = get_components_from_bzl("../../../ic-os/components/boundary-guestos.bzl")?;

    let mut all_components = Vec::new();
    all_components.extend(guestos_components);
    all_components.extend(hostos_components);
    all_components.extend(setupos_components);
    all_components.extend(boundary_guestos_components);

    Ok(all_components)
}
