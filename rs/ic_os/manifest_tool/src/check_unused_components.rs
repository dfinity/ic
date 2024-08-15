use anyhow::Result;
use std::path::PathBuf;

use crate::components_parser::get_icos_manifest;

pub fn check_unused_components(repo_root: &PathBuf) -> Result<()> {
    let icos_components = get_icos_manifest(repo_root)?;

    // Logic to check for unused components

    dbg!(icos_components);
    dbg!(repo_root);

    Ok(())
}
