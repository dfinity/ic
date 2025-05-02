use anyhow::{Context, Result};
use config_types::CONFIG_VERSION;
use config_types_compatibility_lib::generate_fixtures;
use std::path::PathBuf;

fn main() -> Result<()> {
    let repo_root = get_repo_root()?;

    let fixtures_dir = repo_root.join("rs/ic_os/config_types/compatibility_tests/fixtures");

    generate_fixtures(&fixtures_dir)?;
    println!(
        "Generated fixtures for version {} in {}",
        CONFIG_VERSION,
        fixtures_dir.display()
    );
    Ok(())
}

/// Get the repository root directory by looking for the .git directory
fn get_repo_root() -> Result<PathBuf> {
    std::env::current_dir()?
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .context("Could not find .git directory")
        .map(|p| p.to_path_buf())
}
