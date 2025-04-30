use anyhow::Result;
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
fn get_repo_root() -> Result<PathBuf, std::io::Error> {
    let mut current_dir = std::env::current_dir()?;

    // Look for the .git directory by walking up the directory tree
    loop {
        if current_dir.join(".git").exists() {
            return Ok(current_dir);
        }

        if !current_dir.pop() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Could not find .git directory",
            ));
        }
    }
}
