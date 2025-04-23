use config_types::CONFIG_VERSION;
use config_types_compatibility_lib::generate_fixtures;
use std::path::PathBuf;

fn main() {
    let repo_root = get_repo_root().expect("Failed to get repository root");

    let fixtures_dir = repo_root.join("rs/ic_os/config_types/compatibility_tests/fixtures");

    if let Err(e) = generate_fixtures(&fixtures_dir) {
        eprintln!("Error generating fixtures: {}", e);
        std::process::exit(1);
    }
    println!(
        "Generated fixtures for version {} in {}",
        CONFIG_VERSION,
        fixtures_dir.display()
    );
}

/// Get the repository root directory by looking for the .git directory
fn get_repo_root() -> Result<PathBuf, std::io::Error> {
    let mut current_dir = std::env::current_dir()?;

    // Look for the .git directory by walking up the directory tree
    loop {
        if current_dir.join(".git").exists() {
            return Ok(current_dir);
        }

        // Try to move up one directory
        if !current_dir.pop() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Could not find .git directory",
            ));
        }
    }
}
