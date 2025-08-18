use anyhow::{Context, Result};
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const CONFIG_ROOT_PATH: &str = "/boot/config";
const STATE_ROOT_PATH: &str = "/var/lib/ic";

/// Process the bootstrap package to populate SSH keys and injected data
pub fn process_bootstrap(
    bootstrap_tar: &Path,
    config_root: &Path,
    state_root: &Path,
) -> Result<()> {
    let tmpdir = TempDir::new().context("Failed to create temporary directory")?;

    let status = Command::new("tar")
        .args(["xf", bootstrap_tar.to_str().unwrap()])
        .current_dir(tmpdir.path())
        .status()
        .context("Failed to extract bootstrap tar file")?;

    if !status.success() {
        anyhow::bail!("tar extraction failed with status: {}", status);
    }

    // take injected config bits and move them to state directories
    let ic_crypto_src = tmpdir.path().join("ic_crypto");
    let ic_crypto_dst = state_root.join("crypto");
    if ic_crypto_src.exists() {
        println!("Installing initial crypto material");
        copy_directory_recursive(&ic_crypto_src, &ic_crypto_dst)?;
    }

    let ic_state_src = tmpdir.path().join("ic_state");
    let ic_state_dst = state_root.join("data/ic_state");
    if ic_state_src.exists() {
        println!("Installing initial state");
        copy_directory_recursive(&ic_state_src, &ic_state_dst)?;
    }

    let ic_registry_src = tmpdir.path().join("ic_registry_local_store");
    let ic_registry_dst = state_root.join("data/ic_registry_local_store");
    if ic_registry_src.exists() {
        println!("Setting up initial ic_registry_local_store");
        copy_directory_recursive(&ic_registry_src, &ic_registry_dst)?;
    }

    // set up initial nns_public_key.pem
    let nns_key_src = tmpdir.path().join("nns_public_key.pem");
    let nns_key_dst = state_root.join("data/nns_public_key.pem");
    if nns_key_src.exists() {
        println!("Setting up initial nns_public_key.pem");
        fs::copy(&nns_key_src, &nns_key_dst)?;
        fs::set_permissions(&nns_key_dst, fs::Permissions::from_mode(0o444))?;
    }

    // set up initial node_operator_private_key.pem
    let node_op_key_src = tmpdir.path().join("node_operator_private_key.pem");
    let node_op_key_dst = state_root.join("data/node_operator_private_key.pem");
    if node_op_key_src.exists() {
        println!("Setting up initial node_operator_private_key.pem");
        fs::copy(&node_op_key_src, &node_op_key_dst)?;
        fs::set_permissions(&node_op_key_dst, fs::Permissions::from_mode(0o400))?;
    }

    // set up initial ssh authorized keys
    let ssh_keys_src = tmpdir.path().join("accounts_ssh_authorized_keys");
    let ssh_keys_dst = config_root.join("accounts_ssh_authorized_keys");
    if ssh_keys_src.exists() {
        println!("Setting up accounts_ssh_authorized_keys");
        copy_directory_recursive(&ssh_keys_src, &ssh_keys_dst)?;
    }

    // Fix up permissions. Ideally this is specific to only what is copied. If
    // we do make this change, we need to make sure `data` itself has the
    // correct permissions.
    let status = Command::new("chown")
        .args(["ic-replica:nogroup", "-R"])
        .arg(state_root.join("data"))
        .status()
        .context("Failed to change ownership of data directory")?;

    if !status.success() {
        anyhow::bail!("chown failed with status: {}", status);
    }

    // Synchronize the above cached writes to persistent storage
    // to make sure the system can boot successfully after a hard shutdown.
    let status = Command::new("sync")
        .status()
        .context("Failed to sync filesystem")?;

    if !status.success() {
        anyhow::bail!("sync failed with status: {}", status);
    }

    Ok(())
}

/// Bootstrap IC Node from a bootstrap package
pub fn bootstrap_ic_node(bootstrap_tar_path: &Path) -> Result<()> {
    let config_root = Path::new(CONFIG_ROOT_PATH);
    let state_root = Path::new(STATE_ROOT_PATH);
    let configured_marker = config_root.join("CONFIGURED");

    if configured_marker.exists() {
        println!("Bootstrap completed already");
        return Ok(());
    }

    println!("Checking for bootstrap configuration");

    if bootstrap_tar_path.exists() {
        println!(
            "Processing bootstrap data from {}",
            bootstrap_tar_path.display()
        );
        process_bootstrap(bootstrap_tar_path, config_root, state_root)?;
        println!("Successfully processed bootstrap data");

        File::create(&configured_marker)?;
    } else {
        anyhow::bail!("No registration configuration provided to bootstrap IC node");
    }

    Ok(())
}

fn copy_directory_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !src.is_dir() {
        anyhow::bail!("Source path is not a directory: {}", src.display());
    }

    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_directory_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_copy_directory_recursive() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        fs::write(src_dir.path().join("file1.txt"), "content1").unwrap();
        fs::create_dir(src_dir.path().join("subdir")).unwrap();
        fs::write(src_dir.path().join("subdir").join("file2.txt"), "content2").unwrap();

        copy_directory_recursive(src_dir.path(), dst_dir.path()).unwrap();

        assert!(dst_dir.path().join("file1.txt").exists());
        assert!(dst_dir.path().join("subdir").join("file2.txt").exists());
        assert_eq!(
            fs::read_to_string(dst_dir.path().join("file1.txt")).unwrap(),
            "content1"
        );
        assert_eq!(
            fs::read_to_string(dst_dir.path().join("subdir").join("file2.txt")).unwrap(),
            "content2"
        );
    }

    #[test]
    fn test_copy_directory_recursive_nonexistent_source() {
        let dst_dir = TempDir::new().unwrap();
        let result = copy_directory_recursive(Path::new("/nonexistent"), dst_dir.path());
        assert!(result.is_err());
    }
}
