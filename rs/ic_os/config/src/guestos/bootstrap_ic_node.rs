use anyhow::{Context, Result};
use fs_extra;
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
    } else {
        anyhow::bail!("node_operator_private_key.pem does not exist in the bootstrap tarball");
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
    let _ = Command::new("chown")
        .args(["ic-replica:nogroup", "-R"])
        .arg(state_root.join("data"))
        .status();

    // Synchronize the above cached writes to persistent storage
    // to make sure the system can boot successfully after a hard shutdown.
    let _ = Command::new("sync").status();

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

    let mut options = fs_extra::dir::CopyOptions::new();
    options.overwrite = true;
    options.copy_inside = true;
    options.content_only = true;

    fs_extra::dir::copy(src, dst, &options)
        .map_err(|e| anyhow::anyhow!("Failed to copy directory: {}", e))?;

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
        let dst_parent = TempDir::new().unwrap();
        let dst_path = dst_parent.path().join("dst");

        fs::write(src_dir.path().join("file1.txt"), "content1").unwrap();
        fs::create_dir(src_dir.path().join("subdir")).unwrap();
        fs::write(src_dir.path().join("subdir").join("file2.txt"), "content2").unwrap();

        assert!(!dst_path.exists());
        copy_directory_recursive(src_dir.path(), &dst_path).unwrap();
        assert!(dst_path.exists());

        assert!(dst_path.join("file1.txt").exists());
        assert!(dst_path.join("subdir").join("file2.txt").exists());
        assert_eq!(
            fs::read_to_string(dst_path.join("file1.txt")).unwrap(),
            "content1"
        );
        assert_eq!(
            fs::read_to_string(dst_path.join("subdir").join("file2.txt")).unwrap(),
            "content2"
        );
    }

    #[test]
    fn test_copy_directory_recursive_nonexistent_source() {
        let dst_dir = TempDir::new().unwrap();
        let result = copy_directory_recursive(Path::new("/nonexistent"), dst_dir.path());
        assert!(result.is_err());
    }

    fn create_test_bootstrap_tar(temp_dir: &TempDir) -> std::path::PathBuf {
        let bootstrap_dir = temp_dir.path().join("bootstrap");
        fs::create_dir_all(&bootstrap_dir).unwrap();

        // Create test files and directories
        fs::create_dir_all(bootstrap_dir.join("ic_crypto")).unwrap();
        fs::write(
            bootstrap_dir.join("ic_crypto").join("key.pem"),
            "test_crypto_key",
        )
        .unwrap();

        fs::create_dir_all(bootstrap_dir.join("ic_state")).unwrap();
        fs::write(
            bootstrap_dir.join("ic_state").join("state.dat"),
            "test_state_data",
        )
        .unwrap();

        fs::create_dir_all(bootstrap_dir.join("ic_registry_local_store")).unwrap();
        fs::write(
            bootstrap_dir
                .join("ic_registry_local_store")
                .join("registry.dat"),
            "test_registry_data",
        )
        .unwrap();

        fs::write(bootstrap_dir.join("nns_public_key.pem"), "test_nns_key").unwrap();
        fs::write(
            bootstrap_dir.join("node_operator_private_key.pem"),
            "test_node_op_key",
        )
        .unwrap();

        fs::create_dir_all(bootstrap_dir.join("accounts_ssh_authorized_keys")).unwrap();
        fs::write(
            bootstrap_dir
                .join("accounts_ssh_authorized_keys")
                .join("authorized_keys"),
            "ssh-rsa test_key",
        )
        .unwrap();

        // Create tar file
        let tar_path = temp_dir.path().join("bootstrap.tar");
        let status = Command::new("tar")
            .args(["cf", tar_path.to_str().unwrap()])
            .current_dir(&bootstrap_dir)
            .args([
                "./ic_crypto",
                "./ic_state",
                "./ic_registry_local_store",
                "./nns_public_key.pem",
                "./node_operator_private_key.pem",
                "./accounts_ssh_authorized_keys",
            ])
            .status()
            .unwrap();

        assert!(status.success());
        tar_path
    }

    #[test]
    fn test_process_bootstrap_success() {
        let temp_dir = TempDir::new().unwrap();
        let bootstrap_tar = create_test_bootstrap_tar(&temp_dir);

        let config_root = temp_dir.path().join("config");
        let state_root = temp_dir.path().join("state");
        fs::create_dir_all(&config_root).unwrap();
        fs::create_dir_all(&state_root).unwrap();

        let result = process_bootstrap(&bootstrap_tar, &config_root, &state_root);
        assert!(result.is_ok());

        // Verify files were copied correctly
        assert!(state_root.join("crypto").join("key.pem").exists());
        assert!(state_root.join("data/ic_state").join("state.dat").exists());
        assert!(state_root
            .join("data/ic_registry_local_store")
            .join("registry.dat")
            .exists());
        assert!(state_root.join("data/nns_public_key.pem").exists());
        assert!(state_root
            .join("data/node_operator_private_key.pem")
            .exists());
        assert!(config_root
            .join("accounts_ssh_authorized_keys")
            .join("authorized_keys")
            .exists());

        // Verify file contents
        assert_eq!(
            fs::read_to_string(state_root.join("crypto").join("key.pem")).unwrap(),
            "test_crypto_key"
        );
        assert_eq!(
            fs::read_to_string(state_root.join("data/ic_state").join("state.dat")).unwrap(),
            "test_state_data"
        );
    }

    #[test]
    fn test_process_bootstrap_missing_tar_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_root = temp_dir.path().join("config");
        let state_root = temp_dir.path().join("state");
        fs::create_dir_all(&config_root).unwrap();
        fs::create_dir_all(&state_root).unwrap();

        let nonexistent_tar = temp_dir.path().join("nonexistent.tar");
        let result = process_bootstrap(&nonexistent_tar, &config_root, &state_root);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_bootstrap_invalid_tar_file() {
        let temp_dir = TempDir::new().unwrap();
        let invalid_tar = temp_dir.path().join("invalid.tar");
        fs::write(&invalid_tar, "not a tar file").unwrap();

        let config_root = temp_dir.path().join("config");
        let state_root = temp_dir.path().join("state");
        fs::create_dir_all(&config_root).unwrap();
        fs::create_dir_all(&state_root).unwrap();

        let result = process_bootstrap(&invalid_tar, &config_root, &state_root);
        assert!(result.is_err());
    }
}
