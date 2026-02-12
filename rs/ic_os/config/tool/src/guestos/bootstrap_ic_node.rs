use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use config_types::GuestOSConfig;
use fs_extra;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

// Paths under root (without / prefix)
const CONFIG_ROOT_PATH: &str = "boot/config";
const STATE_ROOT_PATH: &str = "var/lib/ic";
const NNS_KEY_DEFAULT_PATH: &str = "opt/ic/share/nns_public_key.pem";
const NNS_KEY_PATH: &str = "run/config/nns_public_key.pem";
const NODE_OPERATOR_KEY_PATH: &str = "data/node_operator_private_key.pem";

/// Populates the NNS root key where `ic-replica` expects it.
/// In a dev environment it will take the overriden key from the GuestOS config
/// if it's provided there.
#[allow(unused_variables)]
fn populate_nns_public_key(
    root: &Path,
    bootstrap_dir: &Path,
    guestos_config: &GuestOSConfig,
) -> Result<()> {
    let nns_key_dst = root.join(NNS_KEY_PATH);

    // Get the override key from the config if we're in dev environment & it was set
    #[cfg(feature = "dev")]
    if let Some(v) = guestos_config
        .guestos_settings
        .guestos_dev_settings
        .nns_pub_key_override
        .as_ref()
    {
        println!(
            "Writing NNS public key override to {}",
            nns_key_dst.display()
        );

        if let Some(parent) = nns_key_dst.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&nns_key_dst, v).context("unable to write NNS public key")?;
        fs::set_permissions(&nns_key_dst, fs::Permissions::from_mode(0o444))
            .context("unable to set NNS public key permissions")?;
        return Ok(());
    };

    let nns_key_src = root.join(NNS_KEY_DEFAULT_PATH);
    // Otherwise just copy the normal key from the rootfs
    println!(
        "Copying {} to {}",
        nns_key_src.display(),
        nns_key_dst.display()
    );

    copy_file_with_parent_dir(&nns_key_src, &nns_key_dst).with_context(|| {
        format!(
            "Failed to copy NNS public key from {} to {}",
            nns_key_src.display(),
            nns_key_dst.display()
        )
    })?;

    fs::set_permissions(&nns_key_dst, fs::Permissions::from_mode(0o444))
        .context("unable to set NNS public key permissions")?;

    Ok(())
}

/// Bootstrap IC Node from a bootstrap package
#[cfg(target_os = "linux")]
pub fn bootstrap_ic_node(bootstrap_dir: &Path, guestos_config: GuestOSConfig) -> Result<()> {
    let is_sev_active = sev_guest::is_sev_active()?;
    bootstrap_ic_node_impl(bootstrap_dir, Path::new("/"), guestos_config, is_sev_active)
}

fn bootstrap_ic_node_impl(
    bootstrap_dir: &Path,
    root: &Path,
    guestos_config: GuestOSConfig,
    is_sev_active: bool,
) -> Result<()> {
    let config_root = root.join(CONFIG_ROOT_PATH);
    let state_root = root.join(STATE_ROOT_PATH);
    let configured_marker = config_root.join("CONFIGURED");

    if configured_marker.exists() {
        println!("Bootstrap completed already");
        return Ok(());
    }

    populate_nns_public_key(root, bootstrap_dir, &guestos_config)
        .context("unable to populate NNS public key")?;

    println!("Processing bootstrap data from {}", bootstrap_dir.display());
    process_bootstrap(
        bootstrap_dir,
        &config_root,
        &state_root,
        guestos_config,
        is_sev_active,
    )
    .context("bootstrap failed")?;

    println!("Successfully processed bootstrap data");

    File::create(&configured_marker)?;

    Ok(())
}

/// Process the bootstrap package to copy config contents
fn process_bootstrap(
    bootstrap_dir: &Path,
    config_root: &Path,
    state_root: &Path,
    guestos_config: GuestOSConfig,
    is_sev_active: bool,
) -> Result<()> {
    copy_bootstrap_files(bootstrap_dir, config_root, state_root, is_sev_active)?;

    // Write the node operator key if it was configured
    let node_op_key_dst = state_root.join(NODE_OPERATOR_KEY_PATH);
    if let Some(v) = guestos_config.icos_settings.node_operator_private_key {
        println!("Setting up initial {}", node_op_key_dst.display());
        fs::write(&node_op_key_dst, v).context("unable to write node operator private key")?;
        fs::set_permissions(&node_op_key_dst, fs::Permissions::from_mode(0o400))?;
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

fn copy_state_injection_files(bootstrap_dir: &Path, state_root: &Path) -> Result<()> {
    let ic_crypto_src = bootstrap_dir.join("ic_crypto");
    let ic_crypto_dst = state_root.join("crypto");
    if ic_crypto_src.exists() {
        println!("Installing initial crypto material");
        copy_directory_recursive(&ic_crypto_src, &ic_crypto_dst)?;
    }

    let ic_state_src = bootstrap_dir.join("ic_state");
    let ic_state_dst = state_root.join("data/ic_state");
    if ic_state_src.exists() {
        println!("Installing initial state");
        copy_directory_recursive(&ic_state_src, &ic_state_dst)?;
    }

    let ic_registry_src = bootstrap_dir.join("ic_registry_local_store");
    let ic_registry_dst = state_root.join("data/ic_registry_local_store");
    if ic_registry_src.exists() {
        println!("Setting up initial ic_registry_local_store");
        copy_directory_recursive(&ic_registry_src, &ic_registry_dst)?;
    }

    Ok(())
}

/// Copy select bootstrap files from extracted directory to their destinations with custom SEV checker
fn copy_bootstrap_files(
    bootstrap_dir: &Path,
    config_root: &Path,
    state_root: &Path,
    is_sev_active: bool,
) -> Result<()> {
    // set up initial ssh authorized keys
    let ssh_keys_src = bootstrap_dir.join("accounts_ssh_authorized_keys");
    let ssh_keys_dst = config_root.join("accounts_ssh_authorized_keys");
    if ssh_keys_src.exists() {
        println!("Copying accounts_ssh_authorized_keys");
        copy_directory_recursive(&ssh_keys_src, &ssh_keys_dst)?;
    }

    // Restrict state injection on SEV production nodes
    if is_sev_active {
        #[cfg(not(feature = "dev"))]
        {
            println!("SEV is active - blocking state injection files for production variant");
        }
        #[cfg(feature = "dev")]
        {
            println!("SEV is active - allowing state injection files for dev variant");
            copy_state_injection_files(bootstrap_dir, state_root)?;
        }
    } else {
        println!("SEV is not active - allowing state injection files");
        copy_state_injection_files(bootstrap_dir, state_root)?;
    }

    Ok(())
}

fn copy_file_with_parent_dir(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst)?;
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
    use std::path::PathBuf;
    use tempfile::TempDir;

    struct TestRoot {
        temp_dir: TempDir,
    }

    impl TestRoot {
        fn new() -> Self {
            let temp_dir = TempDir::new().unwrap();
            fs::create_dir_all(temp_dir.path().join(CONFIG_ROOT_PATH)).unwrap();
            fs::create_dir_all(temp_dir.path().join(STATE_ROOT_PATH)).unwrap();
            fs::create_dir_all(temp_dir.path().join("run")).unwrap();

            Self { temp_dir }
        }

        fn root_path(&self) -> &Path {
            self.temp_dir.path()
        }

        fn path(&self, path: impl AsRef<Path>) -> PathBuf {
            self.temp_dir.path().join(path)
        }

        /// Create a default NNS public key at /opt/ic/share/nns_public_key.pem
        fn create_rootfs_nns_key(&self, content: &str) {
            let nns_key_path = self.path(NNS_KEY_DEFAULT_PATH);
            fs::create_dir_all(nns_key_path.parent().unwrap()).unwrap();
            fs::write(&nns_key_path, content).unwrap();
        }
    }

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

    fn create_test_bootstrap_dir() -> TempDir {
        let bootstrap_temp_dir = TempDir::new().unwrap();
        let bootstrap_dir = bootstrap_temp_dir.path();

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

        fs::create_dir_all(bootstrap_dir.join("accounts_ssh_authorized_keys")).unwrap();
        fs::write(
            bootstrap_dir
                .join("accounts_ssh_authorized_keys")
                .join("authorized_keys"),
            "ssh-rsa test_key",
        )
        .unwrap();

        bootstrap_temp_dir
    }

    #[test]
    fn test_process_bootstrap_success() {
        let test_root = TestRoot::new();
        test_root.create_rootfs_nns_key("default_nns_key");
        let bootstrap_dir = create_test_bootstrap_dir();

        let mut guestos_config = GuestOSConfig::default();
        guestos_config.icos_settings.node_operator_private_key =
            Some("test_node_operator_key".into());
        guestos_config
            .guestos_settings
            .guestos_dev_settings
            .nns_pub_key_override = Some("test_nns_key_override".into());

        let result = bootstrap_ic_node_impl(
            bootstrap_dir.path(),
            test_root.root_path(),
            guestos_config,
            /*is_sev_active*/ false,
        );
        assert!(result.is_ok());

        // Verify files were copied correctly
        let state_root = test_root.path(STATE_ROOT_PATH);
        let config_root = test_root.path(CONFIG_ROOT_PATH);

        assert!(state_root.join("crypto").join("key.pem").exists());
        assert!(state_root.join("data/ic_state").join("state.dat").exists());
        assert!(
            state_root
                .join("data/ic_registry_local_store")
                .join("registry.dat")
                .exists()
        );
        assert!(
            config_root
                .join("accounts_ssh_authorized_keys")
                .join("authorized_keys")
                .exists()
        );
        assert!(state_root.join(NODE_OPERATOR_KEY_PATH).exists());
        assert!(test_root.path(NNS_KEY_PATH).exists());

        // Verify file contents
        assert_eq!(
            fs::read_to_string(state_root.join("crypto").join("key.pem")).unwrap(),
            "test_crypto_key"
        );
        assert_eq!(
            fs::read_to_string(state_root.join("data/ic_state").join("state.dat")).unwrap(),
            "test_state_data"
        );

        // Make sure that with dev feature we get the overriden key
        #[cfg(feature = "dev")]
        {
            assert_eq!(
                fs::read_to_string(test_root.path(NNS_KEY_PATH)).unwrap(),
                "test_nns_key_override"
            );
        }

        // Make sure that w/o dev feature we get the default key
        #[cfg(not(feature = "dev"))]
        {
            assert_eq!(
                fs::read_to_string(test_root.path(NNS_KEY_PATH)).unwrap(),
                "default_nns_key"
            );
        }
        assert_eq!(
            fs::read_to_string(state_root.join(NODE_OPERATOR_KEY_PATH)).unwrap(),
            "test_node_operator_key"
        );

        let perms = fs::metadata(test_root.path(NNS_KEY_PATH))
            .unwrap()
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o444);

        // Verify CONFIGURED marker was created
        assert!(config_root.join("CONFIGURED").exists());
    }

    #[test]
    fn test_process_bootstrap_default_nns_key_and_no_operator_key() {
        let test_root = TestRoot::new();
        test_root.create_rootfs_nns_key("default_nns_key");
        let bootstrap_dir = create_test_bootstrap_dir();

        let guestos_config = GuestOSConfig::default();

        bootstrap_ic_node_impl(
            bootstrap_dir.path(),
            test_root.root_path(),
            guestos_config,
            /*is_sev_active*/ false,
        )
        .unwrap();

        // Verify files were copied correctly
        let state_root = test_root.path(STATE_ROOT_PATH);
        let config_root = test_root.path(CONFIG_ROOT_PATH);

        assert!(state_root.join("crypto").join("key.pem").exists());
        assert!(state_root.join("data/ic_state").join("state.dat").exists());
        assert!(
            state_root
                .join("data/ic_registry_local_store")
                .join("registry.dat")
                .exists()
        );
        assert!(
            config_root
                .join("accounts_ssh_authorized_keys")
                .join("authorized_keys")
                .exists()
        );
        assert!(!state_root.join(NODE_OPERATOR_KEY_PATH).exists());
        assert!(test_root.path(NNS_KEY_PATH).exists());

        // Verify file contents
        assert_eq!(
            fs::read_to_string(state_root.join("crypto").join("key.pem")).unwrap(),
            "test_crypto_key"
        );
        assert_eq!(
            fs::read_to_string(state_root.join("data/ic_state").join("state.dat")).unwrap(),
            "test_state_data"
        );
        assert_eq!(
            fs::read_to_string(test_root.path(NNS_KEY_PATH)).unwrap(),
            "default_nns_key"
        );

        // Verify CONFIGURED marker was created
        assert!(config_root.join("CONFIGURED").exists());
    }

    #[test]
    fn test_copy_bootstrap_files_normal() {
        // Create extracted directory structure
        let temp_dir = TempDir::new().unwrap();
        let extracted_dir = temp_dir.path().join("extracted");
        let config_root = temp_dir.path().join("config");
        let state_root = temp_dir.path().join("state");
        fs::create_dir_all(&extracted_dir).unwrap();
        fs::create_dir_all(&config_root).unwrap();
        fs::create_dir_all(&state_root).unwrap();

        // Create test files and directories
        fs::create_dir_all(extracted_dir.join("ic_crypto")).unwrap();
        fs::write(
            extracted_dir.join("ic_crypto").join("key.pem"),
            "test_crypto_key",
        )
        .unwrap();

        fs::create_dir_all(extracted_dir.join("ic_state")).unwrap();
        fs::write(
            extracted_dir.join("ic_state").join("state.dat"),
            "test_state_data",
        )
        .unwrap();

        fs::create_dir_all(extracted_dir.join("ic_registry_local_store")).unwrap();
        fs::write(
            extracted_dir
                .join("ic_registry_local_store")
                .join("registry.dat"),
            "test_registry_data",
        )
        .unwrap();

        fs::create_dir_all(extracted_dir.join("accounts_ssh_authorized_keys")).unwrap();
        fs::write(
            extracted_dir
                .join("accounts_ssh_authorized_keys")
                .join("authorized_keys"),
            "ssh-rsa test_key",
        )
        .unwrap();

        let result = copy_bootstrap_files(&extracted_dir, &config_root, &state_root, false);
        assert!(result.is_ok());

        // Verify files were copied correctly
        assert!(state_root.join("crypto").join("key.pem").exists());
        assert!(state_root.join("data/ic_state").join("state.dat").exists());
        assert!(
            state_root
                .join("data/ic_registry_local_store")
                .join("registry.dat")
                .exists()
        );
        assert!(
            config_root
                .join("accounts_ssh_authorized_keys")
                .join("authorized_keys")
                .exists()
        );

        // Verify file contents
        assert_eq!(
            fs::read_to_string(state_root.join("crypto").join("key.pem")).unwrap(),
            "test_crypto_key"
        );
        assert_eq!(
            fs::read_to_string(state_root.join("data/ic_state").join("state.dat")).unwrap(),
            "test_state_data"
        );
        assert_eq!(
            fs::read_to_string(
                state_root
                    .join("data/ic_registry_local_store")
                    .join("registry.dat")
            )
            .unwrap(),
            "test_registry_data"
        );
        assert_eq!(
            fs::read_to_string(
                config_root
                    .join("accounts_ssh_authorized_keys")
                    .join("authorized_keys")
            )
            .unwrap(),
            "ssh-rsa test_key"
        );
    }

    #[test]
    fn test_configured_marker() {
        let test_root = TestRoot::new();

        // Create CONFIGURED marker to simulate already-configured system
        fs::write(test_root.path(CONFIG_ROOT_PATH).join("CONFIGURED"), "").unwrap();

        // Create existing files that should NOT be overridden
        let state_root = test_root.path(STATE_ROOT_PATH);
        fs::create_dir_all(state_root.join("crypto")).unwrap();
        fs::write(
            state_root.join("crypto").join("key.pem"),
            "existing_crypto_key",
        )
        .unwrap();

        fs::create_dir_all(state_root.join("data/ic_state")).unwrap();
        fs::write(
            state_root.join("data/ic_state").join("state.dat"),
            "existing_state_data",
        )
        .unwrap();

        let bootstrap_dir = create_test_bootstrap_dir();

        bootstrap_ic_node_impl(
            bootstrap_dir.path(),
            test_root.root_path(),
            GuestOSConfig::default(),
            /*is_sev_active*/ false,
        )
        .unwrap();

        // Verify existing files were NOT overridden
        assert_eq!(
            fs::read_to_string(state_root.join("crypto").join("key.pem")).unwrap(),
            "existing_crypto_key"
        );
        assert_eq!(
            fs::read_to_string(state_root.join("data/ic_state").join("state.dat")).unwrap(),
            "existing_state_data"
        );

        // Verify that bootstrap files from the bootstrap dir were NOT copied
        // (because CONFIGURED marker exists, bootstrap process is skipped)
        assert!(
            !state_root
                .join("data/ic_registry_local_store/registry.dat")
                .exists()
        );
    }

    #[test]
    #[cfg(not(feature = "dev"))]
    fn test_sev_active_prod_state_injection_blocked() {
        // Create extracted directory structure
        let temp_dir = TempDir::new().unwrap();
        let extracted_dir = temp_dir.path().join("extracted");
        let config_root = temp_dir.path().join("config");
        let state_root = temp_dir.path().join("state");
        fs::create_dir_all(&extracted_dir).unwrap();
        fs::create_dir_all(&config_root).unwrap();
        fs::create_dir_all(&state_root).unwrap();

        // Create state injection files that should be blocked when SEV is active in production
        fs::create_dir_all(extracted_dir.join("ic_crypto")).unwrap();
        fs::write(
            extracted_dir.join("ic_crypto").join("key.pem"),
            "test_crypto_key",
        )
        .unwrap();
        fs::create_dir_all(extracted_dir.join("ic_state")).unwrap();
        fs::write(
            extracted_dir.join("ic_state").join("state.dat"),
            "test_state_data",
        )
        .unwrap();
        fs::create_dir_all(extracted_dir.join("ic_registry_local_store")).unwrap();
        fs::write(
            extracted_dir
                .join("ic_registry_local_store")
                .join("registry.dat"),
            "test_registry_data",
        )
        .unwrap();

        // Set SEV as active (simulating production environment with SEV)
        let result = copy_bootstrap_files(&extracted_dir, &config_root, &state_root, true);
        assert!(result.is_ok());

        // Verify that state injection files were NOT copied when SEV is active in production
        assert!(!state_root.join("crypto").join("key.pem").exists());
        assert!(!state_root.join("data/ic_state").join("state.dat").exists());
        assert!(
            !state_root
                .join("data/ic_registry_local_store")
                .join("registry.dat")
                .exists()
        );
    }
}
