// We disable clippy warnings for the whole module because they apply to
// generated code, meaning we can't locally disable the warnings (the code is
// defined in another module).
#![allow(clippy::redundant_closure)]
#![allow(clippy::unit_arg)]

use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempDir;

#[cfg(test)]
use proptest::prelude::{any, Strategy};
#[cfg(test)]
use proptest_derive::Arbitrary;
use std::fs::Permissions;

// This path is not used in practice. The code should panic if it is.
pub const CRYPTO_ROOT_DEFAULT_PATH: &str = "/This/must/not/be/a/real/path";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(Arbitrary))]
pub enum CspVaultType {
    InReplica,
    #[cfg_attr(
        test,
        proptest(
            strategy = "any::<String>().prop_map(|x| CspVaultType::UnixSocket(PathBuf::from(x)))"
        )
    )]
    UnixSocket(PathBuf),
}

impl Default for CspVaultType {
    fn default() -> Self {
        CspVaultType::InReplica
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default)]
#[cfg_attr(test, derive(Arbitrary))]
/// #
/// ```
/// # use ic_config::crypto::CryptoConfig;
/// let config = "{ crypto_root: '/tmp/ic_crypto', csp_vault_type: 'in_replica' }";
/// # let deserialized: CryptoConfig = json5::from_str(&config).unwrap();
/// ```
pub struct CryptoConfig {
    /// Path to use for storing state on the file system.
    /// It is needed for either value of `csp_vault_type`, as the config
    /// is used both for starting a replica, and for starting the `CspVault`-server.
    #[cfg_attr(
        test,
        proptest(strategy = "any::<String>().prop_map(|x| PathBuf::from(x))")
    )]
    pub crypto_root: PathBuf,
    pub csp_vault_type: CspVaultType,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            crypto_root: PathBuf::from(CRYPTO_ROOT_DEFAULT_PATH),
            csp_vault_type: CspVaultType::InReplica,
        }
    }
}

impl CryptoConfig {
    /// Returns a new CryptoConfig with the given crypto_root path.
    pub fn new(crypto_root: PathBuf) -> Self {
        Self {
            crypto_root,
            csp_vault_type: CspVaultType::InReplica,
        }
    }

    /// Returns a new CryptoConfig with the given `crypto_root` path, with
    /// CspVault at the specified `socket_path`.
    pub fn new_with_unix_socket_vault(crypto_root: PathBuf, socket_path: PathBuf) -> Self {
        Self {
            crypto_root,
            csp_vault_type: CspVaultType::UnixSocket(socket_path),
        }
    }

    /// Creates a new CryptoConfig in a temporary directory for testing.
    /// The directory has the permissions required for storing crypto state (see
    /// [`Self::check_dir_has_required_permissions`]) and will be automatically
    /// deleted when the returned `TempDir` goes out of scope.
    /// Panics if creating the directory or setting the permissions fails.
    pub fn new_in_temp_dir() -> (Self, TempDir) {
        let temp_dir = tempfile::Builder::new()
            .prefix("ic_crypto_")
            .tempdir()
            .expect("failed to create temporary crypto directory");
        fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o750)).unwrap_or_else(|_| {
            panic!(
                "failed to set permissions of crypto directory {}",
                temp_dir.path().display()
            )
        });
        let temp_dir_path = temp_dir.path().to_path_buf();
        CryptoConfig::check_dir_has_required_permissions(&temp_dir_path)
            .expect("Wrong dir permissions");
        let config = CryptoConfig::new(temp_dir_path);
        (config, temp_dir)
    }

    /// Run the given `run` function with a new CryptoConfig created from a
    /// temporary directory, which is automatically removed afterwards.
    pub fn run_with_temp_config<T>(run: impl FnOnce(Self) -> T) -> T {
        let (config, _temp_dir) = Self::new_in_temp_dir();
        run(config)
    }

    /// Checks that directory `dir` has permissions required for storing crypto
    /// states, i.e. the owner can read/write files in the directly, but the
    /// directory should not be world-accessible.  (Group permissions are
    /// not checked, as these are up to the system setup.) Returns an error
    /// if it fails. NOTE: this is only a basic sanity check; the exact
    /// permissions depend on the system setup and are out of scope of
    /// Crypto Component.
    pub fn check_dir_has_required_permissions(dir: &Path) -> Result<(), String> {
        if !dir.exists() {
            return Err(format!(
                "Crypto state directory does not exist: {}",
                dir.display()
            ));
        }
        let metadata = fs::metadata(&dir).map_err(|err| {
            format!(
                "Cannot get the metadata of the crypto state directory {}: {:?}",
                dir.display(),
                err
            )
        })?;
        if !metadata.is_dir() {
            return Err(format!(
                "Crypto state directory should be a directory, not a file: {}",
                dir.display()
            ));
        }
        let permissions = metadata.permissions();
        let unix_permission_bits = permissions.mode();
        let permissions_owner = unix_permission_bits & 0o700;
        if permissions_owner != 0o700 {
            return Err(format!(
                "Crypto state directory {} has permissions {:#o}, disallowing owner access",
                &dir.display(),
                unix_permission_bits
            ));
        }
        let permissions_all = unix_permission_bits & 0o007;
        if permissions_all != 0 {
            return Err(format!(
                "Crypto state directory {} has permissions {:#o}, allowing general access",
                &dir.display(),
                unix_permission_bits
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir as tempdir_deleted_at_end_of_scope;

    // TODO(CRP-1338): review the creation/usage of the temp dirs.
    pub fn mk_temp_dir_with_permissions(mode: u32) -> TempDir {
        let dir = tempdir_deleted_at_end_of_scope().unwrap();
        fs::set_permissions(dir.path(), Permissions::from_mode(mode))
            .expect("Could not set the permissions of the new test directory.");
        dir
    }

    fn serde_test(config: CryptoConfig) {
        let serialized = json5::to_string(&config).unwrap();
        let deserialized: CryptoConfig = json5::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn default_config_serializes_and_deserializes() {
        CryptoConfig::run_with_temp_config(|config| serde_test(config));
    }

    proptest! {
        #[test]
        #[ignore]
        // TODO(CRP-323): The current json5 implementation is buggy:
        // Unicode code points U+2028 and U+2029 are not escaped/parsed properly.
        // This test is disabled until issue is fixed.
        // https://github.com/callum-oakley/json5-rs/issues/21
        fn arbitrary_config_serializes_and_deserializes(config: CryptoConfig) {
            serde_test(config);
        }
    }

    #[test]
    fn should_create_path_as_directory() {
        CryptoConfig::run_with_temp_config(|config| assert!(config.crypto_root.is_dir()));
    }

    #[test]
    fn should_create_with_path_that_exists() {
        CryptoConfig::run_with_temp_config(|config| assert!(config.crypto_root.exists()));
    }

    #[test]
    fn should_set_correct_path_permissions() {
        CryptoConfig::run_with_temp_config(|config| {
            CryptoConfig::check_dir_has_required_permissions(&*config.crypto_root)
                .expect("Wrong direcotry permissions");
        })
    }

    #[test]
    fn config_dir_check_should_fail_for_paths_that_do_not_exist() {
        let dir_path = {
            let dir = tempdir_deleted_at_end_of_scope().unwrap();
            dir.path().to_owned()
        };
        let result = CryptoConfig::check_dir_has_required_permissions(&dir_path);
        assert!(result.is_err(), "{:?}", result);
    }

    #[test]
    fn config_dir_check_should_fail_for_paths_that_are_widely_readable() {
        let dir = mk_temp_dir_with_permissions(0o700);
        let result = CryptoConfig::check_dir_has_required_permissions(dir.as_ref());
        assert!(result.is_ok(), "{:?}", result);
        for mode in 0o701..=0o707 {
            let dir = mk_temp_dir_with_permissions(mode);
            let result = CryptoConfig::check_dir_has_required_permissions(dir.as_ref());
            assert!(result.is_err(), "{:?}", result);
        }
    }

    #[test]
    fn config_dir_check_should_fail_for_paths_that_are_not_accessible_for_owner() {
        let dir = mk_temp_dir_with_permissions(0o700);
        let result = CryptoConfig::check_dir_has_required_permissions(dir.as_ref());
        assert!(result.is_ok(), "{:?}", result);
        for mode in [0o000, 0o100, 0o200, 0o300, 0o400, 0o500, 0o600] {
            let dir = mk_temp_dir_with_permissions(mode);
            let result = CryptoConfig::check_dir_has_required_permissions(dir.as_ref());
            assert!(result.is_err(), "{:?}", result);
        }
    }
}
