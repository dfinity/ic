//! Shared helpers for wiping a node's subnet state.
//!
//! Used by both the regular `Upgrade` task (when a node becomes unassigned) and
//! by the `AiNodeManager` task (when an AI node loses or changes its
//! `AiNodeRecord.subnet_id`). Mirrors what was previously private to
//! `upgrade.rs::remove_node_state`.

use ic_logger::{ReplicaLogger, info};
use std::path::PathBuf;
use tokio::process::Command;

pub(crate) const KEY_CHANGES_FILENAME: &str = "key_changed_metric.cbor";

/// Deletes the subnet state consisting of the consensus pool, execution state,
/// the local CUP and the persisted error metric of threshold key changes.
///
/// Behavior matches the historical `remove_node_state` in `upgrade.rs`:
/// - removes the consensus pool dir entirely
/// - removes everything under the state root EXCEPT the `page_deltas/`
///   directory itself (its contents are emptied), to preserve SELinux
///   labelling for the sandbox
/// - removes the local CUP file
/// - removes the persisted master-public-key-changed metric file, if present
pub(crate) fn remove_node_state(
    replica_config_file: PathBuf,
    cup_path: PathBuf,
    orchestrator_data_directory: PathBuf,
) -> Result<(), String> {
    use ic_config::{Config, ConfigSource};
    use std::fs::{remove_dir_all, remove_file};
    let tmpdir = tempfile::Builder::new()
        .prefix("ic_config")
        .tempdir()
        .map_err(|err| format!("Couldn't create a temporary directory: {err:?}"))?;
    let config = Config::load_with_tmpdir(
        ConfigSource::File(replica_config_file),
        tmpdir.path().to_path_buf(),
    );

    let consensus_pool_path = config.artifact_pool.consensus_pool_path;
    if consensus_pool_path.exists() {
        remove_dir_all(&consensus_pool_path).map_err(|err| {
            format!("Couldn't delete the consensus pool at {consensus_pool_path:?}: {err:?}")
        })?;
    }

    let state_path = config.state_manager.state_root();

    if state_path.exists() {
        // We have to explicitly delete child sub-directories and files from the state_root,
        // instead of calling remove_dir_all(state_path) because
        // deleting the "page_deltas" directory results in a SELinux issue: upon deletion of
        // a directory/file, its SELinux class is not persisted if it's recreated. Upon
        // re-creation, the SELinux rights of the creator are applied, not the "old" ones.
        // Deleting the page_deltas directory would thus remove the sandbox capacity to
        // do IO in the page delta files.
        for entry in std::fs::read_dir(state_path.as_path()).map_err(|err| {
            format!(
                "Error iterating through dir {:?}, because {:?}",
                state_path.as_path(),
                err
            )
        })? {
            let en = entry
                .as_ref()
                .expect("Getting reference of dir entry failed.");
            // If this isn't the page deltas directory, it's safe to delete.
            if en
                .file_name()
                .into_string()
                .expect("Converting file name to string failed.")
                != config.state_manager.page_deltas_dirname()
            {
                if en
                    .file_type()
                    .expect("IO error fetching file type.")
                    .is_dir()
                {
                    remove_dir_all(en.path())
                } else {
                    std::fs::remove_file(en.path())
                }
                .map_err(|err| {
                    format!(
                        "Couldn't delete the path {:?}, because {:?}",
                        en.path(),
                        err
                    )
                })?;
            } else {
                // Look into the page_deltas/ directory and delete any possible leftover files.
                let page_deltas_dir = state_path
                    .as_path()
                    .join(config.state_manager.page_deltas_dirname());
                if page_deltas_dir.exists() {
                    for entry in std::fs::read_dir(&page_deltas_dir).map_err(|err| {
                        format!(
                            "Error iterating through dir {:?}, because {:?}",
                            page_deltas_dir, err
                        )
                    })? {
                        std::fs::remove_file(
                            entry.expect("Error getting file under page_delta/.").path(),
                        )
                        .map_err(|err| {
                            format!(
                                "Couldn't delete the file {:?}, because {:?}",
                                en.path(),
                                err
                            )
                        })?;
                    }
                }
            }
        }
    }

    if cup_path.exists() {
        remove_file(&cup_path)
            .map_err(|err| format!("Couldn't delete the CUP at {cup_path:?}: {err:?}"))?;
    }

    let key_changed_metric = orchestrator_data_directory.join(KEY_CHANGES_FILENAME);
    if key_changed_metric.try_exists().map_err(|err| {
        format!("Failed to check if {key_changed_metric:?} exists, because {err:?}")
    })? {
        remove_file(&key_changed_metric).map_err(|err| {
            format!("Couldn't delete the key changes metric at {key_changed_metric:?}: {err:?}")
        })?;
    }

    Ok(())
}

/// Best-effort `sync` + `fstrim` after wiping state. Errors are logged but not
/// propagated.
pub(crate) async fn sync_and_trim_fs(logger: &ReplicaLogger) -> Result<(), String> {
    let mut fstrim_script = Command::new("/opt/ic/bin/sync_fstrim.sh");
    info!(logger, "Running {fstrim_script:?}");
    match fstrim_script.status().await {
        Ok(status) => {
            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "Failed to run command '{fstrim_script:?}', return value: {status}"
                ))
            }
        }
        Err(err) => Err(format!(
            "Failed to run command '{fstrim_script:?}', error: {err}"
        )),
    }
}
