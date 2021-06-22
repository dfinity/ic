use crate::state_layout::CheckpointManager;
use crate::utils::do_copy;
use ic_logger::ReplicaLogger;
use std::io::Error;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// `BasicCheckpointManager` manages canister checkpoints and tip state
/// on traditional non copy-on-write filesystems. It use full file copy
/// and atomic renames to create checkpoints.
///
/// Checkpoints are created under "checkpoints" directory. fs_tmp directory
/// is used as intermediate scratchpad area. Additional directory structure
/// could be overlaid by state_layout on top of following directory structure.
///
/// The enforced layout is:
///
/// ```text
/// <root>
/// │
/// ├── backups
/// │   └──<name>
/// │      └── ...
/// |
/// ├── checkpoints
/// │   └──<name>
/// │      └── ...
/// │
/// ├── diverged_checkpoints
/// │   └──<name>
/// │      └── ...
/// |
/// └── fs_tmp
/// ```
///
/// # Notes on FS syncing
///
/// For correctness reasons we need to make sure that checkpoints we create are
/// internally consistent and only "publish" them in the `checkpoints` directory
/// once they are fully synced to disk.
///
/// There are 2 ways to construct a checkpoint:
///   1. Compute it locally by applying blocks to an older state.
///   2. Fetch it from a peer using the state sync protocol.
///
/// Let's look at how each case is handled.
///
/// ## Promoting a TIP to a checkpoint
///
///   1. Dump the state to files and directories under "<state_root>/tip", sync
///      all the files.  This sync is probably not required, but it makes
///      it easier to reason about reflinking (see the next step).
///
///   2. Reflink/copy all the files from "<state_root>/tip" to
///      "<state_root>/fs_tmp/scratchpad_<height>", sync both files and
///      directories under the scratchpad directory, including the scratchpad
///      directory itself.
///
///   3. Rename "<state_root>/fs_tmp/scratchpad_<height>" to
///      "<state_root>/checkpoints/<height>", sync "<state_root>/checkpoints".
///
/// ## Promoting a State Sync artifact to a checkpoint
///
///   1. Create state files directly in
///      "<state_root>/fs_tmp/state_sync_scratchpad_<height>".
///
///   2. When all the writes are complete, call sync_and_mark_files_readonly()
///      on "<state_root>/fs_tmp/state_sync_scratchpad_<height>".  This function
///      syncs all the files and directories under the scratchpad directory,
///      including the scratchpad directory itself.
///
///   3. Rename "<state_root>/fs_tmp/state_sync_scratchpad_<height>" to
///      "<state_root>/checkpoints/<height>", sync "<state_root>/checkpoints".
#[derive(Clone)]
pub struct BasicCheckpointManager {
    root: PathBuf,
    log: ReplicaLogger,
}

impl BasicCheckpointManager {
    pub fn new(log: ReplicaLogger, root: PathBuf) -> Self {
        Self { log, root }
    }

    fn tmp(&self) -> PathBuf {
        self.root.join("fs_tmp")
    }

    fn checkpoints(&self) -> PathBuf {
        self.root.join("checkpoints")
    }

    fn diverged_checkpoints(&self) -> PathBuf {
        self.root.join("diverged_checkpoints")
    }

    fn backups(&self) -> PathBuf {
        self.root.join("backups")
    }

    fn ensure_dir_exists(&self, p: &PathBuf) -> std::io::Result<()> {
        std::fs::create_dir_all(&p.as_path())
    }

    /// Atomically copies a checkpoint with the specified name located at src
    /// path into the specified dst path.
    fn copy_checkpoint(&self, name: &str, src: &Path, dst: &Path) -> std::io::Result<()> {
        let scratch_name = format!("scratchpad_{}", name);
        let scratchpad = self.tmp().join(&scratch_name);
        self.ensure_dir_exists(&scratchpad)?;

        if dst.exists() {
            return Err(Error::new(io::ErrorKind::AlreadyExists, name));
        }

        let copy_atomically = || {
            copy_recursively_respecting_tombstones(
                &self.log,
                src,
                scratchpad.as_path(),
                FilePermissions::ReadOnly,
            )?;
            std::fs::rename(&scratchpad, &dst)
        };

        match copy_atomically() {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = std::fs::remove_dir_all(&scratchpad);
                Err(err)
            }
        }
    }

    /// Atomically removes path by first renaming it into tmp_path, and then
    /// deleting tmp_path.
    fn atomically_remove_via_path(&self, path: &Path, tmp_path: &Path) -> std::io::Result<()> {
        // We first move the checkpoint directory into a temporary directory to
        // maintain the invariant that <root>/checkpoints/<height> are always
        // internally consistent.
        match std::fs::rename(&path, &tmp_path) {
            Ok(_) => (),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(err) => return Err(err),
        }
        std::fs::remove_dir_all(&tmp_path)
    }
}

impl CheckpointManager for BasicCheckpointManager {
    fn raw_path(&self) -> &Path {
        &self.root
    }

    fn tip_to_checkpoint(&self, tip: &Path, name: &str) -> std::io::Result<PathBuf> {
        self.ensure_dir_exists(&self.checkpoints())?;
        let cp_path = self.checkpoints().join(name);

        if cp_path.exists() {
            return Err(Error::new(io::ErrorKind::AlreadyExists, name));
        }
        self.copy_checkpoint(name, tip, cp_path.as_path())?;
        Ok(cp_path)
    }

    fn scratchpad_to_checkpoint(&self, scratchpad: &Path, name: &str) -> std::io::Result<PathBuf> {
        self.ensure_dir_exists(&self.checkpoints())?;
        sync_and_mark_files_readonly(scratchpad)?;
        let checkpoints_path = self.checkpoints();
        let cp_path = checkpoints_path.join(name);
        std::fs::rename(scratchpad, &cp_path)?;
        sync_path(&checkpoints_path)?;
        Ok(cp_path)
    }

    fn checkpoint_to_scratchpad(&self, name: &str, scratchpad: &Path) -> std::io::Result<()> {
        let cp_path = self.checkpoints().join(name);
        copy_recursively_respecting_tombstones(
            &self.log,
            &cp_path,
            scratchpad,
            FilePermissions::ReadWrite,
        )
    }

    fn get_checkpoint_path(&self, name: &str) -> PathBuf {
        self.checkpoints().join(name)
    }

    fn remove_checkpoint(&self, name: &str) -> std::io::Result<()> {
        let cp_name = Path::new(&name);
        let cp_path = self.checkpoints().join(cp_name);
        let tmp_path = self.tmp().join(cp_name);

        self.atomically_remove_via_path(&cp_path, &tmp_path)?;
        sync_path(&self.checkpoints())
    }

    fn mark_checkpoint_diverged(&self, name: &str) -> std::io::Result<()> {
        let cp_path = self.get_checkpoint_path(name);
        let diverged_checkpoints_dir = self.diverged_checkpoints();
        self.ensure_dir_exists(&diverged_checkpoints_dir)?;

        let dst_path = diverged_checkpoints_dir.join(name);

        match std::fs::rename(&cp_path, &dst_path) {
            Ok(()) => sync_path(&self.checkpoints()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    fn backup_checkpoint(&self, name: &str) -> std::io::Result<()> {
        let cp_path = self.get_checkpoint_path(name);
        if !cp_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Cannot backup non-existent checkpoint {}", name),
            ));
        }

        let backups_dir = self.backups();
        self.ensure_dir_exists(&backups_dir)?;
        let dst = backups_dir.join(name);
        self.copy_checkpoint(name, cp_path.as_path(), dst.as_path())?;
        sync_path(&backups_dir)
    }

    fn list_diverged_checkpoints(&self) -> std::io::Result<Vec<String>> {
        dir_file_names(&self.diverged_checkpoints())
    }

    fn get_diverged_checkpoint_path(&self, name: &str) -> PathBuf {
        self.diverged_checkpoints().join(name)
    }

    fn get_backup_path(&self, name: &str) -> PathBuf {
        self.backups().join(name)
    }

    fn remove_diverged_checkpoint(&self, name: &str) -> std::io::Result<()> {
        let cp_path = self.diverged_checkpoints().join(name);
        let tmp_path = self.tmp().join(format!("diverged_checkpoint_{}", name));
        self.atomically_remove_via_path(&cp_path, &tmp_path)
    }

    fn remove_backup(&self, name: &str) -> std::io::Result<()> {
        let backup_path = self.backups().join(name);
        let tmp_path = self.tmp().join(format!("backup_{}", name));
        self.atomically_remove_via_path(backup_path.as_path(), tmp_path.as_path())
    }

    fn list_checkpoints(&self) -> std::io::Result<Vec<String>> {
        dir_file_names(&self.checkpoints())
    }

    fn list_backups(&self) -> std::io::Result<Vec<String>> {
        dir_file_names(&self.backups())
    }

    fn reset_tip_to(&self, tip: &PathBuf, name: &str) -> std::io::Result<()> {
        if tip.exists() {
            std::fs::remove_dir_all(tip.as_path())?;
        }

        let cp_path = self.checkpoints().join(name);
        if !cp_path.exists() {
            return Ok(());
        }

        match copy_recursively_respecting_tombstones(
            &self.log,
            cp_path.as_path(),
            tip.as_path(),
            FilePermissions::ReadWrite,
        ) {
            Ok(()) => Ok(()),
            Err(e) => {
                std::fs::remove_dir_all(&tip.as_path())?;
                Err(e)
            }
        }
    }
}

fn dir_file_names(p: &Path) -> std::io::Result<Vec<String>> {
    if !p.exists() {
        return Ok(vec![]);
    }
    let mut result = vec![];
    for e in p.read_dir()? {
        let string = e?.file_name().into_string().map_err(|file_name| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to convert file name {:?} to string", file_name),
            )
        })?;
        result.push(string);
    }
    Ok(result)
}

#[derive(Clone, Copy)]
enum FilePermissions {
    ReadOnly,
    ReadWrite,
}

/// Recursively copies `src` to `dst` using the given permission policy for
/// files. Directories containing a file called "tombstone" are not copied to
/// the destination.
///
/// NOTE: If the function returns an error, the changes to the file
/// system applied by this function are not undone.
fn copy_recursively_respecting_tombstones(
    log: &ReplicaLogger,
    src: &Path,
    dst: &Path,
    dst_permissions: FilePermissions,
) -> std::io::Result<()> {
    let src_metadata = src.metadata()?;

    if src_metadata.is_dir() {
        if src.join("tombstone").exists() {
            // The source directory was marked as removed by placing a
            // 'tombstone' file inside. We don't want this directory in
            // a checkpoint.
            return Ok(());
        }

        let entries = src.read_dir()?;

        // Note: all the files and directories below DST and DST itself will be
        // synced after this function returns.  However, create_dir_all might
        // create some parents that won't be synced. It's fine because
        //
        //   1. We only care about internal consistency of checkpoints, and the
        //   parents create_dir_all might have created do not belong to a
        //   checkpoint.
        //
        //   2. We only invoke this function with DST being a child of a
        //   directory that is wiped out on replica start, so we don't care much
        //   about this temporary directory being properly synced.
        fs::create_dir_all(&dst)?;

        for entry_result in entries {
            let entry = entry_result?;
            let dst_entry = dst.join(entry.file_name());
            copy_recursively_respecting_tombstones(
                log,
                &entry.path(),
                &dst_entry,
                dst_permissions,
            )?;
        }
    } else {
        do_copy(log, src, dst)?;

        // We keep the directory writable though to make sure we can rename
        // them or delete the files.
        let dst_metadata = dst.metadata()?;
        let mut permissions = dst_metadata.permissions();
        match dst_permissions {
            FilePermissions::ReadOnly => permissions.set_readonly(true),
            FilePermissions::ReadWrite => permissions.set_readonly(false),
        }
        fs::set_permissions(dst, permissions)?;
    }

    // Note that the directory is synced after all the files and directories in
    // it had been recursively synced.
    sync_path(dst)
}

/// Recursively set permissions to readonly for all files under the given
/// `path`.
fn sync_and_mark_files_readonly(path: &Path) -> std::io::Result<()> {
    let metadata = path.metadata()?;

    if metadata.is_dir() {
        let entries = path.read_dir()?;

        for entry_result in entries {
            let entry = entry_result?;
            sync_and_mark_files_readonly(&entry.path())?;
        }
    } else {
        // We keep directories writable to be able to rename them or delete the
        // files.
        let mut permissions = metadata.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions).map_err(|e| {
            Error::new(
                e.kind(),
                format!(
                    "failed to set readonly permissions for file {}: {}",
                    path.display(),
                    e
                ),
            )
        })?;
    }
    sync_path(path)
}

/// Invokes sync_all on the file or directory located at given path.
fn sync_path(path: &Path) -> std::io::Result<()> {
    // There is no special API for syncing directories, so we do the same thing
    // for both files and directories. This works because directories are just
    // files treated in a special way by the kernel.
    let f = std::fs::File::open(path)?;
    f.sync_all().map_err(|e| {
        Error::new(
            e.kind(),
            format!("failed to sync path {}: {}", path.display(), e),
        )
    })
}
