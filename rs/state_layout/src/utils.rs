use ic_logger::{warn, ReplicaLogger};
use ic_sys::fs::copy_file_sparse;
use std::io::Error;
use std::path::Path;

/// Copies `src` into `dst`.
///
/// Attempts to make a reflink (copy-on-write clone) of `src` into `dst` first.
/// If reflinks aren't supported by the FS, logs a warning and falls back to a
/// regular file copy.
pub fn do_copy(log: &ReplicaLogger, src: &Path, dst: &Path) -> std::io::Result<()> {
    use ic_sys::fs::FileCloneError;
    use std::sync::atomic::{AtomicBool, Ordering};

    static ON_COW_FS: AtomicBool = AtomicBool::new(true);
    static SAME_FS: AtomicBool = AtomicBool::new(true);

    let on_err = |e: Error| -> Error {
        Error::new(
            e.kind(),
            format!(
                "failed to copy {} -> {}: {}",
                src.display(),
                dst.display(),
                e
            ),
        )
    };

    if ON_COW_FS.load(Ordering::Relaxed) && SAME_FS.load(Ordering::Relaxed) {
        match ic_sys::fs::clone_file(src, dst) {
            Err(FileCloneError::DifferentFileSystems) => {
                if SAME_FS.swap(false, Ordering::Relaxed) {
                    warn!(
                        log,
                        "state_manager.state_root spans multiple filesystems \
                           (attempted to reflink {} => {}), running big canisters can be very slow",
                        src.display(),
                        dst.display()
                    );
                }
                copy_file_sparse(src, dst).map_err(on_err)?;
                Ok(())
            }
            Err(FileCloneError::OperationNotSupported) => {
                if ON_COW_FS.swap(false, Ordering::Relaxed) {
                    warn!(
                        log,
                        "StateManager runs on a filesystem not supporting reflinks \
                         (attempted to reflink {} => {}), running big canisters can be very slow",
                        src.display(),
                        dst.display(),
                    );
                }
                copy_file_sparse(src, dst).map_err(on_err)?;
                Ok(())
            }
            Err(FileCloneError::IoError(e)) => Err(Error::new(
                e.kind(),
                format!(
                    "failed to clone {} -> {}: {}",
                    src.display(),
                    dst.display(),
                    e
                ),
            )),
            Ok(()) => Ok(()),
        }
    } else {
        copy_file_sparse(src, dst).map_err(on_err)?;
        Ok(())
    }
}

/// Copies `src` into `dst` using do_copy semantics overwriting destination if
/// it exists
pub fn do_copy_overwrite(log: &ReplicaLogger, src: &Path, dst: &Path) -> std::io::Result<()> {
    if dst.exists() {
        std::fs::remove_file(dst)?;
    }
    do_copy(log, src, dst)
}

/// Marks `src` as readonly and then hardlinks it to `dst` overwriting the destination if it exists.
pub fn mark_readonly_and_hardlink_file(
    _log: &ReplicaLogger,
    src: &Path,
    dst: &Path,
) -> std::io::Result<()> {
    let src_metadata = src.metadata()?;
    if !src_metadata.permissions().readonly() {
        // writable src should come from state_sync_cache, not checkpoint.
        debug_assert!(src.to_string_lossy().contains("state_sync_cache"));
        debug_assert!(!src.to_string_lossy().contains("checkpoint"));
        // writable src should be newly downloaded, not hardlinked from checkpoint.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            debug_assert_eq!(src_metadata.nlink(), 1);
        }
        // Mark src as readonly.
        let mut permissions = src_metadata.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(src, permissions)?;
    }
    // Hardlink requires the destination to not exist.
    if dst.exists() {
        std::fs::remove_file(dst)?;
    }
    std::fs::hard_link(src, dst)
}
